# -*- coding: utf-8 -*-
"""PDF 报告导出：含测试 URL、Payload、影响证明与深入利用结果。"""
import re
from pathlib import Path

from sqlalchemy.orm import Session

from app.core import config
from app.models.endpoint import Endpoint
from app.models.task import Task
from app.models.vuln import Evidence, Vulnerability

_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\simhei.ttf",
    r"C:\Windows\Fonts\msyh.ttf",
    r"C:\Windows\Fonts\deng.ttf",
    r"C:\Windows\Fonts\simfang.ttf",
]


def find_cjk_font() -> str | None:
    for f in _FONT_CANDIDATES:
        if Path(f).exists():
            return f
    return None


def build_report(db: Session, task_id: int) -> Path:
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise ValueError("任务不存在")
    vulns = (db.query(Vulnerability, Endpoint)
             .join(Endpoint, Vulnerability.endpoint_id == Endpoint.id)
             .filter(Vulnerability.task_id == task_id)
             .order_by(Vulnerability.severity.desc()).all())

    out_dir = Path(config.DATA_DIR) / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    font = find_cjk_font()
    if font is None:
        return _build_txt(out_dir, task, vulns, db)
    return _build_pdf(out_dir, task, vulns, font, db)


def _waf_lines(db: Session, task_id: int) -> list[str]:
    """只有**确认存在 WAF**时才输出画像段；没有就整段不出现。"""
    from app.models.waf import WafProfile
    row = db.query(WafProfile).filter(WafProfile.task_id == task_id).first()
    if not row or not row.has_waf:
        return []
    lines = ["", "━━━ WAF 画像 ━━━",
             f"产品: {row.product or 'unknown'}"
             f"（置信度 {row.product_confidence or 0}）"]
    if row.block_behavior:
        lines.append(f"拦截行为: {row.block_behavior}")
    if row.bypass_suggestions:
        lines.append(f"建议绕过策略: {row.bypass_suggestions}")
    if row.probe_history:
        lines.append(f"探测记录: {str(row.probe_history)[:400]}")
    return lines


def _test_url(task: Task, e: Endpoint) -> str:
    scheme = "https" if (task.target or "").startswith("https") else "http"
    path = (e.raw_path or e.path or "/").split("?")[0]
    q = {}
    for p in (e.params or []):
        if p.get("location") in (None, "query"):
            q[p["name"]] = p.get("sample_value") or "1"
    from urllib.parse import urlencode
    url = f"{scheme}://{e.host}{path}"
    if q:
        url += "?" + urlencode(q)
    return url


# 只有这些阶段产出的表信息可信；union_extract / ai_char_union 在非 SQLite
# 靶点上会把 PHP 报错页单词当表名（Less-23 实测），不得进入报告。
# stop/result 只是状态汇总，可能把旧的脏 state 再带一遍，也不可信。
_TRUSTED_TABLE_STAGES = {"impact_tables", "dump_result"}

# 表名列表里一旦出现 PHP 报错特征，整份列表都判为噪声（而不是只删几个词）。
_TYPE_CN = {
    "sql_injection_boolean": "SQL注入·布尔盲注",
    "sql_injection_time": "SQL注入·时间盲注",
    "sql_injection_error": "SQL注入·报错注入",
    "sql_injection_union": "SQL注入·UNION注入",
}
_SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
_STATUS_CN = {"pending_review": "待复核", "confirmed": "已确认",
              "false_positive": "误报"}

_TABLE_ERROR_TOKENS = {
    "mysql_fetch_array", "phpstudy", "expects", "warning", "notice",
    "deprecated", "fatal", "parse", "uncaught", "undefined", "stack",
    "trace", "php", "www", "sqli", "labs", "dhakkan",
}


def _clean_tables(items) -> list[str]:
    vals = [str(t).strip() for t in (items or []) if str(t).strip()]
    if any(v.lower() in _TABLE_ERROR_TOKENS for v in vals):
        return []
    return vals
_TRUSTED_SCHEMA_STAGES = {"impact_current_db", "impact_db_name", "current_db",
                          "db_name", "stop", "result", "blind_extract", "reuse",
                          "budget", "unreachable"}


def _deep_score(ev) -> int:
    """深入利用证据排序：带 flag > 带可信库/表 > 流程记录。"""
    meta = ev.meta or {}
    content = ev.content or ""
    stage = str(meta.get("stage") or "")
    score = 0
    if meta.get("flag_sample") or "flag{" in content:
        score += 100
    if stage in _TRUSTED_TABLE_STAGES and (
            meta.get("tables") or meta.get("dbs") or meta.get("database") or meta.get("db")):
        score += 50
    if stage in _TRUSTED_SCHEMA_STAGES:
        score += 10
    return score


def _deep_facts(evids) -> tuple[str, list[str], str]:
    """汇总数据库名/schema、表、样例：结构化 meta 优先，文本兜底。

    PostgreSQL 的 `--current-db` 只返回 schema（public），真实库名由
    deep_exploit 的 `current_database()` 步骤补取；两者都有时显示
    `appdb (schema=public)`。
    """
    db_name, schema, tables, sample = "", "", [], ""
    deeps = sorted([e for e in evids if e.evidence_type == "deep_exploit"],
                   key=lambda e: (_deep_score(e), getattr(e, "seq", 0)),
                   reverse=True)
    for ev in deeps:
        meta = ev.meta or {}
        text = ev.content or ""
        stage = str(meta.get("stage") or "")
        if not db_name and stage in _TRUSTED_SCHEMA_STAGES:
            db_name = meta.get("db_name") or ""
            if not db_name:
                m = re.search(r"真实数据库名\s*[:：]\s*([\w\-.$]+)", text)
                if m:
                    db_name = m.group(1)
        if not schema and stage in _TRUSTED_SCHEMA_STAGES:
            schema = meta.get("schema") or ""
            if not schema:
                d = meta.get("dbs")
                if isinstance(d, list) and d:
                    schema = str(d[0])
                elif isinstance(d, str) and d.strip():
                    schema = d.strip()
            if not schema:
                schema = meta.get("db") or meta.get("database") or ""
            if not schema:
                m = re.search(
                    r"(?:current database[^:\n]*|database|库/schema)\s*[:=]\s*'?([\w\-.$]+)",
                    text, re.I)
                if m:
                    schema = m.group(1)
        if not tables and stage in _TRUSTED_TABLE_STAGES:
            t = meta.get("tables")
            if isinstance(t, list):
                tables = _clean_tables(t)
            elif isinstance(t, str) and t.strip():
                tables = _clean_tables(re.split(r"[,，]", t))
            if not tables:
                m = re.search(r"(?:tables|表)\s*[:=]\s*\[([^\]]*)\]", text, re.I)
                if m:
                    tables = _clean_tables(x.strip().strip("'\"")
                                           for x in m.group(1).split(","))
        if not sample:
            sample = meta.get("flag_sample") or ""
            if not sample:
                m = re.search(r"flag\{[^}]+\}", text, re.I)
                if m:
                    sample = m.group(0)
    display = db_name or schema
    if db_name and schema and db_name != schema:
        display = f"{db_name} (schema={schema})"
    return display, tables, sample


def _deep_extra(evids) -> str:
    for ev in sorted([e for e in evids if e.evidence_type == "deep_exploit"],
                     key=lambda e: (_deep_score(e), getattr(e, "seq", 0)),
                     reverse=True):
        extra = (ev.meta or {}).get("extra")
        if extra:
            return " ".join(str(x) for x in extra)
    return ""


def _deep_extract(evids) -> str:
    """返回“用什么方式拿到库名/表”：sqlmap 命令优先，其次等价 SQL。

    用户要求：如果是 sqlmap 跑的，就展示 sqlmap 的实际语句/参数，
    不要用推测出来的 SELECT。
    """
    deeps = sorted([e for e in evids if e.evidence_type == "deep_exploit"],
                   key=lambda e: (_deep_score(e), getattr(e, "seq", 0)),
                   reverse=True)
    # 1) 优先：任何一条证据里记录的 sqlmap 参数（extract_extra / extra）
    for ev in deeps:
        meta = ev.meta or {}
        extra = meta.get("extract_extra") or meta.get("extra")
        if isinstance(extra, list) and extra:
            return "sqlmap " + " ".join(str(x) for x in extra)
    # 2) 新证据的显式 query
    for ev in deeps:
        q = (ev.meta or {}).get("extract_query")
        if q:
            return str(q)
    # 3) 旧证据兜底：按 impact_* 阶段反推等价语句
    for ev in deeps:
        meta = ev.meta or {}
        stage = str(meta.get("stage") or "")
        dbms = str(meta.get("dbms") or "").lower()
        d = meta.get("dbs")
        schema = (str(d[0]) if isinstance(d, list) and d else "") or str(meta.get("schema") or "")
        if stage == "impact_current_db":
            return "SELECT current_schema()" if "postgres" in dbms else "SELECT DATABASE()"
        if stage == "impact_db_name":
            return "SELECT current_database()"
        if stage == "impact_tables" and schema:
            return (f"SELECT table_name FROM information_schema.tables "
                    f"WHERE table_schema='{schema}'")
    return ""


def _payload_texts(evids) -> list[str]:
    """确认 Payload：payload 证据优先；缺失时从 sqlmap 原始输出兜底。

    超时升级为 vuln_confirmed 的旧数据可能没有 payload 证据行，
    但 console_log / deep_exploit 里的 `Payload:` 行仍然可用。
    """
    payloads = [x.content for x in evids if x.evidence_type == "payload"]
    if not payloads:
        for ev in evids:
            m = re.search(r"^\s*Payload:\s*(.+)$", ev.content or "", re.I | re.M)
            if m:
                payloads.append(m.group(1).strip())
                break
    # 优先展示真正起作用的绕过 payload（/**/、关键字双写），而不是探测期的 `1'`
    def _score(p: str) -> int:
        low = (p or "").lower()
        s = 0
        if "/**/" in low:
            s += 10000
        if "uunionnion" in low and "sselectelect" in low:
            s += 6000
        elif "uunionnion" in low or "sselectelect" in low:
            s += 3000
        # sqlite_master 是 SQLite 专用探测词，不能排在 MySQL 靶点的确认 Payload 前面
        if "sqlite_master" in low:
            s -= 4000
        return s + len(p or "")
    return sorted(payloads, key=_score, reverse=True)


def _key_evidence(evids) -> list[str]:
    """从 sqlmap console/log 证据里提取关键判定行（报告“获取过程”用）。"""
    pat = re.compile(
        r"back-end DBMS|appears to be .*injectable|technique appears to be usable|"
        r"current database|fetched data|\[\d+\s+tables?\]|"
        r"identified the following injection", re.I)
    out = []
    for ev in evids:
        if ev.evidence_type not in ("console_log", "deep_exploit"):
            continue
        for line in (ev.content or "").splitlines():
            if pat.search(line):
                line = line.strip()
                if line and line not in out:
                    out.append(line)
    return out[:4]


def _vuln_lines(task, vulns, db: Session) -> list[str]:
    lines = [
        f"任务: {task.name}  (#{task.id})",
        f"目标: {task.target}",
        f"状态: {task.status}    生成时间: {task.updated_at or task.created_at}",
        f"漏洞总数: {len(vulns)}  (confirmed={sum(1 for v, _ in vulns if v.status == 'confirmed')},"
        f" pending_review={sum(1 for v, _ in vulns if v.status == 'pending_review')},"
        f" false_positive={sum(1 for v, _ in vulns if v.status == 'false_positive')})",
        "",
    ]
    # 仅有 WAF 时才加画像段（用户要求：没有就不出现）
    lines += _waf_lines(db, task.id)
    for i, (v, e) in enumerate(vulns, 1):
        test_url = _test_url(task, e)
        evids = (db.query(Evidence).filter(Evidence.vulnerability_id == v.id)
                 .order_by(Evidence.seq.asc()).all())
        payloads = _payload_texts(evids)
        db_name, tables, sample = _deep_facts(evids)
        extract_query = _deep_extract(evids)
        key_lines = _key_evidence(evids)
        cmd_extra = _deep_extra(evids)

        lines += [
            f"━━━ 漏洞 {i} ━━━",
            f"标题: {v.title}",
            f"类型: {_TYPE_CN.get(v.vuln_type, v.vuln_type)}   "
            f"严重度: {_SEV_CN.get(v.severity, v.severity)}   "
            f"状态: {_STATUS_CN.get(v.status, v.status)}",
            f"接口: {e.method} {e.host}{e.raw_path or e.path}",
            f"测试URL: {test_url}",
            f"请求方法: {e.method}",
            f"参数: {e.params}",
            f"数据库类型: {v.dbms or '未知'}   命中向量数: {v.vector_count}",
            "确认 Payload:",
        ]
        if payloads:
            lines += [f"  {p[:500]}" for p in payloads[:3]]
        else:
            lines.append("  （无）")

        lines.append("影响证明:")
        lines.append(f"  - 注入类型: {_TYPE_CN.get(v.vuln_type, v.vuln_type)}"
                     f"（数据库类型={v.dbms or '未知'}）")
        lines.append(f"  - 当前库/schema: {db_name or '（未取得）'}")
        lines.append(f"  - 表: {', '.join(tables) if tables else '（未取得）'}")
        lines.append(f"  - 数据样本/flag: {sample or '（未取得）'}")

        lines.append("获取过程:")
        lines.append(f"  - 测试URL: {test_url}")
        lines.append(f"  - 请求方法: {e.method}   参数: "
                     f"{[p.get('name') for p in (e.params or [])]}")
        if extract_query:
            _label = ("sqlmap 提取命令" if extract_query.startswith("sqlmap ")
                      else "提取语句")
            lines.append(f"  - {_label}: {extract_query[:600]}")
        elif cmd_extra:
            lines.append(f"  - sqlmap 参数: {cmd_extra[:600]}")
        if key_lines:
            lines.append("  - 关键判定:")
            lines += [f"      {ln[:300]}" for ln in key_lines]
        else:
            lines.append("  - 关键判定: （无结构化记录）")

        lines.append("结论:")
        _concl = (f"  已确认 {_TYPE_CN.get(v.vuln_type, v.vuln_type)}"
                  f"（{v.dbms or '未知'}），当前库/schema={db_name or '未取得'}")
        if tables:
            _concl += f"，表={', '.join(tables)}"
        if sample:
            _concl += f"，数据样本={sample}"
        lines.append(_concl)
        lines.append("加固建议:")
        lines += [f"  - {a}" for a in (v.hardening_advice or [])]
        lines.append("")
    return lines


def _build_pdf(out_dir: Path, task, vulns, font: str, db: Session) -> Path:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_font("cjk", "", font)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("cjk", size=16)
    pdf.cell(0, 10, "mhszed-sql Web 安全测试报告", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    pdf.set_font("cjk", size=10.5)
    for line in _vuln_lines(task, vulns, db):
        safe = line.encode("gbk", "replace").decode("gbk")
        pdf.multi_cell(0, 6.5, safe, new_x="LMARGIN", new_y="NEXT")

    out = out_dir / f"report_task_{task.id}.pdf"
    pdf.output(str(out))
    return out


def _build_txt(out_dir: Path, task, vulns, db: Session) -> Path:
    out = out_dir / f"report_task_{task.id}.txt"
    out.write_text("\n".join(_vuln_lines(task, vulns, db)), encoding="utf-8")
    return out
