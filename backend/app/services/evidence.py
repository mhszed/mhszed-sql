# -*- coding: utf-8 -*-
"""证据归档：漏洞产出、证据链（只追加）、场景化加固建议、PDF 报告导出。"""
import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from app.core import config
from app.models.base import utcnow_iso
from app.models.endpoint import Endpoint
from app.models.task import Task
from app.models.vuln import Evidence, Vulnerability
from app.services import knowledge
from app.services.event_bus import bus

# ============ 加固建议库（按 漏洞类型 × DBMS 场景化） ============

_ADVICE_BASE = {
    "sql_injection_boolean": [
        "使用参数化查询（预编译语句），禁止将用户输入拼接进 SQL 文本",
        "对该接口的所有入参做服务端白名单校验（类型/长度/字符集）",
    ],
    "sql_injection_time": [
        "使用参数化查询；数据库账号最小权限化，禁用 SLEEP/BENCHMARK 类函数调用权限",
        "为该接口配置请求超时与异常监控，盲注时延特征应触发告警",
    ],
    "sql_injection_error": [
        "使用参数化查询；生产环境关闭数据库报错回显（详细错误只写日志）",
        "统一错误响应模板，避免把数据库原始错误返回给客户端",
    ],
    "sql_injection_union": [
        "使用参数化查询；查询结果只返回业务所需字段，禁止 SELECT * 透出",
        "对返回行数与字段数做服务端限制，破坏 UNION 回显的可用性",
    ],
}

_ADVICE_DBMS = {
    "mysql": ["开启 sql_mode=STRICT_ALL_TABLES；应用侧避免拼接 ORDER BY/表名字段"],
    "mssql": ["最小权限数据库账号；禁用 xp_cmdshell 等扩展存储过程"],
    "postgresql": ["使用 $n 占位符预编译；数据库账号回收 SUPERUSER 权限"],
    "oracle": ["使用绑定变量；回收 DBA 角色与 UTL_HTTP 等危险包的 EXECUTE 权限"],
}

_SEVERITY_BY_TYPE = {
    "sql_injection_union": "critical",
    "sql_injection_error": "high",
    "sql_injection_boolean": "high",
    "sql_injection_time": "high",
}


def build_advice(vuln_type: str, dbms: str | None) -> list[str]:
    advice = list(_ADVICE_BASE.get(vuln_type, ["使用参数化查询，禁止拼接用户输入"]))
    if dbms:
        for key, tips in _ADVICE_DBMS.items():
            if key in (dbms or "").lower():
                advice.extend(tips)
                break
    return advice


# ============ 漏洞产出 ============

def create_vulnerability(db: Session, *, task_id: int, endpoint: Endpoint,
                         scan_job_id: int | None, vuln_type: str, title: str,
                         dbms: str | None = None, vector_count: int = 1,
                         hits: list[dict] | None = None) -> Vulnerability:
    vuln = Vulnerability(
        task_id=task_id, endpoint_id=endpoint.id, scan_job_id=scan_job_id,
        vuln_type=vuln_type, severity=_SEVERITY_BY_TYPE.get(vuln_type, "high"),
        title=title, dbms=dbms, vector_count=vector_count,
        status="pending_review",                    # 闸门④：一律人工复核
        hardening_advice=build_advice(vuln_type, dbms),
    )
    db.add(vuln)
    db.flush()

    # ---- 证据链 ----
    seq = 1
    for h in (hits or []):
        # meta 带结构化 payload（原文照抄，不做任何拆分）：deep_exploit 取注入语境
        # 直接读 meta，不再从文本反解析——payload 里含 `=` 时旧的 split("=",1)
        # 会把 `1' and '1'='1` 砍成 `'1`，直接卡死深入利用（47887 实测）
        seq = _add_evidence(db, vuln.id, seq, "payload",
                            f"[{h.get('vector')}] {h.get('payload')}\n预期判据: {h.get('criteria')}",
                            meta={"vector": h.get("vector"), "payload": h.get("payload"),
                                  "criteria": h.get("criteria"),
                                  # 受控时间对等强证据：深挖取注入语境时优先，
                                  # 避免被「带 /**/ 的普通布尔命中」抢走（2026-10-23）
                                  "controlled": bool(h.get("controlled"))})
    # WAF 信息
    from app.models.waf import WafProfile
    wp = db.query(WafProfile).filter(WafProfile.task_id == task_id).first()
    if wp:
        seq = _add_evidence(db, vuln.id, seq, "waf_info",
                            f"has_waf={bool(wp.has_waf)} product={wp.product} "
                            f"confidence={wp.product_confidence}")
    # 业务链路信息
    if endpoint.chain_id:
        from app.models.endpoint import BusinessChain
        chain = db.query(BusinessChain).filter(BusinessChain.id == endpoint.chain_id).first()
        if chain:
            seq = _add_evidence(db, vuln.id, seq, "chain_info",
                                f"链路[{chain.reconstruct_method}] conf={chain.confidence}: {chain.name}")
    # 接口请求特征
    seq = _add_evidence(db, vuln.id, seq, "request",
                        f"{endpoint.method} {endpoint.host}{endpoint.raw_path or endpoint.path}\n"
                        f"params={endpoint.params}")

    db.commit()
    bus.publish("vuln", f"产出漏洞（待复核）: {title}", task_id=task_id, level="error")
    return vuln


def add_response_evidence(db: Session, vuln_id: int, seq: int, response_text: str,
                          status_code: int, elapsed_ms: int) -> int:
    return _add_evidence(db, vuln_id, seq, "response", response_text[:20000],
                         meta={"http_status": status_code, "elapsed_ms": elapsed_ms})


def _add_evidence(db: Session, vuln_id: int, seq: int, etype: str, content: str,
                  meta: dict | None = None) -> int:
    row = Evidence(
        vulnerability_id=vuln_id, evidence_type=etype, seq=seq,
        content=content, meta=meta or {"bytes": len(content)},
        sha256=hashlib.sha256(content.encode("utf-8", "replace")).hexdigest(),
        created_at=utcnow_iso(),
    )
    db.add(row)
    return seq + 1


def append_evidence(db: Session, vuln_id: int, etype: str, content: str,
                    meta: dict | None = None) -> int:
    """对外追加证据（深入利用等）；自动分配 seq。"""
    seq = (db.query(Evidence).filter(Evidence.vulnerability_id == vuln_id).count()) + 1
    # evidence_type 列宽 16：deep_exploit=12 OK；过长则落 console_log
    if len(etype) > 16:
        meta = {**(meta or {}), "orig_type": etype}
        etype = "console_log"
    _add_evidence(db, vuln_id, seq, etype, content[:50000], meta=meta)
    db.commit()
    return seq


def confirm_vulnerability(db: Session, vuln: Vulnerability, review_id: int | None = None,
                          feed_kb: bool = False):
    """人工确认漏洞 → 状态 confirmed；Payload 回流知识库仅在 feed_kb=True 时执行。"""
    vuln.status = "confirmed"
    if feed_kb:
        evidence_rows = db.query(Evidence).filter(Evidence.vulnerability_id == vuln.id,
                                                  Evidence.evidence_type == "payload").all()
        for ev in evidence_rows:
            import re
            m = re.match(r"\[(\w+)\]\s*(.+)", ev.content, re.S)
            if m:
                _pl = m.group(2).split("\n")[0].strip()
                knowledge.feedback_success(
                    db, vulnerability=vuln, payload=_pl, vector=m.group(1),
                    # 记录「用了什么绕过手法」：下次遇到同类过滤/同类 WAF 可优先取用
                    bypass_tags=knowledge.infer_bypass_tags(_pl))
    db.commit()
