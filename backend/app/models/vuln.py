# -*- coding: utf-8 -*-
"""漏洞表 + 证据链表（证据只追加不修改、永不删除）。"""
from sqlalchemy import JSON, Index, Integer, String, Text

from app.models.base import Base, IdMixin, TimestampMixin, Column

VULN_TYPES = ("sql_injection_boolean", "sql_injection_time", "sql_injection_error", "sql_injection_union")
SEVERITIES = ("critical", "high", "medium")


class Vulnerability(IdMixin, TimestampMixin, Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vuln_task_status", "task_id", "status"),
        Index("ix_vuln_endpoint", "endpoint_id"),
    )

    task_id = Column(Integer, nullable=False)
    endpoint_id = Column(Integer, nullable=False)
    scan_job_id = Column(Integer, nullable=True)
    vuln_type = Column(String(32), nullable=False)
    severity = Column(String(16), nullable=False, default="high")
    title = Column(String(512), nullable=False)
    dbms = Column(String(64), nullable=True)           # 仅库名/版本（合规红线）
    vector_count = Column(Integer, nullable=False, default=1)  # >=2 才产出
    status = Column(String(16), nullable=False, default="pending_review")
    hardening_advice = Column(JSON, nullable=True)


class Evidence(IdMixin, Base):
    """created_at 恒定，无 updated_at —— 只追加。"""
    __tablename__ = "evidences"
    __table_args__ = (Index("ix_evidence_vuln_seq", "vulnerability_id", "seq"),)

    vulnerability_id = Column(Integer, nullable=False)
    evidence_type = Column(String(16), nullable=False)  # request/response/payload/waf_info/chain_info/console_log
    seq = Column(Integer, nullable=False, default=1)
    content = Column(Text, nullable=False)
    meta = Column(JSON, nullable=True)
    sha256 = Column(String(64), nullable=False)
    created_at = Column(String(32), nullable=False)
