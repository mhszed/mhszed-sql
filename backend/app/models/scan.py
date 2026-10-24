# -*- coding: utf-8 -*-
"""探测子任务表：流水线两引擎（sqlmap / ai_probe）统一记录。"""
from sqlalchemy import JSON, Index, Integer, String

from app.models.base import Base, IdMixin, TimestampMixin, Column

ENGINES = ("sqlmap", "ai_probe")
JOB_STATUSES = ("queued", "running", "finished", "timeout", "killed", "error")
RESULT_CLASSES = ("vuln_confirmed", "no_vuln", "waf_blocked", "inconclusive", "timeout")


class ScanJob(IdMixin, TimestampMixin, Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_job_task_engine_status", "task_id", "engine", "status"),
        Index("ix_job_endpoint_round", "endpoint_id", "round"),
    )

    task_id = Column(Integer, nullable=False)
    endpoint_id = Column(Integer, nullable=False)
    engine = Column(String(16), nullable=False)
    round = Column(Integer, nullable=False, default=1)
    status = Column(String(16), nullable=False, default="queued")
    result_class = Column(String(16), nullable=True)
    request_meta = Column(JSON, nullable=True)
    ai_payloads = Column(JSON, nullable=True)
    bypass_strategy = Column(JSON, nullable=True)
    started_at = Column(String(32), nullable=True)
    finished_at = Column(String(32), nullable=True)
    duration_ms = Column(Integer, nullable=True)
