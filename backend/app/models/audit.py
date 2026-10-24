# -*- coding: utf-8 -*-
"""审计日志表 + Burp 连接状态表。"""
from sqlalchemy import Index, Integer, String, Text

from app.models.base import Base, IdMixin, TimestampMixin, Column, utcnow_iso

AUDIT_ACTIONS = (
    "login", "logout", "task_create", "task_stop", "scan_start", "scan_request",
    "review_submit", "kb_edit", "report_export", "config_change", "circuit_break", "auth_reject",
)


class AuditLog(IdMixin, Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_user_time", "user_id", "created_at"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_time", "created_at"),
    )

    user_id = Column(Integer, nullable=True)
    action = Column(String(32), nullable=False)
    resource_type = Column(String(32), nullable=True)
    resource_id = Column(Integer, nullable=True)
    detail = Column(Text, nullable=True)      # JSON 字符串
    prev_hash = Column(String(64), nullable=True)
    hash = Column(String(64), nullable=True)
    created_at = Column(String(32), nullable=False, default=utcnow_iso)


class BurpSession(IdMixin, Base):
    __tablename__ = "burp_sessions"

    client_id = Column(String(64), unique=True, nullable=False)
    last_heartbeat = Column(String(32), nullable=True)
    pushed_count = Column(Integer, nullable=False, default=0)
    dropped_count = Column(Integer, nullable=False, default=0)
    version = Column(String(32), nullable=True)
    first_seen_at = Column(String(32), nullable=False, default=utcnow_iso)
