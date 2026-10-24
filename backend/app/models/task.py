# -*- coding: utf-8 -*-
"""任务表：状态机唯一事实源。"""
from sqlalchemy import JSON, Integer, String, Text

from app.models.base import Base, IdMixin, TimestampMixin, Column

# 状态机：pending → collecting → scanning → review → done
#                 ↘ terminated（任意状态可终止）
#            scanning → paused_circuit（熔断暂停）→ scanning（人工恢复）
TASK_STATUSES = ("pending", "collecting", "scanning", "review", "done", "terminated", "paused_circuit")
COLLECT_MODES = ("static", "burp", "both")


class Task(IdMixin, TimestampMixin, Base):
    __tablename__ = "tasks"

    name = Column(String(128), nullable=False)
    target = Column(String(512), nullable=False, index=True)
    auth_scope_id = Column(Integer, nullable=True, index=True)
    status = Column(String(16), nullable=False, default="pending", index=True)
    collect_mode = Column(String(16), nullable=False, default="both")
    scan_config = Column(JSON, nullable=True)
    progress = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(String(32), nullable=True)
    finished_at = Column(String(32), nullable=True)
    created_by = Column(Integer, nullable=True)
