# -*- coding: utf-8 -*-
"""授权范围表：任务启动前置校验的白名单。"""
from sqlalchemy import String, Text

from app.models.base import Base, IdMixin, TimestampMixin, SoftDeleteMixin, Column

SCOPE_TYPES = ("domain", "wildcard", "ip")


class AuthScope(IdMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "auth_scopes"
    __table_args__ = (
        # SQLite 建联合索引用 Index 在 __init_args 外声明
    )

    name = Column(String(128), nullable=False)
    scope_type = Column(String(16), nullable=False, index=True)   # domain / wildcard / ip
    scope_value = Column(String(256), nullable=False, index=True)
    note = Column(Text, nullable=True)                             # 授权凭证/工单号
    expires_at = Column(String(32), nullable=True)
