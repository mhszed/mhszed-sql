# -*- coding: utf-8 -*-
"""人工确认 Payload：把手工验证成功的一条 payload 挂到接口上，供探测器优先复测。

用途（2026-10-23 某靶场）：过滤型靶场的可用形态不在内置字典里，分析员手工
验证成功后粘进来，工具以它为基础做受控对照（真/假变体）与回显判据，把一次人工
发现转成可复用的能力。
"""
from sqlalchemy import Index, Integer, String, Text

from app.models.base import Base, IdMixin, TimestampMixin, Column


class ConfirmedPayload(IdMixin, TimestampMixin, Base):
    __tablename__ = "confirmed_payloads"
    __table_args__ = (Index("ix_confirmed_endpoint", "endpoint_id"),)

    endpoint_id = Column(Integer, nullable=False)
    # 注入参数名（多参数接口必须指定；如 action=test&username=… 的 username）
    param = Column(String(64), nullable=True)
    payload = Column(Text, nullable=False)
    note = Column(String(256), nullable=True)
    created_by = Column(Integer, nullable=True)
