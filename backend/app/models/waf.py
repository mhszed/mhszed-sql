# -*- coding: utf-8 -*-
"""WAF 指纹画像表。"""
from sqlalchemy import JSON, Index, Integer, String

from app.models.base import Base, IdMixin, TimestampMixin, Column


class WafProfile(IdMixin, TimestampMixin, Base):
    __tablename__ = "waf_profiles"
    __table_args__ = (Index("ix_task_host", "task_id", "host"),)

    task_id = Column(Integer, nullable=False)
    host = Column(String(256), nullable=False)
    has_waf = Column(Integer, nullable=False, default=0)
    product = Column(String(64), nullable=True)        # 产品名 / unknown
    product_confidence = Column(String(16), nullable=True)
    block_behavior = Column(JSON, nullable=True)       # {status_code, page_fingerprint_hash, headers, block_keyword}
    probe_history = Column(JSON, nullable=True)
    bypass_suggestions = Column(JSON, nullable=True)
