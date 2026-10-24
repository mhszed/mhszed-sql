# -*- coding: utf-8 -*-
"""接口表 + 业务会话链表。"""
from sqlalchemy import JSON, Index, Integer, String, Text, UniqueConstraint

from app.models.base import Base, IdMixin, TimestampMixin, Column


class Endpoint(IdMixin, TimestampMixin, Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("task_id", "dedup_hash", name="uq_task_dedup"),
        Index("ix_task_readwrite", "task_id", "read_write"),
        Index("ix_chain", "chain_id"),
    )

    task_id = Column(Integer, nullable=False, index=True)
    source = Column(String(16), nullable=False, default="crawler")   # crawler / burp / manual
    dedup_hash = Column(String(64), nullable=False)
    method = Column(String(8), nullable=False)
    path = Column(Text, nullable=False)          # 归一后路径（{id} 占位）
    raw_path = Column(Text, nullable=True)
    host = Column(String(256), nullable=False)
    params = Column(JSON, nullable=True)          # [{name, location, type, sample_value, required}]
    headers = Column(JSON, nullable=True)
    read_write = Column(String(8), nullable=False, default="read")
    chain_id = Column(Integer, nullable=True)
    chain_inferred = Column(Integer, nullable=False, default=0)
    burp_seen_at = Column(String(32), nullable=True)


class BusinessChain(IdMixin, TimestampMixin, Base):
    __tablename__ = "business_chains"

    task_id = Column(Integer, nullable=False, index=True)
    name = Column(String(256), nullable=True)
    reconstruct_method = Column(String(32), nullable=False)  # referer / token_derive / temporal_cluster
    confidence = Column(String(16), nullable=False, default="1.0")
    node_ids = Column(JSON, nullable=True)                    # 有序 endpoint id
    sample_session = Column(JSON, nullable=True)
