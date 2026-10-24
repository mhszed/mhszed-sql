# -*- coding: utf-8 -*-
"""知识库：成功 Payload 库 + 误报样本库。"""
from sqlalchemy import JSON, Index, Integer, String, Text

from app.models.base import Base, IdMixin, TimestampMixin, SoftDeleteMixin, Column


class KbPayload(IdMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "kb_payloads"
    __table_args__ = (Index("ix_kbp_waf_vector", "target_waf", "vector"),)

    payload = Column(Text, nullable=False)
    vector = Column(String(16), nullable=False)          # boolean / time / error / union
    target_waf = Column(String(64), nullable=True, index=True)
    bypass_tags = Column(JSON, nullable=True)
    dbms = Column(String(64), nullable=True)
    source = Column(String(16), nullable=False, default="manual")  # auto_feedback / manual
    source_vuln_id = Column(Integer, nullable=True)
    success_count = Column(Integer, nullable=False, default=0)
    use_count = Column(Integer, nullable=False, default=0)
    created_by = Column(Integer, nullable=True)
    is_active = Column(Integer, nullable=False, default=1)


class KbFalsePositive(IdMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "kb_false_positives"
    __table_args__ = (
        Index("ix_fp_endpoint_sig", "endpoint_signature"),
        Index("ix_fp_response_sig", "response_signature"),
    )

    endpoint_signature = Column(String(64), nullable=False)
    response_signature = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    source = Column(String(16), nullable=False, default="manual")
    source_review_id = Column(Integer, nullable=True)
    hit_count = Column(Integer, nullable=False, default=0)


class KbArticle(IdMixin, TimestampMixin, SoftDeleteMixin, Base):
    """投喂的原文（只存在工具库，不进赏金记忆框架）。"""
    __tablename__ = "kb_articles"

    title = Column(String(256), nullable=False)
    source_url = Column(String(512), nullable=True)
    content = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    created_by = Column(Integer, nullable=True)
    insight_count = Column(Integer, nullable=False, default=0)


class KbInsight(IdMixin, TimestampMixin, SoftDeleteMixin, Base):
    """从文章蒸馏出的可检索知识点，供研判/利用检索。"""
    __tablename__ = "kb_insights"
    __table_args__ = (
        Index("ix_insight_kind", "kind"),
        Index("ix_insight_tags", "tags"),
    )

    article_id = Column(Integer, nullable=True, index=True)
    kind = Column(String(32), nullable=False)  # playbook/oracle/payload_pattern/bypass/dbms_quirk
    title = Column(String(256), nullable=False)
    body = Column(Text, nullable=False)
    tags = Column(JSON, nullable=True)         # ["postgresql","union","char"]
    dbms = Column(String(64), nullable=True)
    example_payload = Column(Text, nullable=True)
    use_count = Column(Integer, nullable=False, default=0)
    is_active = Column(Integer, nullable=False, default=1)
    created_by = Column(Integer, nullable=True)
