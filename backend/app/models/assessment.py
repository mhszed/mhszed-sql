# -*- coding: utf-8 -*-
"""AI 研判表 + 人工复核表。"""
from sqlalchemy import JSON, Index, Integer, String, Text

from app.models.base import Base, IdMixin, TimestampMixin, Column

ROUTES = ("auto_pass", "manual_review", "suspicious")


class RiskAssessment(IdMixin, TimestampMixin, Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        Index("ix_task_route", "task_id", "route"),
        Index("ix_endpoint", "endpoint_id"),
    )

    task_id = Column(Integer, nullable=False)
    endpoint_id = Column(Integer, nullable=False)
    risk_score = Column(String(8), nullable=False)      # 0~100
    confidence = Column(String(8), nullable=False)      # 0~1
    route = Column(String(16), nullable=False)          # auto_pass / manual_review / suspicious
    reasons = Column(JSON, nullable=True)
    model_info = Column(JSON, nullable=True)
    kb_negatives_hit = Column(JSON, nullable=True)


class ReviewAction(IdMixin, TimestampMixin, Base):
    __tablename__ = "review_actions"
    __table_args__ = (
        Index("ix_review_task_type", "task_id", "target_type"),
        Index("ix_review_target", "target_type", "target_id"),
    )

    task_id = Column(Integer, nullable=True)
    target_type = Column(String(16), nullable=False)    # assessment / vulnerability
    target_id = Column(Integer, nullable=False)
    action = Column(String(16), nullable=False)         # confirm / false_positive / adjust
    adjusted_score = Column(String(8), nullable=True)
    comment = Column(Text, nullable=True)
    reviewer_id = Column(Integer, nullable=True)
    reviewed_at = Column(String(32), nullable=True)
