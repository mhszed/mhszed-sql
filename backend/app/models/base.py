# -*- coding: utf-8 -*-
"""模型基类与公共 Mixin。"""
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Text

from app.core.database import Base


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class TimestampMixin:
    created_at = Column(String(32), default=utcnow_iso, nullable=False)
    updated_at = Column(String(32), default=utcnow_iso, onupdate=utcnow_iso, nullable=False)


class SoftDeleteMixin:
    deleted_at = Column(String(32), nullable=True)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


class IdMixin:
    id = Column(Integer, primary_key=True, autoincrement=True)


__all__ = ["Base", "IdMixin", "TimestampMixin", "SoftDeleteMixin", "utcnow_iso", "Column", "Integer", "String", "Text"]
