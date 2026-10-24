# -*- coding: utf-8 -*-
"""系统表：users / settings。"""
from sqlalchemy import Integer, String, Text

from app.models.base import Base, IdMixin, TimestampMixin, SoftDeleteMixin, Column


class User(IdMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "users"

    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(16), nullable=False, default="operator")  # admin / operator
    is_active = Column(Integer, nullable=False, default=1)
    last_login_at = Column(String(32), nullable=True)


class Setting(IdMixin, TimestampMixin, Base):
    __tablename__ = "settings"

    key = Column(String(128), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)          # 敏感项 AES 加密后存
    is_secret = Column(Integer, nullable=False, default=0)
    updated_by = Column(Integer, nullable=True)

    # 常用键
    KEY_AI_BASE_URL = "ai.base_url"
    KEY_AI_API_KEY = "ai.api_key"
    KEY_AI_MODEL = "ai.model"
    KEY_SQLMAP_PATH = "sqlmap.path"
