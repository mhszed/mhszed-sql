# -*- coding: utf-8 -*-
"""审计日志：全操作落库 + 链式哈希防篡改。"""
import hashlib
import json

from sqlalchemy.orm import Session

from app.core import config
from app.models.audit import AuditLog


def log_action(
    db: Session,
    *,
    user_id: int | None,
    action: str,
    resource_type: str | None = None,
    resource_id: int | None = None,
    detail: dict | None = None,
    client_ip: str | None = None,
) -> AuditLog:
    """写一条审计日志（调用方负责 commit 或由请求生命周期统一 commit）。

    链式哈希：hash = SHA256(prev_hash + user_id + action + resource + detail + created_at)
    """
    last = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .first()
    )
    prev_hash = last.hash if last else "GENESIS"

    row = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=json.dumps(detail or {}, ensure_ascii=False),
        prev_hash=prev_hash,
    )
    material = f"{prev_hash}|{user_id}|{action}|{resource_type}|{resource_id}|{row.detail}|{row.created_at}"
    row.hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
    if not config.AUDIT_CHAIN_HASH:
        row.prev_hash = None
        row.hash = None
    db.add(row)
    return row


def verify_chain(db: Session) -> tuple[bool, int]:
    """校验审计链完整性，返回 (是否完整, 断裂位置id)。"""
    rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    prev = "GENESIS"
    for r in rows:
        material = f"{prev}|{r.user_id}|{r.action}|{r.resource_type}|{r.resource_id}|{r.detail}|{r.created_at}"
        expect = hashlib.sha256(material.encode("utf-8")).hexdigest()
        if r.prev_hash != prev or (config.AUDIT_CHAIN_HASH and r.hash != expect):
            return False, r.id
        prev = r.hash
    return True, 0
