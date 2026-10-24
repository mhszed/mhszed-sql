# -*- coding: utf-8 -*-
"""审计日志路由：查询 + 可选清理（写入由 log_action 完成）。

注意：删除会打断 hash 链完整性，仅用于清理测试噪音；生产慎用。
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.audit import AuditLog
from app.models.system import User

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit(
    page: int = 1,
    page_size: int = 15,
    user_id: int | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    user: User = Depends(get_current_user),      # 审计日志仅登录用户可见
    db: Session = Depends(get_db),
):
    """分页查询审计日志，按时间倒序；user_id/action/resource_type 可选筛选。"""
    q = db.query(AuditLog)
    if user_id is not None:
        q = q.filter(AuditLog.user_id == user_id)
    if action:
        q = q.filter(AuditLog.action.contains(action))
    if resource_type:
        q = q.filter(AuditLog.resource_type == resource_type)
    total = q.count()
    rows = (q.order_by(AuditLog.created_at.desc())
            .offset((page - 1) * page_size).limit(page_size).all())

    # user_id → username 映射（本页涉及的）
    uids = {r.user_id for r in rows if r.user_id is not None}
    names = {u.id: u.username for u in db.query(User).filter(User.id.in_(uids))} if uids else {}

    items = [{
        "id": r.id, "user_id": r.user_id,
        "username": names.get(r.user_id),
        "action": r.action, "resource_type": r.resource_type,
        "resource_id": r.resource_id,
        "detail": r.detail, "hash": r.hash,
        "created_at": r.created_at,
    } for r in rows]
    return {"total": total, "page": page, "page_size": page_size, "items": items}


@router.delete("/{log_id}")
def delete_audit_log(log_id: int, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """删除单条审计日志（会破坏 hash 链，仅清理用）。"""
    row = db.query(AuditLog).filter(AuditLog.id == log_id).first()
    if not row:
        raise HTTPException(404, "日志不存在")
    db.delete(row)
    db.commit()
    # 删除动作本身再记一条（新链起点）
    log_action(db, user_id=user.id, action="audit_delete", resource_type="audit_log",
               resource_id=log_id, detail={"note": "手动删除审计条目"})
    db.commit()
    return {"ok": True, "deleted": log_id}


class AuditPurgeReq(BaseModel):
    ids: list[int] = Field(default_factory=list)
    action: str | None = None
    older_than: str | None = None   # ISO 时间，删此之前的
    all: bool = False               # 清空全部（审计页「清空日志」；二选一前置）


@router.post("/purge")
def purge_audit_logs(req: AuditPurgeReq, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """批量清理：清空全部 / 按 ids / 按 action / 按 older_than。

    清空动作本身会再写一条 audit_purge（新链起点），所以清空后列表剩 1 条。
    """
    q = db.query(AuditLog)
    if req.all:
        pass                                  # 不加条件 = 全部
    elif req.ids:
        q = q.filter(AuditLog.id.in_(req.ids))
    elif req.action:
        q = q.filter(AuditLog.action.contains(req.action))
        if req.older_than:
            q = q.filter(AuditLog.created_at < req.older_than)
    elif req.older_than:
        q = q.filter(AuditLog.created_at < req.older_than)
    else:
        raise HTTPException(400, "请提供 ids / action / older_than 之一")
    ids = [r.id for r in q.all()]
    n = q.delete(synchronize_session=False)
    db.commit()
    log_action(db, user_id=user.id, action="audit_purge", resource_type="audit_log",
               resource_id=None, detail={"deleted": n, "ids_sample": ids[:20]})
    db.commit()
    return {"ok": True, "deleted": n}
