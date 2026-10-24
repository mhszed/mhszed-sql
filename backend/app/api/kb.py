# -*- coding: utf-8 -*-
"""知识库路由：Payload 库 CRUD + 误报样本库查看。"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.kb import KbArticle, KbFalsePositive, KbInsight, KbPayload
from app.models.base import utcnow_iso
from app.models.system import User
from app.services import knowledge

router = APIRouter(prefix="/api/kb", tags=["kb"])


class PayloadReq(BaseModel):
    payload: str = Field(min_length=1, max_length=2000)
    vector: str = Field(pattern="^(boolean|time|error|union)$")
    target_waf: str | None = None
    bypass_tags: list[str] | None = None
    dbms: str | None = None


@router.get("/payloads")
def list_payloads(page: int = 1, page_size: int = 15, waf: str | None = None,
                  vector: str | None = None,
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(KbPayload).filter(KbPayload.deleted_at.is_(None))
    if waf:
        q = q.filter(KbPayload.target_waf == waf)
    if vector:
        q = q.filter(KbPayload.vector == vector)
    total = q.count()
    rows = q.order_by(KbPayload.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [{
        "id": r.id, "payload": r.payload, "vector": r.vector, "target_waf": r.target_waf,
        "bypass_tags": r.bypass_tags, "dbms": r.dbms, "source": r.source,
        "success_count": r.success_count, "use_count": r.use_count,
        "is_active": bool(r.is_active), "created_at": r.created_at,
    } for r in rows]}


@router.post("/payloads")
def create_payload(req: PayloadReq, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    # 人工入库同样过破坏性语句检查
    from app.core.security import is_destructive_payload
    payload = req.payload.strip()
    if not payload:
        raise HTTPException(400, "payload 不能为空")
    if is_destructive_payload(payload):
        raise HTTPException(400, "payload 含破坏性语句，拒绝入库")
    # 查重：同 payload + vector + WAF 只保留一条（含 target_waf 为 NULL 的情况）
    existing = knowledge.find_duplicate_payload(
        db, payload=payload, vector=req.vector, target_waf=req.target_waf)
    if existing:
        if req.bypass_tags is not None:
            existing.bypass_tags = req.bypass_tags
        if req.dbms:
            existing.dbms = req.dbms
        existing.is_active = 1
        db.commit()
        return {"id": existing.id, "deduped": True}
    row = KbPayload(**{**req.model_dump(), "payload": payload},
                    source="manual", created_by=user.id)
    db.add(row)
    log_action(db, user_id=user.id, action="kb_edit", resource_type="kb_payload",
               detail={"op": "create", "vector": req.vector})
    db.commit()
    return {"id": row.id}


@router.put("/payloads/{pid}")
def update_payload(pid: int, req: PayloadReq, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    row = db.query(KbPayload).filter(KbPayload.id == pid, KbPayload.deleted_at.is_(None)).first()
    if not row:
        raise HTTPException(404, "样本不存在")
    for k, v in req.model_dump().items():
        setattr(row, k, v)
    log_action(db, user_id=user.id, action="kb_edit", resource_type="kb_payload",
               resource_id=pid, detail={"op": "update"})
    db.commit()
    return {"ok": True}


@router.post("/payloads/{pid}/toggle")
def toggle_payload(pid: int, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    row = db.query(KbPayload).filter(KbPayload.id == pid).first()
    if not row:
        raise HTTPException(404, "样本不存在")
    row.is_active = 0 if row.is_active else 1
    db.commit()
    return {"is_active": bool(row.is_active)}


@router.delete("/payloads/{pid}")
def delete_payload(pid: int, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    row = db.query(KbPayload).filter(KbPayload.id == pid).first()
    if not row:
        raise HTTPException(404, "样本不存在")
    row.deleted_at = utcnow_iso()
    log_action(db, user_id=user.id, action="kb_edit", resource_type="kb_payload",
               resource_id=pid, detail={"op": "delete"})
    db.commit()
    return {"ok": True}


@router.get("/false-positives")
def list_fps(page: int = 1, page_size: int = 15,
             user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(KbFalsePositive).filter(KbFalsePositive.deleted_at.is_(None))
    total = q.count()
    rows = q.order_by(KbFalsePositive.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [{
        "id": r.id, "endpoint_signature": r.endpoint_signature,
        "response_signature": r.response_signature, "reason": r.reason,
        "source": r.source, "hit_count": r.hit_count, "created_at": r.created_at,
    } for r in rows]}


# 文章投喂功能已按用户要求下线：不保存原文，仅保留 Payload 库供 AI 模仿生成。
