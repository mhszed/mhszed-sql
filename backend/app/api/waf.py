# -*- coding: utf-8 -*-
"""WAF 画像查询路由。"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.system import User
from app.models.waf import WafProfile

router = APIRouter(prefix="/api/waf", tags=["waf"])


@router.get("/profile")
def get_profile(task_id: int, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    row = db.query(WafProfile).filter(WafProfile.task_id == task_id).first()
    if not row:
        raise HTTPException(404, "该任务尚无 WAF 画像")
    return {
        "id": row.id, "host": row.host, "has_waf": bool(row.has_waf),
        "product": row.product, "product_confidence": float(row.product_confidence or 0),
        "block_behavior": row.block_behavior, "probe_history": row.probe_history,
        "bypass_suggestions": row.bypass_suggestions, "created_at": row.created_at,
    }
