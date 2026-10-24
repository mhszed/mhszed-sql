# -*- coding: utf-8 -*-
"""Burp 联动路由：流量推送（批量、幂等）、心跳、连接状态。"""
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.audit import BurpSession
from app.models.system import User
from app.services import collector

router = APIRouter(prefix="/api/burp", tags=["burp"])


class PushRecord(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: str = ""
    referer: str | None = None
    timestamp: str | None = None


class PushReq(BaseModel):
    client_id: str = Field(min_length=8, max_length=64)
    task_id: int | None = None
    records: list[PushRecord] = Field(max_length=200)


class HeartbeatReq(BaseModel):
    client_id: str
    version: str | None = None


@router.post("/push")
def push(req: PushReq, db: Session = Depends(get_db)):
    """插件推送无需登录态（Burp 侧不方便带 token），但仅接收 + 入库，不触发扫描动作。"""
    stats = collector.handle_burp_push(
        db, req.client_id, [r.model_dump() for r in req.records], task_id=req.task_id)
    return stats


@router.post("/heartbeat")
def heartbeat(req: HeartbeatReq, db: Session = Depends(get_db)):
    collector.burp_heartbeat(db, req.client_id, req.version)
    return {"ok": True}


@router.get("/status")
def status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """连接状态灯数据：30 秒内心跳视为在线。"""
    from app.models.base import utcnow_iso
    now_iso = utcnow_iso()
    rows = db.query(BurpSession).order_by(BurpSession.id.desc()).limit(20).all()
    items = []
    for r in rows:
        online = bool(r.last_heartbeat) and (now_iso[:19] == (r.last_heartbeat or "")[:19]
                                             or _within(r.last_heartbeat, 30))
        items.append({"client_id": r.client_id, "online": online,
                      "last_heartbeat": r.last_heartbeat,
                      "pushed_count": r.pushed_count, "dropped_count": r.dropped_count,
                      "version": r.version})
    return {"items": items}


def _within(iso_ts: str | None, seconds: int) -> bool:
    if not iso_ts:
        return False
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() <= seconds
    except Exception:
        return False
