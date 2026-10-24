# -*- coding: utf-8 -*-
"""任务路由 + 授权范围路由。"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.auth import AuthScope
from app.models.system import User
from app.models.task import Task
from app.services import task_manager
from app.services.safety import AuthorizationError

router = APIRouter(prefix="/api/task", tags=["task"])


class TaskCreateReq(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=3, max_length=512)
    collect_mode: str = "both"          # static / burp / both
    scan_config: dict | None = None


class TaskOut(BaseModel):
    id: int
    name: str
    target: str
    status: str
    collect_mode: str
    scan_config: dict | None
    progress: dict | None
    error_message: str | None
    started_at: str | None
    finished_at: str | None
    created_at: str | None

    class Config:
        from_attributes = True


@router.post("", response_model=TaskOut)
def create_task(req: TaskCreateReq, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    if req.collect_mode not in ("static", "burp", "both"):
        raise HTTPException(400, "collect_mode 必须是 static/burp/both")
    task = task_manager.create_task(db, user_id=user.id, name=req.name, target=req.target,
                                    collect_mode=req.collect_mode, scan_config=req.scan_config)
    return task


@router.get("")
def list_tasks(page: int = 1, page_size: int = 10, status: str | None = None,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Task)
    if status:
        q = q.filter(Task.status == status)
    total = q.count()
    rows = q.order_by(Task.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"total": total, "page": page, "page_size": page_size,
            "items": [TaskOut.model_validate(r).model_dump() for r in rows]}


@router.get("/{task_id}", response_model=TaskOut)
def get_task(task_id: int, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    return task


@router.post("/{task_id}/start", response_model=TaskOut)
def start_task(task_id: int, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    try:
        return task_manager.start_task(db, task_id, user_id=user.id)
    except AuthorizationError as e:
        raise HTTPException(403, str(e))
    except task_manager.TaskStateError as e:
        raise HTTPException(400, str(e))


@router.post("/{task_id}/stop", response_model=TaskOut)
def stop_task(task_id: int, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    try:
        return task_manager.stop_task(db, task_id, user_id=user.id)
    except task_manager.TaskStateError as e:
        raise HTTPException(400, str(e))


_ACTIVE_STATUSES = ("collecting", "scanning")


def _hard_delete_task(db: Session, task: Task) -> None:
    """硬删除单个任务及其关联数据（无 DB 级 FK，手工级联）。"""
    from app.models.endpoint import Endpoint, BusinessChain
    from app.models.vuln import Vulnerability, Evidence
    from app.models.assessment import RiskAssessment, ReviewAction
    from app.models.scan import ScanJob
    from app.models.waf import WafProfile

    tid = task.id
    vuln_ids = [r[0] for r in db.query(Vulnerability.id).filter(Vulnerability.task_id == tid).all()]
    if vuln_ids:
        db.query(Evidence).filter(Evidence.vulnerability_id.in_(vuln_ids)).delete(
            synchronize_session=False)
    db.query(Vulnerability).filter(Vulnerability.task_id == tid).delete(synchronize_session=False)
    db.query(RiskAssessment).filter(RiskAssessment.task_id == tid).delete(synchronize_session=False)
    db.query(ReviewAction).filter(ReviewAction.task_id == tid).delete(synchronize_session=False)
    db.query(ScanJob).filter(ScanJob.task_id == tid).delete(synchronize_session=False)
    db.query(WafProfile).filter(WafProfile.task_id == tid).delete(synchronize_session=False)
    db.query(BusinessChain).filter(BusinessChain.task_id == tid).delete(synchronize_session=False)
    db.query(Endpoint).filter(Endpoint.task_id == tid).delete(synchronize_session=False)
    db.delete(task)


@router.delete("/{task_id}")
def delete_task(task_id: int, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    """硬删除任务及其采集/扫描关联数据。

    历史 bug：Task 未挂 SoftDeleteMixin，写 deleted_at 是空操作，
    前端显示删除成功但任务仍留在面板。现改为真正 DELETE。
    """
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    if task.status in _ACTIVE_STATUSES:
        raise HTTPException(400, "任务运行中，请先终止")
    _hard_delete_task(db, task)
    db.commit()
    return {"ok": True, "hard_deleted": True, "task_id": task_id}


class BatchDeleteReq(BaseModel):
    ids: list[int] = Field(min_length=1)


@router.post("/batch-delete")
def batch_delete_tasks(req: BatchDeleteReq, user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    """多选批量硬删除。运行中的任务跳过并回报。"""
    deleted, skipped, missing = [], [], []
    for tid in req.ids:
        task = db.query(Task).filter(Task.id == tid).first()
        if not task:
            missing.append(tid)
            continue
        if task.status in _ACTIVE_STATUSES:
            skipped.append({"id": tid, "status": task.status, "reason": "运行中，请先终止"})
            continue
        _hard_delete_task(db, task)
        deleted.append(tid)
    db.commit()
    return {"ok": True, "deleted": deleted, "skipped": skipped, "missing": missing}


# ================= 授权范围 =================

scope_router = APIRouter(prefix="/api/scope", tags=["scope"])


class ScopeReq(BaseModel):
    name: str
    scope_type: str          # domain / wildcard / ip
    scope_value: str
    note: str | None = None
    expires_at: str | None = None


def normalize_scope_value(value: str | None) -> str:
    """授权范围值归一：去空白、小写，并容忍误填的协议/端口/路径。

    例：`http://127.0.0.1:8899/` → `127.0.0.1`；`https://Example.com/path` → `example.com`。
    2026-10-24：前端把整个 URL 当成范围值时，存储 `http://127.0.0.1` 与目标主机
    `127.0.0.1` 永远匹配不上 → 任务被拒（403）。
    """
    from urllib.parse import urlparse

    v = (value or "").strip().lower()
    if not v:
        return ""
    if "://" in v:
        v = urlparse(v).hostname or v
    elif ":" in v and not v.startswith("["):     # 裸 host:port（IPv6 带方括号不拆）
        host, _, port = v.partition(":")
        if port.isdigit():
            v = host
    return v.strip().strip("/")


def find_duplicate_scope(db: Session, scope_type: str,
                         scope_value: str) -> AuthScope | None:
    value = normalize_scope_value(scope_value)
    rows = db.query(AuthScope).filter(
        AuthScope.scope_type == scope_type,
        AuthScope.deleted_at.is_(None)).all()
    return next((r for r in rows
                 if normalize_scope_value(r.scope_value) == value), None)


@scope_router.post("")
def create_scope(req: ScopeReq, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    if req.scope_type not in ("domain", "wildcard", "ip"):
        raise HTTPException(400, "scope_type 必须是 domain/wildcard/ip")
    value = normalize_scope_value(req.scope_value)
    if not value:
        raise HTTPException(400, "scope_value 不能为空")
    existing = find_duplicate_scope(db, req.scope_type, value)
    if existing:
        # 已有同类型同值授权：更新备注/有效期，不新增重复记录
        if req.note is not None:
            existing.note = req.note
        if req.expires_at is not None:
            existing.expires_at = req.expires_at
        if req.name and req.name != existing.name:
            existing.name = req.name
        db.commit()
        return {"id": existing.id, "deduped": True}
    row = AuthScope(**{**req.model_dump(), "scope_value": value})
    db.add(row)
    db.commit()
    return {"id": row.id}


@scope_router.get("")
def list_scopes(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(AuthScope).filter(AuthScope.deleted_at.is_(None)).order_by(
        AuthScope.id.desc()).all()
    return {"items": [
        {"id": r.id, "name": r.name, "scope_type": r.scope_type,
         "scope_value": r.scope_value, "note": r.note, "expires_at": r.expires_at}
        for r in rows]}


@scope_router.delete("/{scope_id}")
def delete_scope(scope_id: int, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    from app.models.base import utcnow_iso
    row = db.query(AuthScope).filter(AuthScope.id == scope_id).first()
    if not row:
        raise HTTPException(404, "授权范围不存在")
    row.deleted_at = utcnow_iso()
    db.commit()
    return {"ok": True}
