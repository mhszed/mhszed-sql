# -*- coding: utf-8 -*-
"""漏洞路由：列表、详情、证据链、人工复核、报告导出。"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.assessment import ReviewAction
from app.models.base import utcnow_iso
from app.models.endpoint import Endpoint
from app.models.system import User
from app.models.vuln import Evidence, Vulnerability
from app.services import evidence as evidence_svc
from app.services import knowledge
from app.services.report import build_report

router = APIRouter(prefix="/api/vuln", tags=["vuln"])


@router.get("")
def list_vulns(task_id: int, page: int = 1, page_size: int = 10, status: str | None = None,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = (db.query(Vulnerability, Endpoint)
         .join(Endpoint, Vulnerability.endpoint_id == Endpoint.id)
         .filter(Vulnerability.task_id == task_id))
    if status:
        q = q.filter(Vulnerability.status == status)
    total = q.count()
    rows = q.order_by(Vulnerability.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [{
        "id": v.id, "title": v.title, "vuln_type": v.vuln_type, "severity": v.severity,
        "status": v.status, "dbms": v.dbms, "vector_count": v.vector_count,
        "method": e.method, "path": e.path, "host": e.host,
        "hardening_advice": v.hardening_advice, "created_at": v.created_at,
    } for v, e in rows]}


@router.get("/{vuln_id}")
def vuln_detail(vuln_id: int, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "漏洞不存在")
    e = db.query(Endpoint).filter(Endpoint.id == v.endpoint_id).first()
    return {
        "id": v.id, "title": v.title, "vuln_type": v.vuln_type, "severity": v.severity,
        "status": v.status, "dbms": v.dbms, "vector_count": v.vector_count,
        "task_id": v.task_id, "scan_job_id": v.scan_job_id,
        "endpoint": {"method": e.method, "path": e.path, "host": e.host,
                     "params": e.params, "read_write": e.read_write} if e else None,
        "hardening_advice": v.hardening_advice, "created_at": v.created_at,
    }


@router.get("/{vuln_id}/evidence")
def vuln_evidence(vuln_id: int, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "漏洞不存在")
    rows = (db.query(Evidence).filter(Evidence.vulnerability_id == vuln_id)
            .order_by(Evidence.seq.asc()).all())
    return {"items": [{
        "seq": r.seq, "evidence_type": r.evidence_type, "content": r.content,
        "meta": r.meta, "sha256": r.sha256, "created_at": r.created_at,
    } for r in rows]}


class VulnReviewReq(BaseModel):
    action: str = Field(pattern="^(confirm|false_positive)$")
    comment: str | None = None
    # 确认漏洞时是否把成功 Payload 回流知识库；默认否（按需勾选）
    feed_kb: bool = False


@router.post("/{vuln_id}/review")
def review_vuln(vuln_id: int, req: VulnReviewReq,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "漏洞不存在")
    review = ReviewAction(task_id=v.task_id, target_type="vulnerability", target_id=vuln_id,
                          action=req.action, comment=req.comment, reviewer_id=user.id,
                          reviewed_at=utcnow_iso())
    db.add(review)

    if req.action == "confirm":
        v.status = "confirmed"
        db.commit()
        evidence_svc.confirm_vulnerability(
            db, v, review_id=review.id, feed_kb=bool(req.feed_kb))
    else:
        v.status = "false_positive"
        ep = db.query(Endpoint).filter(Endpoint.id == v.endpoint_id).first()
        if ep:
            knowledge.feedback_false_positive(
                db, endpoint=ep, review=review,
                reason=req.comment or "漏洞人工标记误报")
        db.commit()

    log_action(db, user_id=user.id, action="review_submit", resource_type="vulnerability",
               resource_id=vuln_id, detail={"action": req.action, "feed_kb": req.feed_kb})
    db.commit()
    return {"ok": True, "status": v.status}


class DeepExploitReq(BaseModel):
    # enum=库表枚举；dump=受限脱裤；ai=AI/规则自测为主（可辅 sqlmap）
    mode: str = Field(pattern="^(enum|dump|ai)$")
    # 每次必选：schema=实战库表/结构；flag=靶场 flag。不设默认值。
    goal: str = Field(pattern="^(schema|flag)$")


@router.post("/{vuln_id}/deep-exploit")
def deep_exploit(vuln_id: int, req: DeepExploitReq,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """人在回路：确认/待复核漏洞上触发深入利用（枚举库表 或 受限脱裤）。"""
    from app.services import deep_exploit as deep_svc
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "漏洞不存在")
    try:
        st = deep_svc.start_deep_exploit(vuln_id, req.mode, goal=req.goal,
                                         user_id=user.id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    log_action(db, user_id=user.id, action="deep_exploit_start",
               resource_type="vulnerability", resource_id=vuln_id,
               detail={"mode": req.mode, "goal": req.goal})
    db.commit()
    return {"ok": True, "status": st}


@router.get("/{vuln_id}/deep-exploit/status")
def deep_exploit_status(vuln_id: int, user: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    from app.services import deep_exploit as deep_svc
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "漏洞不存在")
    return deep_svc.get_status(vuln_id)


@router.get("/report/download")
def download_report(task_id: int, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    try:
        path = build_report(db, task_id)
    except Exception as exc:
        raise HTTPException(500, f"报告生成失败: {exc}")
    log_action(db, user_id=user.id, action="report_export", resource_type="task",
               resource_id=task_id, detail={"file": str(path)})
    db.commit()
    return FileResponse(path, filename=path.name,
                        media_type="application/pdf" if path.suffix == ".pdf" else "text/plain")
