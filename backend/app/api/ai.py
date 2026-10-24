# -*- coding: utf-8 -*-
"""AI 研判路由：复核队列、人工复核提交（人在回路）、重新研判。"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.assessment import ReviewAction, RiskAssessment
from app.models.base import utcnow_iso
from app.models.endpoint import Endpoint
from app.models.system import User
from app.services import ai, knowledge

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.get("/review-queue")
def review_queue(task_id: int, page: int = 1, page_size: int = 15,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """人工复核队列：manual_review + suspicious（不再自动猛扫）。"""
    # 已复核（confirm / false_positive）的条目**先排除再计数**：
    # 旧实现 total 按 route 统计、列表却排除已复核 → 队列显示 3 条但列表为空。
    reviewed = {r.target_id for r in db.query(ReviewAction)
                .filter(ReviewAction.task_id == task_id,
                        ReviewAction.target_type == "assessment",
                        ReviewAction.action != "adjust").all()}
    q = (db.query(RiskAssessment, Endpoint)
         .join(Endpoint, RiskAssessment.endpoint_id == Endpoint.id)
         .filter(RiskAssessment.task_id == task_id,
                 RiskAssessment.route.in_(("manual_review", "suspicious"))))
    if reviewed:
        q = q.filter(~RiskAssessment.id.in_(reviewed))
    total = q.count()
    rows = (q.order_by(RiskAssessment.risk_score.desc())
            .offset((page - 1) * page_size).limit(page_size).all())
    items = [{
        "assessment_id": a.id, "endpoint_id": e.id, "method": e.method, "path": e.path,
        "params": e.params, "read_write": e.read_write,
        "risk_score": float(a.risk_score), "confidence": float(a.confidence),
        "reasons": a.reasons, "model_info": a.model_info,
        "kb_negatives_hit": a.kb_negatives_hit,
        "reviewed": a.id in reviewed,
    } for a, e in rows]
    return {"total": total, "page": page, "page_size": page_size, "items": items}


@router.get("/assessments")
def list_assessments(task_id: int, page: int = 1, page_size: int = 15,
                     user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """全部研判结果（AI 研判页面展示用）。"""
    q = (db.query(RiskAssessment, Endpoint)
         .join(Endpoint, RiskAssessment.endpoint_id == Endpoint.id)
         .filter(RiskAssessment.task_id == task_id))
    total = q.count()
    rows = (q.order_by(RiskAssessment.id.desc())
            .offset((page - 1) * page_size).limit(page_size).all())
    return {"total": total, "page": page, "page_size": page_size, "items": [{
        "assessment_id": a.id, "endpoint_id": e.id, "method": e.method, "path": e.path,
        "read_write": e.read_write, "risk_score": float(a.risk_score),
        "confidence": float(a.confidence), "route": a.route, "reasons": a.reasons,
        "model_info": a.model_info,
    } for a, e in rows]}


@router.get("/endpoint/{endpoint_id}/judgment")
def endpoint_judgment(endpoint_id: int, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    """点开某个接口 URL 时用：AI 是否怀疑 SQL 注入 + 探测结果摘要。"""
    from app.models.scan import ScanJob
    from app.models.vuln import Vulnerability

    ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not ep:
        raise HTTPException(404, "接口不存在")

    assessment = (db.query(RiskAssessment)
                  .filter(RiskAssessment.endpoint_id == endpoint_id)
                  .order_by(RiskAssessment.id.desc()).first())
    jobs = (db.query(ScanJob)
            .filter(ScanJob.endpoint_id == endpoint_id)
            .order_by(ScanJob.id.desc()).limit(5).all())
    vulns = (db.query(Vulnerability)
             .filter(Vulnerability.endpoint_id == endpoint_id)
             .order_by(Vulnerability.id.desc()).all())

    # 综合结论：供页面一眼判断「有没有 SQL」
    if vulns:
        sql_verdict = "confirmed"
        sql_verdict_label = "已确认存在 SQL 注入"
    elif any(j.result_class == "vuln" for j in jobs):
        sql_verdict = "detected"
        sql_verdict_label = "探测引擎已命中（待归档确认）"
    elif any(j.result_class == "no_vuln" for j in jobs):
        sql_verdict = "not_found"
        sql_verdict_label = "已探测，当前未发现可注入"
    elif assessment and float(assessment.risk_score) >= 40:
        sql_verdict = "suspected"
        sql_verdict_label = "AI 怀疑存在注入风险，尚未/正在探测"
    elif assessment:
        sql_verdict = "low_risk"
        sql_verdict_label = "AI 评估风险偏低"
    else:
        sql_verdict = "pending"
        sql_verdict_label = "尚未研判（任务可能还没跑到 AI 阶段）"

    return {
        "endpoint": {
            "id": ep.id, "task_id": ep.task_id, "method": ep.method,
            "path": ep.path, "raw_path": ep.raw_path, "host": ep.host,
            "params": ep.params, "source": ep.source, "read_write": ep.read_write,
        },
        "sql_verdict": sql_verdict,
        "sql_verdict_label": sql_verdict_label,
        "assessment": None if not assessment else {
            "assessment_id": assessment.id,
            "risk_score": float(assessment.risk_score),
            "confidence": float(assessment.confidence),
            "route": assessment.route,
            "reasons": assessment.reasons,
            "model_info": assessment.model_info,
            "kb_negatives_hit": assessment.kb_negatives_hit,
            "created_at": assessment.created_at,
        },
        "scan_jobs": [{
            "id": j.id, "engine": j.engine, "status": j.status,
            "result_class": j.result_class, "round": j.round,
            "duration_ms": j.duration_ms, "finished_at": j.finished_at,
        } for j in jobs],
        "vulnerabilities": [{
            "id": v.id, "vuln_type": v.vuln_type, "severity": v.severity,
            "title": v.title, "status": v.status, "dbms": v.dbms,
        } for v in vulns],
    }


class ReviewReq(BaseModel):
    action: str = Field(pattern="^(confirm|false_positive|adjust)$")
    adjusted_score: float | None = Field(default=None, ge=0, le=100)
    comment: str | None = None


@router.post("/review/{assessment_id}")
def submit_review(assessment_id: int, req: ReviewReq,
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """人在回路：人工复核研判条目。"""
    a = db.query(RiskAssessment).filter(RiskAssessment.id == assessment_id).first()
    if not a:
        raise HTTPException(404, "研判记录不存在")
    if user.role not in ("admin",) and req.action == "confirm":
        pass  # operator 也可复核；后续如需收紧再加权限

    review = ReviewAction(
        task_id=a.task_id, target_type="assessment", target_id=assessment_id,
        action=req.action, adjusted_score=(str(req.adjusted_score)
                                           if req.adjusted_score is not None else None),
        comment=req.comment, reviewer_id=user.id, reviewed_at=utcnow_iso(),
    )
    db.add(review)

    if req.action == "adjust" and req.adjusted_score is not None:
        a.risk_score = str(req.adjusted_score)
    if req.action == "confirm":
        a.route = "auto_pass"                     # 人工确认 → 放行进入探测
    if req.action == "false_positive":
        ep = db.query(Endpoint).filter(Endpoint.id == a.endpoint_id).first()
        if ep:
            knowledge.feedback_false_positive(
                db, endpoint=ep, review=review,
                reason=req.comment or "人工标记误报")   # 误报样本回流

    log_action(db, user_id=user.id, action="review_submit", resource_type="assessment",
               resource_id=assessment_id,
               detail={"action": req.action, "comment": (req.comment or "")[:200]})
    db.commit()
    _refresh_review_progress(db, a.task_id)
    return {"ok": True}


def _refresh_review_progress(db: Session, task_id: int):
    """复核后刷新任务进度文案（旧实现一直停在复核前的“等待 N 条”）。"""
    from app.models.task import Task
    from app.services.event_bus import bus

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task or task.status != "review":
        return
    reviewed = {r.target_id for r in db.query(ReviewAction)
                .filter(ReviewAction.task_id == task_id,
                        ReviewAction.target_type == "assessment",
                        ReviewAction.action != "adjust").all()}
    q = db.query(RiskAssessment).filter(
        RiskAssessment.task_id == task_id,
        RiskAssessment.route.in_(("manual_review", "suspicious")))
    if reviewed:
        q = q.filter(~RiskAssessment.id.in_(reviewed))
    pending = q.count()
    prog = dict(task.progress or {})
    prog.update({
        "stage": "review",
        "current_step": (f"等待人工复核（{pending} 条）" if pending
                         else "复核完成，可恢复扫描"),
    })
    task.progress = prog
    db.commit()
    if pending == 0:
        bus.publish("task", f"任务 #{task_id} 复核完成，可恢复扫描",
                    task_id=task_id, level="success")


@router.post("/reassess/{endpoint_id}")
def reassess(endpoint_id: int, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)):
    """重新研判单个接口（配置 AI 后重跑）。"""
    ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not ep:
        raise HTTPException(404, "接口不存在")
    from app.models.waf import WafProfile
    profile = db.query(WafProfile).filter(WafProfile.task_id == ep.task_id).first()
    row = ai.assess_endpoint(db, ep, profile)
    return {"assessment_id": row.id, "risk_score": float(row.risk_score),
            "confidence": float(row.confidence), "route": row.route,
            "model_info": row.model_info}
