# -*- coding: utf-8 -*-
"""采集路由：接口列表（分页/筛选）、手动录入、业务链列表。"""
from urllib.parse import urljoin, urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.endpoint import BusinessChain, Endpoint
from app.models.system import User
from app.models.task import Task
from app.services import normalizer

router = APIRouter(prefix="/api/collect", tags=["collect"])


class ManualParam(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    location: str = "query"          # query / body / header
    sample_value: str = ""
    required: bool = False


class ManualEndpointReq(BaseModel):
    task_id: int
    method: str = "GET"
    url: str = Field(min_length=1, max_length=1024)   # 完整 URL，或相对路径如 /check?id=1
    params: list[ManualParam] | None = None
    headers: dict[str, str] | None = None


def _ep_dict(r: Endpoint) -> dict:
    return {
        "id": r.id, "source": r.source, "method": r.method, "path": r.path,
        "raw_path": r.raw_path, "host": r.host, "params": r.params,
        "read_write": r.read_write, "chain_id": r.chain_id,
        "chain_inferred": bool(r.chain_inferred), "burp_seen_at": r.burp_seen_at,
        "created_at": r.created_at,
    }


@router.get("/endpoints")
def list_endpoints(task_id: int, page: int = 1, page_size: int = 15,
                   read_write: str | None = None, source: str | None = None,
                   keyword: str | None = None,
                   user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    q = db.query(Endpoint).filter(Endpoint.task_id == task_id)
    if read_write:
        q = q.filter(Endpoint.read_write == read_write)
    if source:
        q = q.filter(Endpoint.source.contains(source))
    if keyword:
        q = q.filter(Endpoint.path.contains(keyword))
    total = q.count()
    rows = q.order_by(Endpoint.id.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"total": total, "page": page, "page_size": page_size,
            "items": [_ep_dict(r) for r in rows]}


@router.post("/endpoints")
def create_manual_endpoint(req: ManualEndpointReq, user: User = Depends(get_current_user),
                           db: Session = Depends(get_db)):
    """手动录入接口：可选方法 + URL/路径 + 参数列表。

    用于静态爬虫挖不到的动态接口（如 JS 模板字符串里的 /check?id=${...}）。
    """
    task = db.query(Task).filter(Task.id == req.task_id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    method = (req.method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        raise HTTPException(400, f"不支持的方法: {method}")

    raw = (req.url or "").strip()
    if not raw:
        raise HTTPException(400, "url 不能为空")
    if raw.startswith("http://") or raw.startswith("https://"):
        full = raw
    else:
        # 相对路径：挂到任务目标上
        base = task.target if task.target.endswith("/") else task.target + "/"
        full = urljoin(base, raw.lstrip("/?") if raw.startswith("?") else raw)

    parsed = urlparse(full)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(400, "无法解析为合法 URL，请填完整地址或 /path?a=1")

    body_params = None
    header_params = []
    if req.params:
        body_params, query_extra = [], []
        for p in req.params:
            loc = (p.location or "query").lower()
            if loc not in ("query", "body", "header"):
                raise HTTPException(400, f"参数 {p.name} location 须为 query/body/header")
            item = {"name": p.name, "location": loc, "type": "string",
                    "sample_value": (p.sample_value or "")[:200], "required": bool(p.required)}
            if loc == "header":
                header_params.append(item)
            elif loc == "body":
                body_params.append(item)
            else:
                query_extra.append(item)
        # query 参数并进 URL，便于 upsert 解析
        if query_extra:
            from urllib.parse import urlencode, parse_qsl, urlunparse
            q = dict(parse_qsl(parsed.query, keep_blank_values=True))
            for p in query_extra:
                q.setdefault(p["name"], p.get("sample_value") or "1")
            full = urlunparse(parsed._replace(query=urlencode(q)))
            parsed = urlparse(full)

    headers = dict(req.headers or {})
    for hp in header_params:
        headers.setdefault(hp["name"], hp.get("sample_value") or "")

    ep = normalizer.upsert_endpoint(
        db, task_id=task.id, source="manual", method=method, url=full,
        headers=headers or None, body_params=body_params or None,
    )
    # upsert 对已存在接口不改 source 为纯 manual 时可能合并；保证 params 里 header 也留下
    if header_params:
        ep.params = normalizer._merge_params(ep.params, header_params)
    db.commit()
    db.refresh(ep)
    return {"ok": True, "item": _ep_dict(ep)}


class ConfirmedPayloadReq(BaseModel):
    payload: str = Field(min_length=1, max_length=2000)
    param: str | None = Field(default=None, max_length=64)   # 注入参数名（多参数接口必填）
    note: str | None = None


@router.get("/endpoints/{endpoint_id}/confirmed-payload")
def list_confirmed_payloads(endpoint_id: int, user: User = Depends(get_current_user),
                            db: Session = Depends(get_db)):
    from app.models.confirmed import ConfirmedPayload
    rows = (db.query(ConfirmedPayload)
            .filter(ConfirmedPayload.endpoint_id == endpoint_id)
            .order_by(ConfirmedPayload.id.desc()).all())
    return {"items": [{"id": r.id, "payload": r.payload, "note": r.note,
                       "created_at": r.created_at} for r in rows]}


@router.post("/endpoints/{endpoint_id}/confirmed-payload")
def add_confirmed_payload(endpoint_id: int, req: ConfirmedPayloadReq,
                          user: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    """录入人工确认的 payload：探测器会优先用它做受控对照复测。

    返回反推出的注入语境（prefix/suffix），便于分析员确认闭合方式是否正确。
    """
    from app.models.confirmed import ConfirmedPayload

    ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not ep:
        raise HTTPException(404, "接口不存在")
    payload = (req.payload or "").strip()
    if not payload:
        raise HTTPException(400, "payload 不能为空")
    existing = (db.query(ConfirmedPayload)
                .filter(ConfirmedPayload.endpoint_id == endpoint_id,
                        ConfirmedPayload.payload == payload).first())
    if existing:
        if req.param:
            existing.param = req.param.strip()[:64]
            db.commit()
        return {"ok": True, "id": existing.id, "deduped": True,
                "context": _confirmed_context(payload)}
    row = ConfirmedPayload(endpoint_id=endpoint_id, payload=payload,
                           param=((req.param or "").strip()[:64] or None),
                           note=(req.note or "")[:256], created_by=user.id)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"ok": True, "id": row.id, "context": _confirmed_context(payload)}


def _confirmed_context(payload: str) -> dict:
    from app.services.deep_exploit import _derive_prefix_suffix
    ps = _derive_prefix_suffix(payload)
    return {"prefix": ps[0] if ps else None,
            "suffix": ps[1] if ps else None,
            "quote": (ps[0][-1] if ps and ps[0] and ps[0][-1] in ("'", '"') else None)}


@router.post("/endpoints/{endpoint_id}/scan")
def scan_endpoint(endpoint_id: int, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    """定向重扫单个接口（手动录入后的补扫）。

    不重新采集、不碰其他接口：只对该接口跑探测调度（AI 探针 / sqlmap）。
    允许 done/terminated 任务回到 scanning（见 task_manager._TRANSITIONS）。
    """
    from app.services import task_manager
    from app.services.safety import AuthorizationError

    ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not ep:
        raise HTTPException(404, "接口不存在")
    try:
        task = task_manager.start_endpoint_scan(db, ep.task_id, endpoint_id,
                                                user_id=user.id)
    except AuthorizationError as e:
        raise HTTPException(403, str(e))
    except task_manager.TaskStateError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "task_id": task.id, "status": task.status}


@router.delete("/endpoints/{endpoint_id}")
def delete_endpoint(endpoint_id: int, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """删除单个接口及其扫描/漏洞关联数据。

    删除前检查所属任务状态：采集中/扫描中禁止删（会与正在跑的
    pipeline 抢数据），与任务删除的守卫保持一致。
    """
    from app.models.assessment import RiskAssessment
    from app.models.scan import ScanJob
    from app.models.vuln import Evidence, Vulnerability

    ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not ep:
        raise HTTPException(404, "接口不存在")
    task = db.query(Task).filter(Task.id == ep.task_id).first()
    if task and task.status in ("collecting", "scanning"):
        raise HTTPException(400, "任务运行中，请先终止再删除接口")

    vuln_ids = [r[0] for r in db.query(Vulnerability.id)
                .filter(Vulnerability.endpoint_id == endpoint_id).all()]
    if vuln_ids:
        db.query(Evidence).filter(Evidence.vulnerability_id.in_(vuln_ids)).delete(
            synchronize_session=False)
        db.query(Vulnerability).filter(Vulnerability.endpoint_id == endpoint_id).delete(
            synchronize_session=False)
    db.query(ScanJob).filter(ScanJob.endpoint_id == endpoint_id).delete(
        synchronize_session=False)
    db.query(RiskAssessment).filter(RiskAssessment.endpoint_id == endpoint_id).delete(
        synchronize_session=False)
    # 业务链里还挂着被删接口 → 剔除；不足两条节点的链直接删除，
    # 否则页面会显示 "POST /verify → POST /search" 这种指向已删接口的残链。
    for ch in db.query(BusinessChain).filter(BusinessChain.task_id == ep.task_id).all():
        ids = [i for i in (ch.node_ids or []) if i != endpoint_id]
        if len(ids) == len(ch.node_ids or []):
            continue
        if len(ids) < 2:
            db.delete(ch)
        else:
            ch.node_ids = ids
    db.delete(ep)
    db.commit()
    return {"ok": True, "endpoint_id": endpoint_id, "deleted_vulns": len(vuln_ids)}


@router.get("/chains")
def list_chains(task_id: int, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    rows = db.query(BusinessChain).filter(BusinessChain.task_id == task_id).all()
    return {"items": [
        {"id": r.id, "name": r.name, "reconstruct_method": r.reconstruct_method,
         "confidence": r.confidence, "node_ids": r.node_ids}
        for r in rows]}
