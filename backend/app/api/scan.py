# -*- coding: utf-8 -*-
"""扫描路由：实时进度、SSE 日志流、复核后恢复扫描。"""
import asyncio
import json
import queue as queue_mod
import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.endpoint import Endpoint
from app.models.scan import ScanJob
from app.models.system import User
from app.models.task import Task
from app.services import scheduler, task_manager
from app.services.event_bus import bus
from app.services.pipeline import _ep_route

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.get("/progress")
def progress(task_id: int, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    jobs = db.query(ScanJob).filter(ScanJob.task_id == task_id).order_by(ScanJob.id.desc()).limit(10).all()
    return {"status": task.status, "progress": task.progress,
            "recent_jobs": [{
                "id": j.id, "engine": j.engine, "endpoint_id": j.endpoint_id,
                "status": j.status, "result_class": j.result_class, "round": j.round,
                "duration_ms": j.duration_ms,
            } for j in jobs]}


@router.get("/stream/logs")
async def stream_logs(request: Request, task_id: int | None = None,
                      user: User = Depends(get_current_user)):
    """SSE 实时日志流。task_id 可选过滤（系统级日志始终放行）。

    连接时先回放 bus 历史，避免任务跑完再点「日志」一片空白。
    """
    q = bus.subscribe()

    async def gen():
        try:
            # 1) 历史回放（先于实时，否则早于订阅的日志永远看不到）
            for ev in bus.recent(500, task_id=task_id):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
            yield ": history-done\n\n"

            # 2) 实时
            while True:
                if await request.is_disconnected():
                    break
                sent = False
                while True:
                    try:
                        ev = q.get_nowait()
                    except queue_mod.Empty:
                        break
                    if task_id is None or ev.get("task_id") in (task_id, None):
                        yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
                        sent = True
                if not sent:
                    yield ": heartbeat\n\n"
                await asyncio.sleep(1)
        finally:
            bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "Connection": "keep-alive",
                                      "X-Accel-Buffering": "no"})


class ClearLogsReq(BaseModel):
    # 省略 task_id = 清空全部历史；指定 = 只清该任务的日志（系统级日志保留）
    task_id: int | None = None


@router.post("/logs/clear")
def clear_logs(req: ClearLogsReq | None = None,
               user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    """清空进程内日志历史：SSE 重连不再回放旧日志（前端同时清空本地列表）。"""
    from app.core.audit import log_action
    tid = req.task_id if req else None
    n = bus.clear(task_id=tid)
    log_action(db, user_id=user.id, action="logs_clear",
               detail={"task_id": tid, "cleared": n})
    db.commit()
    return {"ok": True, "cleared": n}


class ResumeReq(BaseModel):
    task_id: int


# 允许恢复扫描的任务状态：review = 正常复核后；done / terminated = 任务跑完后
# 又人工确认了新接口（旧实现只认 review，确认了也永远扫不到，2026-11-06 实测）。
_RESUMABLE_STATUSES = ("review", "done", "terminated")
# 同一任务的 resume 串行化：用户连点/前端自动重试时，第二个请求看到 scanning 直接返回，
# 不会拉起第二个扫描线程（run_scan 本身是单线程逐个接口扫，不存在并发扩散）。
_resume_lock = threading.Lock()


def _scan_complete_for(db: Session, task_id: int, endpoint_id: int,
                       engines: dict | None = None) -> bool:
    """该接口是否已经跑完**所有启用的引擎**。

    只看单个 job 的状态不够：ai_probe 完成 + sqlmap 被中断时，接口实际没测完。
    规则与 run_scan 的执行顺序一致：
      · 任一 job 已 vuln_confirmed → 完成（确认后不再跑下一个引擎）；
      · 否则按启用引擎逐个要求存在 finished/timeout 的 job。
    """
    engines = engines or {}
    jobs = (db.query(ScanJob)
            .filter(ScanJob.task_id == task_id, ScanJob.endpoint_id == endpoint_id)
            .all())
    if any(j.result_class == "vuln_confirmed" for j in jobs):
        return True

    def _terminal(engine: str) -> bool:
        return any(j.engine == engine and j.status in ("finished", "timeout") for j in jobs)

    ai_on = bool(engines.get("ai_probe_enabled", True))
    sm_on = bool(engines.get("sqlmap_enabled", True))
    if ai_on and sm_on:
        return _terminal("ai_probe") and _terminal("sqlmap")
    if sm_on:
        return _terminal("sqlmap")
    if ai_on:
        return _terminal("ai_probe")
    return True


@router.post("/resume")
def resume_scan(req: ResumeReq, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    """人工复核确认后恢复扫描：把已确认的接口纳入探测。

    允许 review / done / terminated 三种状态；重复调用幂等。
    """
    with _resume_lock:
        task = db.query(Task).filter(Task.id == req.task_id).first()
        if not task:
            raise HTTPException(404, "任务不存在")
        if task.status == "scanning":
            if task_manager.is_scan_running(task.id):
                return {"ok": True, "scanned": 0, "message": "扫描已在进行"}
            # 僵尸 scanning（线程已结束/服务重启）：复位后接管
            task_manager.set_status(db, task.id, "terminated",
                                    error="扫描线程已结束，接管恢复")
        if task.status not in _RESUMABLE_STATUSES:
            raise HTTPException(
                400, f"任务状态 {task.status} 不可恢复扫描（需 review/done/terminated）")

        cfg = task.scan_config or {}
        engines = cfg.get("engines", {})
        # 待扫 = 已确认/存疑，且**所有启用引擎都没有跑完**（见 _scan_complete_for）。
        # 不能只看"有没有 job"：ai_probe 完成 + sqlmap 被中断时，接口实际没测完。
        endpoints = db.query(Endpoint).filter(Endpoint.task_id == task.id).all()
        todo = [ep for ep in endpoints
                if _ep_route(db, ep.id) in ("auto_pass", "suspicious")
                and not _scan_complete_for(db, task.id, ep.id, engines)]
        if not todo:
            # 没有新接口：review 状态下视为复核完成；done/terminated 保持原状态
            if task.status == "review":
                task_manager.set_status(db, task.id, "done")
            return {"ok": True, "scanned": 0, "message": "无待扫接口"}

        task_manager.set_status(db, task.id, "scanning")
        allowed_hosts = {h for h in task_manager.TASK_CONTROL.get(task.id, {}).get("hosts", set())} \
            or {task.target.split("//")[-1].split("/")[0].split(":")[0]}

        def _run():
            from app.core.database import SessionLocal
            s = SessionLocal()
            try:
                stats = scheduler.run_scan(
                    s, task.id, todo, cfg, allowed_hosts,
                    stop_check=lambda: task_manager.is_stop_requested(task.id))
                if stats.get("unreachable"):
                    # 恢复扫描同样受“目标不可达即停”约束（否则任务会被标成 done）。
                    task_manager.set_status(
                        s, task.id, "terminated",
                        error="目标不可达：连续连接失败，已停止探测（保护目标）")
                    task_manager.update_progress(
                        s, task.id, stage="terminated", done=1, total=1,
                        current_step="目标不可达，探测中止")
                    return
                # 扫完：若还有未复核项回 review，否则 done
                remaining = [ep for ep in todo if _ep_route(s, ep.id) == "manual_review"]
                if remaining:
                    task_manager.set_status(s, task.id, "review")
                else:
                    task_manager.set_status(s, task.id, "done")
                    task_manager.update_progress(s, task.id, stage="done", done=1, total=1,
                                                 current_step="恢复扫描完成")
            finally:
                s.close()

        t = threading.Thread(target=_run, name=f"resume-{task.id}", daemon=True)
        task_manager.register_scan_thread(task.id, t, allowed_hosts)
        t.start()
        return {"ok": True, "scanned": len(todo)}
