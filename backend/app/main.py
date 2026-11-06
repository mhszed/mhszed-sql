# -*- coding: utf-8 -*-
"""mhszed-sql 后端入口。

启动：cd backend && venv\\Scripts\\uvicorn app.main:app --host 127.0.0.1 --port 8787
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import init_db
from app.api import auth, task, collect, burp, settings, ai, kb, waf, scan, vuln, audit


def _recover_stale_tasks():
    """服务重启后复位"僵尸"任务。

    进程被杀时后台线程终止，但 DB 里的 collecting/scanning 状态会残留，
    再点定向复测就会报「非法状态迁移：scanning → scanning」。启动时把
    无存活线程的活动任务标为 terminated，避免卡死。
    """
    from app.core.database import SessionLocal
    from app.models.task import Task
    from app.services import task_manager

    db = SessionLocal()
    try:
        for t in db.query(Task).filter(Task.status.in_(("collecting", "scanning"))).all():
            ctl = task_manager.TASK_CONTROL.get(t.id)
            if ctl and ctl.get("thread") and ctl["thread"].is_alive():
                continue
            t.status = "terminated"
            t.error_message = "服务重启，任务被中断"
        db.commit()
    finally:
        db.close()


def _recover_stale_jobs(db=None):
    """服务重启后把中断的 scan_job 标为已终止。

    进程被杀时线程直接消失，但 DB 里的 queued/running 会残留，界面一直显示"运行中"。
    重启后这些 job 不可能再有结果，统一落为 killed（前端已有对应文案）。
    """
    from app.core.database import SessionLocal
    from app.models.base import utcnow_iso
    from app.models.scan import ScanJob
    from app.services.event_bus import bus

    own = db is None
    if own:
        db = SessionLocal()
    try:
        rows = db.query(ScanJob).filter(ScanJob.status.in_(("queued", "running"))).all()
        now = utcnow_iso()
        for j in rows:
            j.status = "killed"
            j.finished_at = j.finished_at or now
        if rows:
            db.commit()
            bus.publish("system", f"启动清理：{len(rows)} 条中断的扫描任务已标记为已终止",
                        level="warn")
        return len(rows)
    finally:
        if own:
            db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()          # 建表 + 种子管理员（幂等）
    _recover_stale_tasks()
    _recover_stale_jobs()
    yield


app = FastAPI(title="mhszed-sql", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],  # 前端 dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(task.router)
app.include_router(task.scope_router)
app.include_router(collect.router)
app.include_router(burp.router)
app.include_router(settings.router)
app.include_router(ai.router)
app.include_router(kb.router)
app.include_router(waf.router)
app.include_router(scan.router)
app.include_router(vuln.router)
app.include_router(audit.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "mhszed-sql"}
