# -*- coding: utf-8 -*-
"""mhszed-sql 后端入口。

启动：cd backend && venv\\Scripts\\uvicorn app.main:app --host 127.0.0.1 --port 8787
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import init_db
from app.api import auth, task, collect, burp, settings, ai, kb, waf, scan, vuln, audit


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()          # 建表 + 种子管理员（幂等）
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
