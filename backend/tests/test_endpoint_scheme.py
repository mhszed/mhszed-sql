# -*- coding: utf-8 -*-
"""接口协议（http/https）落库与探测 URL 构造 单元测试。

不依赖服务（无需 uvicorn / demo_site / 真实 HTTPS 目标）。
运行：venv/Scripts/python tests/test_endpoint_scheme.py
"""
import sys
import tempfile
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  注册全部模型
from app.core import database as database_mod
from app.core.database import Base
from app.models.endpoint import Endpoint
from app.services import ai, normalizer, prober

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def _db_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _endpoint(**kw):
    base = dict(task_id=1, source="crawler", dedup_hash="h", method="GET",
                path="/a", raw_path="/a", host="example.com", params=[], read_write="read")
    base.update(kw)
    return Endpoint(**base)


def test_upsert_stores_scheme():
    maker = _db_factory()
    db = maker()
    try:
        ep = normalizer.upsert_endpoint(
            db, task_id=1, source="crawler", method="GET",
            url="https://example.com/login?u=1")
        check("https 目标存 scheme=https", ep.scheme == "https", f"got={ep.scheme!r}")

        ep2 = normalizer.upsert_endpoint(
            db, task_id=1, source="crawler", method="GET",
            url="http://plain.example.com/list?q=1")
        check("http 目标存 scheme=http", ep2.scheme == "http", f"got={ep2.scheme!r}")

        # 老数据 scheme 为空：再次采集同一接口时应补上
        ep.scheme = None
        db.commit()
        again = normalizer.upsert_endpoint(
            db, task_id=1, source="crawler", method="GET",
            url="https://example.com/login?u=1")
        check("老接口补 scheme", again.scheme == "https", f"got={again.scheme!r}")
    finally:
        db.close()


def test_build_request_uses_scheme():
    ep_https = _endpoint(scheme="https", params=[
        {"name": "id", "location": "query", "sample_value": "1"}])
    url, params, data = prober._build_request(ep_https, "id", "1")
    check("_build_request 走 https", url.startswith("https://example.com/a"), url)

    url2, _, _ = prober._build_request_keep(ep_https, "id", "1")
    check("_build_request_keep 走 https", url2.startswith("https://example.com/a"), url2)

    ep_legacy = _endpoint(params=[{"name": "id", "location": "query", "sample_value": "1"}])
    url3, _, _ = prober._build_request(ep_legacy, "id", "1")
    check("老数据（scheme=None）回退 http", url3.startswith("http://example.com/a"), url3)


def test_ai_probe_uses_scheme():
    import httpx

    calls = []

    class _Resp:
        status_code = 200
        text = ""
        content = b""

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def get(self, url, params=None):
            calls.append(url)
            return _Resp()

        def post(self, url, data=None):
            calls.append(url)
            return _Resp()

        def close(self):
            pass

    ep = _endpoint(scheme="https", params=[
        {"name": "q", "location": "query", "sample_value": "1"}])

    orig_client, orig_sleep = httpx.Client, time.sleep
    httpx.Client, time.sleep = _FakeClient, (lambda _s: None)
    try:
        ai._collect_sqli_probes(ep)
    finally:
        httpx.Client, time.sleep = orig_client, orig_sleep

    check("研判探针确实发了请求", len(calls) > 0, f"calls={len(calls)}")
    check("研判探针全部走 https", all(u.startswith("https://example.com/") for u in calls),
          calls[0] if calls else "无请求")


def test_migrate_adds_and_backfills_scheme():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "old.db"
        eng = create_engine(f"sqlite:///{path}")
        with eng.begin() as conn:
            conn.execute(text("CREATE TABLE tasks (id INTEGER PRIMARY KEY, target VARCHAR(512))"))
            conn.execute(text("CREATE TABLE endpoints (id INTEGER PRIMARY KEY, task_id INTEGER, "
                              "host VARCHAR(256))"))
            conn.execute(text("INSERT INTO tasks VALUES (1,'https://a.example'),"
                              "(2,'http://b.example')"))
            conn.execute(text("INSERT INTO endpoints VALUES (1,1,'a.example'),"
                              "(2,2,'b.example'),(3,99,'orphan.example')"))

        orig_engine = database_mod.engine
        database_mod.engine = eng
        try:
            database_mod._migrate()
            with eng.connect() as conn:
                cols = [r[1] for r in conn.execute(text("PRAGMA table_info(endpoints)"))]
                rows = dict(conn.execute(text("SELECT id, scheme FROM endpoints")).fetchall())
        finally:
            database_mod.engine = orig_engine
            eng.dispose()

    check("迁移补出 scheme 列", "scheme" in cols, f"cols={cols}")
    check("https 任务回填 https", rows.get(1) == "https", f"got={rows.get(1)!r}")
    check("http 任务回填 http", rows.get(2) == "http", f"got={rows.get(2)!r}")
    check("孤儿接口保持 NULL（探测端回退 http）", rows.get(3) is None, f"got={rows.get(3)!r}")


def main():
    test_upsert_stores_scheme()
    test_build_request_uses_scheme()
    test_ai_probe_uses_scheme()
    test_migrate_adds_and_backfills_scheme()
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
