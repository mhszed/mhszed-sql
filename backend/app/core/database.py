# -*- coding: utf-8 -*-
"""数据库引擎与会话：SQLite + SQLAlchemy，方言隔离（换 PG 只改 config.DB_URL）。"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

from app.core import config

# check_same_thread=False：FastAPI 多线程访问 SQLite 连接池
engine = create_engine(
    config.DB_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)

# WAL 模式：读写并发更好（证据归档写日志时不阻塞列表查询）
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()


def get_db():
    """FastAPI 依赖：请求级会话。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """建表 + 种子数据（默认管理员 + 内置 Payload 库）。幂等。"""
    import app.models  # noqa: F401 确保所有模型注册到 Base.metadata
    Base.metadata.create_all(engine)
    _migrate()
    _seed_admin()
    _seed_payloads()


def _migrate():
    """轻量迁移：create_all 不会给已有表补新列，此处手工补齐。幂等。"""
    from sqlalchemy import text
    with engine.connect() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(kb_false_positives)"))]
        if cols and "deleted_at" not in cols:
            conn.execute(text("ALTER TABLE kb_false_positives ADD COLUMN deleted_at VARCHAR(32)"))
            conn.commit()
        # 人工确认 payload：补 param 列（多参数接口指定注入参数）
        ccols = [r[1] for r in conn.execute(text("PRAGMA table_info(confirmed_payloads)"))]
        if ccols and "param" not in ccols:
            conn.execute(text("ALTER TABLE confirmed_payloads ADD COLUMN param VARCHAR(64)"))
            conn.commit()


def _seed_admin():
    from app.models.system import User
    from app.core.security import hash_password

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            db.add(User(
                username=config.DEFAULT_ADMIN["username"],
                password_hash=hash_password(config.DEFAULT_ADMIN["password"]),
                role="admin",
            ))
            db.commit()
    finally:
        db.close()


def _seed_payloads():
    """首次启动时导入内置 Payload 库（随仓库分发的通用样本，不含任何目标数据）。"""
    import json
    from pathlib import Path

    from app.models.kb import KbPayload

    fp = Path(__file__).resolve().parent.parent / "data" / "seed_payloads.json"
    if not fp.exists():
        return
    db = SessionLocal()
    try:
        if db.query(KbPayload).count() > 0:
            return
        try:
            rows = json.loads(fp.read_text(encoding="utf-8"))
        except Exception:
            return
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict) or not r.get("payload"):
                continue
            db.add(KbPayload(
                payload=str(r["payload"])[:2000],
                vector=str(r.get("vector") or "boolean")[:16],
                target_waf=(r.get("target_waf") or None),
                bypass_tags=r.get("bypass_tags"),
                dbms=(r.get("dbms") or None),
                source=str(r.get("source") or "manual")[:16],
                success_count=int(r.get("success_count") or 0),
                use_count=int(r.get("use_count") or 0),
            ))
        db.commit()
    finally:
        db.close()
