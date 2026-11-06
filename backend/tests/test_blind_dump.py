# -*- coding: utf-8 -*-
"""盲注脱裤（表枚举 + 单表 ≤5 行）单元测试。

运行：venv/Scripts/python tests/test_blind_dump.py
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.database import Base
from app.services import deep_exploit

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def _db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


TABLES_OUT = """Database: root
[3 tables]
+----------+
| users    |
| admin    |
| flag     |
+----------+
"""

DUMP_OUT = """Database: root
Table: flag
[1 entry]
+----+--------------------+
| id | content            |
+----+--------------------+
| 1  | flag{local_lab}    |
+----+--------------------+
"""


def _run(db, fake):
    orig = deep_exploit.runner.run_sqlmap
    deep_exploit.runner.run_sqlmap = fake
    try:
        return deep_exploit._blind_sqlmap_dump(
            db, SimpleNamespace(id=99, task_id=1, endpoint_id=1,
                                vuln_type="sql_injection_time"),
            SimpleNamespace(read_write="read"),
            "http://target.local:8080/vul/sqli/sqli_blind_b.php?name=1", "GET",
            None, "name", None, "MySQL", "root")
    finally:
        deep_exploit.runner.run_sqlmap = orig


def test_dump_flow():
    db = _db()
    calls = []

    def fake(**kw):
        calls.append(kw)
        if len(calls) == 1:
            return {"status": "finished", "result_class": "exploit_ok",
                    "full_output": TABLES_OUT, "duration_ms": 100}
        return {"status": "finished", "result_class": "exploit_ok",
                "full_output": DUMP_OUT, "duration_ms": 200}

    tables, table, sample, note = _run(db, fake)
    check("表枚举解析", "flag" in tables and "users" in tables, str(tables))
    check("优先 flag 表", table == "flag", f"table={table}")
    check("样本包含脱裤数据", "flag{local_lab}" in sample, sample[:80])
    check("表枚举用 --tables + 600s",
          calls[0]["extra_args"][:4] == ["--technique", "T", "--time-sec", "2"]
          and "--tables" in calls[0]["extra_args"]
          and calls[0]["timeout_s"] == 600)
    dump_extra = calls[1]["extra_args"]
    check("脱裤用 --dump + --stop 5 + 300s",
          "--dump" in dump_extra and "-T" in dump_extra
          and dump_extra[dump_extra.index("-T") + 1] == "flag"
          and "--stop" in dump_extra
          and dump_extra[dump_extra.index("--stop") + 1] == "5"
          and calls[1]["timeout_s"] == 300)
    check("脱裤只读（is_write=False）", calls[1]["is_write"] is False)
    db.close()


def test_no_tables_skips_dump():
    db = _db()
    calls = []

    def fake(**kw):
        calls.append(kw)
        return {"status": "timeout", "result_class": "timeout",
                "full_output": "", "duration_ms": 300}

    tables, table, sample, note = _run(db, fake)
    check("表为空不继续脱裤", tables == [] and table is None and len(calls) == 1,
          f"calls={len(calls)}")
    check("失败留痕", "未取到" in note, note)
    db.close()


def main():
    test_dump_flow()
    test_no_tables_skips_dump()
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
