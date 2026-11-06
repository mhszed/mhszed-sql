# -*- coding: utf-8 -*-
"""盲注轻量提取失败后的 sqlmap 回退 单元测试。

重点：回退不能把目标钉死在盲注技法上（必须是 BEUSTQ，让 sqlmap 自己选最快技法）。
运行：venv/Scripts/python tests/test_blind_fallback.py
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


def _call(db, vuln_type, fake):
    orig = deep_exploit.runner.run_sqlmap
    deep_exploit.runner.run_sqlmap = fake
    try:
        return deep_exploit._blind_sqlmap_current_db(
            db, SimpleNamespace(id=99, task_id=1, endpoint_id=1, vuln_type=vuln_type),
            SimpleNamespace(read_write="read"),
            "http://target.local:8080/vul/sqli/sqli_id.php", "POST",
            "id=1&submit=x", "id", None, "MySQL")
    finally:
        deep_exploit.runner.run_sqlmap = orig


def test_success_and_techniques():
    db = _db()
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return {"status": "finished", "result_class": "vuln_confirmed",
                "full_output": ("current database: 'pikachu'\n"
                                "Payload: name=1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))x)"),
                "data_payload": "1' AND (SELECT 1 FROM (SELECT(SLEEP(2-(IF(1=1,0,2)))))x)",
                "duration_ms": 1234}

    name, note, payload, data_payload = _call(db, "sql_injection_time", fake)
    check("回退取到库名", name == "pikachu", f"got={name!r}")
    check("回退记录检测 Payload", bool(payload) and "SLEEP" in payload, str(payload))
    check("回退记录可复现的取数 Payload",
          bool(data_payload) and "IF(1=1" in data_payload, str(data_payload))
    extra = seen.get("extra_args") or []
    check("time 型用 T 技法", extra[:2] == ["--technique", "T"], str(extra))
    check("回退带 --current-db", "--current-db" in extra)
    check("time-sec 用 2（慢目标更稳）",
          "--time-sec" in extra and extra[extra.index("--time-sec") + 1] == "2")
    check("回退复用已知 DBMS", seen.get("dbms_hint") == "MySQL")
    check("回退用独立输出目录（不复用旧 session）",
          str(seen.get("out_dir_key") or "").startswith("vuln_99_deep_"))
    db.close()


def test_boolean_also_normal_techniques():
    db = _db()
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return {"status": "finished", "result_class": "no_vuln", "full_output": ""}

    name, note, payload, data_payload = _call(db, "sql_injection_boolean", fake)
    check("boolean 型用 B 技法",
          (seen.get("extra_args") or [])[:2] == ["--technique", "B"])
    check("无结果时返回 None 并说明", name is None and "未取到" in note, note)
    db.close()


def test_exception_kept():
    db = _db()

    def fake(**kw):
        raise RuntimeError("boom")

    name, note, payload, data_payload = _call(db, "sql_injection_time", fake)
    check("回退异常 → 返回 None 且留痕",
          name is None and "异常" in note, note)
    db.close()


def main():
    test_success_and_techniques()
    test_boolean_also_normal_techniques()
    test_exception_kept()
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
