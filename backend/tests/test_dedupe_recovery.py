# -*- coding: utf-8 -*-
"""重复漏洞合并 + 启动清理僵尸 scan_job 单元测试。

运行：venv/Scripts/python tests/test_dedupe_recovery.py
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app import main as app_main
from app.core.database import Base
from app.models.endpoint import Endpoint
from app.models.scan import ScanJob
from app.models.vuln import Evidence, Vulnerability
from app.services import evidence as evidence_svc

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def _db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


def _endpoint(db):
    ep = Endpoint(task_id=1, source="crawler", dedup_hash="h", method="GET",
                  path="/vul/sqli/sqli_blind_b.php",
                  raw_path="/vul/sqli/sqli_blind_b.php", host="target.local:8080",
                  scheme="http", read_write="read",
                  params=[{"name": "name", "location": "query", "sample_value": "1"}])
    db.add(ep)
    db.commit()
    return ep


def _vuln(db, ep, payload, job_id=1):
    return evidence_svc.create_vulnerability(
        db, task_id=1, endpoint=ep, scan_job_id=job_id,
        vuln_type="sql_injection_time", title="SQL注入（测试）",
        vector_count=1, hits=[{"vector": "time", "payload": payload, "criteria": "x"}])


def test_same_payload_merges():
    db = _db()
    ep = _endpoint(db)
    v1 = _vuln(db, ep, "1 and sleep(3)-- -", 1)
    v2 = _vuln(db, ep, "1 and sleep(3)-- -", 2)
    check("重复扫描不新建漏洞", db.query(Vulnerability).count() == 1,
          f"count={db.query(Vulnerability).count()}")
    check("返回同一条漏洞", v1.id == v2.id, f"{v1.id} vs {v2.id}")
    n = db.query(Evidence).filter_by(vulnerability_id=v1.id,
                                     evidence_type="payload").count()
    check("相同 payload 证据不重复堆积", n == 1, f"payload evidence={n}")
    db.close()


def test_new_payload_appends_evidence():
    db = _db()
    ep = _endpoint(db)
    v1 = _vuln(db, ep, "1 and sleep(3)-- -", 1)
    _vuln(db, ep, "1 and if(1=1,sleep(3),1)-- -", 2)
    check("不同 payload 仍只有一条漏洞", db.query(Vulnerability).count() == 1)
    n = db.query(Evidence).filter_by(vulnerability_id=v1.id,
                                     evidence_type="payload").count()
    check("不同 payload 证据追加", n == 2, f"payload evidence={n}")
    db.close()


def test_false_positive_not_merged():
    db = _db()
    ep = _endpoint(db)
    v1 = _vuln(db, ep, "1 and sleep(3)-- -", 1)
    v1.status = "false_positive"
    db.commit()
    v2 = _vuln(db, ep, "1 and sleep(3)-- -", 2)
    check("误报后再确认 → 新建记录", v2.id != v1.id and db.query(Vulnerability).count() == 2,
          f"count={db.query(Vulnerability).count()}")
    db.close()


def test_stale_job_recovery():
    db = _db()
    ep = _endpoint(db)
    running = ScanJob(task_id=1, endpoint_id=ep.id, engine="ai_probe",
                      status="running", round=1)
    queued = ScanJob(task_id=1, endpoint_id=ep.id, engine="sqlmap",
                     status="queued", round=1)
    finished = ScanJob(task_id=1, endpoint_id=ep.id, engine="sqlmap",
                       status="finished", result_class="no_vuln", round=1)
    db.add_all([running, queued, finished])
    db.commit()

    n = app_main._recover_stale_jobs(db)
    db.refresh(running)
    db.refresh(queued)
    db.refresh(finished)
    check("启动清理处理 2 条中断 job", n == 2, f"n={n}")
    check("running → killed", running.status == "killed" and bool(running.finished_at))
    check("queued → killed", queued.status == "killed" and bool(queued.finished_at))
    check("已完成的 job 不被改动",
          finished.status == "finished" and not finished.finished_at)
    db.close()


def main():
    test_same_payload_merges()
    test_new_payload_appends_evidence()
    test_false_positive_not_merged()
    test_stale_job_recovery()
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
