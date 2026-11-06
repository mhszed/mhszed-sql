# -*- coding: utf-8 -*-
"""复核确认 → 恢复扫描流程 单元测试（源码级断言，不依赖服务）。

覆盖 2026-11-06 修复：任务 done/terminated 后新确认的接口也必须能恢复扫描；
并发重复调用只拉起一个扫描线程；run_scan 是单线程顺序扫，不会因连点并发扩散。

运行：venv/Scripts/python tests/test_resume_flow.py
"""
import inspect
import sys
import threading
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api import scan as scan_api
from app.core.database import Base
from app.models.endpoint import Endpoint
from app.models.scan import ScanJob
from app.services import scheduler, task_manager

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def _mem_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


def _job(db, eid, engine, status, result=None):
    db.add(ScanJob(task_id=1, endpoint_id=eid, engine=engine, status=status,
                   result_class=result, round=1))
    db.commit()


def test_scan_complete_per_engine():
    db = _mem_db()
    engines = {"ai_probe_enabled": True, "sqlmap_enabled": True}

    _job(db, 1, "ai_probe", "finished", "no_vuln")
    _job(db, 1, "sqlmap", "killed")
    check("ai 完成 + sqlmap 被中断 → 未扫完",
          scan_api._scan_complete_for(db, 1, 1, engines) is False)

    _job(db, 2, "ai_probe", "finished", "no_vuln")
    _job(db, 2, "sqlmap", "finished", "no_vuln")
    check("ai + sqlmap 都完成 → 已扫完",
          scan_api._scan_complete_for(db, 1, 2, engines) is True)

    _job(db, 3, "ai_probe", "finished", "vuln_confirmed")
    check("ai 已确认 → 无需 sqlmap 也算扫完",
          scan_api._scan_complete_for(db, 1, 3, engines) is True)

    _job(db, 4, "ai_probe", "finished", "no_vuln")
    _job(db, 4, "sqlmap", "timeout", "timeout")
    check("ai 完成 + sqlmap 超时 → 已扫完",
          scan_api._scan_complete_for(db, 1, 4, engines) is True)

    _job(db, 5, "ai_probe", "finished", "no_vuln")
    check("只开 ai 引擎 → ai 完成即扫完",
          scan_api._scan_complete_for(
              db, 1, 5, {"ai_probe_enabled": True, "sqlmap_enabled": False}) is True)
    db.close()


def main():
    test_scan_complete_per_engine()
    src = inspect.getsource(scan_api.resume_scan)
    check("允许 review/done/terminated 恢复",
          scan_api._RESUMABLE_STATUSES == ("review", "done", "terminated"),
          str(scan_api._RESUMABLE_STATUSES))
    check("resume 用锁串行化", "with _resume_lock:" in src)
    check("僵尸 scanning 会被接管复位", "扫描线程已结束，接管恢复" in src)
    check("resume 线程登记进 TASK_CONTROL",
          "register_scan_thread" in src)
    check("resume 用逐引擎判定是否扫完", "_scan_complete_for(" in src)

    stop_src = inspect.getsource(task_manager.stop_task)
    check("停止任务时把在跑 job 标 killed（源头防漏扫）",
          'ScanJob.status.in_(("queued", "running"))' in stop_src
          and 'j.status = "killed"' in stop_src)

    tr = task_manager._TRANSITIONS
    check("状态机允许 pending → scanning（手动接口任务）", "scanning" in tr.get("pending", set()))
    check("状态机允许 done → scanning", "scanning" in tr.get("done", set()))
    check("状态机允许 terminated → scanning", "scanning" in tr.get("terminated", set()))

    # run_scan 必须是单线程逐个接口：连点确认不会变成多线程同时打目标
    run_src = inspect.getsource(scheduler.run_scan)
    check("run_scan 单线程顺序遍历接口",
          "for idx, ep in enumerate(endpoints" in run_src)
    check("run_scan 无 ThreadPool 并发扩散", "ThreadPool" not in run_src)

    # is_scan_running / register_scan_thread 行为
    tid = -987654
    task_manager.TASK_CONTROL.pop(tid, None)
    check("无登记线程 → 未运行", task_manager.is_scan_running(tid) is False)

    t = threading.Thread(target=lambda: None)
    task_manager.register_scan_thread(tid, t, {"example.com"})
    t.start()
    t.join()
    check("线程结束后 → 未运行（僵尸可接管）", task_manager.is_scan_running(tid) is False)
    check("登记时写入授权 host",
          task_manager.TASK_CONTROL[tid]["hosts"] == {"example.com"})
    task_manager.TASK_CONTROL.pop(tid, None)

    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
