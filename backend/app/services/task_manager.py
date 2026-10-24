# -*- coding: utf-8 -*-
"""任务管理：状态机 + 终止信号 + 后台流水线线程调度。

状态机：
  pending → collecting → scanning → review → done
  任意活动态 → terminated（终止）/ paused_circuit（熔断暂停）
非法跳变直接拒绝（ValueError）。
"""
import threading

from sqlalchemy.orm import Session

from app.core import config
from app.core.audit import log_action
from app.models.base import utcnow_iso
from app.models.task import Task
from app.services.event_bus import bus
from app.services import safety

# 合法状态迁移表
_TRANSITIONS = {
    "pending":       {"collecting"},
    "collecting":    {"scanning", "terminated", "paused_circuit"},
    "scanning":      {"review", "done", "terminated", "paused_circuit"},
    "paused_circuit": {"scanning", "terminated"},
    "review":        {"done", "terminated", "scanning"},
    # 定向重扫（手动录入接口后补扫）：终态任务允许回到 scanning，
    # 但只由 start_endpoint_scan 触发，start_task 仍要求 pending/stopped/error。
    "done":          {"scanning"},
    "terminated":    {"scanning"},
}
_ACTIVE = {"pending", "collecting", "scanning", "paused_circuit", "review"}

# 进程内任务控制区：task_id -> {"stop": Event, "thread": Thread, "hosts": set}
TASK_CONTROL: dict[int, dict] = {}
_tc_lock = threading.Lock()


class TaskStateError(Exception):
    pass


def normalize_target(target: str) -> str:
    """目标 URL 去首尾空白。

    urlparse 能容忍 `" http://..."`，httpx 不能 → 采集阶段每个请求都抛
    UnsupportedProtocol 又被吞掉，任务 1 秒结束、0 接口（2026-10-22 实测 #26）。
    """
    return (target or "").strip()


def create_task(db: Session, *, user_id: int, name: str, target: str,
                collect_mode: str = "both", scan_config: dict | None = None) -> Task:
    target = normalize_target(target)
    cfg = dict(config.DEFAULT_SCAN_CONFIG)
    if scan_config:
        cfg.update(scan_config)          # 浅合并；circuit_breaker 子 dict 需深合并
        if "circuit_breaker" in scan_config:
            cfg["circuit_breaker"] = {**config.DEFAULT_SCAN_CONFIG["circuit_breaker"],
                                      **scan_config["circuit_breaker"]}
    task = Task(name=name, target=target, status="pending",
                collect_mode=collect_mode, scan_config=cfg,
                progress={"stage": "pending", "done": 0, "total": 0, "current_step": ""},
                created_by=user_id)
    db.add(task)
    db.flush()
    log_action(db, user_id=user_id, action="task_create", resource_type="task",
               resource_id=task.id, detail={"target": target, "mode": collect_mode})
    db.commit()
    return task


def start_task(db: Session, task_id: int, user_id: int | None = None) -> Task:
    """前置授权校验 → 状态迁移 → 拉起流水线后台线程。"""
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise TaskStateError("任务不存在")
    # 兼容历史任务（#26 的 target 带前导空格）：启动时顺手修正并落库。
    _clean_target = normalize_target(task.target)
    if _clean_target != task.target:
        task.target = _clean_target
        db.commit()
    _assert_transition(task.status, "collecting")

    # ---- 授权校验（红线：未授权目标拒绝启动）----
    from urllib.parse import urlparse
    host = urlparse(task.target if "//" in task.target else f"http://{task.target}").hostname or ""
    ok, scope, reason = safety.check_authorization(db, task.target)
    if not ok:
        log_action(db, user_id=user_id, action="auth_reject", resource_type="task",
                   resource_id=task.id, detail={"target": task.target, "reason": reason})
        db.commit()
        raise safety.AuthorizationError(reason)
    task.auth_scope_id = scope.id

    # 授权 host 集合 = 目标 host（爬虫/Burp 流量按此约束，防漂移到范围外）
    allowed_hosts = {host}

    with _tc_lock:
        if task_id in TASK_CONTROL and TASK_CONTROL[task_id]["thread"].is_alive():
            raise TaskStateError("任务线程已在运行")
        control = {"stop": threading.Event(), "thread": None, "hosts": allowed_hosts}
        TASK_CONTROL[task_id] = control

    task.status = "collecting"
    task.started_at = utcnow_iso()
    task.error_message = None
    log_action(db, user_id=user_id, action="scan_start", resource_type="task",
               resource_id=task.id, detail={"target": task.target, "scope": scope.name})
    db.commit()

    from app.services import pipeline
    t = threading.Thread(target=pipeline.run_task, args=(task_id, allowed_hosts),
                         name=f"task-{task_id}", daemon=True)
    with _tc_lock:
        TASK_CONTROL[task_id]["thread"] = t
    t.start()
    bus.publish("task", f"任务 #{task_id} 启动：{task.target}", task_id=task_id, level="success")
    return task


def start_endpoint_scan(db: Session, task_id: int, endpoint_id: int,
                        user_id: int | None = None) -> Task:
    """定向重扫单个接口（手动录入后的补扫）。

    不重新采集、不碰其他接口：直接对这一个接口跑探测调度（AI 探针 / sqlmap）。
    允许从 done/terminated 回到 scanning（见 _TRANSITIONS），收口由
    pipeline.run_endpoint_scan 负责（有 pending_review 漏洞 → review，否则 done）。
    """
    from urllib.parse import urlparse

    from app.models.endpoint import Endpoint

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise TaskStateError("任务不存在")
    ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id,
                                   Endpoint.task_id == task_id).first()
    if not ep:
        raise TaskStateError("接口不存在或不属于该任务")
    _assert_transition(task.status, "scanning")

    ok, scope, reason = safety.check_authorization(db, task.target)
    if not ok:
        log_action(db, user_id=user_id, action="auth_reject", resource_type="task",
                   resource_id=task.id, detail={"target": task.target, "reason": reason})
        db.commit()
        raise safety.AuthorizationError(reason)
    task.auth_scope_id = scope.id

    host = urlparse(task.target if "//" in task.target else f"http://{task.target}").hostname or ""
    allowed_hosts = {host}
    with _tc_lock:
        ctl = TASK_CONTROL.get(task_id)
        if ctl and ctl.get("thread") and ctl["thread"].is_alive():
            raise TaskStateError("任务线程已在运行")
        control = {"stop": threading.Event(), "thread": None, "hosts": allowed_hosts}
        TASK_CONTROL[task_id] = control

    task.status = "scanning"
    task.error_message = None
    log_action(db, user_id=user_id, action="endpoint_scan", resource_type="endpoint",
               resource_id=endpoint_id, detail={"task_id": task_id})
    db.commit()

    from app.services import pipeline
    t = threading.Thread(target=pipeline.run_endpoint_scan,
                         args=(task_id, endpoint_id, allowed_hosts),
                         name=f"task-{task_id}-ep{endpoint_id}", daemon=True)
    with _tc_lock:
        TASK_CONTROL[task_id]["thread"] = t
    t.start()
    bus.publish("task", f"任务 #{task_id} 定向重扫接口 #{endpoint_id}"
                        f"（{ep.method} {ep.path}）", task_id=task_id, level="success")
    return task


def stop_task(db: Session, task_id: int, user_id: int | None = None) -> Task:
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise TaskStateError("任务不存在")
    if task.status not in _ACTIVE:
        raise TaskStateError(f"任务状态 {task.status} 不可终止")

    with _tc_lock:
        control = TASK_CONTROL.get(task_id)
        if control:
            control["stop"].set()

    task.status = "terminated"
    task.finished_at = utcnow_iso()
    task.error_message = task.error_message or "人工终止"
    log_action(db, user_id=user_id, action="task_stop", resource_type="task",
               resource_id=task_id, detail={})
    db.commit()
    bus.publish("task", f"任务 #{task_id} 已终止", task_id=task_id, level="warn")
    return task


def set_status(db: Session, task_id: int, new_status: str, error: str | None = None) -> Task:
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise TaskStateError("任务不存在")
    _assert_transition(task.status, new_status)
    task.status = new_status
    if new_status == "done":
        task.finished_at = utcnow_iso()
    if error:
        task.error_message = error
    db.commit()
    return task


def update_progress(db: Session, task_id: int, **fields):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        return
    prog = dict(task.progress or {})
    prog.update(fields)
    task.progress = prog
    db.commit()


def is_stop_requested(task_id: int) -> bool:
    with _tc_lock:
        control = TASK_CONTROL.get(task_id)
    return bool(control and control["stop"].is_set())


def cleanup_control(task_id: int):
    with _tc_lock:
        TASK_CONTROL.pop(task_id, None)


def _assert_transition(current: str, new: str):
    if new not in _TRANSITIONS.get(current, set()):
        raise TaskStateError(f"非法状态迁移：{current} → {new}")
