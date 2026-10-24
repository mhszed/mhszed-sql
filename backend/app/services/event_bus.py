# -*- coding: utf-8 -*-
"""进程内事件总线：实时日志（SSE）与模块解耦的发布/订阅。

线程安全：业务线程 publish，SSE 端点 subscribe 后异步轮询队列。
"""
import threading
from collections import deque
from datetime import datetime, timezone

from app.models.base import utcnow_iso


class EventBus:
    def __init__(self, max_history: int = 3000):
        self._lock = threading.Lock()
        self._subscribers: list = []          # list[queue.Queue]
        self._history = deque(maxlen=max_history)

    def publish(self, channel: str, message: str, *, task_id: int | None = None,
                level: str = "info"):
        event = {
            "ts": utcnow_iso(),
            "channel": channel,       # task / collect / waf / ai / scan / vuln / system
            "task_id": task_id,
            "level": level,           # info / warn / error / success
            "message": message,
        }
        with self._lock:
            self._history.append(event)
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except Exception:
                    pass              # 订阅者消费过慢则丢弃（日志可丢，不能阻塞业务）

    def subscribe(self):
        import queue
        q = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def clear(self, task_id: int | None = None) -> int:
        """清空历史日志（SSE 重连时不再回放）。

        task_id=None 清全部；指定时只清该任务的条目（系统级 task_id=None 的日志保留，
        因为它们是全局上下文，不属于某个任务的现场）。返回清除条数。
        """
        with self._lock:
            if task_id is None:
                n = len(self._history)
                self._history.clear()
                return n
            keep = [e for e in self._history if e["task_id"] != task_id]
            n = len(self._history) - len(keep)
            self._history.clear()
            self._history.extend(keep)
            return n

    def recent(self, n: int = 100, task_id: int | None = None):
        with self._lock:
            items = list(self._history)
        if task_id is not None:
            items = [e for e in items if e["task_id"] in (task_id, None)]
        return items[-n:]


bus = EventBus()
