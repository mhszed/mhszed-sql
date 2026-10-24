# -*- coding: utf-8 -*-
"""安全管控：授权校验 / 速率限制 / 熔断器 / 写接口保护 / 安全 HTTP 客户端。

所有对目标站点的请求必须经过 SafeHttpClient —— 它是唯一出口，强制执行：
  1. 目标 host 必须命中任务授权范围（防漂移）
  2. 速率限制（滑动窗口，写接口更保守）
  3. 熔断器状态检查（打开时拒绝请求）
  4. 写接口 payload 破坏性语句黑名单拦截
  5. 每个带 payload 的请求写审计日志
"""
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.core.security import is_destructive_payload
from app.services.event_bus import bus


# ============ 授权校验 ============

class AuthorizationError(Exception):
    pass


def check_authorization(db: Session, target: str, *, now: str | None = None) -> tuple[bool, object, str]:
    """目标 host 必须命中未过期、未删除的授权范围。

    返回 (是否通过, 命中的AuthScope或None, 原因说明)。
    """
    from app.models.auth import AuthScope
    from app.models.base import utcnow_iso

    host = urlparse(target if "//" in target else f"http://{target}").hostname or ""
    if not host:
        return False, None, "无法解析目标主机名"

    now = now or utcnow_iso()
    scopes = db.query(AuthScope).filter(AuthScope.deleted_at.is_(None)).all()
    for s in scopes:
        if s.expires_at and s.expires_at < now:
            continue
        if s.scope_type == "domain" and host == s.scope_value:
            return True, s, f"命中精确域名授权: {s.name}"
        if s.scope_type == "wildcard":
            suffix = s.scope_value.lstrip("*").lstrip(".")
            if host == s.scope_value.lstrip("*.") or host.endswith("." + suffix):
                return True, s, f"命中通配符授权: {s.name}"
        if s.scope_type == "ip" and host == s.scope_value:
            return True, s, f"命中 IP 授权: {s.name}"
    return False, None, f"目标 {host} 不在任何授权范围内，拒绝启动"


# ============ 速率限制（滑动窗口） ============

class RateLimiter:
    """按 host 的滑动窗口 QPS 限制。写接口使用更低的独立配额。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._windows: dict = defaultdict(lambda: {"read": deque(), "write": deque()})

    def _wait(self, host: str, mode: str, qps: float):
        key = host.lower()
        window = 1.0
        while True:
            with self._lock:
                dq = self._windows[key][mode]
                now = time.monotonic()
                while dq and dq[0] < now - window:
                    dq.popleft()
                limit = 1 if qps <= 0 else qps
                if len(dq) < limit:
                    dq.append(now)
                    return
                # 需等待：最早一条出窗的时刻
                wait = dq[0] + window - now
            time.sleep(max(wait, 0.01))

    def wait_read(self, host: str, qps: float):
        self._wait(host, "read", qps)

    def wait_write(self, host: str, qps: float):
        self._wait(host, "write", qps)


rate_limiter = RateLimiter()


# ============ 熔断器（三态：closed / open / half_open） ============

class CircuitOpenError(Exception):
    pass


class CircuitBreaker:
    """按任务统计滑动窗口内的错误率与 WAF 拦截率，超阈值跳闸。

    open 状态持续 cooldown 秒后进入 half_open：放行单个探测请求，
    成功则恢复 closed，失败则重回 open。
    """

    def __init__(self, error_threshold: float = 0.3, waf_threshold: float = 0.5,
                 window_seconds: int = 60, cooldown_seconds: int = 300):
        self.error_threshold = error_threshold
        self.waf_threshold = waf_threshold
        self.window = window_seconds
        self.cooldown = cooldown_seconds
        self._lock = threading.Lock()
        self._state: dict = {}     # task_id -> {state, opened_at, results: deque[(ts, kind)]}

    def _entry(self, task_id: int):
        if task_id not in self._state:
            self._state[task_id] = {"state": "closed", "opened_at": 0.0, "results": deque()}
        return self._state[task_id]

    def allow(self, task_id: int) -> bool:
        with self._lock:
            e = self._entry(task_id)
            if e["state"] == "open":
                if time.monotonic() - e["opened_at"] >= self.cooldown:
                    e["state"] = "half_open"
                    return True          # 放行一个探测请求
                return False
            return True                   # closed / half_open

    def record(self, task_id: int, kind: str):
        """kind: ok / error / waf_blocked"""
        with self._lock:
            e = self._entry(task_id)
            now = time.monotonic()
            dq = e["results"]
            dq.append((now, kind))
            while dq and dq[0][0] < now - self.window:
                dq.popleft()
            total = len(dq)
            if total < 5:
                return                   # 样本不足不跳闸
            errs = sum(1 for _, k in dq if k == "error")
            wafs = sum(1 for _, k in dq if k == "waf_blocked")
            if e["state"] == "half_open" and kind != "ok":
                self._trip(task_id, e)
                return
            if errs / total >= self.error_threshold or wafs / total >= self.waf_threshold:
                self._trip(task_id, e)

    def _trip(self, task_id: int, e: dict):
        e["state"] = "open"
        e["opened_at"] = time.monotonic()
        e["results"].clear()
        bus.publish("system", f"熔断器跳闸：任务 #{task_id} 错误率/拦截率超阈值，暂停 {self.cooldown}s",
                    task_id=task_id, level="error")

    def state(self, task_id: int) -> str:
        with self._lock:
            return self._entry(task_id)["state"]

    def reset(self, task_id: int):
        with self._lock:
            self._state.pop(task_id, None)


circuit_breaker = CircuitBreaker()


# ============ 写接口保护 ============

class WriteProtectionError(Exception):
    pass


def assert_payload_safe(payload: str):
    """写接口的注入探测 payload 必须通过黑名单检查。"""
    if is_destructive_payload(payload):
        raise WriteProtectionError(f"写接口保护：payload 含破坏性语句，已拦截 → {payload[:60]}")


# ============ 安全 HTTP 客户端（唯一出口） ============

class SafeHttpClient:
    """所有探测/采集请求的统一出口。构造时绑定任务与授权 host 集合。"""

    def __init__(self, db_factory, task_id: int, allowed_hosts: set[str],
                 scan_config: dict, breaker: CircuitBreaker = circuit_breaker):
        self._db_factory = db_factory            # 零参函数，返回 Session（审计用后即关）
        self.task_id = task_id
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.cfg = scan_config
        self.breaker = breaker
        # 上一次请求的**纯 HTTP 往返耗时**（不含限速等待）。
        # 限速 wait 在 t0 之前完成，因此这里测到的才是真正的服务端响应时间，
        # 供布尔盲注的耗时判据使用（prober 自己包在外面计时会把限速等待算进去）。
        self.last_elapsed = 0.0
        self.client = httpx.Client(
            timeout=httpx.Timeout(20.0, read=30.0),
            follow_redirects=True,
            verify=False,
            # 目标探测不走系统代理：本机代理环境下会让 httpx 把目标请求
            # 交给一个不可达/很慢的代理，表现为 30s ReadTimeout（实测 17133）。
            trust_env=False,
        )

    def _preflight(self, url: str, method: str, payload: str | None):
        host = (urlparse(url).hostname or "").lower()
        if host not in self.allowed_hosts:
            raise AuthorizationError(f"请求目标 {host} 不在任务授权 host 集合内，拒绝发送")
        if not self.breaker.allow(self.task_id):
            raise CircuitOpenError(f"任务 #{self.task_id} 熔断器处于打开状态")
        if payload:
            assert_payload_safe(payload) if method.upper() in ("POST", "PUT", "PATCH", "DELETE") else None

    def request(self, method: str, url: str, *, payload: str | None = None,
                headers: dict | None = None, params: dict | None = None,
                data=None, audit: bool = True) -> httpx.Response:
        """发请求。写接口自动走更保守的限速通道。

        payload 参数：本次注入的 payload 文本（用于写保护检查与审计留痕，
        实际注入位置由调用方通过 params/data/headers 决定）。
        """
        # 目标串可能带首尾空白（用户从聊天/文档里复制粘贴很常见）。
        # urlparse 能容忍，httpx 不能 → "Request URL is missing an 'http://' protocol"，
        # 爬虫把这个异常当抓取失败吞掉，整个任务 1 秒跑完且 0 接口（2026-10-22 实测）。
        url = (url or "").strip()
        self._preflight(url, method, payload)
        is_write = method.upper() in ("POST", "PUT", "PATCH", "DELETE")
        qps = self.cfg.get("rate_limit_qps", 1.0)
        if is_write:
            rate_limiter.wait_write(urlparse(url).hostname or "", qps * 0.3)
        else:
            rate_limiter.wait_read(urlparse(url).hostname or "", qps)

        t0 = time.monotonic()
        kind = "ok"
        try:
            resp = self.client.request(method, url, headers=headers, params=params, data=data)
            if resp.status_code in (403, 404, 406, 412, 429, 500, 501, 508) and self._looks_like_waf(resp):
                kind = "waf_blocked"
            elif resp.status_code >= 500:
                kind = "error"
            return resp
        except httpx.HTTPError:
            kind = "error"
            raise
        finally:
            self.last_elapsed = time.monotonic() - t0
            self.breaker.record(self.task_id, kind)
            if audit and payload:
                self._audit_scan_request(method, url, payload, kind, time.monotonic() - t0)

    @staticmethod
    def _looks_like_waf(resp: httpx.Response) -> bool:
        """粗判响应是否为 WAF 拦截页（详细画像由 waf 模块负责，这里只喂熔断器）。"""
        head = resp.text[:2000].lower()
        keywords = ("waf", "拦截", "非法请求", "firewall", "blocked", "安全防护", "modsecurity", "雷池")
        return any(k in head for k in keywords)

    def _audit_scan_request(self, method: str, url: str, payload: str, kind: str, elapsed: float):
        from app.core.audit import log_action
        db = self._db_factory()
        try:
            log_action(db, user_id=None, action="scan_request",
                       resource_type="task", resource_id=self.task_id,
                       detail={"method": method, "url": url, "payload": payload[:500],
                               "result": kind, "elapsed_ms": int(elapsed * 1000)})
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    def close(self):
        self.client.close()
