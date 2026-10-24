# -*- coding: utf-8 -*-
"""接口采集：静态爬虫 + Burp 插件实时推送。

静态爬虫：抓 HTML（<a>/<form>/<script>）与 JS 文件，正则提取 API 路径；
          仅同 host、跳过静态资源、深度/数量受限。
Burp 推送：/api/burp/push 批量接收，经归一去重后入库；请求哈希 LRU 快速幂等。
"""
import re
import threading
from collections import OrderedDict
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.audit import BurpSession
from app.models.base import utcnow_iso
from app.services import normalizer
from app.services.event_bus import bus
from app.services.safety import AuthorizationError, SafeHttpClient

# ---- JS 中 API 路径提取正则 ----
# 匹配引号/反引号内以 / 开头的路径（排除静态资源），可带 query；
# 模板字符串里的 ${...} 保留，后续归一成样例值。
_RE_API_PATH = re.compile(
    r"['\"`]((?:https?://[^'\"`]+)?/(?:api|v\d|rest|graphql|gw|gateway|service|app|admin|user|order|pay|check)"
    r"(?:/[\w\-./%${}~]*)?(?:\?[^'\"`]{0,120})?)['\"`]",
    re.IGNORECASE,
)
# 更宽松：任意以 / 开头的"路径样式"字符串（含模板字符串）
_RE_ANY_PATH = re.compile(r"['\"`](/[\w\-./${}]{2,120}(?:\?[^'\"`]{0,120})?)['\"`]")
# fetch/axios/$.get 等调用里的首参路径
_RE_FETCH_PATH = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post|ajax))\s*\(\s*[`'\"]([^`'\"\s]+)[`'\"]""",
    re.IGNORECASE,
)

_CRAWL_DEFAULTS = {"max_pages": 30, "max_depth": 3}

# 无表单/无链接参数时的常见 GET 参数名兜底探测。
# 背景（2026-10-15 sqli-labs）：表单被删后 Less-1~10 全漏检；推 Burp 喂 ?id=1
# 后工具立刻能测 → 缺的是「参数发现」，不是探测能力。
_GUESS_NAMES = ("id", "q", "sort", "order", "search", "keyword",
                "name", "page", "category", "user", "uid", "type")
_GUESS_LIMIT = {"low": 4, "medium": 8, "high": 12}
_GUESS_MAX_PAGES = {"low": 3, "medium": 10, "high": 20}
# 实验室实测：sqli-labs Less-5/8/10 的 ?id= 与基线只差 12 字节，
# Less-7 差 15 字节 → 阈值必须低于 12，否则这些关卡全部发现不了。
_GUESS_EFFECT_DELTA = 10


def _guess_query_params(db: Session, task_id: int, page_url: str,
                        baseline_status: int, baseline_len: int,
                        safe_client: SafeHttpClient, intensity: str,
                        allowed_hosts: set[str]) -> int:
    """对「没有任何参数」的 GET 页面试常见参数名。

    只做一次轻量试探：响应状态或长度明显变化才认为该参数被页面使用。
    全部请求走 SafeHttpClient（授权/限速/熔断/审计）。
    """
    parsed = urlparse(page_url)
    if parsed.query:
        return 0
    limit = _GUESS_LIMIT.get(intensity, 6)
    count = 0
    for name in _GUESS_NAMES[:limit]:
        q = {name: "1"}
        guess = urlunparse(parsed._replace(query=urlencode(q)))
        try:
            r = safe_client.request("GET", guess,
                                    headers={"User-Agent": "mhszed-sql-crawler/0.1"},
                                    audit=False)
        except Exception as exc:
            bus.publish("collect", f"参数探测失败 {guess}: {exc}",
                        task_id=task_id, level="warn")
            continue
        if r.status_code != baseline_status or abs(len(r.text or "") - baseline_len) > _GUESS_EFFECT_DELTA:
            normalizer.upsert_endpoint(db, task_id=task_id, source="crawler",
                                       method="GET", url=guess)
            count += 1
            bus.publish("collect", f"参数发现：{parsed.path} 疑似使用 ?{name}=",
                        task_id=task_id, level="success")
    return count


def crawl_static(db_factory, task_id: int, start_url: str, allowed_hosts: set[str],
                 scan_config: dict, stop_event) -> int:
    """静态爬虫主入口。db_factory: 零参函数返回 Session。返回采集（新增）接口数。

    注意：爬虫走 SafeHttpClient —— 授权 host 校验 + 限速同样生效。
    """
    cfg = {**_CRAWL_DEFAULTS}
    intensity = scan_config.get("intensity", "medium")
    if intensity == "low":
        cfg.update(max_pages=15, max_depth=2)
    elif intensity == "high":
        cfg.update(max_pages=80, max_depth=5)

    # 目标串去空白（httpx 对 " http://..." 会直接 UnsupportedProtocol）。
    start_url = (start_url or "").strip()
    safe_client = SafeHttpClient(db_factory, task_id, allowed_hosts, scan_config)
    visited: set[str] = set()
    new_count = 0
    guess_pages = 0
    try:
        from collections import deque
        queue = deque([(start_url.rstrip("/"), 0)])
        while queue and not stop_event.is_set() and len(visited) < cfg["max_pages"]:
            url, depth = queue.popleft()
            url = url.split("#")[0]
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = safe_client.request("GET", url, headers={"User-Agent": "mhszed-sql-crawler/0.1"},
                                           audit=False)
            except (AuthorizationError, Exception) as exc:
                bus.publish("collect", f"抓取失败 {url}: {exc}", task_id=task_id, level="warn")
                continue
            if resp.status_code != 200:
                continue
            ctype = resp.headers.get("content-type", "")
            db = db_factory()
            try:
                if "text/html" in ctype:
                    added, has_params = _parse_html(
                        db, task_id, url, resp.text, queue, visited, depth, cfg,
                        allowed_hosts, start_url)
                    new_count += added
                    # 无表单/无链接参数时，用常见参数名轻量试一下（仅深 0-1 页）
                    if (not has_params and scan_config.get("param_guess", True)
                            and depth <= 1
                            and guess_pages < _GUESS_MAX_PAGES.get(intensity, 10)):
                        guess_pages += 1
                        new_count += _guess_query_params(
                            db, task_id, url, resp.status_code,
                            len(resp.text or ""), safe_client, intensity,
                            allowed_hosts)
                elif "javascript" in ctype or url.endswith(".js"):
                    new_count += _parse_js(db, task_id, url, resp.text, allowed_hosts, start_url)
                db.commit()
            finally:
                db.close()
    finally:
        safe_client.close()
    bus.publish("collect", f"静态爬虫完成：访问 {len(visited)} 页，新增接口 {new_count} 个",
                task_id=task_id, level="success")
    return new_count


def _same_host(url: str, hosts: set[str]) -> bool:
    return (urlparse(url).hostname or "").lower() in {h.lower() for h in hosts}


def _parse_html(db: Session, task_id: int, page_url: str, html: str, queue, visited,
                depth: int, cfg: dict, allowed_hosts: set[str],
                start_url: str) -> tuple[int, bool]:
    count = 0
    has_params = bool(urlparse(page_url).query)
    soup = BeautifulSoup(html, "lxml")

    # <a> 入队（导航，继续爬）；带 query 的链接同时直接登记为接口
    if depth < cfg["max_depth"]:
        for a in soup.find_all("a", href=True):
            link = urljoin(page_url, a["href"]).split("#")[0]
            if link.startswith("http") and _same_host(link, allowed_hosts) \
                    and not normalizer.is_asset_path(urlparse(link).path) and link not in visited:
                if urlparse(link).query:
                    normalizer.upsert_endpoint(db, task_id=task_id, source="crawler",
                                               method="GET", url=link, referer=page_url)
                    count += 1
                    has_params = True
                queue.append((link, depth + 1))

    # <form> 直接产生接口
    for form in soup.find_all("form"):
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "GET").upper()
        body_params = []
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if name:
                # 表单空值默认样例 1，避免后续 sqlmap 对空参数空转
                body_params.append({
                    "name": name, "location": "body", "type": "text",
                    "sample_value": (inp.get("value") or "1")[:100],
                    "required": bool(inp.get("required")),
                })
        # 只有 **query 参数** 才阻止常见参数名探测。POST 表单（reset/登录等）
        # 不代表页面没有 GET 注入点：sqli-labs Less-59 就是只有 POST 表单、
        # 真正的注入在 ?id=，旧逻辑因 body_params 非空直接跳过了参数猜测。
        if urlparse(action).query:
            has_params = True
        if method == "GET" and body_params:
            has_params = True
        normalizer.upsert_endpoint(db, task_id=task_id, source="crawler", method=method,
                                   url=action, body_params=body_params, referer=page_url)
        count += 1

    # 内联 <script> 也要挖 API（好靶场这类把 fetch(`/check?id=${...}`) 写在首页）
    for s in soup.find_all("script"):
        if s.get("src"):
            continue
        inline = s.string or s.get_text() or ""
        if inline.strip():
            js_added = _parse_js(db, task_id, page_url, inline, allowed_hosts, start_url)
            count += js_added
            if js_added:
                has_params = True

    # <script src> 入队（外链 JS 里挖 API）
    if depth < cfg["max_depth"]:
        for s in soup.find_all("script", src=True):
            src = urljoin(page_url, s["src"])
            if _same_host(src, allowed_hosts) and src not in visited:
                queue.append((src, depth + 1))
    return count, has_params


def _normalize_js_path(path: str) -> str:
    """把模板变量 ${...} / :id 收敛成可探测样例，保留参数名。"""
    path = re.sub(r"\$\{[^}]*}", "1", path)
    path = re.sub(r"\{[^}/]+}", "1", path)
    return path


def _parse_js(db: Session, task_id: int, js_url: str, js_text: str,
              allowed_hosts: set[str], start_url: str) -> int:
    count = 0
    found: set[str] = set()
    for m in _RE_API_PATH.finditer(js_text):
        found.add(m.group(1))
    for m in _RE_ANY_PATH.finditer(js_text):
        p = m.group(1)
        if p not in found and not normalizer.is_asset_path(p.split("?")[0]):
            found.add(p)
    for m in _RE_FETCH_PATH.finditer(js_text):
        p = m.group(1)
        if p.startswith("/") or p.startswith("http"):
            found.add(p)

    # fetch('/search', { method: 'POST', body: `keyword=${...}` })
    # 只取路径会丢掉 method 与 body 参数 —— 静态爬虫会把 POST 搜索框登记成
    # 无参数的 GET /search，研判探针为空、sqlmap 打 405，漏洞直接漏掉。
    post_targets: dict[str, list[str]] = {}
    for m in re.finditer(
            r"fetch\(\s*['\"]([^'\"]+)['\"]\s*,\s*\{(.*?)\}\s*\)",
            js_text, re.S | re.I):
        path, opts = m.group(1), m.group(2)
        if not re.search(r"method\s*:\s*['\"]POST['\"]", opts, re.I):
            continue
        names: list[str] = []
        bm = re.search(r"body\s*:\s*(?:`([^`]*)`|['\"]([^'\"]*)['\"])", opts, re.S)
        body = (bm.group(1) or bm.group(2) or "") if bm else ""
        for name in re.findall(r"(?:^|[&?])\s*([A-Za-z_][\w\-]*)\s*=", body):
            if name not in names:
                names.append(name)
        post_targets[_normalize_js_path(path)] = names
        found.add(path)

    base_origin = f"{urlparse(start_url).scheme}://{urlparse(start_url).netloc}"
    for path in found:
        path = _normalize_js_path(path)
        if path.startswith("http"):
            full = path
        else:
            full = urljoin(base_origin + "/", path.lstrip("/"))
        if not _same_host(full, allowed_hosts):
            continue
        if normalizer.is_asset_path(urlparse(full).path):
            continue
        if path in post_targets:
            body_params = [{"name": n, "location": "body", "type": "text",
                            "sample_value": "1", "required": False}
                           for n in post_targets[path]]
            normalizer.upsert_endpoint(db, task_id=task_id, source="crawler",
                                       method="POST", url=full,
                                       body_params=body_params or None)
            count += 1
            continue
        normalizer.upsert_endpoint(db, task_id=task_id, source="crawler", method="GET", url=full)
        count += 1
    return count


# ============ Burp 推送 ============

# 请求哈希 LRU（进程内快速幂等；DB 层 dedup_hash 兜底）
_PUSH_LRU_SIZE = 5000
_push_lock = threading.Lock()
_push_lru: "OrderedDict[str, None]" = OrderedDict()


def _push_seen(req_hash: str) -> bool:
    with _push_lock:
        if req_hash in _push_lru:
            _push_lru.move_to_end(req_hash)
            return True
        _push_lru[req_hash] = None
        if len(_push_lru) > _PUSH_LRU_SIZE:
            _push_lru.popitem(last=False)
        return False


def _push_hash(task_id, method: str, url: str, body: str) -> str:
    """推送去重键。

    **必须含 task_id**：同一接口推给不同任务是两份独立数据；若键里没有 task_id，
    进程级 LRU 会把第二个任务整条吞掉（表现为该任务拿不到任何端点、后续无扫描）。
    """
    import hashlib as _h
    return _h.sha256(f"{task_id}|{method}|{url}|{body}".encode()).hexdigest()


def handle_burp_push(db: Session, client_id: str, records: list[dict],
                     task_id: int | None = None) -> dict:
    """处理 Burp 插件批量推送。

    record 结构：{method, url, headers(dict), body(str), referer(str, 可选), timestamp}
    返回 {received, new, duplicate, skipped}。
    """
    session = db.query(BurpSession).filter(BurpSession.client_id == client_id).first()
    if not session:
        session = BurpSession(client_id=client_id, version=records[0].get("plugin_version") if records else None)
        db.add(session)
    session.last_heartbeat = utcnow_iso()

    stats = {"received": len(records), "new": 0, "duplicate": 0, "skipped": 0}
    if not task_id:
        stats["skipped"] = len(records)
        session.dropped_count += len(records)   # 未绑定任务：暂不计入接口库
        db.commit()
        return stats

    for rec in records:
        method = (rec.get("method") or "GET").upper()
        url = rec.get("url") or ""
        body = rec.get("body") or ""
        headers = rec.get("headers") or {}
        if not url.startswith("http"):
            stats["skipped"] += 1
            continue

        req_hash = _push_hash(task_id, method, url, body)
        if _push_seen(req_hash):
            stats["duplicate"] += 1
            continue

        body_params = None
        if body and "json" in str(headers.get("Content-Type", "")).lower():
            import json as _json
            try:
                j = _json.loads(body)
                if isinstance(j, dict):
                    body_params = [{"name": k, "location": "body", "type": "string",
                                    "sample_value": str(v)[:100], "required": False} for k, v in j.items()]
            except Exception:
                pass
        elif body:
            from urllib.parse import parse_qsl
            body_params = [{"name": k, "location": "body", "type": "string",
                            "sample_value": (v or "")[:100], "required": False}
                           for k, v in parse_qsl(body, keep_blank_values=True)]

        normalizer.upsert_endpoint(db, task_id=task_id, source="burp", method=method,
                                   url=url, headers=headers, body_params=body_params,
                                   referer=rec.get("referer") or headers.get("Referer"))
        stats["new"] += 1
        session.pushed_count += 1

    db.commit()
    if stats["new"]:
        bus.publish("collect", f"Burp 推送：新增 {stats['new']}，重复 {stats['duplicate']}，"
                               f"跳过 {stats['skipped']}", task_id=task_id)
    return stats


def burp_heartbeat(db: Session, client_id: str, version: str | None = None) -> bool:
    session = db.query(BurpSession).filter(BurpSession.client_id == client_id).first()
    if not session:
        session = BurpSession(client_id=client_id, version=version)
        db.add(session)
    session.last_heartbeat = utcnow_iso()
    if version:
        session.version = version
    db.commit()
    return True
