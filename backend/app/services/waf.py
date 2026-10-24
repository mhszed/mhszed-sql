# -*- coding: utf-8 -*-
"""WAF 指纹画像：前置探测，产出产品级画像（非二元判断）。

流程：
  1. 基线请求（无 payload）记录正常响应特征
  2. 发送 2~3 个轻量探针（编码后的常见触发特征）
  3. 对比基线：状态码/页面指纹/Header → 判断是否拦截、命中哪个产品
  4. 落库 WafProfile（产品名/置信度/拦截行为/绕过建议）
探针也是"带 payload 请求"，走 SafeHttpClient —— 限速与熔断同样生效。
"""
import hashlib
from urllib.parse import urlparse, urlencode

from sqlalchemy.orm import Session

from app.models.waf import WafProfile
from app.services.event_bus import bus
from app.services.safety import SafeHttpClient

# ============ 指纹库 ============
# markers: 按 (header 子串, body 关键词, 状态码) 组合匹配，命中记权重的产品判定
FINGERPRINTS = [
    {"product": "cloudflare", "weight": 0.9,
     "headers": ("cf-ray", "cloudflare"),
     "body_kw": ("cloudflare", "attention required!", "cf-browser-verification")},
    {"product": "aliyun", "weight": 0.85,
     "headers": (), "body_kw": ("aliyun", "阿里云", "您请求的页面被防火墙拦截")},
    {"product": "tencent", "weight": 0.85,
     "headers": ("tencent",), "body_kw": ("腾讯云", "腾讯防水墙", "waf.tencentcloudapi")},
    {"product": "safedog", "weight": 0.9,
     "headers": ("safedog",), "body_kw": ("安全狗", "safedog", "请求被安全狗防护拦截")},
    {"product": "d_shield", "weight": 0.9,
     "headers": ("d_shield",), "body_kw": ("d盾", "dun.security", "D 盾")},
    {"product": "bt", "weight": 0.85,
     "headers": ("btwaf",), "body_kw": ("宝塔", "btwaf", "宝塔网站防火墙")},
    {"product": "safeline", "weight": 0.85,
     "headers": ("safeline", "sl-waf"),
     "body_kw": ("雷池", "safeline", "长亭雷池")},
    {"product": "modsecurity", "weight": 0.8,
     "headers": ("mod_security", "modsecurity", "nosession"),
     "body_kw": ("modsecurity", "method not implemented", "not acceptable")},
    {"product": "f5", "weight": 0.85,
     "headers": ("f5", "bigipserver"),
     "body_kw": ("f5", "the requested url was rejected", "bigip")},
    {"product": "anquanbao", "weight": 0.8,
     "headers": ("anquanbao",), "body_kw": ("安全宝", "anquanbao")},
    {"product": "yundun", "weight": 0.8,
     "headers": ("yundun",), "body_kw": ("云盾", "yundun")},
]

# 拦截页常见状态码
BLOCK_STATUS = {403, 406, 412, 418, 429, 500, 501, 508}

# 产品 → 建议绕过策略标签
BYPASS_MAP = {
    "cloudflare": ["encoding", "case_mix"],
    "aliyun": ["comment_split", "encoding", "whitespace"],
    "tencent": ["comment_split", "encoding"],
    "safedog": ["case_mix", "comment_split", "whitespace"],
    "d_shield": ["encoding", "case_mix"],
    "bt": ["comment_split", "encoding"],
    "safeline": ["encoding", "whitespace"],
    "modsecurity": ["case_mix", "comment_split", "encoding", "whitespace"],
    "f5": ["encoding"],
    "anquanbao": ["case_mix", "comment_split"],
    "yundun": ["encoding", "whitespace"],
    # 静默过滤：不返回拦截页，只把含空格/关键字的 payload 吃掉 → 必须空间替代 + 关键字双写
    "silent_filter": ["space_alt", "keyword_double_write"],
    "unknown": ["case_mix", "comment_split", "encoding", "whitespace"],
}

# 轻量探针（编码后发送；目的是触发 WAF 行为，不是注入本身）
PROBES = [
    ("id", "1%27%20and%20%271%27%3D%271"),        # 1' and '1'='1
    ("q", "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),  # <script>alert(1)</script>
    ("id", "1%20union%20select%201"),              # 1 union select 1
]


def _page_fingerprint(text: str) -> str:
    return hashlib.sha256(text[:4000].encode("utf-8", "replace")).hexdigest()[:16]


def _detect_product(resp) -> tuple[str, float]:
    """按指纹库匹配产品，返回 (产品名, 置信度)。"""
    header_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = resp.text[:4000].lower()
    best, best_w = "unknown", 0.0
    for fp in FINGERPRINTS:
        w = 0.0
        for h in fp["headers"]:
            if h in header_blob:
                w = fp["weight"]
                break
        if w == 0.0:
            for kw in fp["body_kw"]:
                if kw.lower() in body_blob:
                    w = fp["weight"] * 0.9     # body 命中略降权
                    break
        if w > best_w:
            best, best_w = fp["product"], w
    return best, round(best_w, 2)


def _with_param(base_url: str, name: str, value: str) -> str:
    """把参数塞进现有 query（保留其它参数）。"""
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    p = urlparse(base_url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _is_blocked(baseline_status: int, baseline_fp: str, resp) -> bool:
    if resp.status_code in BLOCK_STATUS and resp.status_code != baseline_status:
        return True
    if _page_fingerprint(resp.text) != baseline_fp and resp.status_code != baseline_status:
        return True
    return False


def profile_waf(db_factory, task_id: int, target: str, allowed_hosts: set[str],
                scan_config: dict, stop_event) -> WafProfile:
    """对目标做 WAF 指纹画像，落库并返回。幂等：同任务同 host 覆盖旧画像。"""
    safe_client = SafeHttpClient(db_factory, task_id, allowed_hosts, scan_config)
    host = urlparse(target).netloc
    try:
        bus.publish("waf", f"WAF 画像探测开始：{host}", task_id=task_id)

        # 基线
        baseline = safe_client.request("GET", target, headers={"User-Agent": "mhszed-sql/0.1"},
                                       audit=False)
        base_status = baseline.status_code
        base_fp = _page_fingerprint(baseline.text)

        has_waf = 0
        product, confidence = "unknown", 0.0
        block_behavior: dict = {}
        probe_history: list = []

        # 优先对已采集接口打探针，避免只污染首页导致误标产品
        probe_bases: list[str] = []
        # (base_url, param_name, sample_value)：静默过滤探测要往真实参数里塞 payload
        probe_params: list[tuple[str, str, str]] = []
        try:
            from app.models.endpoint import Endpoint
            _db = db_factory()
            try:
                for ep in (_db.query(Endpoint).filter(Endpoint.task_id == task_id)
                           .order_by(Endpoint.id.asc()).limit(3).all()):
                    scheme = "https" if target.startswith("https") else "http"
                    path = ep.raw_path or ep.path or "/"
                    base_url = f"{scheme}://{ep.host}{path}"
                    probe_bases.append(base_url)
                    for p in (ep.params or []):
                        if p.get("name") and p.get("location") in (None, "query"):
                            probe_params.append(
                                (base_url, p["name"], str(p.get("sample_value") or "1")))
                            break
            finally:
                _db.close()
        except Exception:
            probe_bases = []
        if not probe_bases:
            probe_bases = [target.rstrip("/")]

        for name, encoded in PROBES:
            if stop_event.is_set():
                break
            base = probe_bases[0]
            sep = "&" if ("?" in base) else "?"
            url = f"{base}{sep}{name}={encoded}"
            try:
                resp = safe_client.request("GET", url, audit=True, payload=f"{name}={encoded}")
            except Exception as exc:
                bus.publish("waf", f"探针异常（可能被前置拦截）: {exc}", task_id=task_id, level="warn")
                continue
            blocked = _is_blocked(base_status, base_fp, resp)
            probe_history.append({
                "probe": f"{name}={encoded[:60]}", "url": url[:160],
                "status": resp.status_code,
                "blocked": blocked, "length": len(resp.content),
            })
            if blocked:
                has_waf = 1
                p, w = _detect_product(resp)
                if w > confidence:
                    product, confidence = p, w
                block_behavior = {
                    "status_code": resp.status_code,
                    "page_fingerprint_hash": _page_fingerprint(resp.text),
                    "headers": {k: v[:100] for k, v in resp.headers.items()
                                if any(x in k.lower() for x in ("server", "waf", "x-powered", "set-cookie"))},
                    "block_keyword": _first_keyword(resp.text),
                }
                break        # 已确认拦截，减少带 payload 请求（节奏控制）

        # 静默过滤探测：靶机可能"不返回拦截页，只是把含空格/关键字的 payload 吃掉"。
        # 判据（严格）：同一参数下
        #   ① `1'`（无空格无关键字）相对基线**有变化** → 有注入迹象
        #   ② `1' and 1=1 -- `（含空格+关键字）相对基线**零变化** → payload 被吃掉
        # 两条同时成立才判 silent_filter，避免把"参数不参与查询"误标成 WAF。
        if not has_waf and probe_params:
            base_url, pname, sample = probe_params[0]
            try:
                url0 = _with_param(base_url, pname, sample)
                r0 = safe_client.request("GET", url0, audit=False)
                ref_len, ref_fp = len(r0.content), _page_fingerprint(r0.text)

                url1 = _with_param(base_url, pname, f"{sample}'")
                r1 = safe_client.request("GET", url1, audit=True, payload=f"{sample}'")
                inj_signal = (abs(len(r1.content) - ref_len) > 20
                              or _page_fingerprint(r1.text) != ref_fp)

                url2 = _with_param(base_url, pname, f"{sample}' and 1=1 -- ")
                r2 = safe_client.request("GET", url2, audit=True,
                                         payload=f"{sample}' and 1=1 -- ")
                silent = (len(r2.content) == ref_len
                          and _page_fingerprint(r2.text) == ref_fp)

                probe_history.append({
                    "probe": "silent_filter_check", "url": url2[:160],
                    "status": r2.status_code, "blocked": False,
                    "length": len(r2.content), "injection_signal": inj_signal,
                    "silent_filter": bool(inj_signal and silent),
                })
                if inj_signal and silent:
                    has_waf = 1
                    product, confidence = "silent_filter", 0.6
                    block_behavior = {
                        "mode": "silent",
                        "note": "含空格/关键字的 payload 被静默过滤（响应无变化），"
                                "裸引号仍有响应差异",
                        "sample_injection_len": len(r1.content),
                    }
                    bus.publish("waf", f"{host} 疑似**静默过滤**：含空格/关键字的 payload "
                                       f"无任何效果（注入迹象存在）→ 启用空格替代+关键字双写",
                                task_id=task_id, level="warn")
            except Exception as exc:
                bus.publish("waf", f"静默过滤探测异常: {exc}", task_id=task_id, level="warn")

        if not has_waf:
            # 探针未拦截时：禁止用正文关键词误标（首页误报 f5 等）；仅当响应头强特征才记
            header_blob = " ".join(f"{k}:{v}" for k, v in baseline.headers.items()).lower()
            header_hit = None
            for fp in FINGERPRINTS:
                if any(h and h in header_blob for h in fp.get("headers") or []):
                    header_hit = fp
                    break
            if header_hit:
                product, confidence = header_hit["product"], round(header_hit["weight"] * 0.7, 2)
                bus.publish("waf", f"响应头疑似 {product}，但探针未拦截",
                            task_id=task_id, level="warn")
            else:
                product, confidence = "none", 0.0

        suggestions = BYPASS_MAP.get(product if has_waf else "none", [])

        db = db_factory()
        try:
            profile = db.query(WafProfile).filter(
                WafProfile.task_id == task_id, WafProfile.host == host).first()
            if not profile:
                profile = WafProfile(task_id=task_id, host=host)
                db.add(profile)
            profile.has_waf = has_waf
            profile.product = product
            profile.product_confidence = str(confidence)
            profile.block_behavior = block_behavior or None
            profile.probe_history = probe_history or None
            profile.bypass_suggestions = suggestions or None
            db.commit()
            db.refresh(profile)
        finally:
            db.close()

        level = "warn" if has_waf else "success"
        bus.publish("waf", f"WAF 画像完成：{'检测到 ' + product + f' (置信度 {confidence})' if has_waf else '未检测到 WAF'}"
                           f"{'，建议绕过策略: ' + ','.join(suggestions) if suggestions else ''}",
                    task_id=task_id, level=level)
        return profile
    finally:
        safe_client.close()


def _first_keyword(text: str) -> str:
    for kw in ("拦截", "illegal", "blocked", "waf", "防火墙", "非法", "reject"):
        if kw in text.lower():
            return kw
    return ""
