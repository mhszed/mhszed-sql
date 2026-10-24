# -*- coding: utf-8 -*-
"""接口归一建模：归一去重、读写分类、业务会话链路还原（三级降级策略）。

三级链路还原：
  L1 referer        —— Burp 流量带 Referer，直接还原（置信度 0.95）
  L2 token_derive   —— 共享同一会话 Token/Cookie 值聚类（置信度 0.8）
  L3 temporal_cluster —— 时间序 + 路径首段语义聚类（置信度 0.5，标记 inferred）
推断链路（L2 部分、L3 全部）只用于展示与误报辅助，不作为写接口探测放行依据。
"""
import hashlib
import re
from urllib.parse import urlparse, parse_qsl

from sqlalchemy.orm import Session

from app.models.endpoint import Endpoint, BusinessChain
from app.models.base import utcnow_iso
from app.services.event_bus import bus

# ---- 路径段归一 ----
_RE_NUMERIC = re.compile(r"^\d+$")
_RE_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_RE_HEX = re.compile(r"^[0-9a-fA-F]{12,}$")
# 形如 base64 / 长随机串（含大小写数字，长度>=20，无点）
_RE_RANDOM = re.compile(r"^[A-Za-z0-9_\-]{20,}$")

_ASSET_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp")

READ_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# 语义修正：路径含这些片段时强制归类（覆盖方法默认值）
_FORCE_READ = ("/search", "/query", "/list", "/detail", "/info", "/get", "/page")
_FORCE_WRITE = ("/create", "/add", "/update", "/edit", "/delete", "/remove",
                "/submit", "/save", "/upload", "/pay", "/order/submit", "/register", "/login")


def normalize_segment(seg: str) -> str:
    if not seg:
        return seg
    if _RE_NUMERIC.match(seg) or _RE_UUID.match(seg) or _RE_HEX.match(seg):
        return "{id}"
    if _RE_RANDOM.match(seg) and "." not in seg:
        return "{token}"
    return seg


def normalize_path(path: str) -> str:
    path = path.split("?")[0].split("#")[0]
    segs = [normalize_segment(s) for s in path.split("/")]
    return "/".join(segs)


def is_asset_path(path: str) -> bool:
    return path.lower().endswith(_ASSET_EXT)


def dedup_hash(method: str, path: str, param_names: list[str]) -> str:
    material = f"{method.upper()}|{normalize_path(path)}|{','.join(sorted(param_names))}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def classify_rw(method: str, path: str) -> str:
    m = method.upper()
    p = path.lower()
    if any(k in p for k in _FORCE_WRITE):
        return "write"
    if any(k in p for k in _FORCE_READ):
        return "read"
    return "read" if m in READ_METHODS else ("write" if m in WRITE_METHODS else "read")


def parse_params_from_url(url: str) -> list[dict]:
    """从 URL query 提取参数结构。"""
    qs = urlparse(url).query
    out = []
    for k, v in parse_qsl(qs, keep_blank_values=True):
        sample = (v[:100] if v else "")
        # 空样例会导致 sqlmap 打空串，字符型题极难命中 → 默认补 1
        if sample == "":
            sample = "1"
        out.append({"name": k, "location": "query", "type": "string",
                    "sample_value": sample, "required": False})
    return out


def _merge_params(existing: list[dict] | None, new: list[dict]) -> list[dict]:
    merged = {p["name"]: p for p in (existing or [])}
    for p in new or []:
        merged.setdefault(p["name"], p)
    # 统一补空样例
    for p in merged.values():
        if not (p.get("sample_value") or "").strip():
            p["sample_value"] = "1"
    return list(merged.values())


def upsert_endpoint(
    db: Session,
    *,
    task_id: int,
    source: str,                 # crawler / burp / manual
    method: str,
    url: str,
    headers: dict | None = None,
    body_params: list[dict] | None = None,
    referer: str | None = None,
) -> Endpoint:
    """归一 + 去重 + 读写分类，upsert 接口。已存在则合并参数/样本头。"""
    parsed = urlparse(url)
    host = parsed.netloc.split("@")[-1]
    raw_path = parsed.path or "/"
    norm_path = normalize_path(raw_path)

    params = parse_params_from_url(url)
    if body_params:
        # GET 表单按浏览器语义提交在 query string；只有非 GET 的 body 参数才走请求体
        loc = "query" if method.upper() == "GET" else "body"
        params += [dict(p, location=loc) for p in body_params]
    param_names = [p["name"] for p in params]
    h = dedup_hash(method, norm_path, param_names)

    existing = db.query(Endpoint).filter(
        Endpoint.task_id == task_id, Endpoint.dedup_hash == h
    ).first()

    # 样本头：脱敏（去掉 Cookie/Authorization 值，保留键名），附加 referer
    sample_headers = _sanitize_headers(headers)
    if referer:
        sample_headers = dict(sample_headers or {})
        sample_headers["Referer"] = referer

    if existing:
        existing.params = _merge_params(existing.params, params)
        if source == "burp":                       # burp 样本更真实，覆盖
            existing.headers = sample_headers or existing.headers
            existing.raw_path = raw_path
            existing.burp_seen_at = existing.burp_seen_at or utcnow_iso()
        if existing.source != source and "," not in existing.source:
            existing.source = f"{existing.source},{source}"
        return existing

    ep = Endpoint(
        task_id=task_id,
        source=source,
        dedup_hash=h,
        method=method.upper(),
        path=norm_path,
        raw_path=raw_path,
        host=host,
        params=params or None,
        headers=sample_headers or None,
        read_write=classify_rw(method, norm_path),
        burp_seen_at=utcnow_iso() if source == "burp" else None,
    )
    db.add(ep)
    db.flush()
    bus.publish("collect", f"[{source}] {method.upper()} {norm_path} "
                           f"({ep.read_write}, {len(params)}参数)", task_id=task_id)
    return ep


def _sanitize_headers(headers: dict | None) -> dict:
    if not headers:
        return {}
    import hashlib as _h
    out = {}
    for k, v in headers.items():
        if k.lower() in ("cookie", "authorization", "x-api-key", "token"):
            # 会话凭证指纹：SHA256 前 12 位 —— 不落库存凭证，但可用于同会话聚类（L2 链路还原）
            fp = _h.sha256(str(v).encode("utf-8")).hexdigest()[:12]
            out[k] = f"<fp:{fp}>"
        else:
            out[k] = str(v)[:200]
    return out


def _session_fp(headers: dict | None) -> str | None:
    """从样本头提取会话凭证指纹（用于 L2 token_derive 聚类）。"""
    for k, v in (headers or {}).items():
        if k.lower() in ("cookie", "authorization", "x-api-key", "token"):
            if isinstance(v, str) and v.startswith("<fp:"):
                return v
    return None


# ============ 业务会话链路还原 ============

def reconstruct_chains(db: Session, task_id: int) -> int:
    """三级降级还原，返回建立的链数。幂等：先清掉本任务旧链再重建。"""
    db.query(BusinessChain).filter(BusinessChain.task_id == task_id).delete()
    db.query(Endpoint).filter(Endpoint.task_id == task_id)\
        .update({Endpoint.chain_id: None, Endpoint.chain_inferred: 0}, synchronize_session=False)
    db.commit()

    endpoints = db.query(Endpoint).filter(Endpoint.task_id == task_id)\
        .order_by(Endpoint.id.asc()).all()
    if not endpoints:
        return 0

    by_path = {}
    for ep in endpoints:
        by_path.setdefault(ep.path, []).append(ep)

    chains: list[dict] = []      # {name, method, confidence, nodes:[ep], sample}

    # ---- L1 referer（并查集连通分量，分支不丢） ----
    edges = {}                   # ep_id -> 上一个 ep_id
    for ep in endpoints:
        referer = (ep.headers or {}).get("Referer") if ep.headers else None
        if not referer:
            continue
        ref_path = normalize_path(urlparse(referer).path or "/")
        candidates = by_path.get(ref_path)
        if candidates:
            # 取同 host 且 id 最小（最早出现）的来源接口
            src = next((c for c in candidates if c.host == ep.host), candidates[0])
            if src.id != ep.id:
                edges[ep.id] = src.id

    parent = {ep.id: ep.id for ep in endpoints}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int):
        parent[find(a)] = find(b)

    for dst, src in edges.items():
        union(dst, src)

    components: dict = {}
    for ep in endpoints:
        components.setdefault(find(ep.id), []).append(ep.id)

    visited = set()
    for root, ids in components.items():
        if len(ids) < 2:
            continue
        # 排序：无 referer 的来源在前，其余按出现时间（id 序）
        ids.sort(key=lambda i: (i in edges, i))
        _save_chain(db, task_id, chains, ids, by_id={e.id: e for e in endpoints},
                    method="referer", confidence=0.95)
        visited.update(ids)

    # ---- L2 token_derive（同会话凭证指纹聚类） ----
    token_groups: dict = {}
    for ep in endpoints:
        if ep.id in visited:
            continue
        fp = _session_fp(ep.headers)
        if fp:                            # 只有带会话凭证的接口参与
            token_groups.setdefault((ep.host, fp), []).append(ep.id)
    for key, ids in token_groups.items():
        if len(ids) >= 2:
            _save_chain(db, task_id, chains, ids, by_id={e.id: e for e in endpoints},
                        method="token_derive", confidence=0.8)
            visited.update(ids)

    # ---- L3 temporal_cluster ----
    rest = [ep for ep in endpoints if ep.id not in visited]
    groups: dict = {}
    for ep in rest:
        first = "/" + (ep.path.split("/") or ["misc"])[0].lstrip("/")
        groups.setdefault((ep.host, first), []).append(ep.id)
    for (host, first), ids in groups.items():
        if len(ids) >= 2:
            _save_chain(db, task_id, chains, ids, by_id={e.id: e for e in endpoints},
                        method="temporal_cluster", confidence=0.5, inferred=True)

    db.commit()
    bus.publish("collect", f"会话链路还原完成：{len(chains)} 条链（referer/"
                           f"token/temporal 三级降级）", task_id=task_id)
    return len(chains)


def _walk(start_id: int, edges: dict) -> list[int]:
    """保留给单链场景的兼容走链（当前主流程已改用并查集）。"""
    chain = [start_id]
    cur = start_id
    seen = {start_id}
    while True:
        nxts = [d for d, s in edges.items() if s == cur and d not in seen]
        if not nxts:
            break
        nxt = nxts[0]
        chain.append(nxt)
        seen.add(nxt)
        cur = nxt
    return chain


def _save_chain(db: Session, task_id: int, chains: list, node_ids: list,
                by_id: dict, method: str, confidence: float, inferred: bool = False):
    nodes = [by_id[i] for i in node_ids if i in by_id]
    name = " → ".join(f"{ep.method} {ep.path.split('?')[0][:40]}" for ep in nodes[:6])
    if len(nodes) > 6:
        name += f" …(+{len(nodes) - 6})"
    chain = BusinessChain(
        task_id=task_id,
        name=name,
        reconstruct_method=method,
        confidence=str(confidence),
        node_ids=node_ids,
        sample_session={"edge_count": len(node_ids) - 1} if method == "referer" else None,
    )
    db.add(chain)
    db.flush()
    for ep in nodes:
        ep.chain_id = chain.id
        ep.chain_inferred = 1 if inferred else (0 if method == "referer" else 1)
    chains.append(chain)
