# -*- coding: utf-8 -*-
"""知识库服务：Payload 检索、误报负样本匹配、回流闭环。"""
import re

from sqlalchemy.orm import Session

from app.models.assessment import ReviewAction
from app.models.endpoint import Endpoint
from app.models.kb import KbArticle, KbFalsePositive, KbInsight, KbPayload
from app.services.event_bus import bus


# ============ 查询 ============

def find_payloads(db: Session, *, waf_product: str | None = None,
                  vector: str | None = None, limit: int = 20) -> list[KbPayload]:
    q = db.query(KbPayload).filter(
        KbPayload.deleted_at.is_(None), KbPayload.is_active == 1)
    if waf_product:
        # 同产品的已验证 payload + 通用（target_waf=NULL）都可用；
        # 后者常在"应用层过滤"目标上验证出来，不该被 WAF 过滤条件排除。
        from sqlalchemy import or_
        q = q.filter(or_(KbPayload.target_waf == waf_product,
                         KbPayload.target_waf.is_(None)))
    if vector:
        q = q.filter(KbPayload.vector == vector)
    rows = q.order_by(KbPayload.success_count.desc(), KbPayload.id.desc()).limit(limit).all()
    for r in rows:
        r.use_count = (r.use_count or 0) + 1        # 检索即计数
    db.commit()
    return rows


def match_false_positives(db: Session, endpoint: Endpoint,
                          response_signature: str | None = None) -> list[KbFalsePositive]:
    """研判前置负样本检索：接口指纹或响应指纹命中即返回疑似误报。"""
    q = db.query(KbFalsePositive).filter(KbFalsePositive.deleted_at.is_(None))
    rows = q.filter((KbFalsePositive.endpoint_signature == endpoint.dedup_hash) |
                    (KbFalsePositive.response_signature == (response_signature or "__none__"))).all()
    for r in rows:
        r.hit_count = (r.hit_count or 0) + 1
    db.commit()
    return rows


# ============ 回流 ============

_PAYLOAD_NUM_RE = re.compile(r"(?<![A-Za-z0-9_])\d+(?:\.\d+)?(?![A-Za-z0-9_])")


def payload_signature(payload: str) -> str:
    """Payload 结构签名：数字字面量归一成 0，空白/大小写归一。

    用途：`id=1001) AND 9885=9885 AND (1311=1311` 与
    `id=1001) AND 2522=2522 AND (3404=3404` 是**同一种注入模式**，
    只保留一条代表样本；具体数字交给 AI 举一反三生成。
    """
    p = (payload or "").strip().lower()
    p = re.sub(r"\s+", " ", p)
    return _PAYLOAD_NUM_RE.sub("0", p)


def find_duplicate_payload(db: Session, *, payload: str, vector: str,
                           target_waf: str | None) -> KbPayload | None:
    """查重：先精确匹配，再按结构签名匹配（数字不同的同型 payload 合并）。"""
    q = db.query(KbPayload).filter(
        KbPayload.payload == payload, KbPayload.vector == vector,
        KbPayload.deleted_at.is_(None))
    if target_waf is None:
        q = q.filter(KbPayload.target_waf.is_(None))
    else:
        q = q.filter(KbPayload.target_waf == target_waf)
    exact = q.first()
    if exact:
        return exact

    # 结构签名兜底：同 vector + WAF 下，数字字面量不同的同型 payload 视为重复
    same_group = db.query(KbPayload).filter(
        KbPayload.vector == vector, KbPayload.deleted_at.is_(None))
    if target_waf is None:
        same_group = same_group.filter(KbPayload.target_waf.is_(None))
    else:
        same_group = same_group.filter(KbPayload.target_waf == target_waf)
    sig = payload_signature(payload)
    return next((r for r in same_group.all()
                 if payload_signature(r.payload) == sig), None)


_TAG_RULES = (
    ("inline_comment", lambda p: "/**/" in p),
    ("version_comment", lambda p: "/*!" in p),
    ("operator_replace", lambda p: ("&&" in p) or ("||" in p)),
    ("double_write", lambda p: bool(re.search(
        r"(oorr|aandnd|anandd|sselect|uunionnion|ffrroomm)", p, re.I))),
    ("whitespace_replace", lambda p: bool(re.search(r"(%0a|%09|\\t|\t)", p, re.I))),
    ("hex_encoding", lambda p: bool(re.search(r"\b0x[0-9a-f]{2,}", p, re.I))),
    ("function_alt", lambda p: bool(re.search(
        r"\b(char|concat|substr|mid|ord|hex|benchmark|pg_sleep)\s*\(", p, re.I))),
)


def infer_bypass_tags(payload: str) -> list[str]:
    """从成功 payload 的形态反推用了哪些绕过手法，供知识库展示/下次优先取用。"""
    p = payload or ""
    return [name for name, fn in _TAG_RULES if fn(p)]


def feedback_success(db: Session, *, vulnerability, payload: str, vector: str,
                     bypass_tags: list[str] | None = None) -> KbPayload:
    """确认漏洞 → 成功 Payload 回流。查重：同 payload+vector+waf 只更新计数。"""
    waf = None
    from app.models.waf import WafProfile
    wp = db.query(WafProfile).filter(WafProfile.task_id == vulnerability.task_id).first()
    if wp and wp.has_waf:
        waf = wp.product

    existing = find_duplicate_payload(
        db, payload=payload, vector=vector, target_waf=waf)
    if existing:
        existing.success_count += 1
        db.commit()
        return existing

    row = KbPayload(
        payload=payload, vector=vector, target_waf=waf, bypass_tags=bypass_tags,
        dbms=vulnerability.dbms, source="auto_feedback",
        source_vuln_id=vulnerability.id, success_count=1,
    )
    db.add(row)
    db.commit()
    bus.publish("system", f"知识库回流：成功 Payload (vector={vector}, waf={waf or '无'})",
                task_id=vulnerability.task_id, level="success")
    return row


def feedback_false_positive(db: Session, *, endpoint: Endpoint,
                            review: ReviewAction, reason: str) -> KbFalsePositive:
    """人工标记误报 → 误报样本回流（含接口指纹 + 响应指纹）。"""
    row = KbFalsePositive(
        endpoint_signature=endpoint.dedup_hash,
        response_signature=_response_signature(endpoint),
        reason=reason, source="auto_feedback", source_review_id=review.id,
    )
    db.add(row)
    db.commit()
    bus.publish("system", f"知识库回流：误报样本 ({reason[:40]})", task_id=endpoint.task_id)
    return row


def _response_signature(endpoint: Endpoint) -> str:
    """接口的响应侧稳定指纹：host+method+归一路径（响应体取证时另有证据链，此处做粗粒度关联）。"""
    import hashlib
    return hashlib.sha256(f"{endpoint.host}|{endpoint.method}|{endpoint.path}".encode()).hexdigest()[:32]


# ============ 文章学习（仅工具库） ============

_INGEST_SYSTEM = """你是渗透知识蒸馏引擎。阅读用户投喂的技术文章，抽出可复用的注入/利用知识点。
只输出 JSON：
{"summary":"一文摘要",
 "insights":[
   {"kind":"playbook|oracle|payload_pattern|bypass|dbms_quirk",
    "title":"短标题",
    "body":"可执行说明（步骤/判据/注意点）",
    "tags":["postgresql","union","char"],
    "dbms":"mysql|postgresql|mssql|oracle|null",
    "example_payload":"示例payload或空字符串"}
 ]}
要求：
- 出「怎么测/怎么判断/怎么利用」的种子，不要空泛鸡汤
- 字符型/布尔/UNION/报错要分开
- MySQL 与 PostgreSQL 的差异要标明
- 最多 8 条 insights
"""


def search_insights(db: Session, *, keywords: list[str] | None = None,
                    kind: str | None = None, dbms: str | None = None,
                    limit: int = 8) -> list[KbInsight]:
    q = db.query(KbInsight).filter(KbInsight.deleted_at.is_(None), KbInsight.is_active == 1)
    if kind:
        q = q.filter(KbInsight.kind == kind)
    if dbms:
        q = q.filter((KbInsight.dbms == dbms) | (KbInsight.dbms.is_(None)))
    rows = q.order_by(KbInsight.id.desc()).limit(80).all()
    if keywords:
        keys = [k.lower() for k in keywords if k]
        scored = []
        for r in rows:
            blob = f"{r.title} {r.body} {' '.join(r.tags or [])} {r.example_payload or ''}".lower()
            hit = sum(1 for k in keys if k in blob)
            if hit:
                scored.append((hit, r))
        scored.sort(key=lambda x: -x[0])
        rows = [r for _, r in scored[:limit]]
    else:
        rows = rows[:limit]
    for r in rows:
        r.use_count = (r.use_count or 0) + 1
    db.commit()
    return rows


def ingest_article(db: Session, *, title: str, content: str,
                   source_url: str | None, user_id: int | None) -> dict:
    """投喂文章 → AI 蒸馏 insights → 写入工具库。"""
    from app.services import ai as ai_svc
    import json

    text = (content or "").strip()
    if len(text) < 40:
        raise ValueError("正文太短，至少 40 字")
    # 截断，避免爆上下文
    text = text[:20000]
    art = KbArticle(title=(title or "未命名文章")[:256], source_url=source_url,
                    content=text, created_by=user_id)
    db.add(art)
    db.flush()

    client = ai_svc.get_ai_client(db)
    insights_data = []
    summary = None
    if client:
        prompt = json.dumps({"title": title, "source_url": source_url, "content": text},
                            ensure_ascii=False)
        result = client.chat_json(_INGEST_SYSTEM, prompt)
        if isinstance(result, dict):
            summary = result.get("summary")
            insights_data = result.get("insights") or []
    if not insights_data:
        # 无 AI：粗规则抽几条，保证能入库
        insights_data = [{
            "kind": "playbook",
            "title": f"手工笔记：{title[:40]}",
            "body": text[:1500],
            "tags": ["manual"],
            "dbms": None,
            "example_payload": "",
        }]
        summary = summary or text[:200]

    created = []
    for item in insights_data[:8]:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "playbook")[:32]
        title_i = str(item.get("title") or "未命名知识点")[:256]
        body = str(item.get("body") or "").strip()
        if not body:
            continue
        row = KbInsight(
            article_id=art.id, kind=kind, title=title_i, body=body[:8000],
            tags=item.get("tags") if isinstance(item.get("tags"), list) else [],
            dbms=(str(item["dbms"]) if item.get("dbms") else None),
            example_payload=(str(item.get("example_payload") or "")[:2000] or None),
            created_by=user_id,
        )
        db.add(row)
        created.append(row)

    art.summary = (summary or "")[:2000]
    art.insight_count = len(created)
    db.commit()
    bus.publish("system", f"文章学习完成：{art.title} → {len(created)} 条知识点", level="success")
    return {
        "article_id": art.id,
        "summary": art.summary,
        "insight_count": len(created),
        "insights": [{"id": r.id, "kind": r.kind, "title": r.title,
                      "example_payload": r.example_payload, "tags": r.tags} for r in created],
    }
