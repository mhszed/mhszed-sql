# -*- coding: utf-8 -*-
"""orand：OR / AND 关键字双写。

针对「黑名单把 or / and 各删除一次（不区分大小写）」的过滤：
    OR  -> OORR   （被删一次 or 后仍剩 OR）
    AND -> AANNDD
与 doublekeywords 的区别：doublekeywords 只处理 select/from/union/where；
本脚本专治 19330 这类只过滤逻辑运算符的目标。保留原大小写。
"""
import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST


def dependencies():
    pass


def _double(word: str) -> str:
    return word[:1] + word + word[1:]


def tamper(payload, **kwargs):
    if not payload:
        return payload
    out = re.sub(r"\b(or)\b", lambda m: _double(m.group(0)), payload, flags=re.I)
    out = re.sub(r"\b(and)\b", lambda m: _double(m.group(0)), out, flags=re.I)
    return out
