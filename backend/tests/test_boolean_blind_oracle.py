# -*- coding: utf-8 -*-
"""布尔页面对比提取器测试（离线，模拟 HTTP，不依赖网络/DB）。

覆盖：
  1) 值预测命中库名候选；
  2) 候选未命中时二分提取；
  3) 动态时间戳噪声下仍能判真假；
  4) 等值复核失败会重搜，不输出错字符；
  5) 真假页不可区分时中止（不猜结果）。

运行：venv/Scripts/python tests/test_boolean_blind_oracle.py
"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401
from app.services import boolean_blind as bb

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


class Resp:
    def __init__(self, text):
        self.status_code = 200
        self.text = text


class OracleClient:
    """把布尔条件模拟成固定页面；可注入动态内容 / 复核翻转。"""

    def __init__(self, values, *, noise=False, flip_equal_once=None):
        self.values = values
        self.noise = noise
        self.flip_equal_once = set(flip_equal_once or [])
        self.calls = 0
        self.seen_equal = set()

    @staticmethod
    def _cond_of(payload):
        m = re.search(r"AND \((.*)\)\s*(?:and\s+\(?['\"]1['\"]=['\"]1|--)",
                      payload, re.I | re.S)
        return m.group(1) if m else ""

    def _page(self, truth: bool):
        self.calls += 1
        if truth:
            body = "RESULT-OK id=1 name=admin rows=1 " + ("x" * 40)
        else:
            body = "NO-DATA"
        if self.noise:
            body += " ts=%d" % (1700000000 + self.calls)   # 归一化时被剥离
        return Resp(body)

    def _eval(self, cond):
        vals = self.values
        if cond in ("1=1", "(1=1)"):
            return True
        if cond in ("1=2", "(1=2)"):
            return False
        m = re.match(r"^length\(\((.+?)\)\)>=(\d+)$", cond)
        if m:
            return len(vals.get(m.group(1), "")) >= int(m.group(2))
        m = re.match(r"^ascii\(substr\(\((.+?)\),(\d+),1\)\)>=(\d+)$", cond)
        if m:
            s = vals.get(m.group(1), "")
            i = int(m.group(2))
            ch = s[i - 1] if 0 < i <= len(s) else ""
            return bool(ch) and ord(ch) >= int(m.group(3))
        m = re.match(r"^ascii\(substr\(\((.+?)\),(\d+),1\)\)=(\d+)$", cond)
        if m:
            s = vals.get(m.group(1), "")
            i = int(m.group(2))
            ch = s[i - 1] if 0 < i <= len(s) else ""
            eq = bool(ch) and ord(ch) == int(m.group(3))
            key = (m.group(1), i)
            if eq and key in self.flip_equal_once:
                self.flip_equal_once.discard(key)
                return False          # 模拟一次读错
            return eq
        m = re.match(r"^\((.+)\)='(.*)'$", cond)
        if m:
            want = m.group(2).replace("''", "'")
            return vals.get(m.group(1), "") == want
        return False

    def request(self, method, url, params=None, data=None, payload=None, headers=None):
        return self._page(self._eval(self._cond_of(payload or "")))


def make_extractor(client, value, **kw):
    url = "http://127.0.0.1/check?id=1"
    return bb.BooleanBlindExtractor(client=client, url=url, param="id",
                                    base_value="1", quote_style="single", **kw), value


def main():
    # 1) 值预测命中
    c = OracleClient({"database()": "security"})
    ex, val = make_extractor(c, "security")
    check("校准成功", ex.calibrate() is True)
    got = ex.extract_database()
    check("值预测命中候选库名", got == "security", got)
    check("值预测请求数少", ex.requests <= 12, ex.requests)

    # 2) 候选未命中 → 二分
    c = OracleClient({"database()": "zzzq_unknown"})
    ex, _ = make_extractor(c, "zzzq_unknown")
    check("二分校准成功", ex.calibrate() is True)
    got = ex.extract_database()
    check("二分提取未知库名", got == "zzzq_unknown", got)
    check("未误标 partial", ex.partial is False)

    # 3) 动态时间戳噪声
    c = OracleClient({"database()": "zzzq_unknown"}, noise=True)
    ex, _ = make_extractor(c, "zzzq_unknown")
    check("噪声下校准成功", ex.calibrate() is True)
    got = ex.extract_database()
    check("噪声下仍正确提取", got == "zzzq_unknown", got)

    # 4) 第 3 个字符等值复核翻转一次 → 重搜后仍正确
    c = OracleClient({"database()": "ab_cd"}, flip_equal_once={("database()", 3)})
    ex, _ = make_extractor(c, "ab_cd")
    check("复核场景校准成功", ex.calibrate() is True)
    got = ex.extract_database()
    check("复核失败重搜后正确", got == "ab_cd", got)

    # 5) 真假不可区分 → 中止，不猜
    class Flat(OracleClient):
        def _page(self, truth):
            self.calls += 1
            return Resp("SAME-PAGE")

    c = Flat({"database()": "whatever"})
    ex, _ = make_extractor(c, "whatever")
    ex._refresh_refs = lambda: False   # 保持校准失败语义（避免关键字兜底）
    check("不可区分时校准失败", ex.calibrate() is False)
    out = bb.run_boolean_fallback(
        url="http://127.0.0.1/check?id=1", param="id", client=c,
        endpoint=None, want_flag=False)
    check("不可区分时不返回猜测库名", out.get("db") in ("", None), out.get("db"))

    # 5.5) 闭合语境推断：`1")` 必须先试 paren_double
    hint = '1") AND ORD(MID((IFNULL(CAST(DATABASE() AS NCHAR),0x20)),1,1))>1 AND ("a"="a'
    order = bb.infer_styles(hint)
    check("闭合符推断优先 paren_double", order[0] == "paren_double", order[:3])
    c = OracleClient({"database()": "db9"})
    ex = bb.BooleanBlindExtractor(client=c, url="http://x/check?id=1", param="id",
                                  base_value="1", quote_style="paren_double")
    check("闭括号语境校准成功", ex.calibrate() is True)
    check("闭括号语境提取成功", ex.extract_database() == "db9")

    # 6) 取 flag：必须选 flag 列，不能把 id 当 flag
    from app.services.blind_extract import _COLS_EXPR_MYSQL_FILTERED
    cols = "flag:id,flag:flag"
    vals = {
        _COLS_EXPR_MYSQL_FILTERED: cols,
        "(select group_concat(`id` separator 0x7c) from `flag`)": "1",
        "(select group_concat(`flag` separator 0x7c) from `flag`)": "flag{abc}",
    }
    c = OracleClient(vals)
    ex, _ = make_extractor(c, "")
    check("flag 场景校准成功", ex.calibrate() is True)
    fr = ex.extract_flag()
    check("flag 提取选 flag 列", fr.get("table") == "flag" and fr.get("column") == "flag",
          f"{fr.get('table')}.{fr.get('column')}")
    check("flag 值正确", fr.get("value") == "flag{abc}", fr.get("value"))
    check("flag 完整不标 partial", fr.get("partial") is False and not fr.get("error"))

    # 7) 列清单提取中途超时 → 不产出 flag（不能拿 id 当 flag）
    class TimeoutClient(OracleClient):
        def request(self, *a, **k):
            self.calls += 1
            if self.calls > 6:
                raise TimeoutError("timed out")
            return super().request(*a, **k)

    c = TimeoutClient(vals)
    ex, _ = make_extractor(c, "")
    ex.calibrate()
    fr = ex.extract_flag()
    check("列提取超时不产出 flag", not fr.get("value"), fr.get("value"))
    check("超时时标记 partial/error", fr.get("partial") is True or bool(fr.get("error")))

    # 8) 断点续跑：前缀复核通过 → 从断点继续，得到完整值
    expr = "(select group_concat(`flag` separator 0x7c) from `flag`)"
    c = OracleClient({expr: "flag{abcdef}"})
    ex = bb.BooleanBlindExtractor(client=c, url="http://x/check?id=1", param="id",
                                  base_value="1", quote_style="single")
    check("续跑场景校准成功", ex.calibrate() is True)
    fr = ex.extract_flag(resume={"table": "flag", "column": "flag",
                                 "value": "flag{a", "length": len("flag{abcdef}"),
                                 "expr": expr})
    check("续跑得到完整 flag", fr.get("value") == "flag{abcdef}", fr.get("value"))
    check("续跑标记完整", fr.get("partial") is False)
    check("续跑保留表达式", fr.get("expr") == expr)

    # 9) 前缀复核不一致 → 放弃续跑，改走正常提取，结果仍正确
    cols = _COLS_EXPR_MYSQL_FILTERED
    c = OracleClient({expr: "flag{abcdef}", cols: "flag:flag"})
    ex = bb.BooleanBlindExtractor(client=c, url="http://x/check?id=1", param="id",
                                  base_value="1", quote_style="single")
    ex.calibrate()
    fr = ex.extract_flag(resume={"table": "flag", "column": "flag",
                                 "value": "zzz", "length": len("flag{abcdef}"),
                                 "expr": expr})
    check("错误前缀不续跑且结果正确",
          fr.get("value") == "flag{abcdef}", fr.get("value"))

    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
