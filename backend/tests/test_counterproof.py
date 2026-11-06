# -*- coding: utf-8 -*-
"""布尔误报复核（全量反证）单元测试。不依赖服务与网络。

运行：venv/Scripts/python tests/test_counterproof.py
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401
from app.models.endpoint import Endpoint
from app.services import prober

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


class _Resp:
    def __init__(self, body, status=200):
        self.status_code = status
        self.content = body.encode("utf-8")
        self.text = body


class _Client:
    """按 payload 返回预设响应；可配置抛异常。"""

    last_elapsed = 0.0

    def __init__(self, reply, raises=False):
        self.reply = reply
        self.raises = raises
        self.calls = []

    def request(self, method, url, params=None, data=None, payload=None):
        self.calls.append(payload)
        if self.raises:
            raise RuntimeError("boom")
        return self.reply(payload)


def _endpoint():
    return Endpoint(task_id=1, source="crawler", dedup_hash="h", method="GET",
                    path="/vul/sqli/sqli_id.php", raw_path="/vul/sqli/sqli_id.php",
                    host="target.local:8080", scheme="http",
                    params=[{"name": "id", "location": "query", "sample_value": "1"}],
                    read_write="read")


def test_fresh_pair():
    seed = 5623
    pair = prober._fresh_bool_pair("1001' AND '1'='1", seed)
    check("同构新条件（带引号）",
          pair == ("1001' AND '5623'='5623", "1001' AND '5623'='5624"), str(pair))
    pair2 = prober._fresh_bool_pair("1 AND 1=1", seed)
    check("同构新条件（裸数字）", pair2 == ("1 AND 5623=5623", "1 AND 5623=5624"), str(pair2))
    check("无等值常量返回 None",
          prober._fresh_bool_pair("1' AND (SELECT COUNT(*) FROM t)>0--", seed) is None)


def test_pass():
    payload, false_payload = "1001' AND '1'='1", "1001' AND '1'='2"
    seed = 1000 + sum(payload.encode()) % 8000
    ft, ff = prober._fresh_bool_pair(payload, seed)

    def reply(pl):
        if pl in (payload, ft):
            return _Resp("same-page")
        return _Resp("different-page")

    ok, detail, reqs = prober._counterproof_boolean(
        _Client(reply), _endpoint(), "id", payload, false_payload, None)
    check("新随机真假可区分 → 反证通过", ok, detail)
    check("反证请求数 = 4", reqs == 4, f"reqs={reqs}")


def test_fail_no_control():
    payload, false_payload = "1001' AND '1'='1", "1001' AND '1'='2"

    def reply(pl):
        return _Resp("same-page")          # 所有响应一致：没有受控分支

    ok, detail, reqs = prober._counterproof_boolean(
        _Client(reply), _endpoint(), "id", payload, false_payload, None)
    check("true/false 响应一致 → 撤销", ok is False, detail)


def test_fail_fresh_pair():
    payload, false_payload = "1001' AND '1'='1", "1001' AND '1'='2"
    seed = 1000 + sum(payload.encode()) % 8000
    ft, ff = prober._fresh_bool_pair(payload, seed)

    def reply(pl):
        if pl == payload:
            return _Resp("true-page")
        if pl == false_payload:
            return _Resp("false-page")
        return _Resp("fixed")              # 新条件不再区分

    ok, detail, _ = prober._counterproof_boolean(
        _Client(reply), _endpoint(), "id", payload, false_payload, None)
    check("新条件不响应 → 撤销", ok is False, detail)


def test_skip_no_constants():
    payload = "1' AND (SELECT COUNT(*) FROM t)>0-- -"
    false_payload = "1'"                        # 无同构假值，仅验证原对

    def reply(pl):
        return _Resp("true-page" if pl == payload else "false-page")

    ok, detail, reqs = prober._counterproof_boolean(
        _Client(reply), _endpoint(), "id", payload, false_payload, None)
    check("无等值常量 → 跳过反证，保留原判", ok, detail)
    check("无等值常量不发请求（防误杀）", reqs == 0, f"reqs={reqs}")


def test_skip_waf_and_error():
    payload, false_payload = "1001' AND '1'='1", "1001' AND '1'='2"
    ok, detail, _ = prober._counterproof_boolean(
        _Client(lambda pl: _Resp("blocked", status=403)),
        _endpoint(), "id", payload, false_payload, None)
    check("WAF 拦截 → 保留原判", ok, detail)

    ok2, detail2, _ = prober._counterproof_boolean(
        _Client(lambda pl: None, raises=True),
        _endpoint(), "id", payload, false_payload, None)
    check("请求异常 → 保留原判", ok2, detail2)

    ok3, detail3, _ = prober._counterproof_boolean(
        _Client(lambda pl: _Resp("server error", status=500)),
        _endpoint(), "id", payload, false_payload, None)
    check("服务端 5xx → 保留原判", ok3, detail3)


def main():
    test_fresh_pair()
    test_pass()
    test_fail_no_control()
    test_fail_fresh_pair()
    test_skip_no_constants()
    test_skip_waf_and_error()
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
