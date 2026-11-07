# -*- coding: utf-8 -*-
"""布尔盲注确定性成对探针测试（不依赖 AI / 网络 / 数据库）。

背景：2026-11-07 数字型布尔盲注（id=1 and 1=1 / 1=2）在配置了 AI 的
任务里没有对应形态，AI 探针整条漏检。修复：布尔对与时间对一样，
永远追加、不依赖 AI 生成。

运行：venv/Scripts/python tests/test_bool_pair_templates.py
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401
from app.services import ai

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


class FakeClient:
    """模拟已配置 AI：只返回一条自定义布尔 payload。"""

    def chat_json(self, *_a, **_k):
        return {"payloads": [{
            "payload": "1' and '1'='1", "vector": "boolean",
            "false_variant": "1' and '1'='2",
        }]}


def main():
    ai.get_ai_client = lambda _db: FakeClient()
    ai.knowledge.find_payloads = lambda *_a, **_k: []
    # 避免空 probes 触发真实的研判探针请求
    ai._collect_sqli_probes = lambda _ep: []

    ep = SimpleNamespace(
        method="GET", path="/check", read_write="read",
        scheme="http", host="127.0.0.1",
        params=[{"name": "id", "sample_value": "1", "location": "query"}],
    )
    payloads = ai.generate_payloads(
        None, ep, None, base_value="1",
        probe_context={"probes": [], "likely_dbms": "unknown"},
    )
    by_payload = {p["payload"]: p for p in payloads}

    # 1) AI 生成结果仍然保留
    check("AI 生成的布尔 payload 保留", "1' and '1'='1" in by_payload)

    # 2) 三种语境的确定性布尔对都必须存在（不依赖 AI）
    pairs = [
        ("1 and 1=1", "1 and 1=2"),
        ("1' and '1'='1'-- -", "1' and '1'='2'-- -"),
        ('1" and "1"="1"-- -', '1" and "1"="2"-- -'),
    ]
    for true_p, false_p in pairs:
        item = by_payload.get(true_p)
        check(f"确定性布尔对存在: {true_p}", item is not None)
        if item:
            check(f"为 {true_p} 提供同构 false 变体",
                  item.get("false_variant") == false_p,
                  f"got={item.get('false_variant')!r}")
            check(f"向量为 boolean: {true_p}", item.get("vector") == "boolean")

    # 3) 时间对仍然存在（不回退旧能力）
    check("时间对模板仍追加",
          any(p.get("vector") == "time" and "sleep(" in p["payload"]
              for p in payloads))

    # 4) 去重：同一 payload 不重复追加
    keys = [p["payload"] for p in payloads]
    check("payload 无重复", len(keys) == len(set(keys)))

    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
