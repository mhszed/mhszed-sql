# -*- coding: utf-8 -*-
"""深挖状态卡 running 的恢复机制测试（离线，不依赖 DB/网络）。

覆盖：
  1) 新鲜 running 不降级；
  2) 心跳超时的 running → 降级为 interrupted；
  3) 线程抛异常 → 写 error 终态；
  4) 线程正常返回但忘记写终态 → 自动复位为 done。

运行：venv/Scripts/python tests/test_deep_status_reset.py
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401
from app.services import deep_exploit as de

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def main():
    now = de.utcnow_iso()
    old = "2020-01-01T00:00:00Z"

    # 1) 新鲜 running 保持
    de._STATUS[901] = {"status": "running", "stage": "blind_extract",
                       "summary": "提取中", "started_at": now, "updated_at": now}
    check("新鲜 running 不降级", de.get_status(901)["status"] == "running")

    # 2) 心跳超时 → interrupted
    de._STATUS[902] = {"status": "running", "stage": "blind_extract",
                       "summary": "回退 sqlmap", "started_at": old, "updated_at": old}
    st = de.get_status(902)
    check("心跳超时降级为 error", st["status"] == "error", st["status"])
    check("超时阶段标记为 interrupted", st.get("stage") == "interrupted")

    # 2.1) 动态 stale_seconds：盲注长步（表枚举/脱裤）不应被误判中断
    de._STATUS[905] = {"status": "running", "stage": "blind_dump",
                       "summary": "枚举表中", "started_at": old,
                       "updated_at": old, "stale_seconds": 10 ** 9}
    check("动态 stale_seconds 放宽长步",
          de.get_status(905)["status"] == "running")

    # 3) 线程抛异常 → error 终态
    orig_run = de._run

    def _boom(*_a, **_k):
        raise RuntimeError("boom")

    de._run = _boom
    de._STATUS[903] = {"status": "running", "stage": "starting",
                       "summary": "", "started_at": now, "updated_at": now}
    de._run_guard(903, "ai", "schema", False)
    st = de.get_status(903)
    check("线程异常写 error 终态", st["status"] == "error", st["status"])
    check("异常摘要可读", "boom" in (st.get("summary") or ""))

    # 4) 正常返回但忘写终态 → 自动复位 done
    def _noop(*_a, **_k):
        return

    de._run = _noop
    de._STATUS[904] = {"status": "running", "stage": "blind_extract",
                       "summary": "提取中", "started_at": now, "updated_at": now}
    de._run_guard(904, "ai", "flag", False)
    st = de.get_status(904)
    check("遗留 running 自动复位 done", st["status"] == "done", st["status"])
    check("复位提示写入摘要", "已自动复位" in (st.get("summary") or ""))

    de._run = orig_run
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
