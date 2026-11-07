# -*- coding: utf-8 -*-
"""扫描阶段「时间盲注定向重试」判定测试。

运行：venv/Scripts/python tests/test_time_retry.py
"""
import inspect
import sys
from pathlib import Path
from types import SimpleNamespace

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401
from app.services import deep_exploit, scheduler

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


EP_READ = SimpleNamespace(read_write="read")
EP_WRITE = SimpleNamespace(read_write="write")
SIG = ("[INFO] GET parameter 'name' appears to be 'MySQL RLIKE boolean-based blind "
       "... injectable (with --not-string=\"29\")\n"
       "[WARNING] false positive or unexploitable injection point detected")


def main():
    check("读接口 + 疑似可注 → 重试",
          scheduler._should_time_retry("no_vuln", SIG, EP_READ, "medium") is True)
    check("写接口 → 不自动重试",
          scheduler._should_time_retry("no_vuln", SIG, EP_WRITE, "medium") is False)
    check("high 强度（已含 T）→ 不重试",
          scheduler._should_time_retry("no_vuln", SIG, EP_READ, "high") is False)
    check("已确认 → 不重试",
          scheduler._should_time_retry("vuln_confirmed", SIG, EP_READ, "medium") is False)
    check("无任何可疑信号 → 不重试",
          scheduler._should_time_retry(
              "no_vuln", "[INFO] all tested parameters do not appear injectable",
              EP_READ, "medium") is False)
    check("启发式 might be injectable 也算信号",
          scheduler._should_time_retry(
              "no_vuln", "heuristic test shows that GET parameter 'q' might be injectable",
              EP_READ, "medium") is True)

    src = inspect.getsource(scheduler._run_sqlmap_job)
    # 2026-11-07：超时但 runner 已升级 vuln_confirmed 时，重测会覆盖 result
    # 把已确认的盲注丢掉（某靶场 实测）。守卫必须排除已确认类。
    _guard_at = src.find('result.get("status") == "timeout"')
    _retry_at = src.find("SQLMap 超时，改用轻量策略重测一次")
    check("超时但已确认 → 不触发轻量重测（防覆盖已确认结果）",
          _guard_at != -1
          and 'not in ("vuln_confirmed", "exploit_ok")' in src[_guard_at:_guard_at + 240])
    check("轻量重测日志位于守卫之后（确认时不会执行）",
          -1 < _guard_at < _retry_at)
    check("重试按参数记录疑似信号",
          "time_retry_target = (url, body, param)" in src)
    check("重试使用可疑参数而不是第一个/最后一个",
          "if time_retry_target and last_class in" in src)
    check("重试用 T 技法", "--technique=T" in src)
    check("重试有 180s 预算", "timeout_s=180" in src)
    check("重试用 --time-sec 2（慢目标更稳）", '"--time-sec", "2"' in src)
    check("重试只做读接口（is_write=False）", "is_write=False" in src)

    dsrc = inspect.getsource(deep_exploit._run)
    check("重试把 exploit_ok 也算确认", 'in ("vuln_confirmed", "exploit_ok")' in src)
    check("sqlmap 确认的时间盲注记 time 而不是 boolean",
          '"sql_injection_time" if is_time' in inspect.getsource(scheduler.run_scan))
    check("深挖：读接口自动回退 sqlmap",
          'getattr(ep, "read_write", "read") == "read"' in dsrc)

    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
