# -*- coding: utf-8 -*-
"""跨进程 host 锁测试：两个进程同时抢同一 target 时必须串行。

运行：venv/Scripts/python tests/test_cross_host_lock.py
"""
import subprocess
import sys
import textwrap
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from sqlmap_adapter import runner

passed, failed = [], []
HOST = "http://xproc-lock-test-9876.local/"


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def main():
    child_code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(BACKEND)!r})
        from sqlmap_adapter import runner
        f = runner._acquire_cross_host_lock({HOST!r}, 5)
        print("LOCKED" if f else "FAILED", flush=True)
        time.sleep(4)
        runner._release_cross_host_lock(f)
    """)
    child = subprocess.Popen([sys.executable, "-c", child_code],
                             stdout=subprocess.PIPE, text=True)
    try:
        line = child.stdout.readline().strip()
        check("子进程拿到跨进程锁", line == "LOCKED", line)
        f = runner._acquire_cross_host_lock(HOST, 1.0)
        check("另一进程持锁时本进程等待超时", f is None)
        runner._release_cross_host_lock(f)
    finally:
        child.wait(timeout=15)
    f2 = runner._acquire_cross_host_lock(HOST, 3)
    check("子进程退出后锁自动释放", f2 is not None)
    runner._release_cross_host_lock(f2)

    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
