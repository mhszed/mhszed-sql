# -*- coding: utf-8 -*-
"""「仅测试当前目录及子目录」：目标目录前缀 + 接口路径归属 单元测试。

不依赖服务（无需 uvicorn / demo_site）。
运行：venv/Scripts/python tests/test_low_intensity_scope.py
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.scope import path_under_prefix as _path_under_prefix
from app.services.scope import target_dir_prefix as _target_dir_prefix

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def main():
    # 目标目录解析
    cases = [
        ("http://target.local:8080/vul/sqli/sqli_id.php", "/vul/sqli/"),
        ("http://target.local:8080/vul/sqli/", "/vul/sqli/"),
        ("http://target.local:8080/", "/"),
        ("http://target.local:8080", "/"),
        ("target.local:8080/vul/sqli/sqli_id.php", "/vul/sqli/"),
        ("http://h/vul/sqli/sqli_id.php?id=1", "/vul/sqli/"),
    ]
    for target, want in cases:
        got = _target_dir_prefix(target)
        check(f"目录 {target}", got == want, f"got={got}")

    # 路径归属：同目录 / 子目录 命中；相似前缀、相邻模块、父目录 不命中
    prefix = "/vul/sqli/"
    hit = [
        "/vul/sqli/sqli_id.php",
        "/vul/sqli/sqli_str.php",
        "/vul/sqli/sqli_iu/sqli_login.php",
        "/vul/sqli/sqli_header/sqli_header_login.php",
        "/vul/sqli/sqli_iu/",
    ]
    miss = [
        "/vul/sqli2/x.php",       # 相似前缀不得误伤
        "/vul/xss/xss_01.php",    # 相邻模块
        "/vul/",                  # 父目录
        "/index.php",
        "",
    ]
    for p in hit:
        check(f"命中 {p}", _path_under_prefix(p, prefix))
    for p in miss:
        check(f"排除 {p}", not _path_under_prefix(p, prefix))

    # 根目录前缀 = 不收敛
    check("根目录全放行", _path_under_prefix("/anything.php", "/"))

    # 编码与查询串
    check("编码路径", _path_under_prefix("/vul/sqli%2Fsqli_id.php", prefix))
    check("带查询串", _path_under_prefix("/vul/sqli/sqli_id.php?id=1&x=2", prefix))

    # 模拟阶段5过滤：只留目录内接口
    eps = ["/vul/sqli/sqli_id.php", "/vul/sqli/sqli_blind_b.php",
           "/vul/xss/xss_01.php", "/vul/burteforce/bf_form.php"]
    kept = [p for p in eps if _path_under_prefix(p, prefix)]
    check("过滤后仅目录内", kept == eps[:2], f"kept={kept}")

    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
