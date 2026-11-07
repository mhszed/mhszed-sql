# -*- coding: utf-8 -*-
"""深挖复用历史成果测试（离线，不依赖真实 DB/网络）。

旧实现每次深挖都从零开始：库名已经在证据链里，重跑 dump 仍重新提取库名。
修复：启动时从 evidence.meta 回填库名/表/样本。

运行：venv/Scripts/python tests/test_deep_reuse.py
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


class _Ev:
    def __init__(self, meta):
        self.meta = meta


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *_a, **_k):
        return self

    def order_by(self, *_a, **_k):
        return self

    def limit(self, *_a, **_k):
        return self

    def all(self):
        return self.rows


class _DB:
    def __init__(self, rows):
        self.rows = rows

    def query(self, _model):
        return _Query(self.rows)


def main():
    rows = [
        # 最新在前：脱裤样本
        _Ev({"stage": "blind_dump", "db": "demo_db",
             "tables": ["users", "flag"], "table": "flag",
             "sample": "| id | flag      |\n| 1  | flag{test} |"}),
        _Ev({"stage": "blind_sqlmap_fallback", "db": "demo_db"}),
        _Ev({"stage": "blind_extract_fail", "error": "x"}),
    ]
    got = de._load_prior_deep_result(_DB(rows), 28)
    check("回填库名", got.get("db") == "demo_db", got.get("db"))
    check("回填表名", got.get("tables") == ["users", "flag"], got.get("tables"))
    check("回填样本", "flag{test}" in (got.get("sample") or ""), got.get("sample"))

    # 只有库名时：表/样本为空，但仍应回填 db
    got2 = de._load_prior_deep_result(
        _DB([_Ev({"stage": "blind_sqlmap_fallback", "db": "d1"})]), 1)
    check("只有库名也能复用", got2.get("db") == "d1")
    check("无历史时返回空", de._load_prior_deep_result(_DB([]), 2).get("db") == "")

    # 脱裤样本解析：banner 不得混入，flag 要能提取
    sample_out = """[INFO] fetching entries for table 'flag' in database 'demo_db'
Database: demo_db
Table: flag
[1 entry]
+----+---------------------+
| id | flag                |
+----+---------------------+
| 1  | flag{test_123}      |
+----+---------------------+
 ___ ___| |_____ _|_| |_ ...
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
"""
    rows = de._parse_dump_rows(sample_out)
    check("dump 解析不含 banner",
          all(not any(m in r for m in de._BANNER_MARKERS) for r in rows), rows)
    check("dump 解析出数据行", any("flag{test_123}" in r for r in rows), rows)
    check("flag 提取", de._extract_flag_value("\n".join(rows)) == "flag{test_123}")
    check("banner 历史样本被清洗为空",
          de._clean_sample_text(
              "|_ -| . [.]     | .'| . |\n|_|V...  https://sqlmap.org") == "")

    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
