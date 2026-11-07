# -*- coding: utf-8 -*-
"""报告「深入利用结果」提取测试（离线，不依赖 DB/PDF）。

覆盖：
  1) 完整 flag + 分步 payload 能进报告事实；
  2) 部分 flag（超时前缀）标注“部分、未完整、可续跑”，不冒充完整；
  3) 新证据阶段 bool_page_extract 的表/库可信；
  4) 分步 payload 优先取最新证据。

运行：venv/Scripts/python tests/test_report_deep_summary.py
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.models  # noqa: F401
from app.services import report

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def ev(meta, content="", seq=0, evidence_type="deep_exploit"):
    return SimpleNamespace(evidence_type=evidence_type, content=content,
                           meta=meta, seq=seq)


def main():
    complete = ev({
        "stage": "bool_page_extract", "db": "demo_db",
        "tables": ["users", "flag"], "flag": "flag{demo_ok}",
        "payload_db": "DBPAYLOAD", "payload_tables": "TBLPAYLOAD",
        "payload_flag": "FLAGPAYLOAD", "db_source": "boolean/reuse",
    }, content="【深入利用结果】数据样本/flag：flag{demo_ok}", seq=10)
    display, tables, sample = report._deep_facts([complete])
    check("库名提取", display == "demo_db", display)
    check("表提取", tables == ["users", "flag"], tables)
    check("完整 flag", sample == "flag{demo_ok}", sample)

    dp = report._deep_payloads([complete])
    check("取库 payload", dp["db"] == "DBPAYLOAD", dp["db"])
    check("取表 payload", dp["tables"] == "TBLPAYLOAD", dp["tables"])
    check("取 flag payload", dp["flag"] == "FLAGPAYLOAD", dp["flag"])
    check("库名来源", dp["db_source"] == "boolean/reuse")

    partial = ev({
        "stage": "bool_page_extract", "db": "demo_db",
        "tables": ["users", "flag"], "flag_partial": "flag{demo_pa",
        "flag_length": 38, "payload_flag": "FLAGPART",
    }, content="【深入利用结果】数据样本/flag（部分，未完整）：flag{demo_pa",
        seq=11)
    _, _, psample = report._deep_facts([partial])
    check("部分 flag 不冒充完整", "部分，未完整，可续跑" in psample, psample)

    # 旧证据（无 bool_page_extract 阶段的表）不应压过新证据
    old = ev({"stage": "impact_tables", "tables": ["old_table"]},
             content="", seq=1)
    _, tables2, _ = report._deep_facts([old, complete])
    check("新证据表优先", tables2 == ["users", "flag"], tables2)

    # payload 取最新证据
    newer = ev({"stage": "bool_page_extract", "payload_db": "NEWDB"}, seq=20)
    dp2 = report._deep_payloads([complete, newer])
    check("分步 payload 取最新", dp2["db"] == "NEWDB", dp2["db"])

    # 噪声表名整体丢弃
    check("噪声表名丢弃",
          report._clean_tables(["warning", "users"]) == [])
    check("正常表名保留",
          report._clean_tables(["users", "flag"]) == ["users", "flag"])

    # 10) 值预测的否条件（__x）不能当取数 payload
    ctrl = ev({"stage": "bool_page_extract",
               "payload_tables": "1' AND ((select table_name ...)='flag__x') and '1'='1"},
              seq=30)
    dpc = report._deep_payloads([ctrl])
    check("控制条件被过滤", dpc["tables"] == "", dpc["tables"])

    # 11) payload 证据只取第一行，不把“预期判据”当 payload
    pev = ev({"payload": "1' and '1'='1'-- -"}, evidence_type="payload", seq=31,
             content="1' and '1'='1'-- -\n预期判据: 布尔差异")
    pls = report._payload_texts([pev])
    check("payload 只取第一行", pls == ["1' and '1'='1'-- -"], pls)

    # 12) DBMS 未知但提取语句是 MySQL → 标注推断
    fake_v = SimpleNamespace(dbms="-")
    disp = report._dbms_display(
        fake_v, {"db": "1' AND ((database())='x') and '1'='1", "tables": ""},
        ["users", "flag"])
    check("DBMS 推断为 MySQL", "MySQL" in disp, disp)

    # 13) 库名来源非 sqlmap → 不展示 sqlmap --current-db 命令
    src_ev = ev({"stage": "blind_dump", "db_source": "boolean/reuse",
                 "extract_extra": ["--technique", "B", "--current-db"]}, seq=32)
    check("非 sqlmap 库名抑制 sqlmap 参数",
          report._deep_extract([src_ev]) == "")

    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
