# -*- coding: utf-8 -*-
"""冒烟测试 5（WAF 绕过 + SQLite 深入利用）—— 覆盖 2026-10-15 的改动。

单元（无需服务）：
  1) classify_db_error 正向/负向/无  2) double_write 关键字双写
  3) bypass_variants 顺序（含 union/select 时双写优先；ORDER BY 时纯空格优先）
  4) _is_silently_filtered 静默过滤判据
  5) _with_param / prober._has_new_token / char_union._is_error 认「查询异常」

集成（需 demo_site 8899 + uvicorn 8787）：
  对 demo_site 的 /api/sec/search（模拟 16328：过滤空格 + 单次关键字，SQLite 后端）
  跑完整链路 → 产出漏洞 → 深入利用取出 flag{local_waf_bypass_ok}

前置：demo_site(8899)、uvicorn(8787) 已启动。
"""
import os
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

BASE = "http://127.0.0.1:8787"
DEMO = "http://127.0.0.1:8899"
SEC_URL = f"{DEMO}/api/sec/search?q=1"
FLAG = "flag{local_waf_bypass_ok}"

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'✅' if cond else '❌'} {name} {extra}", flush=True)


# ============ 单元测试 ============

def unit_tests():
    from app.services import ai, prober
    from app.services.char_union_exploit import CharUnionExploiter
    from app.services.waf import BYPASS_MAP, _with_param

    # 1) 错误分级：正向 SQL 报错 / 负向应用层报错 / 无
    cases = [
        ("You have an error in your SQL syntax; check the manual", "sql"),
        ('near "x": syntax error', "sql"),
        ('查询异常: unrecognized token: "\'"', "sql"),
        ("Invalid input syntax for integer: 1'", "non"),
        ("Unexpected token } in JSON at position 5", "non"),
        ("java.lang.Integer cannot be cast", "non"),
        ("<html>normal page</html>", None),
        # 回显型靶点会把发出的 SQL 原样打回页面：裸 DBMS 名不是报错
        # （2026-10-23 smoke_5 实测：sqlite_version() 成功回显被误判报错，
        #  导致 DBMS 判定恒失败、SQLite 剧本被跳过、拿到伪库名 database）
        ('{"sql": "... UNION SELECT sqlite_version(),2,3,4 -- %\'", '
         '"results": [["3.45.3", 2, 3, 4]]}', None),
        ('{"sql": "SELECT ...", "results": [], "db": "mysql"}', None),
        ("sqlite3.OperationalError: no such table: x", "sql"),
        ("Warning: mysql_query(): Access denied for user", "sql"),
    ]
    for text, want in cases:
        pos, neg = ai.classify_db_error(text)
        got = "sql" if pos else ("non" if neg else None)
        check(f"错误分级 {text[:34]!r} → {want}", got == want, f"(实际 {got})")

    # 2) 双写
    for w, want in (("union", "uunionnion"), ("select", "sselectelect"),
                    ("from", "ffromrom"), ("where", "wwherehere")):
        check(f"双写 {w} → {want}", ai.double_write(w) == want, f"(实际 {ai.double_write(w)})")

    # 3) 绕过变体顺序
    v_union = ai.bypass_variants("1' union select 1,2,3,4 from sqlite_master-- ")
    check("含 union/select 时首个变体是双写版",
          "uunionnion" in v_union[0] and "sselectelect" in v_union[0],
          f"(实际 {v_union[0][:60]})")
    v_order = ai.bypass_variants("1' ORDER BY 2 -- ")
    check("ORDER BY 首个变体是纯空格替代（不双写）",
          "ORDER" in v_order[0] and "ORDER" * 2 not in v_order[0].upper(),
          f"(实际 {v_order[0][:60]})")
    check("变体里含 // 空格替代", any("//" in v for v in v_order))
    check("变体去重", len(v_order) == len(set(v_order)))

    # 4) 静默过滤判据
    class _R:
        status_code = 200
        content = b"x" * 100
        text = "x" * 100
    base_key = prober._page_key(_R())   # 用真实判据构造基线键
    check("静默过滤：含空格+关键字且响应=基线 → True",
          prober._is_silently_filtered(_R(), "1' and 1=1 -- ", base_key) is True)
    check("静默过滤：无空格 → False",
          prober._is_silently_filtered(_R(), "1'or(1=1)", base_key) is False)

    # 5) 辅助
    check("_with_param 正确拼接",
          _with_param("http://h/a?q=1&p=2", "q", "1'") .endswith("q=1%27&p=2"))
    check("_has_new_token 识别新标识符",
          prober._has_new_token("alpha secrets table", "alpha") is True)
    check("char_union._is_error 认「查询异常」",
          CharUnionExploiter("http://127.0.0.1:9/")._is_error("查询异常: unrecognized token", 200))
    check("char_union._is_error 不认类型转换错",
          not CharUnionExploiter("http://127.0.0.1:9/")._is_error("must be an integer", 200))
    check("BYPASS_MAP 含 silent_filter",
          BYPASS_MAP.get("silent_filter") == ["space_alt", "keyword_double_write"])

    # 7) 推送去重键必须含 task_id（否则跨任务推送被吞）
    from app.services.collector import _push_hash
    check("推送去重键随 task_id 变化",
          _push_hash(1, "GET", SEC_URL, "") != _push_hash(2, "GET", SEC_URL, ""))

    # 8) payload 归一化：URL 编码要去掉（否则 params 发送时二次编码 → 注入失效）
    check("归一化还原 %27/%20", prober._normalize_payload("1%27%20and%201=1") == "1' and 1=1")
    check("归一化不动普通 payload", prober._normalize_payload("1' and 1=1 -- ") == "1' and 1=1 -- ")
    check("归一化不动裸 %", prober._normalize_payload("100%") == "100%")
    check("encoding 策略不再产生 %XX（避免二次编码）",
          ai._apply_strategy("1' and 1=1", "encoding") == "1' and 1=1")

    # 6) demo 靶点自身的 WAF 行为（作为"标尺"，保证集成测试有意义）
    from tests.demo_site import _sec_filter
    check("靶点 WAF：含空格 payload 被吃掉", _sec_filter("1' and 1=1 -- ") is None)
    check("靶点 WAF：// 恢复空格",
          _sec_filter("1'//and//'1'='1") == "1' and '1'='1")
    check("靶点 WAF：关键字单次剥离 + 双写可还原",
          _sec_filter("//uunionnion//sselectelect//") == " union select ")


# ============ 集成测试 ============

def wait_status(c, H, task_id, targets, budget=300):
    t0 = time.time()
    last = ""
    while time.time() - t0 < budget:
        st = c.get(f"/api/task/{task_id}", headers=H).json()
        if st["status"] != last:
            last = st["status"]
            print(f"   [{int(time.time()-t0)}s] 状态 → {last} "
                  f"({st['progress'].get('current_step','')})", flush=True)
        if st["status"] in targets:
            return st
        time.sleep(3)
    return st


def _clear_ai_config():
    """清空 AI 配置 → 走规则引擎 + 内置模板 + 硬编码绕过，结果确定可复现。"""
    from app.core.database import SessionLocal
    from app.models.system import Setting
    db = SessionLocal()
    try:
        rows = db.query(Setting).filter(
            Setting.key.in_([Setting.KEY_AI_BASE_URL, Setting.KEY_AI_API_KEY,
                             Setting.KEY_AI_MODEL])).all()
        old = [(r.key, r.value, r.is_secret) for r in rows]
        for r in rows:
            db.delete(r)
        db.commit()
        return old
    finally:
        db.close()


def _restore_ai_config(old):
    from app.core.database import SessionLocal
    from app.models.system import Setting
    db = SessionLocal()
    try:
        for key, value, is_secret in old:
            db.add(Setting(key=key, value=value, is_secret=is_secret))
        db.commit()
    finally:
        db.close()


def integration_test():
    old_ai = _clear_ai_config()
    # 异常/提前退出也必须恢复（2026-10-24 教训：启动即崩会永久清空 AI key）
    import atexit
    atexit.register(_restore_ai_config, old_ai)
    c = httpx.Client(base_url=BASE, timeout=60.0, trust_env=False)
    try:
        r = c.post(f"{BASE}/api/auth/login",
                   json={"username": "admin", "password": "admin123"})
        check("登录", r.status_code == 200)
        H = {"Authorization": f"Bearer {r.json()['token']}"}

        r = c.post(f"{BASE}/api/scope", headers=H, json={
            "name": "smoke5-scope", "scope_type": "ip", "scope_value": "127.0.0.1"})
        check("建立授权范围", r.status_code == 200)

        r = c.post(f"{BASE}/api/task", headers=H, json={
            "name": "smoke5-waf-bypass", "target": SEC_URL, "collect_mode": "static",
            "scan_config": {"engines": {"sqlmap_enabled": False, "ai_probe_enabled": True},
                            "intensity": "low"}})
        check("创建任务", r.status_code == 200, r.text[:100])
        task_id = r.json()["id"]

        # 演示站的 /api/sec/search 未挂在页面上，静态爬虫发现不了 →
        # 用 Burp 推送通道直接把该接口喂进来（也是正式支持的入口）
        r = c.post(f"{BASE}/api/burp/push", json={
            "client_id": "smoke5-client-0001", "task_id": task_id,
            "records": [{"method": "GET", "url": SEC_URL,
                         "headers": {"User-Agent": "smoke5"},
                         "body": ""}]})
        check("Burp 推送端点", r.status_code == 200, r.text[:100])

        r = c.post(f"{BASE}/api/task/{task_id}/start", headers=H, json={})
        check("启动任务", r.status_code == 200)
        st = wait_status(c, H, task_id, ("done", "review", "failed", "terminated"))
        check("流水线完成", st["status"] in ("done", "review"), f"status={st['status']}")

        eps = c.get(f"{BASE}/api/collect/endpoints?task_id={task_id}", headers=H).json()
        paths = [e["path"] for e in eps.get("items", [])]
        check("采集到 /api/sec/search", any("sec/search" in p for p in paths), f"{paths}")
        check("解析出 q 参数",
              any(any(p.get("name") == "q" for p in (e.get("params") or []))
                  for e in eps.get("items", [])))

        vulns = c.get(f"{BASE}/api/vuln?task_id={task_id}", headers=H).json()
        items = vulns.get("items") if isinstance(vulns, dict) else vulns
        check("产出漏洞（绕过 WAF 生效）", len(items or []) >= 1,
              f"漏洞数={len(items or [])}")
        if not items:
            return
        vid = items[0]["id"]

        # 深入利用：必须能穿过 WAF 取到 flag（验证 SQLite 分支 + 绕过）
        r = c.post(f"{BASE}/api/vuln/{vid}/deep-exploit", headers=H,
                   json={"mode": "ai", "goal": "flag"})
        check("触发深入利用", r.status_code == 200, r.text[:100])
        t0 = time.time()
        while time.time() - t0 < 240:
            s = c.get(f"{BASE}/api/vuln/{vid}/deep-exploit/status", headers=H).json()
            if s.get("status") in ("done", "failed"):
                break
            time.sleep(5)
        ev = c.get(f"{BASE}/api/vuln/{vid}/evidence", headers=H).json()
        blob = str(ev)
        check("深入利用取到 flag", FLAG in blob, f"(flag 片段: {blob[-200:] if FLAG not in blob else 'OK'})")
    finally:
        c.close()
        _restore_ai_config(old_ai)


if __name__ == "__main__":
    print("=" * 20, "单元测试", "=" * 20)
    unit_tests()
    print("\n" + "=" * 20, "集成测试", "=" * 20)
    integration_test()
    print(f"\n通过 {len(passed)} / 失败 {len(failed)}")
    if failed:
        print("失败项：")
        for f in failed:
            print("  -", f)
        sys.exit(1)
