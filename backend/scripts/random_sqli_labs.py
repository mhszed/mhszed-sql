# -*- coding: utf-8 -*-
"""随机抽取 sqli-labs 关卡，用工具跑全链路（采集→研判→探测→漏洞）。

用法（backend 目录，服务 8787/8081/3306 已启动）：
    venv\\Scripts\\python scripts\\random_sqli_labs.py 2 5 11
    venv\\Scripts\\python scripts\\random_sqli_labs.py          # 默认 2/5/11

说明：
- 不手工代打；只通过工具 API 建任务、复核、恢复扫描、触发深入利用。
- Less-1~10 表单被删，重点验证本轮的「无表单 GET 参数发现」。
- 深入利用统一 goal=schema（实战库表），不依赖 flag。
"""
from __future__ import annotations

import json
import sys
import time

import httpx

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://127.0.0.1:8787"
LAB = "http://127.0.0.1:8081/sqli-labs"
DEFAULT_LEVELS = [2, 5, 11]

passed, failed = [], []


def check(name: str, cond: bool, extra: str = ""):
    (passed if cond else failed).append(name)
    print(f"{'✅' if cond else '❌'} {name} {extra}", flush=True)


def wait_task(c: httpx.Client, h: dict, tid: int, timeout: int = 300) -> dict:
    t0 = time.time()
    st = {}
    while time.time() - t0 < timeout:
        st = c.get(f"/api/task/{tid}", headers=h).json()
        if st.get("status") in ("review", "done", "terminated", "failed"):
            return st
        time.sleep(3)
    return st


def run_level(c: httpx.Client, h: dict, level: int) -> dict:
    target = f"{LAB}/Less-{level}/"
    print(f"\n===== Less-{level} · {target} =====", flush=True)
    r = c.post("/api/task", headers=h, json={
        "name": f"lab-Less-{level}", "target": target, "collect_mode": "static",
        "scan_config": {"intensity": "medium", "rate_limit_qps": 2.0},
    })
    tid = r.json()["id"]
    c.post(f"/api/task/{tid}/start", headers=h, json={})
    st = wait_task(c, h, tid, timeout=300)
    check(f"Less-{level} 流水线结束", st.get("status") in ("review", "done"),
          f"status={st.get('status')} err={st.get('error_message')}")

    eps = c.get("/api/collect/endpoints", params={"task_id": tid}, headers=h).json()
    items = eps.get("items") or []
    names = [(e["method"], e["path"], [p["name"] for p in (e.get("params") or [])])
             for e in items]
    print("   接口:", names, flush=True)
    has_param = any(p for _, _, ps in names for p in ps)
    check(f"Less-{level} 发现带参接口", has_param, f"{names}")

    # 复核队列 → 确认高危，恢复扫描
    rq = c.get("/api/ai/review-queue", params={"task_id": tid, "page_size": 50},
               headers=h).json()
    for it in (rq.get("items") or []):
        c.post(f"/api/ai/review/{it['assessment_id']}",
               headers=h, json={"action": "confirm", "comment": "实验室确认放行"})
    if st.get("status") == "review":
        r = c.post("/api/scan/resume", headers=h, json={"task_id": tid})
        check(f"Less-{level} 恢复扫描", r.status_code == 200, r.text[:100])
        st = wait_task(c, h, tid, timeout=300)

    vulns = c.get("/api/vuln", params={"task_id": tid}, headers=h).json()
    vitems = vulns.get("items") if isinstance(vulns, dict) else vulns
    check(f"Less-{level} 产出漏洞", len(vitems or []) >= 1,
          f"vulns={len(vitems or [])}")
    return {"task_id": tid, "vulns": vitems or [], "status": st.get("status")}


def main() -> int:
    levels = [int(x) for x in sys.argv[1:]] or DEFAULT_LEVELS
    c = httpx.Client(base_url=BASE, timeout=60)
    token = c.post("/api/auth/login",
                   json={"username": "admin", "password": "admin123"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    c.post("/api/scope", headers=h, json={
        "name": "sqli-labs-local", "scope_type": "ip", "scope_value": "127.0.0.1"})

    results = []
    for lvl in levels:
        try:
            results.append((lvl, run_level(c, h, lvl)))
        except Exception as exc:
            check(f"Less-{lvl} 执行异常", False, repr(exc))

    # 每个有漏洞的关卡都做深入利用（goal=schema，实战库表）
    for lvl, res in results:
        if not res["vulns"]:
            continue
        vid = res["vulns"][0]["id"]
        print(f"\n===== Less-{lvl} 深入利用 goal=schema (vuln #{vid}) =====", flush=True)
        r = c.post(f"/api/vuln/{vid}/deep-exploit", headers=h,
                   json={"mode": "ai", "goal": "schema"})
        check(f"Less-{lvl} 触发深入利用", r.status_code == 200, r.text[:100])
        t0 = time.time()
        st = {}
        while time.time() - t0 < 300:
            st = c.get(f"/api/vuln/{vid}/deep-exploit/status", headers=h).json()
            if st.get("status") in ("done", "error", "idle"):
                break
            time.sleep(4)
        blob = json.dumps(st, ensure_ascii=False)
        ok = ("security" in blob or "users" in blob or "emails" in blob
              or "tables" in blob.lower())
        check(f"Less-{lvl} 深入利用拿到库表结构", ok,
              f"status={st.get('status')} summary={str(st.get('summary'))[:160]}")
        deep_done = True

    print(f"\n通过 {len(passed)} / 失败 {len(failed)}")
    if failed:
        print("失败项：")
        for n in failed:
            print("  -", n)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
