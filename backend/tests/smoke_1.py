# -*- coding: utf-8 -*-
"""冒烟测试 1：授权校验 + 任务创建/启动/终止 + 静态爬虫 + 归一 + 链路还原。

前置：demo_site.py (8899) 与 uvicorn (8787) 已启动。
运行：venv/Scripts/python tests/smoke_1.py
"""
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows GBK 控制台兼容

import httpx

BASE = "http://127.0.0.1:8787"
DEMO = "http://127.0.0.1:8899"

passed, failed = [], []


def check(name: str, cond: bool, extra: str = ""):
    (passed if cond else failed).append(f"{name} {extra}")
    print(f"{'✅' if cond else '❌'} {name} {extra}")


def main():
    c = httpx.Client(base_url=BASE, timeout=30, trust_env=False)

    # 登录
    r = c.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    check("登录", r.status_code == 200)
    token = r.json()["token"]
    H = {"Authorization": f"Bearer {token}"}

    # 授权范围：先测未授权拒绝（用固定不可能授权的域名，避免历史数据污染）
    r = c.post("/api/task", json={"name": "smoke-noauth", "target": "http://unauthorized.invalid", "collect_mode": "static"}, headers=H)
    check("创建任务(未授权范围也可创建,pending)", r.status_code == 200)
    task_noauth = r.json()["id"]
    r = c.post(f"/api/task/{task_noauth}/start", headers=H)
    check("启动未授权目标被拒(403)", r.status_code == 403, r.text[:80])
    c.delete(f"/api/task/{task_noauth}", headers=H)

    # 建授权范围（IP 类型）
    r = c.post("/api/scope", json={"name": "smoke-scope", "scope_type": "ip",
                                   "scope_value": "127.0.0.1"}, headers=H)
    check("创建授权范围", r.status_code == 200)

    # 创建并启动合法任务
    r = c.post("/api/task", json={"name": "smoke-1", "target": DEMO, "collect_mode": "static",
                                  "scan_config": {"intensity": "medium"}}, headers=H)
    task_id = r.json()["id"]
    r = c.post(f"/api/task/{task_id}/start", headers=H)
    check("启动授权目标", r.status_code == 200, f"status={r.json()['status']}")

    # 等流水线跑完（静态爬虫 + 链路还原 + WAF 画像 + AI 研判 + 探测调度）
    # 预算 420s，按实测算术定（旧 60s 纯属不够，会把它误判成"卡住"）：
    #   阶段4 研判：6 接口 × ~5s                      ≈  30s
    #   阶段5 探测：4 个 auto_pass 接口 × ai_probe ~43s ≈ 172s
    #     （ai_probe 每个接口 ~34 个请求，被 rate_limit_qps=1.0 各卡 1s）
    #              + sqlmap 兜底若干轮                  ≈  20s
    #   → 实测 ~220s，留 2 倍余量应对 DeepSeek 抖动。
    # break 条件必须含 review——有复核项时流水线停 review 是**正常终态**。
    for _ in range(420):
        time.sleep(1)
        r = c.get(f"/api/task/{task_id}", headers=H).json()
        if r["status"] in ("done", "review", "terminated"):
            break
    check("流水线完成(有复核项停review,否则done)", r["status"] in ("done", "review"),
          f"status={r['status']} err={r['error_message']}")

    # 接口列表
    r = c.get(f"/api/collect/endpoints", params={"task_id": task_id, "page_size": 50}, headers=H).json()
    paths = {(e["method"], e["path"]) for e in r["items"]}
    print("   采集到的接口:", sorted(paths))
    check("采集到 /api/items", any(p == "/api/items" for _, p in paths))
    check("采集到 /api/search", any(p == "/api/search" for _, p in paths))
    check("采集到 /api/login", any(p == "/api/login" for _, p in paths))
    check("采集到 JS 内 /api/user/profile", any(p == "/api/user/profile" for _, p in paths))
    check("POST 接口分类为 write", any(m == "POST" for m, _ in paths))
    check("表单参数被解析", any(e["params"] for e in r["items"]))

    # 链路
    r = c.get(f"/api/collect/chains", params={"task_id": task_id}, headers=H).json()
    print(f"   业务链: {len(r['items'])} 条")
    for ch in r["items"]:
        print(f"   - [{ch['reconstruct_method']}] conf={ch['confidence']} {ch['name']}")
    check("至少还原出 1 条链", len(r["items"]) >= 1)

    # 重复启动应被拒
    r = c.post(f"/api/task/{task_id}/start", headers=H)
    check("done 状态不可再启动", r.status_code == 400)

    print(f"\n通过 {len(passed)} / 失败 {len(failed)}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
