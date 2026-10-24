# -*- coding: utf-8 -*-
"""冒烟测试 3（端到端全链路，含真实 SQLMap 进程调用）：
采集 → WAF画像 → 规则研判 → SQLMap初筛(auto_pass接口) → 人工复核确认 → 恢复扫描 →
漏洞产出 → 漏洞确认(Payload回流知识库) → PDF报告导出。

前置：demo_site(8899)、uvicorn(8787) 已启动；sqlmap 可用。
耗时：约 3-8 分钟（sqlmap 进程串行）。"""
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # backend 根入 path

import httpx

BASE = "http://127.0.0.1:8787"
DEMO = "http://127.0.0.1:8899"

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'✅' if cond else '❌'} {name} {extra}", flush=True)


def wait_status(c, H, task_id, targets, budget=900):
    t0 = time.time()
    last = ""
    while time.time() - t0 < budget:
        st = c.get(f"/api/task/{task_id}", headers=H).json()
        if st["status"] != last:
            last = st["status"]
            print(f"   [{int(time.time()-t0)}s] 状态 → {last} ({st['progress'].get('current_step', '')})", flush=True)
        if st["status"] in targets:
            return st
        time.sleep(3)
    return st


def _clear_ai_config():
    """临时清空 AI 配置 → 本测试按规则引擎确定性路由设计；返回原值供恢复。"""
    from app.core.database import SessionLocal
    from app.models.system import Setting
    keys = [Setting.KEY_AI_BASE_URL, Setting.KEY_AI_API_KEY, Setting.KEY_AI_MODEL]
    db = SessionLocal()
    try:
        saved = {}
        for k in keys:
            row = db.query(Setting).filter(Setting.key == k).first()
            saved[k] = (row.value, row.is_secret) if row else None
            if row:
                row.value = ""
        db.commit()
        return saved
    finally:
        db.close()


def _restore_ai_config(saved):
    from app.core.database import SessionLocal
    from app.models.system import Setting
    if not saved:
        return
    db = SessionLocal()
    try:
        for k, v in saved.items():
            row = db.query(Setting).filter(Setting.key == k).first()
            if v is None:
                if row:
                    row.value = ""
            elif row:
                row.value, row.is_secret = v
            else:
                db.add(Setting(key=k, value=v[0], is_secret=v[1]))
        db.commit()
    finally:
        db.close()


def main():
    # 清理历史 smoke 测试残留的误报样本，避免跨任务负样本压制干扰本测试
    from app.core.database import SessionLocal
    from app.models.kb import KbFalsePositive
    from app.models.base import utcnow_iso
    _db = SessionLocal()
    for _r in _db.query(KbFalsePositive).filter(KbFalsePositive.reason.like("smoke%")).all():
        _r.deleted_at = utcnow_iso()
    _db.commit()
    _db.close()
    print("   已清理历史 smoke 误报样本", flush=True)

    # 临时清空 AI 配置：本测试断言基于规则引擎的确定性路由（DeepSeek 打分会变路由）
    _saved_ai = _clear_ai_config()
    # 异常/提前退出也必须恢复（2026-10-24 教训：启动即崩会永久清空 AI key）
    import atexit
    atexit.register(_restore_ai_config, _saved_ai)

    c = httpx.Client(base_url=BASE, timeout=60, trust_env=False)
    token = c.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()["token"]
    H = {"Authorization": f"Bearer {token}"}

    # SQLMap 可用性（内置 tools/sqlmap / PATH / python -m 均可）
    from sqlmap_adapter import runner
    check("sqlmap 可用", runner.find_sqlmap() is not None)

    r = c.post("/api/task", json={"name": "smoke-3-e2e", "target": DEMO, "collect_mode": "static",
                                  "scan_config": {"intensity": "low"}}, headers=H)
    task_id = r.json()["id"]
    check("创建任务", r.status_code == 200)
    r = c.post(f"/api/task/{task_id}/start", headers=H)
    check("启动任务", r.status_code == 200)

    # 等第一轮跑完（扫描 auto_pass 接口 + 停在 review）
    st = wait_status(c, H, task_id, {"review", "done", "terminated"})
    check("第一轮完成到 review", st["status"] == "review",
          f"status={st['status']} err={st['error_message']}")

    # 扫描子任务应已产生
    r = c.get("/api/scan/progress", params={"task_id": task_id}, headers=H).json()
    print(f"   第一轮子任务: {[(j['engine'], j['result_class']) for j in r['recent_jobs']]}")
    check("SQLMap 子任务已执行", any(j["engine"] == "sqlmap" for j in r["recent_jobs"]))
    check("AI 试探子任务已执行", any(j["engine"] == "ai_probe" for j in r["recent_jobs"]))

    # 人工复核：确认 /api/items 研判（演示站的注入点）
    r = c.get("/api/ai/review-queue", params={"task_id": task_id, "page_size": 50}, headers=H).json()
    items_assess = next((i for i in r["items"] if i["path"] == "/api/items"), None)
    check("复核队列含 /api/items", items_assess is not None)
    if items_assess:
        r2 = c.post(f"/api/ai/review/{items_assess['assessment_id']}",
                    json={"action": "confirm", "comment": "确认高危，放行探测"}, headers=H)
        check("确认 /api/items 研判", r2.status_code == 200)

    # 恢复扫描
    r = c.post("/api/scan/resume", json={"task_id": task_id}, headers=H)
    check("恢复扫描", r.status_code == 200, r.text[:80])

    st = wait_status(c, H, task_id, {"done", "terminated"})
    check("恢复扫描完成", st["status"] == "done", f"status={st['status']} err={st['error_message']}")

    # 漏洞产出（SQLMap 应确认 /api/items 布尔注入）
    r = c.get("/api/vuln", params={"task_id": task_id, "page_size": 50}, headers=H).json()
    print(f"   漏洞: {[(v['vuln_type'], v['status'], v['path']) for v in r['items']]}")
    check("产出漏洞", r["total"] >= 1, f"n={r['total']}")
    check("漏洞为待复核态", all(v["status"] == "pending_review" for v in r["items"]))

    if r["total"] >= 1:
        v = r["items"][0]
        # 证据链
        r2 = c.get(f"/api/vuln/{v['id']}/evidence", headers=H).json()
        types = {e["evidence_type"] for e in r2["items"]}
        print(f"   证据类型: {sorted(types)} (共{len(r2['items'])}条)")
        check("证据链含payload", "payload" in types)
        check("证据链含请求特征", "request" in types)

        # 漏洞确认 → Payload 回流
        # 知识库按结构签名去重：同型 payload（仅随机数字不同）只累加 success_count，
        # 不新增行。因此判据是「总数增加 或 成功次数增加」。
        def kb_snapshot():
            d = c.get("/api/kb/payloads", params={"page_size": 100}, headers=H).json()
            return d["total"], sum(int(i.get("success_count") or 0) for i in d["items"])

        kb_before = kb_snapshot()
        r2 = c.post(f"/api/vuln/{v['id']}/review",
                    json={"action": "confirm", "comment": "确认为真实注入", "feed_kb": True}, headers=H)
        check("确认漏洞", r2.status_code == 200 and r2.json()["status"] == "confirmed")
        kb_after = kb_snapshot()
        check("成功Payload回流知识库",
              kb_after[0] > kb_before[0] or kb_after[1] > kb_before[1],
              f"总数 {kb_before[0]}→{kb_after[0]}, 成功次数 {kb_before[1]}→{kb_after[1]}")

        # 报告导出
        r2 = c.get("/api/vuln/report/download", params={"task_id": task_id}, headers=H)
        check("报告导出成功", r2.status_code == 200, f"content-type={r2.headers.get('content-type','')}")
        if r2.status_code == 200:
            import pathlib
            p = pathlib.Path(f"data/report_smoke3{'.pdf' if 'pdf' in r2.headers.get('content-type','') else '.txt'}")
            p.write_bytes(r2.content)
            check("报告文件非空", len(r2.content) > 500, f"{len(r2.content)} bytes → {p}")

    print(f"\n通过 {len(passed)} / 失败 {len(failed)}")
    _restore_ai_config(_saved_ai)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
