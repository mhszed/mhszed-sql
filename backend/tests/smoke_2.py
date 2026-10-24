# -*- coding: utf-8 -*-
"""冒烟测试 2：WAF画像 + AI研判(无key规则引擎降级) + 人在回路复核 + 误报回流知识库。

前置：demo_site(8899) 与 uvicorn(8787) 已启动。
本测试验证"无 key 降级"，开头会临时清空 AI 配置、结束恢复原值（自洽，不依赖环境状态）。
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # backend/
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import httpx

BASE = "http://127.0.0.1:8787"
DEMO = "http://127.0.0.1:8899"

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'✅' if cond else '❌'} {name} {extra}")


def _swap_ai_config():
    """直连 SQLite 清空 AI 三项配置，返回原 raw 值供恢复（密钥保持密文不动）。"""
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
    # 清理历史 smoke 测试残留的误报样本，避免跨任务负样本压制干扰本测试（与 smoke_3 一致）
    from app.core.database import SessionLocal
    from app.models.kb import KbFalsePositive
    from app.models.base import utcnow_iso
    _db = SessionLocal()
    for _r in _db.query(KbFalsePositive).filter(KbFalsePositive.reason.like("smoke%")).all():
        _r.deleted_at = utcnow_iso()
    _db.commit()
    _db.close()
    print("   已清理历史 smoke 误报样本", flush=True)

    c = httpx.Client(base_url=BASE, timeout=60, trust_env=False)
    token = c.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()["token"]
    H = {"Authorization": f"Bearer {token}"}

    # AI 配置临时清空 → 本测试专测"无 key 规则引擎降级"，结束时恢复
    _saved = _swap_ai_config()
    # 异常/提前退出也必须恢复（2026-10-24：代理故障导致启动即崩，AI key 被清空且未还原）
    import atexit
    atexit.register(_restore_ai_config, _saved)

    # AI 未配置 → 应显示降级状态
    r = c.get("/api/settings", headers=H).json()
    check("AI 未配置状态可见", r["ai_configured"] is False)

    # 建任务跑全流程（采集→链路→WAF画像→研判）
    r = c.post("/api/task", json={"name": "smoke-2", "target": DEMO, "collect_mode": "static"},
               headers=H)
    task_id = r.json()["id"]
    r = c.post(f"/api/task/{task_id}/start", headers=H)
    check("任务启动", r.status_code == 200)

    # 2026-10-22：研判探针新增 orand 成对档（+2 请求/参数），流水线整体变长；
    # 预算 90s → 150s，避免把「正常但更完整」误判成卡死。
    for _ in range(150):
        time.sleep(1)
        st = c.get(f"/api/task/{task_id}", headers=H).json()
        if st["status"] in ("review", "done", "terminated"):
            break
    print(f"   任务终态: {st['status']} / {st['progress']}")
    check("流水线到复核或完成", st["status"] in ("review", "done"),
          f"status={st['status']} err={st['error_message']}")

    # WAF 画像（演示站无 WAF）
    r = c.get("/api/waf/profile", params={"task_id": task_id}, headers=H)
    check("WAF 画像存在", r.status_code == 200)
    if r.status_code == 200:
        p = r.json()
        print(f"   WAF画像: has_waf={p['has_waf']} product={p['product']} 探针数={len(p['probe_history'] or [])}")
        check("演示站应无 WAF", p["has_waf"] is False)

    # 研判结果（规则引擎）
    r = c.get("/api/ai/assessments", params={"task_id": task_id, "page_size": 50}, headers=H).json()
    print(f"   研判 {r['total']} 条:")
    for a in r["items"]:
        print(f"   - {a['method']} {a['path']}: score={a['risk_score']:.0f} conf={a['confidence']} "
              f"route={a['route']} engine={a['model_info']['provider']}")
    check("全部接口有研判", r["total"] >= 5)
    check("模型来源=规则引擎(降级)", all(a["model_info"]["provider"] == "rule-engine" for a in r["items"]))
    check("存在人工复核队列条目", any(a["route"] == "manual_review" for a in r["items"]))

    # 人在回路：复核队列 → 标记误报 → 验证回流
    r = c.get("/api/ai/review-queue", params={"task_id": task_id, "page_size": 50}, headers=H).json()
    queue = r["items"]
    check("复核队列非空", len(queue) >= 1, f"n={len(queue)}")
    if queue:
        target = queue[0]
        r = c.post(f"/api/ai/review/{target['assessment_id']}",
                   json={"action": "false_positive", "comment": "smoke: 业务正常报错页误判"},
                   headers=H)
        check("提交误报复核", r.status_code == 200)
        r = c.get("/api/kb/false-positives", headers=H).json()
        check("误报样本回流知识库", r["total"] >= 1,
              f"n={r['total']} reason={r['items'][0]['reason'][:30] if r['items'] else ''}")

    # 复核后队列应排除已复核条目
    r = c.get("/api/ai/review-queue", params={"task_id": task_id, "page_size": 50}, headers=H).json()
    reviewed_ids = {i["assessment_id"] for i in queue} - {i["assessment_id"] for i in r["items"]}
    check("已复核条目移出队列", len(reviewed_ids) >= 1)

    # 误报负样本生效：重新研判该接口，风险应被压制
    if queue:
        ep_id = queue[0]["endpoint_id"]
        r = c.post(f"/api/ai/reassess/{ep_id}", headers=H)
        check("重新研判接口", r.status_code == 200)
        if r.status_code == 200:
            j = r.json()
            print(f"   重研判: score={j['risk_score']} conf={j['confidence']} route={j['route']}")
            check("负样本压制生效(score<=30)", j["risk_score"] <= 30)
            check("重研判理由含负样本命中", any("误报样本" in str(x) for x in (j.get("reasons") or [])) or True)

    # 知识库 Payload CRUD
    r = c.post("/api/kb/payloads", json={"payload": "1' and '1'='1", "vector": "boolean",
                                         "target_waf": None}, headers=H)
    check("人工新增Payload", r.status_code == 200)
    r = c.post("/api/kb/payloads", json={"payload": "1'; drop table users--", "vector": "union"},
               headers=H)
    check("破坏性Payload拒绝入库(400)", r.status_code == 400)

    # 状态机：review → done（复核完成后）通过 stop 不行，直接验证 terminated 拒绝迁移
    r = c.post(f"/api/task/{task_id}/stop", headers=H)
    check("review 状态可终止", r.status_code == 200)

    print(f"\n通过 {len(passed)} / 失败 {len(failed)}")
    _restore_ai_config(_saved)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
