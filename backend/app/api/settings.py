# -*- coding: utf-8 -*-
"""系统设置路由：AI 接入配置（加密存储）、SQLMap 路径等。"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.system import Setting, User
from app.services import ai

router = APIRouter(prefix="/api/settings", tags=["settings"])


class SettingReq(BaseModel):
    key: str
    value: str
    is_secret: bool = False


class TestAIReq(BaseModel):
    # 未传的字段回退到已保存配置；传入则以请求值测试（不必先保存）
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None


@router.post("/test-ai")
def test_ai(req: TestAIReq | None = None, user: User = Depends(get_current_user),
            db: Session = Depends(get_db)):
    """AI 连通性测试：用当前/传入配置发一次最小 chat/completions 请求。

    返回 {ok, status, elapsed_ms, model, reply|error}；失败也返回 200，
    便于前端直接展示具体原因（405 / 404 / 鉴权失败 / 超时等）。
    """
    import time

    import httpx

    base = ((req.base_url if req and req.base_url else
             ai.get_setting(db, Setting.KEY_AI_BASE_URL)) or "").strip().rstrip("/")
    model = ((req.model if req and req.model else
              ai.get_setting(db, Setting.KEY_AI_MODEL)) or "").strip()
    key = ((req.api_key if req and req.api_key else
            ai.get_setting(db, Setting.KEY_AI_API_KEY, decrypt=True)) or "").strip()
    if not base or not model or not key:
        return {"ok": False, "error": "AI 未配置完整（base_url / api_key / model 都需要）",
                "base_url": base, "model": model}

    t0 = time.monotonic()
    try:
        resp = httpx.post(
            f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model,
                  "messages": [{"role": "user", "content": '只回复 JSON：{"ok":true}'}]},
            timeout=httpx.Timeout(connect=5.0, read=20.0, write=10.0, pool=5.0),
            trust_env=False,   # 不走系统代理：Windows 注册表代理关闭时会 10061 拒连
        )
    except Exception as exc:
        elapsed = int((time.monotonic() - t0) * 1000)
        log_action(db, user_id=user.id, action="ai_test", resource_type="setting",
                   detail={"ok": False, "error": type(exc).__name__, "model": model})
        db.commit()
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300],
                "base_url": base, "model": model, "elapsed_ms": elapsed,
                "hint": "检查 base_url 是否为 API 域名（不是网页控制台）、网络是否可达"}

    elapsed = int((time.monotonic() - t0) * 1000)
    if resp.status_code != 200:
        log_action(db, user_id=user.id, action="ai_test", resource_type="setting",
                   detail={"ok": False, "status": resp.status_code, "model": model})
        db.commit()
        return {"ok": False, "status": resp.status_code,
                "error": (resp.text or "")[:300], "base_url": base,
                "model": model, "elapsed_ms": elapsed,
                "hint": "405/404 通常是 base_url 写错；401/403 是 key 或权限问题"}
    try:
        data = resp.json()
        content = str(data["choices"][0]["message"]["content"])[:300]
    except Exception as exc:
        log_action(db, user_id=user.id, action="ai_test", resource_type="setting",
                   detail={"ok": False, "error": "bad response shape"})
        db.commit()
        return {"ok": False, "status": resp.status_code,
                "error": f"响应不是标准 chat/completions 格式: {exc}"[:300],
                "base_url": base, "model": model, "elapsed_ms": elapsed}
    log_action(db, user_id=user.id, action="ai_test", resource_type="setting",
               detail={"ok": True, "model": model, "elapsed_ms": elapsed})
    db.commit()
    return {"ok": True, "status": 200, "elapsed_ms": elapsed, "model": model,
            "reply": content, "base_url": base}


@router.get("")
def get_settings(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """返回全部设置；敏感项只返回是否已配置，不回显明文。"""
    rows = db.query(Setting).all()
    out = {}
    for r in rows:
        out[r.key] = "<configured>" if r.is_secret and r.value else (r.value or "")
    return {"items": out, "ai_configured": ai.ai_configured(db)}


@router.put("")
def put_settings(req: SettingReq, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    ai.set_setting(db, req.key, req.value, is_secret=req.is_secret, updated_by=user.id)
    log_action(db, user_id=user.id, action="config_change", resource_type="setting",
               resource_id=None, detail={"key": req.key, "secret": req.is_secret})
    db.commit()
    return {"ok": True, "ai_configured": ai.ai_configured(db)}
