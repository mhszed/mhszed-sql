# -*- coding: utf-8 -*-
"""认证路由：登录 / 登出 / 当前用户信息。"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import create_token, hash_password, verify_password
from app.models.base import utcnow_iso
from app.models.system import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginReq(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(req: LoginReq, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.password_hash):
        # 审计：失败登录也记录
        log_action(db, user_id=user.id if user else None, action="login",
                   detail={"ok": False, "username": req.username})
        db.commit()
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    if not user.is_active or user.is_deleted:
        raise HTTPException(status_code=403, detail="账户已禁用")

    user.last_login_at = user.updated_at
    log_action(db, user_id=user.id, action="login", resource_type="user", resource_id=user.id,
               detail={"ok": True})
    db.commit()
    token = create_token(user.id, user.username, user.role)
    return {"token": token, "username": user.username, "role": user.role}


@router.post("/logout")
def logout(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    log_action(db, user_id=user.id, action="logout", resource_type="user", resource_id=user.id)
    db.commit()
    return {"ok": True}


class ChangePasswordReq(BaseModel):
    current_password: str
    new_password: str = Field(min_length=6, max_length=128)


@router.post("/change-password")
def change_password(req: ChangePasswordReq, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """当前登录用户自助修改密码（管理员同样走这里）。"""
    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="当前密码不正确")
    if req.current_password == req.new_password:
        raise HTTPException(status_code=400, detail="新密码不能与当前密码相同")
    user.password_hash = hash_password(req.new_password)
    user.updated_at = utcnow_iso()
    log_action(db, user_id=user.id, action="password_change", resource_type="user",
               resource_id=user.id, detail={"username": user.username})
    db.commit()
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}
