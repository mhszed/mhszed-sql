# -*- coding: utf-8 -*-
"""安全组件：口令哈希、令牌签发校验、敏感配置 AES 加密、写接口保护黑名单。"""
import base64
import hashlib
import hmac
import json
import re
import time

from cryptography.fernet import Fernet

from app.core import config

# ============ 口令哈希（PBKDF2-HMAC-SHA256，无第三方依赖） ============

def hash_password(password: str) -> str:
    salt = hashlib.sha256((password + config.SECRET_KEY).encode()).digest()[:16]
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ============ 令牌（HMAC 签名，无状态） ============

_TOKEN_TTL = 12 * 3600


def create_token(user_id: int, username: str, role: str) -> str:
    payload = {"uid": user_id, "uname": username, "role": role, "exp": int(time.time()) + _TOKEN_TTL}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(config.SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str) -> dict | None:
    """校验通过返回 payload dict，失败返回 None。"""
    try:
        body, sig = token.rsplit(".", 1)
        expect = hmac.new(config.SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ============ 敏感配置加密（Fernet AES） ============

_fernet = Fernet(base64.urlsafe_b64encode(
    hashlib.sha256(("settings:" + config.SECRET_KEY).encode()).digest()))


def encrypt_value(plain: str) -> str:
    return _fernet.encrypt(plain.encode()).decode()


def decrypt_value(cipher: str) -> str:
    try:
        return _fernet.decrypt(cipher.encode()).decode()
    except Exception:
        return ""


# ============ 写接口保护：破坏性 SQL 语句黑名单 ============
# 写接口的注入探测只允许盲注判据（布尔/时间），凡含下列语句直接拒绝——
# 该检查在 HTTP 客户端层强制执行，不依赖调用方自觉。

DESTRUCTIVE_SQL_PATTERN = re.compile(
    r"(?:\b)(?:drop|delete|truncate|update|insert|replace|alter|create|grant|revoke|shutdown|rename|call|exec)\b"
    r"[\s\S]{0,40}?(?:\b(?:table|database|schema|from|into|set|user|users|index|view)\b|@|@@|`)",
    re.IGNORECASE,
)

# 允许出现在写接口探测 payload 里的判据特征（白名单思路：只放行盲注判据语义）
BLIND_CRITERIA_HINTS = ("sleep", "benchmark", "if(", "case when", "and 1=", "and '1'='1",
                        "' and '", "\" and \"", "||", "&&", "substr", "substring", "mid(", "ascii(")


def is_destructive_payload(payload: str) -> bool:
    """返回 True 表示 payload 含破坏性语句，必须拦截。"""
    if DESTRUCTIVE_SQL_PATTERN.search(payload):
        # sleep/benchmark 前若紧跟 delete 等语句仍拦截；黑名单命中即拒绝
        return True
    return False
