# -*- coding: utf-8 -*-
"""一次性数据清理：合并重复的授权范围与知识库 Payload。

用法（在 backend 目录）：
    venv\\Scripts\\python scripts\\dedupe_records.py            # 只预览
    venv\\Scripts\\python scripts\\dedupe_records.py --apply    # 实际写入

策略：
- auth_scopes：同 scope_type + 归一化 scope_value 视为重复；保留记录最完整的一条，
  合并 note/expires_at，其余软删除。
- kb_payloads：同 payload + vector + target_waf 视为重复；保留 success_count 最高
  （并列取最早）的一条，合并 success_count/use_count，其余软删除。
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal  # noqa: E402
from app.models.auth import AuthScope  # noqa: E402
from app.models.base import utcnow_iso  # noqa: E402
from app.models.kb import KbPayload  # noqa: E402
from app.services.knowledge import payload_signature  # noqa: E402


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def dedupe_scopes(db, apply: bool) -> int:
    rows = (db.query(AuthScope).filter(AuthScope.deleted_at.is_(None))
            .order_by(AuthScope.id).all())
    groups: dict[tuple[str, str], list[AuthScope]] = {}
    for r in rows:
        groups.setdefault((r.scope_type, _norm(r.scope_value)), []).append(r)
    merged = 0
    for (stype, value), items in groups.items():
        if len(items) < 2:
            continue
        items.sort(key=lambda r: (-(1 if r.note else 0), -(1 if r.expires_at else 0), r.id))
        keep = items[0]
        for dup in items[1:]:
            keep.note = keep.note or dup.note
            keep.expires_at = keep.expires_at or dup.expires_at
            dup.deleted_at = utcnow_iso()
            merged += 1
        print(f"[scope] keep #{keep.id} {stype}:{value} ← 删除 {[i.id for i in items[1:]]}")
    if apply:
        db.commit()
    return merged


def dedupe_payloads(db, apply: bool) -> int:
    rows = (db.query(KbPayload).filter(KbPayload.deleted_at.is_(None))
            .order_by(KbPayload.id).all())
    groups: dict[tuple[str, str, str | None], list[KbPayload]] = {}
    for r in rows:
        # 结构签名：数字字面量不同的同型 payload（46=46 / 44=44 / …）合并为一条
        groups.setdefault((payload_signature(r.payload), r.vector, r.target_waf), []).append(r)
    merged = 0
    for (payload, vector, waf), items in groups.items():
        if len(items) < 2:
            continue
        items.sort(key=lambda r: (-(r.success_count or 0), r.id))
        keep = items[0]
        for dup in items[1:]:
            keep.success_count = (keep.success_count or 0) + (dup.success_count or 0)
            keep.use_count = (keep.use_count or 0) + (dup.use_count or 0)
            keep.is_active = max(keep.is_active or 0, dup.is_active or 0)
            dup.deleted_at = utcnow_iso()
            merged += 1
        print(f"[payload] keep #{keep.id} {vector}/{waf or '通用'} "
              f"{payload[:50]!r} ← 删除 {[i.id for i in items[1:]]}")
    if apply:
        db.commit()
    return merged


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际写入（默认只预览）")
    args = ap.parse_args()
    db = SessionLocal()
    try:
        scopes = dedupe_scopes(db, args.apply)
        payloads = dedupe_payloads(db, args.apply)
        print(f"完成：范围重复 {scopes} 条，Payload 重复 {payloads} 条"
              f"{'（已写入）' if args.apply else '（预览，未写入）'}")
        if not args.apply:
            db.rollback()
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
