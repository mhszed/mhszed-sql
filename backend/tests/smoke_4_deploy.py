# -*- coding: utf-8 -*-
"""冒烟测试 4：部署自检 —— sqlmap 内置解析 + 交付物完整性。

不依赖 8787/8899 服务（离线可跑），验证其他用户拿到项目目录后开箱即用：
  1. 内置 sqlmap 存在且可独立运行
  2. find_sqlmap() 解析顺序正确（settings > 内置 > PATH）
  3. settings 显式配置优先于内置
  4. 交付物齐全（requirements.txt / 前端构建产物 / 数据目录 / 演示靶站）

运行：venv/Scripts/python tests/smoke_4_deploy.py
"""
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent.parent          # backend/
PROJECT = BASE_DIR.parent                                   # mhszed-sql/

sys.path.insert(0, str(BASE_DIR))

passed, failed = [], []


def check(name: str, cond: bool, extra: str = ""):
    (passed if cond else failed).append(f"{name} {extra}")
    print(f"{'✅' if cond else '❌'} {name} {extra}")


def main():
    # ---------- 1. 内置 sqlmap ----------
    bundled = PROJECT / "tools" / "sqlmap" / "sqlmap.py"
    check("内置 sqlmap 文件存在", bundled.exists(), str(bundled.relative_to(PROJECT)))

    r = subprocess.run([sys.executable, str(bundled), "--version"],
                       capture_output=True, text=True, timeout=60)
    ver = (r.stdout or r.stderr or "").strip().splitlines()[0] if (r.stdout or r.stderr) else ""
    check("内置 sqlmap 可独立运行", r.returncode == 0 and ver != "", f"version={ver}")

    # ---------- 2. find_sqlmap 解析顺序 ----------
    from sqlmap_adapter import runner
    from app.core.database import SessionLocal
    from app.services.ai import set_setting, get_setting
    from app.models.system import Setting

    db = SessionLocal()
    try:
        # 清空显式配置 → 应命中内置
        set_setting(db, Setting.KEY_SQLMAP_PATH, "", updated_by=1)
        db.commit()
        found = runner.find_sqlmap()
        check("无配置时命中项目内置", bool(found) and found != "__pymodule____"
              and "tools" in (found or "") and "sqlmap" in (found or ""), f"{found}")

        # 显式配置一个真实脚本 → 应优先返回配置
        set_setting(db, Setting.KEY_SQLMAP_PATH, str(bundled), updated_by=1)
        db.commit()
        found2 = runner.find_sqlmap()
        check("settings 显式配置优先", found2 == str(bundled), f"{found2}")

        # 配置不存在路径 → 应回退内置
        set_setting(db, Setting.KEY_SQLMAP_PATH, "D:/not/exist/sqlmap.exe", updated_by=1)
        db.commit()
        found3 = runner.find_sqlmap()
        check("配置路径失效时回退内置", bool(found3) and found3 == str(bundled), f"{found3}")

        # 清理：还原为未配置状态
        set_setting(db, Setting.KEY_SQLMAP_PATH, "", updated_by=1)
        db.commit()
        check("清理测试配置", get_setting(db, Setting.KEY_SQLMAP_PATH) == "")
    finally:
        db.close()

    # ---------- 3. 交付物完整性 ----------
    check("requirements.txt 存在", (BASE_DIR / "requirements.txt").exists())
    check("前端构建产物存在", (PROJECT / "frontend" / "dist" / "index.html").exists())
    check("演示靶站存在", (BASE_DIR / "tests" / "demo_site.py").exists())
    check("架构文档存在", (PROJECT / "docs" / "01-架构设计.md").exists())
    check("数据库设计文档存在", (PROJECT / "docs" / "02-数据库设计.md").exists())

    # 关键 Python 依赖可导入（requirements 已装的证据）
    deps = {}
    for mod, pkg in [("fastapi", "fastapi"), ("uvicorn", "uvicorn"),
                     ("sqlalchemy", "sqlalchemy"), ("httpx", "httpx"),
                     ("bs4", "beautifulsoup4"), ("fpdf", "fpdf2"),
                     ("cryptography", "cryptography")]:
        try:
            __import__(mod)
            deps[pkg] = True
        except ImportError:
            deps[pkg] = False
    missing = [k for k, v in deps.items() if not v]
    check("后端依赖全部可导入", not missing, f"缺: {missing}" if missing else "7/7")

    print()
    print(f"通过 {len(passed)} / 失败 {len(failed)}")
    if failed:
        print("失败项:")
        for f in failed:
            print("  -", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
