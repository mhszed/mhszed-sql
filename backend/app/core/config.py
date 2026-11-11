# -*- coding: utf-8 -*-
"""全局配置：路径、数据库、安全密钥、默认参数。"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent   # backend/
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "scanner.db"
DB_URL = f"sqlite:///{DB_PATH}"

# ---- 安全密钥：首次启动生成，落盘 data/secret.key ----
SECRET_KEY_FILE = DATA_DIR / "secret.key"


def _load_or_create_secret() -> str:
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(key, encoding="utf-8")
    return key


SECRET_KEY = _load_or_create_secret()

# ---- 默认管理员（首次启动种子，登录后请改密）----
DEFAULT_ADMIN = {"username": "admin", "password": "admin123"}

# ---- 默认扫描参数（与 docs/02 scan_config 快照结构一致）----
DEFAULT_SCAN_CONFIG = {
    "intensity": "medium",
    # 仅测试目标 URL 所在目录及其子目录（采集仍可全站；与 intensity 正交）。
    "scope_only_current_dir": False,
    "max_concurrency": 3,
    "rate_limit_qps": 1.0,
    "circuit_breaker": {
        "error_rate_threshold": 0.3,
        "waf_block_rate_threshold": 0.5,
        "window_seconds": 60,
        "cooldown_seconds": 300,
    },
    "engines": {"sqlmap_enabled": True, "ai_probe_enabled": True},
    "max_pipeline_rounds": 2,
    # 深入利用整轮总预算（秒）：防止布尔/时间盲注在限流目标上无限施压。
    # 达到预算/连续连接失败都会主动停止。时间盲注逐字符 sleep，900s 只够读短值。
    "deep_total_budget_s": 1800,
    # 盲注分子任务硬预算（秒）：库名 / 表枚举 / 脱裤各一段，均可被总预算截断。
    "deep_blind_db_budget_s": 600,
    "deep_blind_tables_budget_s": 600,
    "deep_blind_dump_budget_s": 900,
    # sqlmap 盲注并行线程（时间盲注逐字符推断可并行；初筛仍固定 1 线程）。
    "deep_sqlmap_threads": 4,
    # 轻量盲注提取当前库名（默认关闭）：实测会把 library 读成 lihrary、
    # challenges 读成 challdnges，误读会直接满足 goal=schema 并停止，
    # 产生错误结论。需要极速探测时再显式开启，并自行复核。
    "deep_use_blind_extract": False,
    "write_endpoint_protection": True,
    # 写接口深度注入测试（INSERT/UPDATE 型需要 --risk≥2）：默认关闭，
    # 开启后会真正执行写语句 —— 仅限靶场/数据可牺牲的授权目标。
    "write_deep_probe": False,
    "bypass_strategies": ["case_mix", "comment_split", "encoding", "whitespace",
                          "space_comment"],
    "time_based_max_delay_s": 5,
}

# ---- 限速默认值（写接口更保守）----
DEFAULT_QPS_READ = 1.0
DEFAULT_QPS_WRITE = 0.3

# ---- 人在回路分级阈值 ----
AI_CONFIDENCE_AUTO = 0.9        # >= 自动通过
AI_CONFIDENCE_MANUAL = 0.6      # 0.6~0.9 人工复核；<0.6 存疑转深测

# ---- 流水线上限 ----
MAX_PIPELINE_ROUNDS = 2

# ---- 审计链式哈希 ----
AUDIT_CHAIN_HASH = True

# ---- SSE 心跳间隔（秒）----
SSE_HEARTBEAT = 15
