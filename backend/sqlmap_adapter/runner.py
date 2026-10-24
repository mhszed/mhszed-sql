# -*- coding: utf-8 -*-
"""SQLMap 进程适配器：subprocess 调用、参数隔离、超时强杀、输出解析、状态管理。

安全设计：
  - args 列表传参，绝不 shell=True（参数隔离）
  - 每个扫描子任务独立输出目录（--output-dir），互不污染
  - PID 登记 + 超时 taskkill /T /F 强杀进程树；任务终止时由调度器统一回收
  - 写接口限制 --technique=BET（布尔/报错/时间），禁 UNION 脱数、禁堆叠查询
"""
import functools
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from app.core import config
from app.services.event_bus import bus

# 进程登记表：job_id -> {"proc": Popen, "started": ts}
_PROCESSES: dict = {}
_lock = threading.Lock()

# 同 host 串行化：2026-10-18 实测，深挖与扫描并发时两个 sqlmap 同时打同一靶机，
# 直接把目标打到连接超时（"靶场老是崩"的真实原因）。按 netloc（含端口）串行。
_HOST_LOCKS: dict[str, threading.Lock] = {}
_HOST_LOCKS_GUARD = threading.Lock()
_MAX_HOST_WAIT_S = 600

# sqlmap 请求间隔（秒）。rate_limit_qps 只约束 SafeHttpClient，管不到 sqlmap 进程；
# 不加 --delay 时 sqlmap 识别注入点后会连续测试所有 DBMS 技法，把靶机打崩。
_SQLMAP_DELAY_S = "0.5"

# 连续连接失败阈值：达到即主动终止 sqlmap。
# 2026-10-22 实测 hbc2:33549：目标进入 SYN_SENT 后 sqlmap 仍按 --retries 3 反复重试，
# 深挖的 tables 步硬等满 900s，继续对已不可达的目标施压。实战中这会把目标彻底打挂。
_CONN_FAIL_ABORT = 4
_RE_CONN_FAIL = re.compile(
    r"connection timed out to the target URL|unable to connect to the target URL|"
    r"failed to connect to the target URL|connection refused|no route to host",
    re.I)
# 有真实产出即清零失败计数，避免长扫描里偶发超时累积误杀。
_RE_PROGRESS = re.compile(
    r"\[info\] (?:retrieved|fetching|fetched data)|appears to be .*injectable|"
    r"identified the following injection point|back-end dbms:", re.I)


def _host_of(url: str) -> str:
    try:
        return urlparse(url or "").netloc or "unknown"
    except Exception:
        return "unknown"


def _host_lock(url: str) -> threading.Lock:
    netloc = _host_of(url)
    with _HOST_LOCKS_GUARD:
        return _HOST_LOCKS.setdefault(netloc, threading.Lock())


def _serialized_per_host(func):
    """同一 host 同时只允许一个 sqlmap 进程（等锁最多 600s，超时返回 error）。"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        url = kwargs.get("url") or (args[0] if args else "")
        lock = _host_lock(str(url))
        if not lock.acquire(timeout=_MAX_HOST_WAIT_S):
            return {"status": "error", "result_class": "error", "dbms": None,
                    "output_tail": "同 host 已有 sqlmap 任务在运行，等待超时后放弃",
                    "payload": None, "pid": None, "exit_code": -1,
                    "duration_ms": 0, "full_output": "", "findings": {}}
        try:
            return func(*args, **kwargs)
        finally:
            lock.release()
    return wrapper

# 强度 → sqlmap level/risk
# 说明：level=1 容易漏掉双引号布尔上下文（如 id=1" and "1"="1）；
# 好靶场这类题目至少需要 level=2。low 也抬到 2，避免默认漏报。
_INTENSITY_MAP = {
    "low": ("--level=2", "--risk=1"),
    "medium": ("--level=2", "--risk=1"),
    "high": ("--level=3", "--risk=2"),
}


# 项目内置 sqlmap（tools/sqlmap/sqlmap.py），随项目分发，用户无需另行安装
_BUNDLED_SQLMAP = config.BASE_DIR.parent / "tools" / "sqlmap" / "sqlmap.py"


def find_sqlmap() -> str | None:
    """定位 sqlmap：settings 显式配置 > 项目内置 tools/sqlmap > PATH > python -m sqlmap。"""
    from app.core.database import SessionLocal
    from app.services.ai import get_setting
    from app.models.system import Setting
    db = SessionLocal()
    try:
        configured = get_setting(db, Setting.KEY_SQLMAP_PATH)
    finally:
        db.close()
    if configured and Path(configured).exists():
        return configured
    if _BUNDLED_SQLMAP.exists():
        return str(_BUNDLED_SQLMAP)
    which = shutil.which("sqlmap")
    if which:
        return which
    return "__pymodule__"        # 用 python -m sqlmap


def kill_all():
    """任务终止时回收全部登记进程。"""
    with _lock:
        procs = list(_PROCESSES.values())
        _PROCESSES.clear()
    for entry in procs:
        _kill_tree(entry["proc"])


def _target_env() -> dict:
    """sqlmap 子进程绕过代理。

    sqlmap 用 urllib 的 ProxyHandler()，会读 **Windows 系统代理**（注册表），
    只删环境变量不够；NO_PROXY=* 会让 urllib 对所有 host 走 bypass。
    """
    env = os.environ.copy()
    for k in list(env):
        if k.lower() in ("http_proxy", "https_proxy", "all_proxy"):
            env.pop(k, None)
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


def _kill_tree(proc):
    try:
        if proc.poll() is None:
            if os.name == "nt":
                # taskkill 必须带超时：杀进程树偶发挂起（曾致调用方永久卡死）
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                               capture_output=True, timeout=10)
            else:
                proc.kill()
    except Exception:
        pass


# 深入利用允许的 sqlmap 参数白名单（禁止 os-shell / file-write 等）
_ALLOWED_EXTRA = {
    "--dbs", "--tables", "--columns", "--dump", "--banner", "--current-db",
    "--current-user", "--hostname", "--schema", "--exclude-sysdbs",
    "--threads", "--technique", "--dbms", "--prefix", "--suffix", "--tamper",
    "--start", "--stop", "--first", "--last", "--count", "--sql-query",
    "--string", "--not-string", "--code",
    "--no-cast", "--hex", "--fresh-queries", "-D", "-T", "-C", "-p",
}

# --tamper 值白名单：只允许项目自带/确认安全的脚本，杜绝任意 py 加载。
_ALLOWED_TAMPERS = {"space2slash", "space2comment", "doublekeywords", "orand"}


# ---- `--dbms` 值归一（2026-10-15 Less-12 深入利用实测）----
# sqlmap 的 `--dbms` **确实支持带版本**，但它自己的解析正则（lib/core/option.py `_setDBMS`）是
#   re.search(r"(MySQL|SQLite|…) ([\d\.]+)", value)
# ——库名后**必须紧跟纯数字**。而 sqlmap 自己指纹输出的格式是 `MySQL >= 5.0.12`（带比较运算符），
# 那个 `>=` 让正则匹配不上，整串于是被拿去和 SUPPORTED_DBMS 逐个比对 → 不匹配 →
#   [CRITICAL] you provided an unsupported back-end database management system
# 并**零执行退出**（实测 job#55：exit_code=1，一个请求都没发）。
# 归一策略：认出库名后**丢掉版本号**——sqlmap 随后会自己指纹版本，多给反而可能给错。
# 认不出 → 返回 None，调用方须**把 `--dbms` 整对丢弃**：不传远好过传错。
_DBMS_CANON = (
    ("microsoft sql server", "Microsoft SQL Server"),
    ("microsoft access", "Microsoft Access"),
    # 长名在前：词边界判据下 `postgres` 匹配不到 `postgresql`（后面还跟着字母）
    ("postgresql", "PostgreSQL"),
    ("postgres", "PostgreSQL"), ("pgsql", "PostgreSQL"),
    ("mariadb", "MySQL"), ("mysql", "MySQL"),
    ("oracle", "Oracle"), ("sqlite", "SQLite"),
    ("cockroach", "CockroachDB"), ("clickhouse", "ClickHouse"),
    ("enterprisedb", "EnterpriseDB"), ("greenplum", "Greenplum"),
    ("yugabyte", "YugabyteDB"), ("virtuoso", "Virtuoso"),
    ("informix", "Informix"), ("firebird", "Firebird"),
    ("altibase", "Altibase"), ("monetdb", "MonetDB"),
    ("presto", "Presto"), ("sybase", "Sybase"), ("percona", "Percona"),
    ("vertica", "Vertica"), ("derby", "Apache Derby"),
    ("hsqldb", "HSQLDB"), ("tidb", "TiDB"), ("db2", "IBM DB2"),
    ("mssql", "Microsoft SQL Server"), ("aurora", "Aurora"), ("h2", "H2"),
)


def normalize_dbms(value) -> str | None:
    """把 sqlmap 指纹串（`MySQL >= 5.0.12`）归一成 `--dbms` 能接受的值（`MySQL`）。

    认不出库名 → 返回 None（调用方须整对丢弃，不可原样传给 sqlmap）。
    """
    if not value:
        return None
    s = re.sub(r"\s*(>=|<=|!=|<>|>|<|=)\s*", " ", str(value)).strip().lower()
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    for needle, canon in _DBMS_CANON:
        if re.search(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", s):
            return canon
    return None


def _sanitize_extra_args(extra_args: list[str] | None) -> list[str]:
    """白名单过滤；强制 dump 行数上限 --stop<=5。"""
    if not extra_args:
        return []
    out: list[str] = []
    i = 0
    stop_forced = False
    while i < len(extra_args):
        tok = str(extra_args[i])
        # 禁止破坏性开关
        low = tok.lower()
        if any(x in low for x in ("os-shell", "os-cmd", "sql-shell", "file-write",
                                  "file-read", "udf-", "priv-esc", "tor", "crawl")):
            i += 1
            continue
        key = tok.split("=")[0]
        if key not in _ALLOWED_EXTRA and not key.startswith("--"):
            # 允许作为 -D/-T 的值
            if out and out[-1] in ("-D", "-T", "-C", "-p", "--dbms", "--technique",
                                   "--start", "--stop", "--first", "--last", "--sql-query"):
                out.append(tok)
            i += 1
            continue
        if key not in _ALLOWED_EXTRA:
            i += 1
            continue
        if key == "--dbms":
            # 值必须归一（见 normalize_dbms）；归一失败就**整对丢弃**——
            # 传一个 sqlmap 不认的值会让它 [CRITICAL] 零执行，比不传糟得多。
            raw = tok.split("=", 1)[1] if "=" in tok else None
            if raw is None and i + 1 < len(extra_args) and \
                    str(extra_args[i + 1]).split("=")[0] not in _ALLOWED_EXTRA:
                raw = str(extra_args[i + 1])
                i += 1
            norm = normalize_dbms(raw)
            if norm:
                out += ["--dbms", norm]
            i += 1
            continue
        if key == "--tamper":
            # 值必须在白名单内（防止任意 .py 被 sqlmap 加载）
            raw = tok.split("=", 1)[1] if "=" in tok else None
            if raw is None and i + 1 < len(extra_args) and \
                    str(extra_args[i + 1]).split("=")[0] not in _ALLOWED_EXTRA:
                raw = str(extra_args[i + 1])
                i += 1
            names = [t.strip().lower() for t in (raw or "").split(",") if t.strip()]
            safe = [t for t in names if t in _ALLOWED_TAMPERS]
            if safe:
                out += ["--tamper", ",".join(safe)]
            i += 1
            continue
        out.append(tok)
        # 吃掉紧随的值参数
        if key in ("-D", "-T", "-C", "-p", "--dbms", "--technique",
                   "--start", "--stop", "--first", "--last", "--sql-query",
                   "--threads", "--string", "--not-string", "--code",
                   "--prefix", "--suffix"):
            # 注意：值本身**可能以 `-` 开头**（最典型的是 MySQL 注释后缀 `-- -`）。
            # 旧写法 `not startswith("-")` 会把它当成"没有值"直接丢弃，
            # 于是 sqlmap 收到 `--suffix --technique` 这种错配（实测 Less-12 深入利用）。
            # 新判据：只有当下一 token **本身是已知选项键**时才视为缺值。
            if i + 1 < len(extra_args) and str(extra_args[i + 1]).split("=")[0] not in _ALLOWED_EXTRA:
                val = str(extra_args[i + 1])
                if key == "--stop":
                    try:
                        val = str(min(5, max(1, int(val))))
                    except ValueError:
                        val = "5"
                    stop_forced = True
                out.append(val)
                i += 1
        i += 1
    if any(a == "--dump" or a.startswith("--dump") for a in out) and not stop_forced:
        out += ["--start", "1", "--stop", "5"]
    return out


@_serialized_per_host
def _exploit_produced(output: str) -> bool:
    """利用模式是否真的产出了战果。

    ⚠️ 不能把 sqlmap 恢复 session 时打印的 `current database:` / `Database:` 当战果：
    2026-10-22 hbc2 job#13 只恢复了会话、随后连接超时、一张表都没拿到，
    却因这两行被判 exploit_ok（假成功）。只认数据类标记。
    """
    low = (output or "").lower()
    return bool(re.search(r"available databases|\[\d+\s+tables?\]|"
                          r"\[info\] retrieved:|\[info\] fetched data|"
                          r"current user:", low))


def run_sqlmap(*, job_id: int, url: str, method: str = "GET", data: str | None = None,
               param: str | None = None, is_write: bool = False,
               intensity: str = "medium", timeout_s: int = 180,
               extra_args: list[str] | None = None,
               exploit_mode: bool = False,
               dbms_hint: str | None = None,
               out_dir_key: str | None = None) -> dict:
    """执行一次 SQLMap 扫描/利用。返回 {status, result_class, dbms, output_tail, ...}。

    exploit_mode=True：已知可注，追加白名单 extra_args（--dbs/--tables/--dump…），
    技术默认仅 B（布尔），避免再跑完整探测矩阵。
    """
    # out_dir_key：同一漏洞的深挖多步共用同一 output-dir → sqlmap 的
    # session.sqlite 复用已识别注入点，避免每一步都重新指纹（420s 预算被重复烧掉）。
    out_dir = Path(config.DATA_DIR) / "sqlmap" / (out_dir_key or f"job_{job_id}")
    out_dir.mkdir(parents=True, exist_ok=True)

    level, risk = _INTENSITY_MAP.get(intensity, _INTENSITY_MAP["medium"])
    sqlmap = find_sqlmap()

    args = ["--batch", "-u", url,
            "--output-dir", str(out_dir),
            "--threads", "1", "--timeout", "15", "--retries", "3",
            "--delay", _SQLMAP_DELAY_S,
            # 部分靶场/站点对 sqlmap 默认 UA 直接丢连接；随机 UA 是常规做法
            "--random-agent"]
    if not exploit_mode:
        args += ["--flush-session", level, risk]
    if method.upper() != "GET" and data:
        args += ["--method", method.upper(), "--data", data]
    if param:
        args += ["-p", param]
    if exploit_mode:
        # 已知可注：仍带 level，避免启发式误判直接放弃。
        # 默认 B+E（布尔+报错）：旧写法只给 B，对**报错型靶点**（如 Less-12 `")`）
        # 等于先把 E 关掉，sqlmap 连试都不试 —— 实测深入利用因此全线不可注入。
        # AI 若在 extra_args 里显式给 --technique 则以后者为准。
        args += [level, risk]
        if not any(a == "--technique" or a.startswith("--technique=") for a in (extra_args or [])):
            args += ["--technique=BE"]
        args += _sanitize_extra_args(extra_args)
    else:
        # 初筛必须含 UNION：medium=BEU，high=BEUSTQ；写接口仍限制 BET
        if is_write:
            args += ["--technique=BET"]
        elif intensity == "high":
            args += ["--technique=BEUSTQ"]
        else:
            args += ["--technique=BEU"]
        args += _sanitize_extra_args(extra_args)
    if dbms_hint and "--dbms" not in args:
        # 复用归一器：dbms_hint 既可能是裸库名（"sqlite"），也可能带版本
        # （"MySQL >= 5.0"，sqlmap 指纹原样回灌）——旧白名单只认裸名，带版本的会被静默丢弃。
        hint = normalize_dbms(dbms_hint)
        if hint:
            args += ["--dbms", hint]

    import sys
    if sqlmap == "__pymodule__":
        cmd = [sys.executable, "-m", "sqlmap"] + args
    elif sqlmap.endswith(".py"):
        cmd = [sys.executable, sqlmap] + args
    else:
        cmd = [sqlmap] + args

    bus.publish("scan", f"[sqlmap] 启动: {' '.join(args[:6])}…")
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace",
                                env=_target_env())
    except FileNotFoundError as exc:
        return {"status": "error", "result_class": "error", "dbms": None,
                "output_tail": f"sqlmap 不可用: {exc}", "pid": None, "exit_code": -1,
                "duration_ms": 0, "full_output": ""}

    with _lock:
        _PROCESSES[job_id] = {"proc": proc, "started": t0}

    # 关键：不能先阻塞读完 stdout 再 wait(timeout)——sqlmap 长时间跑时超时永远不触发。
    output_lines: list[str] = []
    status = "finished"
    rc = None
    conn_fail = 0
    aborted_unreachable = False

    def _reader():
        nonlocal conn_fail, aborted_unreachable
        try:
            for line in proc.stdout:
                output_lines.append(line.rstrip())
                if len(output_lines) > 6000:
                    output_lines.pop(0)
                # 连续连接失败 → 目标大概率已不可达/被限流，主动杀掉，绝不死等超时。
                if _RE_CONN_FAIL.search(line):
                    conn_fail += 1
                    if conn_fail >= _CONN_FAIL_ABORT:
                        aborted_unreachable = True
                        _kill_tree(proc)
                        break
                elif _RE_PROGRESS.search(line):
                    conn_fail = 0
        except Exception:
            pass

    reader = threading.Thread(target=_reader, name=f"sqlmap-reader-{job_id}", daemon=True)
    reader.start()
    reader.join(timeout=timeout_s)
    if aborted_unreachable:
        status = "unreachable"
        _kill_tree(proc)
        reader.join(timeout=5)
        bus.publish("scan", f"[sqlmap] job#{job_id} 连续 {conn_fail} 次连接失败，"
                            f"主动终止（保护目标）", level="warn")
    elif reader.is_alive():
        # 真超时：reader 还在等输出（进程树仍在跑）→ 强杀进程树，再等读者退出
        _kill_tree(proc)
        status = "timeout"
        reader.join(timeout=8)
    # EOF 只说明子解释器关了 stdout：Windows 下 venv python.exe 是启动器，
    # 其退出比真实解释器晚若干毫秒，立即 poll() 会撞上"假存活"窗口，
    # 把正常完成的扫描误杀并误分类为 timeout（曾致 smoke_3 全线 sqlmap 假超时）。
    # 先限时等待真实退出，仍不退才是真僵死。
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        status = "timeout"
        try:
            rc = proc.wait(timeout=5)
        except Exception:
            rc = None
    finally:
        with _lock:
            _PROCESSES.pop(job_id, None)

    full_output = "\n".join(output_lines)
    output = "\n".join(output_lines[-300:])
    duration = int((time.monotonic() - t0) * 1000)

    findings = parse_findings(full_output)   # 超时也不丢已产出的判定

    if status == "unreachable":
        # 连续连接失败主动终止：不再往下做利用/判定分类，交由上层停止整条流水线。
        result_class = "unreachable"
    elif status == "timeout":
        # 超时被掐死前 sqlmap 可能已明确识别出注入点（"identified the following
        # injection point(s)"）——实测 25793 job#130：q 参数已判 boolean-based blind
        # 并带 payload，却因整个 job 超时被判 timeout，漏洞产出为 0。
        # 判定性证据不能随超时丢弃：有注入点块就升级为 vuln_confirmed（仅探测模式）。
        result_class = ("vuln_confirmed"
                        if not exploit_mode and _has_identified_injection(full_output, findings)
                        else "timeout")
    elif exploit_mode:
        # 利用模式：有库名/表名/dump 输出即成功。
        # ⚠️ 不能只看"有没有输出" —— sqlmap 的**错误横幅也是输出**。
        # 实测 job#55：`--dbms` 值不被支持 → `[CRITICAL] you provided an unsupported
        # back-end database management system` + exit_code=1 + 零请求，却被判 exploit_ok
        # （假成功；AI 侧读 tail 反而看懂了，是分类层把它盖住了）。
        # 判据：出现致命标记 **且** 没有产出任何利用结果 → error。
        low = output.lower()
        _fatal = ("[critical]" in low
                  or bool(re.search(r"unhandled exception|connection refused|"
                                    r"failed to connect|unable to connect", low)))
        _produced = _exploit_produced(output)
        if _fatal and not _produced:
            result_class = "error"
        elif output.strip():
            result_class = "exploit_ok"
        else:
            result_class = "inconclusive"
    else:
        result_class = parse_result_class(output, rc)

    dbms = _extract_dbms(full_output)
    bus.publish("scan", f"[sqlmap] job#{job_id} 结束: {result_class}"
                        f"{' dbms=' + dbms if dbms else ''} 耗时 {duration}ms",
                level="success" if result_class in ("vuln_confirmed", "exploit_ok") else "info")
    return {"status": status, "result_class": result_class, "dbms": dbms,
            "unreachable": status == "unreachable",
            "payload": _extract_payload(full_output) if result_class == "vuln_confirmed" else None,
            "output_tail": output[-4000:], "full_output": full_output[-12000:],
            "findings": findings,
            "pid": proc.pid, "exit_code": rc, "duration_ms": duration}


# ============ 输出解析 ============

# 精确的 WAF 命中特征（不能裸匹配 "waf" —— sqlmap 的常规建议文本里就有 "e.g. WAF"）
_RE_WAF = re.compile(
    r"waf/ips|ips/ids|has blocked a previous request|target is protected|"
    r"target appears to be protected", re.IGNORECASE)

# ---- 结构化判定解析（证据链路：sqlmap → AI，2026-10-15）----
# 50590 实测：sqlmap 已判「ORDER BY 可用 + 6 列 + SQLite」，但旧链路只存
# output_tail[-1500:] 再喂 [-1200:]，关键行被切碎，AI 只看到 "unable to connect" 噪音。
# parse_findings 从完整输出抽判定字段；summarize_for_ai 按「关键行优先 + 少量原始尾部」
# 重组，保证掐死在超时前已产出的判断一条不丢。

_RE_TECHNIQUE_USABLE = re.compile(r"'([^']+)' technique appears to be usable", re.I)
_RE_COLUMNS_IN_QUERY = re.compile(r"target URL appears to have (\d+) columns? in query", re.I)
_RE_PARAM_BLOCK = re.compile(
    r"^Parameter:\s*(?P<name>[^\s(]+)(?:\s*\((?P<loc>[^)]+)\))?\s*$"
    r"(?P<body>(?:\n[ \t]+\w+:[^\n]*)+)", re.M)
# 关键行筛选：判定性输出（[PAYLOAD] 试验行噪音大，排除）
_RE_KEY_LINE = re.compile(
    r"\[(?:critical|warning|error)\]"
    r"|testing\s+'"
    r"|technique appears to be usable"
    r"|columns? in query"
    r"|injectable"
    r"|back-end dbms", re.I)


def parse_findings(output: str) -> dict:
    """把 sqlmap 输出解析为结构化判定字段。

    返回 {dbms, techniques_usable, columns, parameters, key_lines, not_injectable}。
    无论 run_sqlmap 最终 status 是 finished 还是 timeout 都执行——
    超时被掐死前 sqlmap 已产出的判断（ORDER BY 可用/列数/DBMS/正在测的技法）
    是下一轮 AI 探测最值钱的输入，绝不随超时丢弃。
    """
    text = (output or "").replace("\r", "")
    findings: dict = {
        "dbms": _extract_dbms(text),
        "techniques_usable": [m.group(1).strip()
                              for m in _RE_TECHNIQUE_USABLE.finditer(text)],
        "columns": None,
        "parameters": [],
        "key_lines": [],
        "not_injectable": bool(re.search(
            r"all tested parameters? (?:do not|don't) appear to be injectable"
            r"|does not seem to be injectable", text, re.I)),
    }
    m = _RE_COLUMNS_IN_QUERY.search(text)
    if m:
        findings["columns"] = int(m.group(1))
    for blk in _RE_PARAM_BLOCK.finditer(text):
        info = {"name": blk.group("name")}
        for field in ("Type", "Title", "Payload"):
            fm = re.search(rf"\b{field}:\s*([^\n]*)", blk.group("body"))
            if fm:
                info[field.lower()] = fm.group(1).strip()[:300]
        findings["parameters"].append(info)
    seen: set[str] = set()
    for line in text.split("\n"):
        line = line.strip()
        if not line or line in seen:
            continue
        if re.search(r"checking if the target is protected", line, re.I):
            continue            # 例行 WAF 检测语句，无信息量
        if _RE_KEY_LINE.search(line):
            seen.add(line)
            findings["key_lines"].append(line[:200])
            if len(findings["key_lines"]) >= 15:
                break
    return findings


_RE_IDENTIFIED_INJECTION = re.compile(
    r"sqlmap identified the following injection point", re.I)
# sqlmap 在完成最终汇总前的单技法判定：
# "GET parameter 'q' appears to be 'AND boolean-based blind ...' injectable"
_RE_PARAM_APPEARS_INJECTABLE = re.compile(
    r"parameter\s+'[^']+'\s+appears to be\s+'[^']+'\s+injectable", re.I)


def _has_identified_injection(output: str, findings: dict | None) -> bool:
    """超时路径专用：sqlmap 在被掐死前是否已明确认定参数可注入。

    认两种形态（均须是 sqlmap 的判定行，而非我们的试探）：
      1) 「identified the following injection point(s)」汇总块 + 参数块；
      2) 汇总前的单技法判定「parameter 'q' appears to be '...' injectable」——
         实测 25793 job#137：超时掐断在 false-positive 复核阶段，只留下了这行。
    不认 "might be injectable" 之类的启发式试探行。
    """
    text = output or ""
    if (_RE_IDENTIFIED_INJECTION.search(text)
            and (findings or {}).get("parameters")):
        return True
    return bool(_RE_PARAM_APPEARS_INJECTABLE.search(text))


def merge_findings(base: dict | None, extra: dict | None) -> dict:
    """跨参数/多轮合并 findings：列表并集去重，标量非空互补。"""
    if not base:
        return dict(extra or {})
    if not extra:
        return dict(base)
    out = dict(base)
    for k in ("techniques_usable", "parameters", "key_lines"):
        merged = list(out.get(k) or [])
        for item in (extra.get(k) or []):
            if item not in merged:
                merged.append(item)
        out[k] = merged[:30]
    if not out.get("dbms") and extra.get("dbms"):
        out["dbms"] = extra["dbms"]
    if not out.get("columns") and extra.get("columns"):
        out["columns"] = extra["columns"]
    # 只有所有轮次都判不可注入才整体不可注入（一轮可注即为可注）
    out["not_injectable"] = bool(out.get("not_injectable") and extra.get("not_injectable"))
    return out


def summarize_for_ai(findings: dict | None, output_tail: str, tail_chars: int = 400) -> str:
    """把结构化判定重组为喂 AI 的摘要：关键行优先 + 少量原始尾部。

    替代旧的 tail 硬截断喂法（50590 实测：'ORDER BY' technique usable 在 tail
    261 位被切、SQLite 线索整条丢失、开场是半截单词）。
    """
    findings = findings or {}
    lines = ["【SQLMap 结构化判定】"]
    if findings.get("dbms"):
        lines.append(f"后端DBMS: {findings['dbms']}")
    if findings.get("techniques_usable"):
        lines.append("可用技法: " + ", ".join(findings["techniques_usable"]))
    if findings.get("columns"):
        lines.append(f"查询列数: {findings['columns']}")
    for p in (findings.get("parameters") or [])[:4]:
        desc = str(p.get("name", "?"))
        if p.get("type"):
            desc += f"（{p['type']}）"
        if p.get("payload"):
            desc += f" payload={p['payload']}"
        lines.append(f"已确认参数: {desc}")
    if findings.get("not_injectable"):
        lines.append("结论: 已测参数用常规写法均不可注入——注意这可能只是被过滤，须换形态（//代空格/双写）")
    if findings.get("key_lines"):
        lines.append("关键输出行:")
        lines += [f"  - {ln}" for ln in findings["key_lines"][:12]]
    tail = (output_tail or "").strip()
    if tail:
        lines.append("【原始输出尾部（截尾）】")
        lines.append(tail[-tail_chars:])
    return "\n".join(lines)


def parse_result_class(output: str, exit_code) -> str:
    low = output.lower()
    # 剥离 sqlmap 每次运行都打印的例行 WAF 探测语句——不能当 WAF 命中证据
    low = re.sub(r"\[info\] checking if the target is protected[^\n]*", "", low)
    if re.search(r"(is vulnerable|might be injectable|is ['\"].+['\"] injectable)", low):
        return "vuln_confirmed"
    if re.search(r"(all tested parameters? (do not|don't) appear to be injectable|not injectable)", low):
        if _RE_WAF.search(low):
            return "waf_blocked"
        return "no_vuln"
    if _RE_WAF.search(low):
        return "waf_blocked"
    if exit_code not in (0, None) and not output.strip():
        return "error"
    if re.search(r"(unhandled exception|critical error|connection refused|failed to connect)", low):
        return "error"
    return "inconclusive"


def _extract_dbms(output: str) -> str | None:
    """提取后端 DBMS 指纹。

    除最终汇总行 `back-end DBMS: X` 外，还必须认 sqlmap 在**探测早期**就打印的
    heuristic 判定行——实测 25793（PostgreSQL 靶场）超时前只留下了：
      "heuristic (extended) test shows that the back-end DBMS could be 'PostgreSQL'"
      "it looks like the back-end DBMS is 'PostgreSQL'"
    旧实现只认最终行 → dbms=None → 漏洞落库无指纹 → 深挖不带 `--dbms PostgreSQL`，
    sqlmap 把所有 DBMS 的技法全测一遍，420s 预算烧光在无关技法上。
    """
    text = output or ""
    for pat in (
        r"back-end dbms:\s*(.+)",
        r"back-end dbms could be\s*'([^']+)'",
        r"back-end dbms is\s*'([^']+)'",
    ):
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:60]
    return None


def _extract_payload(output: str) -> str | None:
    """提取 sqlmap 确认后打印的成功 payload（"Payload: id=..." 行）。"""
    m = re.search(r"^\s*payload:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)
    if m:
        return m.group(1).strip()[:500]
    return None
