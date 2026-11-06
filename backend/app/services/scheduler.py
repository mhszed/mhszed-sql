# -*- coding: utf-8 -*-
"""探测调度：SQLMap 批量初筛 + AI Payload 精细化试探，流水线协同。

协同规则：
  - SQLMap = 吞吐引擎：大批量初筛（auto_pass + suspicious 接口）
  - AI 试探 = 穿透引擎：只接 SQLMap 搞不定的（waf_blocked / inconclusive / timeout）
  - 结果分类器做路由；接口两引擎间最多往返 max_pipeline_rounds 轮（防死循环）
  - SQLMap 确认 → 直接产出漏洞；AI 试探确认 → 双向量闸门后才产出
"""
from urllib.parse import urlencode

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.base import utcnow_iso
from app.models.endpoint import Endpoint
from app.models.scan import ScanJob
from app.services import ai, evidence, prober, knowledge
from app.services.event_bus import bus
from app.services.safety import SafeHttpClient
from sqlmap_adapter import runner


def run_scan(db: Session, task_id: int, endpoints: list[Endpoint],
             cfg: dict, allowed_hosts: set[str], stop_check) -> dict:
    """对给定接口列表执行流水线探测。返回统计。"""
    stats = {"sqlmap_total": 0, "ai_probe_total": 0, "vulns": 0,
             "waf_blocked": 0, "no_vuln": 0, "inconclusive": 0,
             "unreachable": False}
    engines = cfg.get("engines", {})
    max_rounds = cfg.get("max_pipeline_rounds", 2)
    waf_profile = _get_waf_profile(db, task_id)
    safe_client = SafeHttpClient(lambda: _new_session(), task_id, allowed_hosts, cfg)

    total = len(endpoints)
    # 本轮扫描起始 job id：只统计本轮产生的 timeout，避免历史超时被再次误标
    start_job_id = db.query(func.max(ScanJob.id)).scalar() or 0
    # SQLMap 连续超时保护：目标疑似过慢时停止继续施压（阈值 5，命中/正常结果即重置）
    SQLMAP_TIMEOUT_LIMIT = 5
    sqlmap_timeout_streak = 0
    try:
        for idx, ep in enumerate(endpoints, 1):
            if stop_check():
                bus.publish("scan", f"终止信号，停止探测（已完成 {idx - 1}/{total}）",
                            task_id=task_id, level="warn")
                break
            _update_progress(task_id, "scanning", idx - 1, total, f"{ep.method} {ep.path}")

            # ---------- 引擎顺序：AI 探针优先 ----------
            # 理由（2026-10-15 真机实测）：sqlmap 180s 高强度猛扫会把靶机打到限流/掐断，
            # 轮到真正能打的 AI 探针时目标已不响应（tried=0）。AI 探针轻量且带 WAF 绕过，
            # 先跑；它确认了就直接跳过 sqlmap，不再拿目标去换一次没必要的初筛。
            result_class = None
            job_sqlmap = None
            ai_confirmed = False
            sqlmap_on = engines.get("sqlmap_enabled", True)
            if engines.get("ai_probe_enabled", True) and sqlmap_on:
                job_ai, ai_result, ai_extra = _run_ai_probe_job(
                    db, task_id, ep, waf_profile, safe_client, cfg, round_no=1)
                stats["ai_probe_total"] += 1
                if ai_result == "vuln_confirmed":
                    vectors = {h["vector"] for h in ai_extra.get("hits", [])}
                    vt = ("sql_injection_union" if vectors == {"union"} else
                          "sql_injection_time" if vectors == {"time"} else
                          "sql_injection_error" if vectors == {"error"} else
                          "sql_injection_boolean")
                    evidence.create_vulnerability(
                        db, task_id=task_id, endpoint=ep, scan_job_id=job_ai.id,
                        vuln_type=vt, title=f"SQL注入（AI探测确认）: {ep.method} {ep.path}",
                        vector_count=len(vectors), hits=ai_extra.get("hits"))
                    stats["vulns"] += 1
                    ai_confirmed = True
                    bus.publish("scan", f"AI 探针已确认注入，跳过 SQLMap 初筛（保护目标）: "
                                        f"{ep.method} {ep.path}", task_id=task_id, level="success")
                elif ai_result == "unreachable":
                    # 目标已不可达：立刻停整条扫描，绝不继续拿 sqlmap 打同一目标。
                    stats["unreachable"] = True
                    bus.publish("scan", "AI 探针连续连接失败：目标不可达，"
                                        "停止整条扫描（保护目标）",
                                task_id=task_id, level="error")
                    break

            # ---------- 引擎1：SQLMap 初筛（AI 已确认则跳过） ----------
            if not ai_confirmed and sqlmap_on:
                if sqlmap_timeout_streak >= SQLMAP_TIMEOUT_LIMIT:
                    # 连续超时保护：目标疑似过慢，跳过 SQLMap，结论按"未完成"处理
                    result_class = "timeout"
                    stats["sqlmap_total"] += 1
                    bus.publish("scan",
                                f"本轮 SQLMap 连续超时 {sqlmap_timeout_streak} 次，"
                                f"跳过该接口 SQLMap（保护目标）: {ep.method} {ep.path}",
                                task_id=task_id, level="warn")
                else:
                    job_sqlmap, result_class, extra = _run_sqlmap_job(db, task_id, ep, cfg)
                    stats["sqlmap_total"] += 1
                    if result_class == "timeout":
                        sqlmap_timeout_streak += 1
                    elif result_class in ("vuln_confirmed", "no_vuln"):
                        sqlmap_timeout_streak = 0
                if result_class == "unreachable":
                    # sqlmap 连续连接失败主动终止 → 整条流水线停止，防止继续施压。
                    stats["unreachable"] = True
                    bus.publish("scan", "sqlmap 连续连接失败：目标不可达，"
                                        "停止整条扫描（保护目标）",
                                task_id=task_id, level="error")
                    break
                if result_class == "vuln_confirmed":
                    # sqlmap / PG-UNION 补枪确认
                    payload = extra.get("payload") or ""
                    if not payload:
                        # 超时升级为 vuln_confirmed 时 extra.payload 常为空，但结构化
                        # findings 里已经有参数与确认 Payload——必须补进证据链，
                        # 否则报告“确认 Payload: 无”、深挖 payload_hint=None。
                        _params = (extra.get("findings") or {}).get("parameters") or []
                        if _params:
                            payload = _params[0].get("payload") or ""
                    if not payload:
                        payload = runner._extract_payload(extra.get("output") or "") or ""
                    is_union = "union" in payload.lower() or bool(extra.get("pg_union"))
                    # sqlmap 确认的时间盲注：payload 含 SLEEP 或输出写明 time-based
                    _out_low = (extra.get("output") or "").lower()
                    is_time = ("sleep(" in (payload or "").lower()
                               or "time-based" in _out_low)
                    _vector = ("union" if is_union else
                               "time" if is_time else "boolean")
                    _vuln_type = ("sql_injection_union" if is_union else
                                  "sql_injection_time" if is_time else "sql_injection_boolean")
                    hits = ([{"vector": _vector, "payload": payload,
                              "criteria": ("PG-UNION 补枪确认" if extra.get("pg_union")
                                           else "SQLMap 确认注入")}]
                            if payload else None)
                    if extra.get("pg_union") and not hits:
                        pg = extra["pg_union"]
                        hits = [{"vector": "union",
                                 "payload": pg.get("payload") or "UNION ALL SELECT ...",
                                 "criteria": f"flag={pg.get('flag_sample')}"}]
                    _clear_suspected(db, task_id, ep.id)
                    vuln = evidence.create_vulnerability(
                        db, task_id=task_id, endpoint=ep, scan_job_id=job_sqlmap.id,
                        vuln_type=_vuln_type,
                        title=f"SQL注入（{'PG-UNION' if extra.get('pg_union') else 'SQLMap'}确认）: {ep.method} {ep.path}",
                        dbms=extra.get("dbms"), vector_count=2, hits=hits)
                    _save_output_evidence(db, vuln, extra.get("output", ""))
                    if extra.get("pg_union"):
                        from app.services import evidence as evidence_svc
                        evidence_svc.append_evidence(
                            db, vuln.id, "deep_exploit",
                            f"【初筛补枪·PG-UNION】\n{extra['pg_union']}",
                            meta={"stage": "pg_union_scan", **{k: extra['pg_union'].get(k)
                                  for k in ('database', 'tables', 'flag_sample', 'columns')}})
                    stats["vulns"] += 1
                elif result_class == "waf_blocked":
                    stats["waf_blocked"] += 1
                elif result_class == "no_vuln":
                    stats["no_vuln"] += 1
                else:
                    stats["inconclusive"] += 1

            # ---------- 引擎2：AI 精细化（拦截/存疑/未跑sqlmap/高危漏报兜底） ----------
            needs_ai = (not ai_confirmed
                        and engines.get("ai_probe_enabled", True)
                        and result_class in (None, "waf_blocked", "inconclusive", "timeout")
                        and (engines.get("sqlmap_enabled", True) or result_class is None))
            # 高危漏报兜底：sqlmap/补枪判 no_vuln，但最新研判证据显示高危
            # （探针见过 SQL 报错，risk≥75）→ 仍走 AI 探测。
            # sqlmap 对 SQLite/特殊语境漏报是常态，不能让 no_vuln 一票放行。
            if (not needs_ai and engines.get("ai_probe_enabled", True)
                    and result_class == "no_vuln"
                    and ai.latest_risk(db, ep.id) >= 75):
                needs_ai = True
                bus.publish("scan", f"sqlmap 判 no_vuln 但研判风险 "
                                    f"{ai.latest_risk(db, ep.id):.0f}≥75，兜底转入 AI 探测: "
                                    f"{ep.method} {ep.path}", task_id=task_id, level="warn")
            if needs_ai:
                # 反馈环输入：优先结构化摘要（关键行优先 + 少量原始尾部），
                # 老的 raw output 只在摘要缺失时兜底（50590 实测关键行被 tail 截断丢失）
                feedback = None
                if job_sqlmap:
                    feedback = (extra or {}).get("ai_verdict") or (extra or {}).get("output")
                job_ai, ai_result, ai_extra = _run_ai_probe_job(
                    db, task_id, ep, waf_profile, safe_client, cfg,
                    round_no=(job_sqlmap.round + 1) if job_sqlmap else 1,
                    sqlmap_output=feedback)
                stats["ai_probe_total"] += 1
                if ai_result == "vuln_confirmed":
                    _record_ai_vuln(db, task_id, ep, job_ai, ai_extra)
                    stats["vulns"] += 1
                elif ai_result == "waf_blocked":
                    stats["waf_blocked"] += 1
                elif ai_result == "no_vuln":
                    stats["no_vuln"] += 1
                    # 兄弟参数兜底轮（2026-10-15 追加轮·**收紧门控**）：
                    # 只在探针**已经发现可疑兄弟参数**（probe_hint）时才补一轮，
                    # 不再"随便挑一个兄弟"——那会让多参数接口普遍白跑一整轮，
                    # 流水线耗时翻倍（smoke_1 实测 >160s 顶穿 60s 预算）。
                    # **仅对 no_vuln 触发**；waf_blocked / inconclusive / error 不触发。
                    hint = (ai_extra or {}).get("probe_hint") or []
                    sib = hint[0] if hint else None
                    if sib:
                        bus.publish("scan", f"ai_probe 首轮 no_vuln，探针发现可疑兄弟参数 "
                                            f"{sib}，补探一轮（{ep.method} {ep.path}）",
                                    task_id=task_id, level="warn")
                        job_ai2, ai_result2, ai_extra2 = _run_ai_probe_job(
                            db, task_id, ep, waf_profile, safe_client, cfg,
                            round_no=job_ai.round + 1, focus_param=sib)
                        stats["ai_probe_total"] += 1
                        if ai_result2 == "vuln_confirmed":
                            _record_ai_vuln(db, task_id, ep, job_ai2, ai_extra2)
                            stats["vulns"] += 1
                        elif ai_result2 == "waf_blocked":
                            stats["waf_blocked"] += 1
                else:
                    stats["inconclusive"] += 1

            # 探测未确认 → 疑似记录（不计入确认漏洞）：
            # 1) 研判强证据（risk≥85）但探测未确认；
            # 2) 只要出现过 SQLMap 超时，结论不可信，同样标疑似而不是静默当无洞。
            if not ai_confirmed:
                timed_out = (db.query(ScanJob)
                             .filter(ScanJob.task_id == task_id,
                                     ScanJob.endpoint_id == ep.id,
                                     ScanJob.id > start_job_id,
                                     ScanJob.result_class == "timeout")
                             .count() > 0)
                strong = ai.latest_risk(db, ep.id) >= 85
                unfinished = result_class in ("no_vuln", "timeout", None)
                # 疑似门槛：必须有明显 SQL 特征（研判 risk≥85）。
                # 纯超时但无强特征 → 只是「SQLMap 超时」，不建疑似，仅记录日志。
                if strong and (unfinished or timed_out):
                    _record_suspected(db, task_id, ep,
                                      reason="timeout" if timed_out else "strong")
                elif timed_out:
                    # 纯超时、无强特征：不标疑似，但同样进结果页走"未完成"流程
                    _record_suspected(db, task_id, ep, reason="timeout_only")

            if stop_check():
                break
    finally:
        safe_client.close()

    if stats.get("unreachable"):
        _update_progress(task_id, "scanning", total, total, "目标不可达，探测中止")
        bus.publish("scan", "探测调度中止：目标不可达（连续连接失败），"
                            "已停止全部探测以避免打挂目标",
                    task_id=task_id, level="error")
    else:
        _update_progress(task_id, "scanning", total, total, "探测完成")
        bus.publish("scan", f"探测调度完成: sqlmap={stats['sqlmap_total']} "
                            f"ai_probe={stats['ai_probe_total']} 漏洞={stats['vulns']} "
                            f"拦截={stats['waf_blocked']}", task_id=task_id, level="success")
    return stats


def _should_time_retry(result_class: str, output: str, ep: Endpoint, intensity: str) -> bool:
    """是否值得补跑一次「时间盲注定向重试」。

    触发条件（全部满足）：
      · 读接口（写接口的时间盲注可能真的执行 UPDATE，自动补跑风险太高）
      · medium/low 强度（high 本来就有 T）
      · 常规结果为 no_vuln / inconclusive
      · sqlmap 输出里出现过"疑似可注"信号：`appears to be ... injectable` /
        `false positive or unexploitable` / `might be injectable`
        —— 实测 pikachu blind_b/t：sqlmap 判 RLIKE boolean 可注后自己按误报撤销，
        而 medium 的 BEU 又不测时间盲注，于是整条漏掉（2026-11-06）。
    """
    if getattr(ep, "read_write", "read") != "read":
        return False
    if (intensity or "medium") == "high":
        return False
    if result_class not in ("no_vuln", "inconclusive"):
        return False
    low = (output or "").lower()
    return (("appears to be" in low and "injectable" in low)
            or "false positive or unexploitable" in low
            or "might be injectable" in low)


def _run_sqlmap_job(db: Session, task_id: int, ep: Endpoint, cfg: dict):
    """逐参数 SQLMap 初筛：测谁则谁带样例值，其余 query 参数置空。

    返回 (ScanJob, result_class, extra)。任一参数确认注入即返回。
    """
    intensity = cfg.get("intensity", "medium")
    timeout_s = {"low": 90, "medium": 180, "high": 300}.get(intensity, 180)
    # 写接口深度注入测试（默认关）：INSERT/UPDATE 型注入需要 --risk≥2 才会被
    # SQLMap 测试；开启后会真正执行写语句，仅适用于靶场/已授权且数据可牺牲的目标。
    write_deep = bool(cfg.get("write_deep_probe")) and ep.read_write == "write"
    risk_override = 2 if (write_deep and intensity != "high") else None
    path = (ep.raw_path or ep.path or "/").split("?")[0]
    # 按任务目标取 scheme（旧实现硬编码 http，HTTPS 目标初筛 URL 会连错协议）
    from app.models.task import Task as _Task
    _task = db.query(_Task).filter(_Task.id == task_id).first()
    scheme = "https" if (getattr(_task, "target", "") or "").lower().startswith("https") else "http"
    base = f"{scheme}://{ep.host}{path}"

    q_params = [p for p in (ep.params or []) if p.get("location") in (None, "query")]
    b_params = [p for p in (ep.params or []) if p.get("location") == "body"]
    # 纯路径（无任何参数）仍跑一轮，但**限时**：sqlmap 对无参数目标会空转
    # 到 180s，把 smoke 流水线卡在 scanning（2026-10-19 回归实测）。
    if not q_params and not b_params and ep.method.upper() == "GET":
        timeout_s = min(timeout_s, 30)
    targets: list[tuple[str, str | None, str | None, dict]] = []
    if q_params:
        for cur in q_params:
            query = {p["name"]: "" for p in q_params}  # 兄弟置空
            query[cur["name"]] = (cur.get("sample_value") or "1")
            url = f"{base}?{urlencode(query)}"
            targets.append((url, None, cur["name"], {"focus": cur["name"], "query": query}))
    elif ep.method.upper() == "GET":
        targets.append((base, None, None, {"focus": None}))

    if ep.method.upper() != "GET" and b_params:
        for cur in b_params:
            # 兄弟参数保留真实样例值（不再置空）：置空会让注册/登录等前置校验失败，
            # payload 根本到不了 SQL。pikachu reg 页 password 为空 → "必填项不能为空"，
            # 导致 INSERT 注入永远测不出来（2026-11-04 实测）。
            body_map = {p["name"]: (p.get("sample_value") or "1") for p in b_params}
            body_map[cur["name"]] = (cur.get("sample_value") or "1")
            targets.append((base, urlencode(body_map), cur["name"],
                            {"focus": cur["name"], "body": body_map}))
    if not targets:
        targets.append((base, None, None, {"focus": None}))

    # DBMS 提示由研判证据驱动（探针报错语境 → latest_likely_dbms），
    # 不再按路径硬编码：旧的 /search→PostgreSQL 会把 SQLite 靶场喂给 PG 技法白测一遍
    likely = ai.latest_likely_dbms(db, ep.id)
    dbms_hint = {"sqlite": "SQLite", "postgresql": "PostgreSQL",
                 "mysql": "MySQL", "mssql": "MSSQL"}.get(likely)

    last_job, last_class = None, "no_vuln"
    last_extra: dict = {"dbms": None, "output": "", "payload": None}
    merged_findings: dict = {}          # 跨参数累积：所有参数轮的判定并集
    # 疑似信号是**按参数**出现的（pikachu blind_b 只在 name 上有），
    # 必须记住那个参数，不能用最后一个参数（submit）的输出做判断。
    time_retry_target: tuple | None = None
    for url, body, param, meta in targets:
        job = ScanJob(task_id=task_id, endpoint_id=ep.id, engine="sqlmap", round=1,
                      status="running", started_at=utcnow_iso())
        db.add(job)
        db.commit()
        bus.publish("scan", f"SQLMap 测参 {param or '-'} → {url[:120]}", task_id=task_id)
        result = runner.run_sqlmap(
            job_id=job.id, url=url, method=ep.method, data=body, param=param,
            is_write=(ep.read_write == "write"), intensity=intensity,
            timeout_s=timeout_s, dbms_hint=dbms_hint, risk_override=risk_override,
        )
        # 超时策略：多数超时是时间盲注重查询拖的。先禁用时间盲注、
        # 延长 120s 轻量重测一次；仍超时才停止该接口剩余参数。
        retried_light = False
        if result.get("status") == "timeout":
            bus.publish("scan",
                        f"SQLMap 超时，改用轻量策略重测一次（禁时延盲注）: {param or '-'}",
                        task_id=task_id, level="warn")
            result = runner.run_sqlmap(
                job_id=job.id, url=url, method=ep.method, data=body, param=param,
                is_write=(ep.read_write == "write"), intensity=intensity,
                timeout_s=timeout_s + 120, dbms_hint=dbms_hint,
                risk_override=risk_override, extra_args=["--technique=BEU"],
            )
            retried_light = True
        merged_findings = runner.merge_findings(merged_findings,
                                                result.get("findings") or {})
        job.status = result["status"]
        job.result_class = result["result_class"]
        job.request_meta = {
            "pid": result["pid"], "exit_code": result["exit_code"],
            "dbms": result["dbms"], "timeout_s": timeout_s,
            "focus_param": param, "url": url[:200],
            "output_tail": (result.get("output_tail") or "")[-1500:],
            # 结构化判定落库：超时被掐死前 sqlmap 已产出的判断持久保留
            "sqlmap_findings": merged_findings,
        }
        job.finished_at = utcnow_iso()
        job.duration_ms = result.get("duration_ms")
        db.commit()
        # SQLMap 审计留痕（SQLMap 进程不走 SafeHttpClient，默认没有审计记录）
        try:
            from app.core.audit import log_action
            log_action(db, user_id=None, action="sqlmap_scan",
                       resource_type="endpoint", resource_id=ep.id,
                       detail={"param": param, "result_class": result.get("result_class"),
                               "status": result.get("status"),
                               "exit_code": result.get("exit_code"),
                               "timeout_s": timeout_s,
                               "risk_override": risk_override})
            db.commit()
        except Exception:
            db.rollback()
        last_job, last_class = job, result["result_class"]
        last_extra = {"dbms": result["dbms"], "output": result.get("output_tail") or "",
                      "payload": result.get("payload"), "findings": merged_findings,
                      "ai_verdict": runner.summarize_for_ai(
                          merged_findings, result.get("output_tail") or "")}
        if _should_time_retry(result["result_class"], result.get("output_tail") or "",
                              ep, intensity):
            time_retry_target = (url, body, param)
        if result["result_class"] == "unreachable":
            # 连续连接失败已被 runner 主动终止：不再测下一个参数，直接交回上层停流水线。
            return job, "unreachable", last_extra
        if result["result_class"] == "vuln_confirmed":
            return job, result["result_class"], last_extra
        if retried_light and result["result_class"] == "timeout":
            bus.publish("scan",
                        f"轻量重测仍超时，停止该接口剩余参数: {ep.method} {ep.path}",
                        task_id=task_id, level="warn")
            return job, "timeout", last_extra

    # ---- 时间盲注定向重试（2026-11-06）----
    # 常规 BEU 初筛不含 T；若输出里出现"疑似可注"信号，补一次 --technique=T。
    # 只做读接口、只做一次、90s 预算：避免把所有正常接口都拖慢。
    if time_retry_target and last_class in ("no_vuln", "inconclusive"):
        _url, _body, _param = time_retry_target
        rjob = ScanJob(task_id=task_id, endpoint_id=ep.id, engine="sqlmap", round=2,
                       status="running", started_at=utcnow_iso())
        db.add(rjob)
        db.commit()
        bus.publish("scan", f"疑似盲注 → 时间定向重试 --technique=T（{_param or '-'}，180s）",
                    task_id=task_id, level="warn")
        rres = runner.run_sqlmap(
            job_id=rjob.id, url=_url, method=ep.method, data=_body, param=_param,
            is_write=False, intensity=intensity, timeout_s=180, dbms_hint=dbms_hint,
            extra_args=["--technique=T", "--time-sec", "2", "--fresh-queries"],
            exploit_mode=True, out_dir_key=f"job_{rjob.id}_time",
        )
        rjob.status = rres["status"]
        rjob.result_class = rres["result_class"]
        rjob.request_meta = {
            "targeted": "time_blind", "pid": rres["pid"],
            "exit_code": rres["exit_code"], "timeout_s": 180,
            "focus_param": _param, "url": _url[:200],
            "output_tail": (rres.get("output_tail") or "")[-1500:],
        }
        rjob.finished_at = utcnow_iso()
        rjob.duration_ms = rres.get("duration_ms")
        db.commit()
        if rres.get("result_class") in ("vuln_confirmed", "exploit_ok"):
            merged2 = runner.merge_findings(merged_findings, rres.get("findings") or {})
            _pl = rres.get("payload") or runner._extract_payload(
                rres.get("full_output") or rres.get("output_tail") or "")
            return rjob, "vuln_confirmed", {
                "dbms": rres.get("dbms"),
                "output": rres.get("full_output") or rres.get("output_tail") or "",
                "payload": _pl, "findings": merged2,
            }
        last_job, last_class = rjob, rres["result_class"]
        last_extra = {"dbms": rres.get("dbms") or last_extra.get("dbms"),
                      "output": rres.get("output_tail") or "", "payload": None,
                      "findings": merged_findings}

    # sqlmap 未确认 → PG-UNION 补枪。仅当研判证据指向 PostgreSQL 才触发
    # （证据驱动的 dbms_hint；对 SQLite/MySQL 靶场跑 PG 补枪纯属浪费请求）
    if last_class in ("no_vuln", "timeout", "inconclusive", "waf_blocked") \
            and dbms_hint == "PostgreSQL":
        focus = q_params[0]["name"] if q_params else "q"
        siblings = {p["name"]: "" for p in q_params if p["name"] != focus}
        from app.services.pg_union_exploit import run_pg_union
        bus.publish("scan", f"SQLMap 未检出，启动 PG-UNION 补枪 param={focus}",
                    task_id=task_id, level="warn")
        pg = run_pg_union(url=f"{base}?{focus}=1", param=focus, base="1",
                          sibling_empty=siblings, task_id=task_id)
        job = ScanJob(task_id=task_id, endpoint_id=ep.id, engine="ai_pg_union", round=2,
                      status="finished", started_at=utcnow_iso(), finished_at=utcnow_iso())
        if pg.get("confirmed") or pg.get("flag_sample"):
            job.result_class = "vuln_confirmed"
            job.request_meta = {"pg_union": pg, "focus_param": focus}
            db.add(job)
            db.commit()
            payload = pg.get("payload") or f"' UNION ALL SELECT ... FROM flag--"
            return job, "vuln_confirmed", {
                "dbms": pg.get("version") or "PostgreSQL",
                "output": str(pg),
                "payload": payload,
                "pg_union": pg,
            }
        job.result_class = "no_vuln"
        job.request_meta = {"pg_union": pg, "focus_param": focus}
        db.add(job)
        db.commit()
        last_job, last_class = job, "no_vuln"
        last_extra = {"dbms": None, "output": str(pg), "payload": None}

    return last_job, last_class, last_extra


def _clear_suspected(db: Session, task_id: int, endpoint_id: int):
    """确认漏洞后清掉同接口的「疑似未确认」记录。"""
    from app.models.vuln import Vulnerability
    db.query(Vulnerability).filter(
        Vulnerability.task_id == task_id,
        Vulnerability.endpoint_id == endpoint_id,
        Vulnerability.status.in_(("suspected", "timeout"))).delete(synchronize_session=False)
    db.commit()


def _record_suspected(db: Session, task_id: int, ep: Endpoint, reason: str = "strong"):
    """探测未完成记录（不计入确认漏洞统计与正式报告）。

    reason=strong      → status=suspected：研判见 SQL 报错/强证据，但探测未确认；
    reason=timeout     → status=suspected：强证据 + 探测超时（疑似，待复核）；
    reason=timeout_only→ status=timeout  ：纯超时、无强 SQL 特征，只是「未完成」，
                         不叫疑似，但同样进结果页、可深入复测。
    """
    from app.models.vuln import Vulnerability
    existing = (db.query(Vulnerability)
                .filter(Vulnerability.task_id == task_id,
                        Vulnerability.endpoint_id == ep.id).first())
    if existing:
        return
    if reason == "timeout_only":
        status = "timeout"
        title = f"探测超时未完成（无强 SQL 特征）: {ep.method} {ep.path}"
        advice = "SQLMap 超时被中断，不能当作无漏洞；建议深入复测或人工核查"
        conclusion = "探测超时未完成，且无强 SQL 特征（不标疑似，仅提示未完成）"
    elif reason == "timeout":
        status = "suspected"
        title = f"疑似SQL注入（探测超时未完成）: {ep.method} {ep.path}"
        advice = "SQLMap 超时被中断，不能当作无漏洞；请延长超时或发起深入复测"
        conclusion = "AI 探针见强 SQL 特征，但探测超时未完成"
    else:
        status = "suspected"
        title = f"疑似SQL注入（探测未确认）: {ep.method} {ep.path}"
        advice = ("研判探针见 SQL 报错/强证据，但探测未确认；"
                  "写接口 INSERT/UPDATE 型需 write_deep_probe(risk≥2) 复测")
        conclusion = "AI 探针见 SQL 报错/强证据，但探测引擎未确认"
    vuln = Vulnerability(
        task_id=task_id, endpoint_id=ep.id, scan_job_id=None,
        vuln_type="sql_injection_error", severity="medium",
        title=title, status=status, vector_count=1,
        hardening_advice={"reason": advice},
    )
    db.add(vuln)
    db.flush()
    evidence.append_evidence(
        db, vuln.id, "request",
        f"{ep.method} {ep.host}{ep.raw_path or ep.path}\n"
        f"研判风险分={ai.latest_risk(db, ep.id):.0f}\n"
        f"结论：{conclusion}。\n"
        f"建议：{advice}",
        meta={"stage": status, "reason": reason},
    )
    db.commit()
    bus.publish("scan", f"疑似注入（探测未确认，已标记待人工核实）: {ep.method} {ep.path}",
                task_id=task_id, level="warn")


def _record_ai_vuln(db: Session, task_id: int, ep: Endpoint, job, extra: dict):
    """把 ai_probe 的确认结果落成漏洞记录（供首轮与兄弟参数兜底轮共用）。"""
    _clear_suspected(db, task_id, ep.id)
    vectors = {h["vector"] for h in (extra or {}).get("hits", [])}
    vt = ("sql_injection_union" if vectors == {"union"} else
          "sql_injection_time" if vectors == {"time"} else
          "sql_injection_error" if vectors == {"error"} else
          "sql_injection_boolean")
    return evidence.create_vulnerability(
        db, task_id=task_id, endpoint=ep, scan_job_id=job.id,
        vuln_type=vt, title=f"SQL注入（AI探测确认）: {ep.method} {ep.path}",
        vector_count=len(vectors), hits=(extra or {}).get("hits"))


def _run_ai_probe_job(db: Session, task_id: int, ep: Endpoint, waf_profile,
                      safe_client, cfg: dict, round_no: int,
                      sqlmap_output: str | None = None,
                      focus_param: str | None = None):
    job = ScanJob(task_id=task_id, endpoint_id=ep.id, engine="ai_probe", round=round_no,
                  status="running", started_at=utcnow_iso())
    db.add(job)
    db.commit()

    # sqlmap_output 进反馈环：AI 能看到 sqlmap 判了什么（不可注入/疑似 WAF），据此改写
    # focus_param：兄弟参数兜底轮强制指定的注入参数
    result = prober.probe_endpoint(db, ep, waf_profile, safe_client, cfg,
                                   sqlmap_output=sqlmap_output,
                                   focus_param=focus_param)

    # C（2026-10-15）：0 个请求成功发出 ≠ "判不出"，而是目标不可达/疑似封禁。
    # 旧行为会落在 inconclusive/error 里，被误读成判据问题（真机踩过）。
    if not result.get("tried") and result["result_class"] in ("error", "inconclusive"):
        result["result_class"] = "unreachable"
        bus.publish("scan", f"[ai_probe] 目标不可达/疑似封禁：0 个请求成功发出 "
                            f"({ep.method} {ep.path})——建议冷却后重试，勿再猛扫",
                    task_id=task_id, level="warn")

    job.status = "finished"
    job.result_class = result["result_class"]
    job.ai_payloads = result["hits"]
    job.bypass_strategy = cfg.get("bypass_strategies")
    job.request_meta = {"tried": result.get("tried"), "sqlmap_feedback": bool(sqlmap_output),
                        # 布尔反证结果（None=未触发；ok=False 时已撤销确认）
                        "counterproof": result.get("counterproof")}
    job.finished_at = utcnow_iso()
    db.commit()
    return job, result["result_class"], result


def _save_output_evidence(db: Session, vuln, output: str):
    from app.models.vuln import Evidence
    import hashlib
    seq = (db.query(Evidence).filter(Evidence.vulnerability_id == vuln.id)
           .count() + 1)
    row = Evidence(vulnerability_id=vuln.id, evidence_type="console_log", seq=seq,
                   content=f"SQLMap 输出节选:\n{output[-3000:]}",
                   meta={"bytes": len(output)},
                   sha256=hashlib.sha256(output[-3000:].encode("utf-8", "replace")).hexdigest(),
                   created_at=utcnow_iso())
    db.add(row)
    db.commit()


def _get_waf_profile(db: Session, task_id: int):
    from app.models.waf import WafProfile
    return db.query(WafProfile).filter(WafProfile.task_id == task_id).first()


def _update_progress(task_id: int, stage: str, done: int, total: int, step: str):
    from app.services import task_manager
    from app.core.database import SessionLocal
    s = SessionLocal()
    try:
        task_manager.update_progress(s, task_id, stage=stage, done=done, total=total,
                                     current_step=step)
    finally:
        s.close()


def _new_session():
    from app.core.database import SessionLocal
    return SessionLocal()
