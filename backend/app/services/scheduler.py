# -*- coding: utf-8 -*-
"""探测调度：SQLMap 批量初筛 + AI Payload 精细化试探，流水线协同。

协同规则：
  - SQLMap = 吞吐引擎：大批量初筛（auto_pass + suspicious 接口）
  - AI 试探 = 穿透引擎：只接 SQLMap 搞不定的（waf_blocked / inconclusive / timeout）
  - 结果分类器做路由；接口两引擎间最多往返 max_pipeline_rounds 轮（防死循环）
  - SQLMap 确认 → 直接产出漏洞；AI 试探确认 → 双向量闸门后才产出
"""
from urllib.parse import urlencode

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
                job_sqlmap, result_class, extra = _run_sqlmap_job(db, task_id, ep, cfg)
                stats["sqlmap_total"] += 1
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
                    hits = ([{"vector": "union" if is_union else "boolean",
                              "payload": payload,
                              "criteria": ("PG-UNION 补枪确认" if extra.get("pg_union")
                                           else "SQLMap 确认注入")}]
                            if payload else None)
                    if extra.get("pg_union") and not hits:
                        pg = extra["pg_union"]
                        hits = [{"vector": "union",
                                 "payload": pg.get("payload") or "UNION ALL SELECT ...",
                                 "criteria": f"flag={pg.get('flag_sample')}"}]
                    vuln = evidence.create_vulnerability(
                        db, task_id=task_id, endpoint=ep, scan_job_id=job_sqlmap.id,
                        vuln_type=("sql_injection_union" if is_union else "sql_injection_boolean"),
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


def _run_sqlmap_job(db: Session, task_id: int, ep: Endpoint, cfg: dict):
    """逐参数 SQLMap 初筛：测谁则谁带样例值，其余 query 参数置空。

    返回 (ScanJob, result_class, extra)。任一参数确认注入即返回。
    """
    intensity = cfg.get("intensity", "medium")
    timeout_s = {"low": 90, "medium": 180, "high": 300}.get(intensity, 180)
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
            body_map = {p["name"]: "" for p in b_params}
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
    for url, body, param, meta in targets:
        job = ScanJob(task_id=task_id, endpoint_id=ep.id, engine="sqlmap", round=1,
                      status="running", started_at=utcnow_iso())
        db.add(job)
        db.commit()
        bus.publish("scan", f"SQLMap 测参 {param or '-'} → {url[:120]}", task_id=task_id)
        result = runner.run_sqlmap(
            job_id=job.id, url=url, method=ep.method, data=body, param=param,
            is_write=(ep.read_write == "write"), intensity=intensity,
            timeout_s=timeout_s, dbms_hint=dbms_hint,
        )
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
        last_job, last_class = job, result["result_class"]
        last_extra = {"dbms": result["dbms"], "output": result.get("output_tail") or "",
                      "payload": result.get("payload"), "findings": merged_findings,
                      "ai_verdict": runner.summarize_for_ai(
                          merged_findings, result.get("output_tail") or "")}
        if result["result_class"] == "unreachable":
            # 连续连接失败已被 runner 主动终止：不再测下一个参数，直接交回上层停流水线。
            return job, "unreachable", last_extra
        if result["result_class"] == "vuln_confirmed":
            return job, result["result_class"], last_extra

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


def _record_ai_vuln(db: Session, task_id: int, ep: Endpoint, job, extra: dict):
    """把 ai_probe 的确认结果落成漏洞记录（供首轮与兄弟参数兜底轮共用）。"""
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
    job.request_meta = {"tried": result.get("tried"), "sqlmap_feedback": bool(sqlmap_output)}
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
