# -*- coding: utf-8 -*-
"""端到端流水线：任务的执行主线（后台线程内运行）。

当前批次实现：采集阶段（静态爬虫）+ 会话链路还原。
后续批次填充：WAF画像 → AI研判 → SQLMap初筛 → AI精细化 → 归档/回流。
每个阶段前检查终止信号；每阶段推进更新 task.progress。
"""
import traceback

from app.core.database import SessionLocal
from app.services import task_manager, collector, normalizer, waf, ai, scheduler
from app.services.event_bus import bus


def run_task(task_id: int, allowed_hosts: set[str]):
    db = SessionLocal()
    try:
        task = db.query  # noqa 占位避免误用；下面显式查询
        from app.models.task import Task
        task = db.query(Task).filter(Task.id == task_id).first()
        if not task:
            return
        stop = _stop_checker(task_id)
        cfg = task.scan_config or {}

        # ---------- 阶段1：接口采集 ----------
        task_manager.update_progress(db, task_id, stage="collecting", done=0, total=1,
                                     current_step="静态爬虫")
        if cfg.get("collect_mode", task.collect_mode) in ("static", "both") \
                or task.collect_mode in ("static", "both"):
            collector.crawl_static(SessionLocal, task_id, task.target, allowed_hosts, cfg,
                                   stop_event=_StopAdapter(task_id))
        # burp 模式：推送随时异步到达（/api/burp/push 直接入库），此处无需阻塞等待；
        # 双模式下静态爬完即继续，Burp 流量在扫描开始前到达的都会被归一入库。

        if stop():
            task_manager.set_status(db, task_id, "terminated", error="采集阶段终止")
            return

        # ---------- 阶段2：归一 & 会话链路建模 ----------
        task_manager.update_progress(db, task_id, stage="modeling", done=0, total=1,
                                     current_step="会话链路还原")
        normalizer.reconstruct_chains(db, task_id)

        # ---------- 阶段3：WAF 指纹画像 ----------
        task_manager.update_progress(db, task_id, stage="waf_profiling",
                                     current_step="WAF 指纹探测")
        task_manager.set_status(db, task_id, "scanning")
        try:
            profile = waf.profile_waf(SessionLocal, task_id, task.target, allowed_hosts, cfg,
                                      stop_event=_StopAdapter(task_id))
        except Exception as exc:
            # WAF 画像只是辅助信息，不能因为一次探针超时就终止整条任务。
            bus.publish("waf", f"WAF 画像暂不可用（继续研判）：{exc}",
                        task_id=task_id, level="warn")
            profile = None
        if stop():
            task_manager.set_status(db, task_id, "terminated", error="WAF画像阶段终止")
            return

        # ---------- 阶段4：AI 分级风险研判 ----------
        task_manager.update_progress(db, task_id, stage="assessing",
                                     current_step="AI 研判")
        from app.models.endpoint import Endpoint
        endpoints = db.query(Endpoint).filter(Endpoint.task_id == task_id).all()
        manual_count = 0
        for ep in endpoints:
            if stop():
                break
            assessment = ai.assess_endpoint(db, ep, profile)
            # suspicious / manual_review 都进人工，避免搜索类接口被自动猛扫
            if assessment.route in ("manual_review", "suspicious"):
                manual_count += 1

        # ---------- 阶段5：流水线探测（仅 auto_pass 自动探；其余等人确认后 resume） ----------
        engines = cfg.get("engines", {})
        eligible = [ep for ep in endpoints if _ep_route(db, ep.id) == "auto_pass"]
        stats = {"vulns": 0}
        if eligible and (engines.get("sqlmap_enabled", True) or engines.get("ai_probe_enabled", True)):
            if stop():
                task_manager.set_status(db, task_id, "terminated", error="探测阶段前终止")
                return
            # 扫描开始前重跑链路还原（Burp 流量可能在采集后才到达）
            normalizer.reconstruct_chains(db, task_id)
            stats = scheduler.run_scan(db, task_id, eligible, cfg, allowed_hosts, stop)
            if stats.get("unreachable"):
                # 连续连接失败已确认目标不可达：整任务停止，不再进入复核/后续阶段。
                task_manager.set_status(
                    db, task_id, "terminated",
                    error="目标不可达：连续连接失败，已停止全部探测（保护目标）")
                task_manager.update_progress(
                    db, task_id, stage="terminated", done=1, total=1,
                    current_step="目标不可达，探测中止")
                return
            if stop():
                task_manager.set_status(db, task_id, "terminated", error="探测阶段终止")
                return
        if manual_count > 0:
            task_manager.set_status(db, task_id, "review")
            task_manager.update_progress(db, task_id, stage="review",
                                         current_step=f"等待人工复核（{manual_count} 条）")
        else:
            task_manager.set_status(db, task_id, "done")
            task_manager.update_progress(db, task_id, stage="done", done=1, total=1,
                                         current_step=f"流水线完成（漏洞 {stats.get('vulns', 0)} 个）")
            task_manager.update_progress(db, task_id, stage="done", done=1, total=1,
                                         current_step="本批次流水线结束")

    except Exception as exc:
        bus.publish("task", f"流水线异常：{exc}\n{traceback.format_exc()[-800:]}",
                    task_id=task_id, level="error")
        try:
            task_manager.set_status(db, task_id, "terminated", error=str(exc))
        except Exception:
            pass
    finally:
        task_manager.cleanup_control(task_id)
        db.close()


def run_endpoint_scan(task_id: int, endpoint_id: int, allowed_hosts: set[str]):
    """定向重扫单个接口（手动录入后的补扫）。

    不重新采集、不重扫其他接口；只跑探测调度。收口：有 pending_review 漏洞 → review，
    否则 done。任务状态由 task_manager.start_endpoint_scan 置为 scanning。
    """
    from app.models.vuln import Vulnerability
    from app.models.task import Task
    from app.models.endpoint import Endpoint

    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id).first()
        ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
        if not task or not ep:
            return
        cfg = task.scan_config or {}
        task_manager.update_progress(db, task_id, stage="scanning", done=0, total=1,
                                     current_step=f"{ep.method} {ep.path}")
        try:
            stats = scheduler.run_scan(db, task_id, [ep], cfg, allowed_hosts,
                                       stop_check=lambda: False)
        except Exception as exc:
            bus.publish("scan", f"定向重扫失败：{exc}", task_id=task_id, level="error")
            task_manager.set_status(db, task_id, "done", error=str(exc)[:200])
            task_manager.update_progress(db, task_id, stage="done", done=1, total=1,
                                         current_step="定向重扫失败")
            return
        has_review = db.query(Vulnerability).filter(
            Vulnerability.task_id == task_id,
            Vulnerability.status == "pending_review").count() > 0
        task_manager.set_status(db, task_id, "review" if has_review else "done")
        task_manager.update_progress(
            db, task_id, stage="review" if has_review else "done", done=1, total=1,
            current_step=("定向重扫完成，有待复核漏洞" if has_review else "定向重扫完成"))
        bus.publish("scan", f"定向重扫完成：{ep.method} {ep.path} "
                            f"漏洞={stats.get('vulns', 0)}", task_id=task_id,
                    level="success")
    finally:
        task_manager.cleanup_control(task_id)
        db.close()


def _ep_route(db, endpoint_id: int) -> str:
    """取接口最新研判的路由。"""
    from app.models.assessment import RiskAssessment
    a = (db.query(RiskAssessment)
         .filter(RiskAssessment.endpoint_id == endpoint_id)
         .order_by(RiskAssessment.id.desc()).first())
    return a.route if a else "suspicious"


class _StopAdapter:
    """把 task_id 适配成 threading.Event 风格的 is_set() 接口。"""
    def __init__(self, task_id: int):
        self.task_id = task_id

    def is_set(self) -> bool:
        return task_manager.is_stop_requested(self.task_id)


def _stop_checker(task_id: int):
    return lambda: task_manager.is_stop_requested(task_id)
