# -*- coding: utf-8 -*-
"""本地演示站点：仅供 mhszed-sql 冒烟测试与联调使用（127.0.0.1）。

模拟一个带 API 的小站：
  /                     首页（含链接、表单、JS）
  /page2.html           二级页面
  /static/app.js        前端 JS（含 /api/ 路径）
  /api/search?q=        GET 查询接口
  /api/sec/search?q=    GET 模拟 16328 靶机：SQLite + WAF（过滤空格 + 单次关键字）
                          payload 含裸空格 → 被静默吃掉（响应=基线）；
                          否则剥离一次 union/select/from/where，并把 // 当空格 → 真执行
                        库中有 secrets 表，值 flag{local_waf_bypass_ok}
  /api/items?id=        GET 详情接口（演示中模拟布尔注入差异响应）
  /api/user/profile     GET 用户信息
  /api/login            POST 登录
  /api/order/submit     POST 下单（写接口）
"""
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qsl

INDEX_HTML = """<!DOCTYPE html>
<html><head><title>Demo Shop</title><script src="/static/app.js"></script></head>
<body>
<h1>Demo Shop</h1>
<a href="/page2.html">Page 2</a>
<a href="/api/items?id=1001">Item Detail</a>
<form action="/api/search" method="GET">
  <input name="q" placeholder="keyword"><input name="page" value="1">
  <button type="submit">Search</button>
</form>
<form action="/api/login" method="POST">
  <input name="username"><input name="password" type="password">
  <button type="submit">Login</button>
</form>
</body></html>"""

PAGE2_HTML = """<!DOCTYPE html>
<html><body><h1>Page 2</h1>
<form action="/api/order/submit" method="POST">
  <input name="item_id" value="1001"><input name="quantity" value="1">
  <button type="submit">Order</button>
</form>
<a href="/">Back</a>
</body></html>"""

APP_JS = """
const API = {
  items: '/api/items?id=1001',
  profile: '/api/user/profile',
  submitOrder: '/api/order/submit',
};
function loadProfile() { fetch(API.profile); }
"""


def _build_sec_db():
    """模拟靶机的 SQLite 后端（含 secrets 表）。"""
    import sqlite3
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE products(id INTEGER, name TEXT, price TEXT, stock TEXT)")
    db.executemany("INSERT INTO products VALUES(?,?,?,?)",
                   [(1, "coffee grinder", "199", "5"),
                    (2, "coffee beans", "88", "20")])
    db.execute("CREATE TABLE secrets(id INTEGER, content TEXT)")
    db.execute("INSERT INTO secrets VALUES(1,'flag{local_waf_bypass_ok}')")
    db.commit()
    return db


SEC_DB = _build_sec_db()


def _sec_filter(raw_q: str):
    """模拟 WAF：① 含裸空格 → 整条吃掉（返回 None，等同没传）
    ② 否则剥离一次 union/select/from/where ③ // 当空格。
    返回过滤后的 q（None = 被静默吃掉）。"""
    if " " in raw_q:
        return None
    q = raw_q
    for kw in ("union", "select", "from", "where"):
        q = re.sub(kw, "", q, count=1, flags=re.I)
    return q.replace("//", " ")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, body: str, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/":
            self._send(200, INDEX_HTML)
        elif p.path == "/page2.html":
            self._send(200, PAGE2_HTML)
        elif p.path == "/static/app.js":
            self._send(200, APP_JS, "application/javascript; charset=utf-8")
        elif p.path == "/api/search":
            qs = dict(parse_qsl(p.query, keep_blank_values=True))
            self._json(200, {"results": [f"result for {qs.get('q', '')}"], "page": qs.get("page", "1")})
        elif p.path == "/api/sec/search":
            qs = dict(parse_qsl(p.query, keep_blank_values=True))
            raw = qs.get("q", "1")
            print(f"[sec-waf] 收到 q={raw!r}", flush=True)
            filtered = _sec_filter(raw)
            q = "1" if filtered is None else filtered
            sql = f"SELECT id,name,price,stock FROM products WHERE name LIKE '%{q}%'"
            try:
                rows = SEC_DB.execute(sql).fetchall()
            except Exception as e:
                self._json(200, {"sql": sql, "error": f"查询异常: {e}", "results": []})
                return
            self._json(200, {"sql": sql, "results": rows,
                             "swallowed": filtered is None})
        elif p.path == "/api/items":
            qs = dict(parse_qsl(p.query, keep_blank_values=True))
            vid = qs.get("id", "1001")
            default = [{"id": 1001, "name": "Phone"}]
            # 模拟教科书式布尔注入：
            #   AND <a>=<b> 等式成立 → 与基线一致；等式不成立或 payload 畸形（如 sqlmap
            #   反 FP 探针 "AND 77 53" 故意去掉等号）→ 空结果（真实 DB 语法错误/条件为假均无行）
            # （不模拟 sleep：避免干扰 sqlmap 对时间盲注的交叉验证产生误判）
            if re.search(r"(?:\band\b|&&)", vid, re.I):
                m = re.search(r"(?:and|&&)\s*'?(\w+)'?\s*=\s*'?(\w+)'?", vid, re.I)
                if not m or m.group(1) != m.group(2):
                    self._json(200, {"items": []})
                    return
            self._json(200, {"items": default})
        elif p.path == "/api/user/profile":
            self._json(200, {"username": "demo", "role": "user"})
        else:
            self._send(404, "not found")

    def do_POST(self):
        p = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if p.path == "/api/login":
            form = dict(parse_qsl(body, keep_blank_values=True))
            if form.get("username") == "admin" and form.get("password") == "admin":
                self._json(200, {"ok": True, "token": "demo-token-123"})
            else:
                self._json(401, {"ok": False})
        elif p.path == "/api/order/submit":
            self._json(200, {"ok": True, "order_id": 202610130001})
        else:
            self._send(404, "not found")


def run(host="127.0.0.1", port=8899):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"demo site on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
