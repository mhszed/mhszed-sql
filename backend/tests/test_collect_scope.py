# -*- coding: utf-8 -*-
"""采集阶段范围过滤 + JS 独立配额 单元测试（不依赖服务）。

运行：venv/Scripts/python tests/test_collect_scope.py
"""
import sys
import threading
from collections import deque
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  注册全部模型
from app.core.database import Base
from app.models.endpoint import Endpoint
from app.services import collector

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'OK' if cond else 'FAIL'} {name} {extra}")


def _db_factory():
    # StaticPool：所有 session 共享同一个内存库，避免每次连接拿到空库
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_parse_html_scope():
    maker = _db_factory()
    db = maker()
    html = """
    <a href="/vul/sqli/sqli_str.php">in</a>
    <a href="/vul/sqli/sqli_blind_t.php?name=1">in-q</a>
    <a href="/vul/xss/xss_01.php">out</a>
    <form method="post" action="/vul/sqli/sqli_widebyte.php"><input name="name" value="1"></form>
    <form method="get" action="/vul/xss/out.php"><input name="q"></form>
    """
    queue = deque()
    collector._parse_html(
        db, 1, "http://target.local:8080/vul/sqli/sqli_id.php", html, queue, set(), 0,
        {"max_depth": 3}, {"target.local"}, "http://target.local:8080/vul/sqli/sqli_id.php",
        "/vul/sqli/")
    paths = sorted(ep.path for ep in db.query(Endpoint).all())
    check("目录内表单登记", "/vul/sqli/sqli_widebyte.php" in paths, str(paths))
    check("目录外表单不登记", "/vul/xss/out.php" not in paths, str(paths))
    check("带参链接登记接口", "/vul/sqli/sqli_blind_t.php" in paths, str(paths))
    queued = [u for u, _ in queue]
    check("目录内链接入队", any("/vul/sqli/sqli_str.php" in u for u in queued), str(queued))
    check("目录外链接不入队", all("/vul/xss/" not in u for u in queued), str(queued))
    db.close()


def test_parse_js_scope():
    maker = _db_factory()
    db = maker()
    js = "fetch('/vul/sqli/sqli_x.php'); fetch('/vul/xss/out.php');"
    collector._parse_js(db, 2, "http://target.local:8080/assets/js/app.js", js,
                        {"target.local"}, "http://target.local:8080/vul/sqli/sqli_id.php",
                        "/vul/sqli/")
    paths = sorted(ep.path for ep in db.query(Endpoint).all())
    check("JS 目录内接口登记", "/vul/sqli/sqli_x.php" in paths, str(paths))
    check("JS 目录外接口过滤", "/vul/xss/out.php" not in paths, str(paths))
    db.close()


class _Resp:
    status_code = 200
    headers = {"content-type": "text/html; charset=utf-8"}

    def __init__(self, text):
        self.text = text


def test_js_quota():
    maker = _db_factory()
    hits = []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def request(self, method, url, headers=None, audit=True):
            hits.append(url)
            links = "".join(f'<a href="/p{i}.php">p</a>' for i in range(40))
            return _Resp(links + '<script src="/a.js"></script><script src="/b.js"></script>'
                         '<script src="/c.js"></script>')

        def close(self):
            pass

    orig = collector.SafeHttpClient
    collector.SafeHttpClient = FakeClient
    try:
        collector.crawl_static(maker, 3, "http://target.local:8080/", {"target.local"},
                               {"intensity": "medium", "param_guess": False},
                               threading.Event())
    finally:
        collector.SafeHttpClient = orig

    pages = [u for u in hits if not u.split("?")[0].endswith(".js")]
    js = [u for u in hits if u.split("?")[0].endswith(".js")]
    check("页面配额 = 30 页", len(pages) == 30, f"pages={len(pages)}")
    check("JS 不占页面配额（3 个 JS 全抓）", len(js) == 3, f"js={len(js)}")
    check("JS 配额按强度缩放", collector._JS_MAX_PAGES == {"low": 10, "medium": 25, "high": 50})


def main():
    test_parse_html_scope()
    test_parse_js_scope()
    test_js_quota()
    print(f"\n通过 {len(passed)}，失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
