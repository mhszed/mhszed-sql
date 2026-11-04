# -*- coding: utf-8 -*-
"""探测范围收敛：目标 URL 所在目录前缀 + 接口路径归属判断。

供采集（collector）与流水线探测（pipeline）共用，保证"仅测试当前目录及子目录"
在采集、研判探针、注入探测三个阶段是同一个边界。
"""
from urllib.parse import unquote, urlparse


def target_dir_prefix(target: str) -> str:
    """目标 URL 所在目录（带尾斜杠）。根路径返回 '/'，表示不做目录收敛。

    http://h/vul/sqli/sqli_id.php → /vul/sqli/
    http://h/vul/sqli/            → /vul/sqli/
    http://h/                     → /
    """
    path = urlparse(target if "//" in target else f"http://{target}").path or "/"
    if not path.startswith("/"):
        path = "/" + path
    path = unquote(path)
    if path.endswith("/"):
        return path
    pos = path.rfind("/")
    return "/" if pos <= 0 else path[: pos + 1]


def path_under_prefix(path: str, prefix: str) -> bool:
    """路径是否位于给定目录前缀下（含子目录）。

    按分隔符语义比较：前缀 /vul/sqli/ 不会误匹配 /vul/sqli2/x。
    """
    p = unquote((path or "").split("?", 1)[0].split("#", 1)[0])
    if not p.startswith("/"):
        p = "/" + p
    if prefix == "/":
        return True
    base = prefix.rstrip("/")
    return p == base or p.startswith(prefix)
