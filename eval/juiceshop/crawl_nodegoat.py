"""NodeGoat traffic generator for the Swarmie A/B eval (cookie-session auth).

Like crawl.py but for a cookie-based server-rendered app: logs in with a cookie jar (form
POST), then walks the authenticated OWASP-Top-10 surface (IDOR allocations, PII profile,
injection/XSS pages, admin-only benefits) and records each pair into a Capture-schema DB.

Usage: python3 -m eval.juiceshop.crawl_nodegoat --base http://localhost:4000 --out eval/juiceshop/nodegoat.db
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

_SCHEMA = """
CREATE TABLE http_traffic (
    request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
    path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
    status_code INTEGER, response_length INTEGER, content_type TEXT,
    extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
);
CREATE TABLE http_messages (
    request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
    response_headers TEXT, response_body BLOB
);
"""

# (method, path, body|None, form?) — GET surface + one form login. Cookie jar carries session.
_PLAN = [
    ("GET", "/", None, False),
    ("GET", "/login", None, False),
    ("POST", "/login", {"userName": "user1", "password": "User1_123"}, True),
    ("GET", "/dashboard", None, False),
    ("GET", "/profile", None, False),
    ("GET", "/contributions", None, False),
    ("GET", "/allocations/1", None, False),
    ("GET", "/allocations/2", None, False),
    ("GET", "/allocations/3", None, False),
    ("GET", "/benefits", None, False),
    ("GET", "/memos", None, False),
    ("GET", "/tutorial", None, False),
]


def _headers_text(items):
    return "".join(f"{k}: {v}\r\n" for k, v in items)


def crawl(base, out):
    out = Path(out)
    if out.exists():
        out.unlink()
    out.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(out)
    conn.executescript(_SCHEMA)
    host = urlsplit(base).netloc
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    rid = 0
    stats = {"rows": 0, "statuses": {}}
    for method, path, body, form in _PLAN:
        rid += 1
        url = base + path
        sp = urlsplit(url)
        headers = {"Accept": "text/html,application/json,*/*", "User-Agent": "swarmie-eval/1"}
        data = None
        if body is not None:
            data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with opener.open(req, timeout=15) as r:
                status, resp_headers, resp_body = r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            status, resp_headers, resp_body = e.code, dict(e.headers), e.read()
        except (urllib.error.URLError, TimeoutError) as e:
            status, resp_headers, resp_body = 0, {}, str(e).encode()
        req_body = data if (data and not form) else b""
        params = sp.query.split("&") if sp.query else []
        conn.execute("INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            rid, f"2026-08-30T02:00:{rid:02d}Z", method, host, sp.path, sp.query,
            len(params), ",".join(sorted(p.split("=")[0] for p in params if p)), status,
            len(resp_body), resp_headers.get("Content-Type", ""), Path(sp.path).suffix.lstrip("."),
            "HTTP/1.1", url, hashlib.sha256(f"{method} {url}".encode()).hexdigest()))
        conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
            rid, _headers_text([("Host", host)]), req_body,
            _headers_text(resp_headers.items()), resp_body))
        stats["rows"] += 1
        stats["statuses"][str(status)] = stats["statuses"].get(str(status), 0) + 1
    conn.commit()
    conn.close()
    return stats


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:4000")
    ap.add_argument("--out", default="eval/juiceshop/nodegoat.db")
    args = ap.parse_args(argv)
    print(json.dumps({"db": args.out, **crawl(args.base, args.out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
