"""Response-side signal analysis for the captured request/response pair.

The capture DBs store the *response* (headers, body, status) alongside each
request. Those are the signals that separate a real hypothesis from noise --
reflection (XSS/SSTI), server error/stack signatures (injection), PII/secret
leakage (excessive-data-exposure / BOLA), permissive CORS, missing security
headers -- and, crucially, whether an id-bearing endpoint returns *data* or a
tracking *pixel*. Everything here reads already-captured bytes; nothing is sent.

Values are analyzed locally; only booleans, param *names*, categories, and a
secret-masked excerpt ever land on a card.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlsplit

# Precise, CASE-SENSITIVE error/stack signatures. Case-sensitivity matters: the
# loose case-insensitive version matched acronym fragments like "odbc" inside
# base64 tokens. These are shapes that only appear in a real server error page.
_ERR = re.compile(
    r"ORA-\d{5}|SQLSTATE\[|SQL syntax.{0,30}near|mysqli?_\w+\(|pg_query\(|"
    r"PG::\w+Error|MongoError:|sqlite3\.\w+Error|System\.Data\.SqlClient|"
    r"Microsoft OLE DB|Unclosed quotation mark|Incorrect syntax near|"
    r"Traceback \(most recent call last\)|\.java:\d+\)|at java\.[a-z]+\.|"
    r"System\.[A-Za-z.]+Exception:|goroutine \d+ \[|"
    r"Fatal error:|Parse error: syntax error|Notice: Undefined \w+|"
    r"Warning: [a-z_]+\(|"
    # added from the Juice Shop assessment: real leaks the tighter regex missed
    r"SQLITE_\w+:|Sequelize\w*Error|ER_[A-Z_]+:|SyntaxError: (?:Unexpected|Expected)"
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PRIVKEY = re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")
_SECRET_KEY = re.compile(
    r'"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|'
    r'private[_-]?key|client[_-]?secret|ssn|credit[_-]?card|card[_-]?number|cvv)"\s*:',
    re.I,
)


def _param_values(seed) -> list[tuple[str, str]]:
    """Request param (name, value) pairs from the query string and body."""
    pairs: list[tuple[str, str]] = []
    for k, vs in parse_qs(urlsplit(seed.url).query).items():
        for v in vs:
            pairs.append((k, v))
    body = seed.body or ""
    ct = (seed.content_type or "").lower()
    if body[:1] in "{[" or "json" in ct:
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            obj = None

        def walk(o, prefix=""):
            if isinstance(o, dict):
                for k, v in o.items():
                    if isinstance(v, (dict, list)):
                        walk(v, f"{prefix}{k}.")
                    else:
                        pairs.append((f"{prefix}{k}", str(v)))
            elif isinstance(o, list):
                for item in o[:10]:
                    walk(item, prefix)
        if obj is not None:
            walk(obj)
    elif "&" in body and "=" in body:
        for p in body.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                pairs.append((k, v))
    return pairs


def redact_text(text: str, limit: int = 240) -> str:
    """A short response excerpt with secrets/PII masked -- safe to show a judge."""
    if not text:
        return ""
    snippet = text[:limit]
    snippet = _JWT.sub("<jwt>", snippet)
    snippet = _EMAIL.sub("<email>", snippet)
    snippet = _PRIVKEY.sub("<private-key>", snippet)
    return snippet


_STATIC_CT = ("image/", "font/", "/css", "javascript", "video/", "audio/", "octet-stream")


def analyze_response(seed) -> dict:
    """Compute response-side signals for one captured pair.

    Static-asset responses (images, fonts, css, js, media) carry no reflection /
    leak / error surface, so they skip the regex scan -- this keeps the browsing
    corpora (mostly static) cheap.
    """
    ct = seed.resp_content_type or ""
    if any(x in ct for x in _STATIC_CT):
        return {
            "status": seed.status, "resp_content_type": ct,
            "resp_length": seed.resp_length or 0, "is_data_response": False,
            "reflected_params": [], "error_signature": None, "sensitive_in_response": [],
        }
    body = seed.resp_body or ""
    rh = {k.lower(): v for k, v in seed.resp_headers.items()}
    length = seed.resp_length or len(body)

    is_data = (
        length > 64
        and "image" not in ct
        and ("json" in ct or "xml" in ct or "html" in ct or "text" in ct or ct == "")
    )

    reflected = []
    if body and ("html" in ct or "json" in ct or "xml" in ct or ct == ""):
        for name, val in _param_values(seed):
            if val and len(val) >= 4 and val in body:
                reflected.append(name)

    err = _ERR.search(body)

    sensitive = []
    if _JWT.search(body):
        sensitive.append("jwt")
    if _PRIVKEY.search(body):
        sensitive.append("private_key")
    if _SECRET_KEY.search(body):
        sensitive.append("secret_keys")
    emails = set(_EMAIL.findall(body))
    if emails:
        sensitive.append(f"emails:{len(emails)}")

    signals: dict = {
        "status": seed.status,
        "resp_content_type": ct,
        "resp_length": length,
        "is_data_response": bool(is_data),
        "reflected_params": sorted(set(reflected))[:10],
        "error_signature": err.group(0)[:48] if err else None,
        "sensitive_in_response": sensitive,
    }

    # CORS only matters when it's actually risky: a *reflected specific origin*
    # or credentialed sharing. A bare ``*`` without credentials is how public
    # APIs/CDNs work -- not a finding.
    aco = rh.get("access-control-allow-origin")
    creds = rh.get("access-control-allow-credentials", "").lower() == "true"
    if aco and (creds or aco not in ("*", "null")):
        signals["cors_allow_origin"] = aco
        if creds:
            signals["cors_credentials"] = True
    if "html" in ct:
        signals["missing_sec_headers"] = [
            h for h in ("content-security-policy", "strict-transport-security", "x-frame-options")
            if h not in rh
        ]
    setcookie = seed.resp_headers.get("Set-Cookie") or rh.get("set-cookie")
    if setcookie:
        low = setcookie.lower()
        flags = [f for f, tok in (("no-HttpOnly", "httponly"), ("no-Secure", "secure")) if tok not in low]
        if flags:
            signals["weak_set_cookie"] = flags
    return signals
