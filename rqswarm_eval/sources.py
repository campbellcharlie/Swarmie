"""Source-agnostic seed reader for captured-traffic databases.

Supported HTTP-capture proxies persist an *identical* ``http_traffic`` ⋈
``http_messages`` SQLite schema: a 26-column ``http_traffic`` table joined to an
``http_messages`` table with ``request_headers/request_body/response_headers/
response_body`` columns. So one reader serves any of them -- point it at any such ``.db``.

Read-only: the source database is opened ``mode=ro`` and never written. Secrets
(cookies, auth headers, credential-shaped body values) are stripped before any
card is produced -- only request *structure* (methods, path shapes, parameter
and body-key *names*, content types, feature flags) ever leaves this module.
Nothing here sends network traffic.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_SECRET_HEADERS = {
    "cookie", "authorization", "proxy-authorization", "x-api-key",
    "x-auth-token", "api-key", "x-csrf-token", "set-cookie",
}
# A path segment that looks like an opaque id (long number, uuid, long hex).
_ID_SEG = re.compile(r"^(\d{2,}|[0-9a-fA-F-]{20,}|[0-9a-fA-F]{12,})$")
# Credential/opaque-token PATH SEGMENTS are collapsed to {id} too, so a secret-shaped value can
# never survive raw inside a path_shape (boundary #6 -- path_shape is emitted in every envelope).
# Shapes mirror the response-body secret patterns in passive.py; every prefix here is unambiguous
# and never occurs as a route name, so collapsing is safe (unlike a generic token regex, which
# would eat words like "documentation").
_SECRET_SEG = re.compile(
    r"(?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"    # AWS access key id
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"                                      # Slack token
    r"|gh[pusor]_[A-Za-z0-9]{20,}"                                       # GitHub token
    r"|(?:sk|pk|rk|cs|whsec)_(?:live|test)_[0-9a-zA-Z]{8,}"              # Stripe key / session id
    r"|sk-[A-Za-z0-9]{20,}"                                               # OpenAI-style key
    r"|AIza[0-9A-Za-z_-]{35}"                                             # Google API key
    r"|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"     # JWT
)


@dataclass
class Seed:
    request_id: int
    method: str
    url: str
    host: str
    path: str
    headers: dict            # parsed request headers, NOT redacted (local profiling only)
    body: str                # request body
    content_type: str        # request content-type
    status: int = 0
    resp_headers: dict = field(default_factory=dict)
    resp_body: str = ""
    resp_content_type: str = ""
    resp_length: int = 0


_MAX_BODY_SCAN = 65536  # cap text used for local scanning (reflection, signatures)


def _as_text(val) -> str:
    """Decode a request/response body to text, capped so scanning stays cheap."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        val = val.decode("utf-8", errors="replace")
    return str(val)[:_MAX_BODY_SCAN]


def parse_headers(raw) -> dict:
    """Parse a raw ``Key: Value`` HTTP header block into a dict (last wins)."""
    out: dict[str, str] = {}
    if not raw:
        return out
    for line in str(raw).splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        if key:
            out[key] = val.strip()
    return out


def path_shape(path: str) -> str:
    """Collapse opaque id segments to ``{id}`` so distinct instances share a shape."""
    return "/".join(
        "{id}" if _ID_SEG.match(seg) or _SECRET_SEG.search(seg) else seg
        for seg in (path or "/").split("/")
    )


def redact_headers(headers: dict) -> dict:
    """Return headers with secret values masked -- names kept, values gone."""
    return {
        k: ("<redacted>" if k.lower() in _SECRET_HEADERS else v)
        for k, v in headers.items()
    }


def body_skeleton(body: str, content_type: str) -> list[str]:
    """Describe a body by its *key names* only -- never its values.

    JSON  -> dotted key paths (values dropped). Form -> field names.
    XML   -> ['<xml>']. Anything else -> ['<opaque N bytes>'].
    A credential-shaped key still emits only its *name*, so no secret value
    ever leaves.
    """
    if not body:
        return []
    stripped = body.lstrip()
    ct = (content_type or "").lower()
    if "json" in ct or stripped[:1] in "{[":
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            return ["<unparsed-json>"]
        keys: list[str] = []

        def walk(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    dotted = f"{prefix}{k}"
                    keys.append(dotted)
                    walk(v, dotted + ".")
            elif isinstance(obj, list) and obj:
                walk(obj[0], prefix + "[].")

        walk(parsed)
        return keys[:40]
    if "form" in ct or ("=" in stripped and "&" in stripped and stripped[:1] != "<"):
        return sorted({p.split("=", 1)[0] for p in stripped.split("&") if p})[:40]
    if "xml" in ct or stripped[:1] == "<":
        return ["<xml>"]
    return [f"<opaque {len(body)} bytes>"]


def iter_seeds(db_path: str, limit: int | None = None, with_body_first: bool = False):
    """Yield ``Seed`` rows from any http_traffic⋈http_messages capture DB (read-only).

    Orders by request_id (primary key) so only the returned rows' bodies are
    read -- fast even on multi-GB corpora. Body columns are ``substr``-capped in
    SQL so multi-MB response blobs are never transferred or decoded. Set
    ``with_body_first`` to prioritize requests carrying a body, at the cost of a
    full-table body scan (only worth it for a small ``limit`` on one big DB).
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        # Captured bodies include binary (images) and imperfect UTF-8; never throw.
        conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
        order = (
            "ORDER BY (LENGTH(COALESCE(m.request_body,'')) > 0) DESC, t.request_id DESC"
            if with_body_first
            else "ORDER BY t.request_id DESC"
        )
        sql = (
            "SELECT t.request_id, t.method, t.url, t.host, t.path, t.content_type, "
            "t.status_code, t.response_length, "
            "m.request_headers, substr(m.request_body,1,65536) AS request_body, "
            "m.response_headers, substr(m.response_body,1,65536) AS response_body "
            "FROM http_traffic t JOIN http_messages m USING(request_id) " + order
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in conn.execute(sql):
            headers = parse_headers(row["request_headers"])
            resp_headers = parse_headers(row["response_headers"])
            body = _as_text(row["request_body"])
            resp_body = _as_text(row["response_body"])
            parts = urlsplit(row["url"] or "")
            if parts.scheme not in ("http", "https"):
                continue  # skip data:/blob:/about: pseudo-requests -- not network traffic
            yield Seed(
                request_id=int(row["request_id"]),
                method=(row["method"] or "GET").upper(),
                url=row["url"] or "",
                host=row["host"] or parts.netloc,
                path=parts.path or (row["path"] or "/"),
                headers=headers,
                body=body,
                content_type=headers.get("Content-Type", headers.get("content-type", "")),
                status=int(row["status_code"] or 0),
                resp_headers=resp_headers,
                resp_body=resp_body,
                resp_content_type=(row["content_type"]
                                   or resp_headers.get("Content-Type", "")).split(";")[0].strip().lower(),
                resp_length=int(row["response_length"] or len(resp_body)),
            )
    finally:
        conn.close()
