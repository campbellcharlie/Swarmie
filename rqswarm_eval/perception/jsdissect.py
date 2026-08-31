"""Structural dissection of a JavaScript bundle — endpoints, params, secrets-by-hash.

Swarmie reads captured JS *as untrusted data* and extracts only STRUCTURE the LLM
hunter can reason about: API-ish paths, query/param names, GraphQL operation names,
client route patterns, referenced hostnames, and the sourcemap URL. Secrets are the
one sensitive class: a match is reported as ``{type, hash, context}`` where ``hash``
is the non-reversible 12-hex handle from :mod:`valuegraph` and ``context`` is only a
key name or short label. The raw secret VALUE is never placed in the returned dict
(project boundary #6 — no raw tokens/credentials leave the perception layer).

Mirrors the style of ``profile_adapter.py``: module-level compiled regexes plus small
pure functions. Stdlib only, deterministic, and never raises on any input — a bad or
non-string body yields the all-empty result rather than an exception.
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit
import re

# --- limits (bound work + output; boundary against pathological bundles) ---------
_MAX_TEXT = 2_000_000     # scan at most 2 MB of source
_MAX_LIST = 500           # cap every list field

# --- string-literal harvesting ---------------------------------------------------
# Contents of "double", 'single', and `template` literals. Newlines only allowed in
# template literals. Escapes are consumed so an escaped quote does not end the string.
_STRING_LITERAL = re.compile(
    r'"(?P<dq>(?:[^"\\\n]|\\.)*)"'
    r"|'(?P<sq>(?:[^'\\\n]|\\.)*)'"
    r"|`(?P<bt>(?:[^`\\]|\\.)*)`"
)

# --- endpoint classification -----------------------------------------------------
_ABS_URL = re.compile(r"^https?://", re.I)
# Static asset / non-endpoint noise to drop (extension at end of path or before query).
_STATIC_ASSET = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|svg|webp|woff2?|ico|map|mp4)(?:$|\?)", re.I
)
# Keep only paths that look API-ish (keyword) or carry a template placeholder.
_API_KEYWORD = re.compile(
    r"(?:api|graphql|v\d|rest|rpc|service|internal|admin|user|account|auth|token"
    r"|upload|download|export)",
    re.I,
)
# Placeholder forms: {id} / :param / %s (a ${x} template also trips the {..} branch).
_PLACEHOLDER = re.compile(r"\{[^}\s]{1,40}\}|/:[A-Za-z_]\w*|%s")

# --- params ----------------------------------------------------------------------
_QUERY_PARAM = re.compile(r"[?&]([A-Za-z_][\w.\-]*)=")
_SEARCHPARAMS = re.compile(
    r"[Ss]earchParams\.\w+\(\s*[\"']([A-Za-z_][\w.\-]*)[\"']"
)
# `params: { ... }` and `URLSearchParams({ ... })` object literals (non-nested body).
_PARAMS_BLOCK = re.compile(
    r"(?:\bparams\s*:\s*|\bURLSearchParams\s*\(\s*)\{([^{}]{0,500})\}"
)
_OBJ_KEY = re.compile(r"(?:^|,)\s*[\"']?([A-Za-z_]\w*)[\"']?\s*:")

# --- graphql ---------------------------------------------------------------------
_GQL_OP = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_]\w*)")
_GQL_OPNAME = re.compile(r"operationName[\"']?\s*[:=]\s*[\"'](\w+)")

# --- secrets (TYPE + hash + context, NEVER raw) ----------------------------------
# Vendor prefixes reused verbatim from passive.py's _JS_SECRET_PATTERNS /
# _PUBLISHABLE_KEY_PATTERNS so classification stays consistent across the codebase.
_SECRET_VENDORS = (
    ("aws_access_key",
     re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("github_token", re.compile(r"\bgh[pusor]_[A-Za-z0-9]{36}\b")),
    ("stripe_secret_key", re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
)
_SECRET_ASSIGN = re.compile(
    r"""(?i)\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token"""
    r"""|auth[_-]?token|password|bearer)\b["']?\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']"""
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")

# Obvious non-secrets to skip (documentation placeholders / filler).
_PLACEHOLDER_PREFIXES = ("your", "example", "changeme", "placeholder", "dummy", "sample")

# --- routes ----------------------------------------------------------------------
_ROUTE_PATH = re.compile(r"""path\s*:\s*["'](/[^"']{1,80})["']""")
_ROUTE_JSX = re.compile(
    r"""<Route\b[^>]*\bpath\s*=\s*["'](/[^"']{1,80})["']""", re.I
)

# --- sourcemap -------------------------------------------------------------------
_SOURCEMAP = re.compile(r"//# sourceMappingURL=(\S+)")

# Boundary #6: a secret can hide in a PATH SEGMENT (/reset/<jwt>), a sourcemap fragment, or a
# mis-parsed "host". _extract_secrets redacts the secrets[] field, but every OTHER structural
# extractor copies substrings verbatim, so scrub secret-shaped substrings from all of them.
_SCRUB = re.compile(
    r"(?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"        # AWS access key
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"                                          # Slack token
    r"|gh[pusor]_[A-Za-z0-9]{20,}"                                            # GitHub token
    r"|(?:sk|pk|rk|cs|whsec)_(?:live|test)_[0-9a-zA-Z]{8,}"                   # Stripe key/session
    r"|AIza[0-9A-Za-z_\-]{35}"                                                # Google API key
    r"|eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"          # JWT
    r"|[0-9a-fA-F]{16,}"                                                       # long hex id/secret
    r"|(?=[A-Za-z0-9_-]{0,80}[0-9])[A-Za-z0-9_-]{20,}",                        # 20+ opaque token w/ a digit
    re.I,
)


def _redact(s: str) -> str:
    """Replace any secret-shaped substring with a stable marker so no raw secret survives in
    endpoints/routes/hosts/sourcemap while the structural shape is preserved (boundary #6)."""
    return _SCRUB.sub("{redacted}", s) if s else s


def value_hash(v: str) -> str:
    """Non-reversible 12-hex handle for a value. Reuses valuegraph.value_hash shape."""
    return hashlib.sha256(str(v).encode("utf-8", "replace")).hexdigest()[:12]


def _empty() -> dict:
    return {
        "endpoints": [],
        "params": [],
        "graphql": [],
        "secrets": [],
        "sourcemap": "",
        "hosts": [],
        "routes": [],
    }


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def _looks_placeholder(v: str) -> bool:
    """True for filler tokens (YOUR_API_KEY, example, xxxx, all-same-char)."""
    s = v.strip()
    if len(s) < 8:
        return True
    if len(set(s)) == 1:            # all-same-char
        return True
    low = s.lower()
    if low.startswith(_PLACEHOLDER_PREFIXES):
        return True
    if "xxxx" in low:
        return True
    return False


def _iter_literals(text: str):
    """Yield the decoded content of each string / template literal in ``text``."""
    for m in _STRING_LITERAL.finditer(text):
        content = m.group("dq")
        if content is None:
            content = m.group("sq")
        if content is None:
            content = m.group("bt")
        if content:
            yield content


def _classify_ref(s: str) -> tuple[str | None, str | None]:
    """Return (endpoint_or_None, host_or_None) for one string literal.

    Endpoints are stored structurally (scheme://host/path or /path) with query and
    fragment stripped so no query VALUES are retained. Every absolute or
    protocol-relative URL contributes its host regardless of endpoint keep/drop.
    """
    s = s.strip()
    if not s:
        return None, None

    if _ABS_URL.match(s):
        p = urlsplit(s)
        host = (p.hostname or "").lower()
        path = p.path or ""
        endpoint = None
        if host and not _STATIC_ASSET.search(path):
            if _API_KEYWORD.search(host + path) or _PLACEHOLDER.search(path):
                endpoint = f"{(p.scheme or 'http').lower()}://{host}{path}"
        return endpoint, (host or None)

    if s.startswith("//") and not s.startswith("///"):
        p = urlsplit("http:" + s)
        host = (p.hostname or "").lower()
        path = p.path or ""
        endpoint = None
        if host and not _STATIC_ASSET.search(path):
            if _API_KEYWORD.search(host + path) or _PLACEHOLDER.search(path):
                endpoint = f"//{host}{path}"
        return endpoint, (host or None)

    if s.startswith("/"):
        path = urlsplit(s).path or ""
        segs = [seg for seg in path.split("/") if seg]
        if len(segs) < 2 or _STATIC_ASSET.search(path):
            return None, None
        if _API_KEYWORD.search(path) or _PLACEHOLDER.search(path):
            return path, None
        return None, None

    return None, None


def _extract_secrets(text: str) -> list[dict]:
    """Vendor + generic-assignment + JWT hits as {type, hash, context}. Raw never kept."""
    seen: dict[tuple[str, str, str], dict] = {}

    def _add(kind: str, raw: str, context: str) -> None:
        if not raw or _looks_placeholder(raw):
            return
        entry = {"type": kind, "hash": value_hash(raw), "context": context[:24]}
        seen[(entry["type"], entry["hash"], entry["context"])] = entry

    for name, pat in _SECRET_VENDORS:
        for m in pat.finditer(text):
            _add(name, m.group(0), name)
    for m in _SECRET_ASSIGN.finditer(text):
        _add("generic_secret", m.group(2), m.group(1) or "generic_secret")
    for m in _JWT.finditer(text):
        _add("jwt", m.group(0), "jwt")

    return sorted(seen.values(), key=lambda d: (d["type"], d["context"], d["hash"]))


def dissect_js(text: str, base_url: str = "") -> dict:
    """Extract structural intelligence from a JS bundle. Never raises.

    Returns the fixed key set; all lists are sorted, deduped, and capped at 500.
    Secrets carry only ``{type, hash, context}`` — the raw matched value appears
    nowhere in the result. ``base_url`` (when a real URL) contributes its origin
    host to ``hosts``; it is otherwise unused (endpoints stay in their literal shape).
    """
    if not isinstance(text, str) or not text:
        return _empty()

    try:
        text = text[:_MAX_TEXT]

        endpoints: set[str] = set()
        hosts: set[str] = set()
        params: set[str] = set()

        base_host = _host_of(base_url) if base_url else ""
        if base_host:
            hosts.add(base_host)

        for lit in _iter_literals(text):
            endpoint, host = _classify_ref(lit)
            if endpoint:
                endpoints.add(endpoint)
            if host:
                hosts.add(host)
            # Query param NAMES from URL-ish literals (values are discarded).
            stripped = lit.strip()
            if stripped[:1] == "/" or _ABS_URL.match(stripped):
                params.update(_QUERY_PARAM.findall(stripped))

        params.update(_SEARCHPARAMS.findall(text))
        for body in _PARAMS_BLOCK.findall(text):
            params.update(_OBJ_KEY.findall(body))

        graphql: set[str] = set()
        graphql.update(_GQL_OP.findall(text))
        graphql.update(_GQL_OPNAME.findall(text))

        routes: set[str] = set()
        routes.update(_ROUTE_PATH.findall(text))
        routes.update(_ROUTE_JSX.findall(text))

        sourcemap = ""
        for m in _SOURCEMAP.finditer(text):
            sourcemap = m.group(1)   # last one wins, per the JS sourcemap convention

        def _cap(values: set[str]) -> list[str]:
            return sorted({_redact(v) for v in values})[:_MAX_LIST]

        return {
            "endpoints": _cap(endpoints),
            "params": _cap(params),
            "graphql": _cap(graphql),
            "secrets": _extract_secrets(text)[:_MAX_LIST],
            "sourcemap": _redact(sourcemap.split("#", 1)[0].split("?", 1)[0])[:512],
            "hosts": _cap(hosts),
            "routes": _cap(routes),
        }
    except Exception:
        # Contract: never raise. A malformed body yields the all-empty result.
        return _empty()
