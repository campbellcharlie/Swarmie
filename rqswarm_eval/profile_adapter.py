"""Read-only observable-feature request profiler + routing.

Deterministic, stdlib-only pass over the harness ``Request`` shape: it derives
observable request features and a set of routing flags (candidate vector
categories) from a captured ``http_traffic`` row, with no network access and no
external dependencies.

The output is a proposal signal plus an explicit anti-overclaim control: a routing
flag is NEVER discovery credit on its own -- only an exact executed transaction
plus a hidden-oracle match earns credit. See ``evidence.is_credited``.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

# --- patterns mirrored from request_profiler.py (observable-feature subset) ---

_ID_KEY_PATTERNS = [
    re.compile(
        r"\b(id|user_?id|account_?id|order_?id|item_?id|doc_?id|file_?id|record_?id)\b",
        re.I,
    ),
]
_ID_VALUE_NUMERIC = re.compile(r"^\d{4,}$")
_ID_VALUE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# X-* headers the real profiler treats as standard (not custom).
_STANDARD_X_HEADERS = {
    "x-content-type-options", "x-frame-options", "x-xss-protection", "x-powered-by",
    "x-request-id", "x-correlation-id", "x-cache", "x-forwarded-for", "x-real-ip",
    "x-amz-cf-id", "x-amz-request-id",
}


def _request_view(request: Any) -> tuple[str, str, dict[str, str], str]:
    """Normalize a Request (or a mapping) into (method, url, lower-key headers, body_str)."""
    if isinstance(request, dict):
        method = request.get("method", "GET")
        url = request.get("url", "")
        headers = request.get("headers", {}) or {}
        body = request.get("body", None)
    else:
        method = getattr(request, "method", "GET")
        url = getattr(request, "url", "")
        headers = getattr(request, "headers", {}) or {}
        body = getattr(request, "body", None)
    lowered = {str(k).lower(): str(v) for k, v in dict(headers).items()}
    if isinstance(body, bytes):
        body_str = body.decode("utf-8", errors="replace")
    elif body is None:
        body_str = ""
    else:
        body_str = str(body)
    return (str(method or "GET").upper(), str(url or ""), lowered, body_str)


def _find_id_params_query(qs: dict[str, list[str]]) -> list[str]:
    ids: list[str] = []
    for key, values in qs.items():
        if any(pat.search(key) for pat in _ID_KEY_PATTERNS):
            ids.append(key)
            continue
        for val in values:
            if _ID_VALUE_NUMERIC.match(val) or _ID_VALUE_UUID.match(val):
                ids.append(key)
                break
    return ids


def _find_id_params_json(obj: Any, depth: int = 0) -> list[str]:
    if depth > 3:
        return []
    ids: list[str] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if any(pat.search(str(key)) for pat in _ID_KEY_PATTERNS):
                ids.append(str(key))
            ids += _find_id_params_json(val, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:5]:
            ids += _find_id_params_json(item, depth + 1)
    return ids


def profile_request(request: Any) -> dict:
    """Deterministic observable-feature profile of a harness ``Request``.

    Mirrors request_profiler.profile_row for the fields derivable without a
    captured response: input surfaces, ID-like params, JWT presence, GraphQL,
    XML, WebSocket, file-upload, cookies, custom headers, and protocol. Response
    signals (reflection, stack traces, CSP) are unknowable at proposal time and
    are reported as their empty/false defaults.
    """
    method, url, headers, body_str = _request_view(request)

    parts = urlsplit(url)
    path = parts.path or "/"
    qs = parse_qs(parts.query)

    req_ct = headers.get("content-type", "").split(";")[0].strip().lower()

    input_surfaces: list[str] = []
    id_params: list[str] = []
    graphql = False
    xml_body = False
    file_upload = False

    if qs:
        input_surfaces.append("url_params")
        id_params += _find_id_params_query(qs)

    if body_str:
        if "json" in req_ct or body_str.lstrip().startswith(("{", "[")):
            input_surfaces.append("json_body")
            try:
                parsed = json.loads(body_str)
            except (ValueError, TypeError):
                parsed = None
            if parsed is not None:
                id_params += _find_id_params_json(parsed)
                if isinstance(parsed, dict) and "query" in parsed:
                    graphql = True
        elif "form" in req_ct:
            if "multipart" in req_ct:
                file_upload = True
            input_surfaces.append("form_fields")
        elif "xml" in req_ct or body_str.lstrip().startswith("<"):
            xml_body = True
            input_surfaces.append("xml_body")
        else:
            input_surfaces.append("body")

    has_user_input = bool(qs) or bool(body_str)

    if headers.get("cookie"):
        input_surfaces.append("cookies")

    if "/graphql" in path.lower():
        graphql = True

    # JWT: scan header values + body (the real profiler scans header text + body).
    scan_text = "\n".join(headers.values()) + "\n" + body_str
    jwt_tokens = sorted(set(_JWT_PATTERN.findall(scan_text)))
    jwt_present = bool(jwt_tokens)

    websocket = "websocket" in headers.get("upgrade", "").lower()

    custom_headers = sorted(
        k for k in headers
        if k.startswith("x-") and k not in _STANDARD_X_HEADERS
    )

    proto_hint = headers.get("http-version", "") or headers.get("x-forwarded-proto", "")
    protocol = "h2" if "2" in proto_hint else "h1"

    return {
        "url": url,
        "method": method,
        "path": path,
        "request_content_type": req_ct,
        "response_content_type": "",       # unknowable at proposal time
        "response_status": 0,
        "input_surfaces": input_surfaces,
        "has_user_input": has_user_input,
        "has_reflection": False,           # requires a response body
        "reflects_params": [],
        "id_params": sorted(set(id_params)),
        "jwt_present": jwt_present,
        "jwt_tokens": jwt_tokens,
        "graphql": graphql,
        "xml_body": xml_body,
        "file_upload": file_upload,
        "websocket": websocket,
        "custom_headers": custom_headers,
        "protocol": protocol,
    }


def route_features(profile: dict) -> list[str]:
    """Map an observable profile to deterministic route-feature tokens.

    Precedence mirrors routing.route: WebSocket/GraphQL short-circuit; then
    file-upload, XXE, IDOR, injection, and JWT accumulate. Tokens are the B7
    routing policy, not evidence. An empty list means "no testable surface" and
    B7 falls back to plain templated replay.
    """
    features: list[str] = []

    if profile.get("websocket"):
        return ["route:websocket-injection"]

    if profile.get("graphql"):
        return ["route:graphql"]

    if profile.get("file_upload"):
        features.append("route:file-attack")

    if profile.get("xml_body"):
        features.append("route:xxe")

    if profile.get("id_params"):
        features.append("route:idor")

    req_ct = profile.get("request_content_type", "")
    if profile.get("has_user_input") and "json" in req_ct:
        features.append("route:injection")

    if profile.get("jwt_present"):
        features.append("route:jwt")

    surfaces = set(profile.get("input_surfaces", []))
    if surfaces & {"url_params", "form_fields"} and "json_body" not in surfaces:
        features.append("route:xss-stored")

    # Deduplicate while preserving precedence order.
    seen: set[str] = set()
    ordered: list[str] = []
    for feat in features:
        if feat not in seen:
            seen.add(feat)
            ordered.append(feat)
    return ordered
