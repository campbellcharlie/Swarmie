"""Deterministic feature layer for a `swarmie.signal.v1` envelope.

One fixed vocabulary of structural "tells" — reason-family counts, request/response
shape, baseline rarity, and signal-level scalars — turned into a flat named vector. The
interest lane (core) and the sidecar scorer both consume this exact vector, so the order
in `FEATURE_NAMES` is FROZEN (ADR-0003) and every name maps to a finite float.

Pure and stdlib-only. Never raises: any missing / malformed key is treated as absent and
scored as zero. Nothing here references a target, product, or environment; the envelope
is untrusted data, read for structure only (CLAUDE.md boundary #8).
"""
from __future__ import annotations

import math

# Canonical feature order, FROZEN. Every consumer indexes by name via this list.
FEATURE_NAMES: list[str] = [
    # reason-family counts (each reason -> a family via REASON_FAMILY; count per family)
    "rf_idor", "rf_injection", "rf_leak", "rf_error", "rf_auth", "rf_cors", "rf_cache",
    "rf_exfil", "rf_redirect", "rf_jwt", "rf_disclosure", "rf_novel_status",
    "rf_novel_shape", "rf_other",
    # request structure
    "req_header_count", "req_query_count", "req_body_key_count", "req_auth_present",
    "req_has_body", "req_ct_json", "req_ct_form", "req_ct_xml", "req_ct_multipart",
    "req_ct_other",
    # response structure
    "resp_2xx", "resp_3xx", "resp_4xx", "resp_5xx",
    "resp_ct_json", "resp_ct_html", "resp_ct_js", "resp_ct_xml", "resp_ct_text",
    "resp_ct_other",
    "resp_length_log", "resp_json_key_count", "resp_has_fingerprint",
    # baseline / rarity
    "base_obs_log", "base_status_seen", "base_ctype_seen",
    # signal-level
    "sig_attention_norm", "sig_reason_count", "sig_hypothesis_count", "sig_lens_count",
    "sig_learned_hit",
]

# Counts are clipped to this cap before being stored as a float, so one pathological
# request (hundreds of headers/keys) cannot dominate the vector. Chosen well above a
# normal header/key/reason count; log-scaled fields (`*_log`) are exempt.
_COUNT_CAP = 32.0

# Reason substring -> rf_* family (the value is the family SUFFIX, i.e. rf_<value>).
# Matching is: lowercase the reason, take the FIRST key that is a substring of it;
# anything unmatched increments rf_other. Order matters — more specific / higher-priority
# keys come first so e.g. an authenticated cache contradiction lands in `cache`, not
# `auth`, and an XSS/XXE/reflection route lands in `injection`. The families themselves
# are frozen by FEATURE_NAMES; this map is the (extensible) reason vocabulary.
REASON_FAMILY: dict[str, str] = {
    "idor": "idor",
    "jwt": "jwt",
    "cors": "cors",
    "cache": "cache",
    "exfil": "exfil",
    "outbound": "exfil",
    "ssrf": "redirect",
    "redirect": "redirect",
    "new_status": "novel_status",
    "new_content_type": "novel_shape",
    "content_type_drift": "novel_shape",
    "schema_expansion": "novel_shape",
    "declared_": "novel_shape",
    "batch_payload": "novel_shape",
    "injection": "injection",
    "xss": "injection",
    "xxe": "injection",
    "reflection": "injection",
    "error": "error",
    "stack": "error",
    "resp:leak": "leak",
    "leak": "leak",
    "excessive": "leak",
    "pii": "leak",
    "secret": "leak",
    "disclosure": "disclosure",
    "exposure": "disclosure",
    "exposed": "disclosure",
    "auth": "auth",
    "credential": "auth",
}

_RF_PREFIX = "rf_"
# The 14 family suffixes, in FEATURE_NAMES order, including the "other" fallback.
_REASON_FAMILIES: list[str] = [n[len(_RF_PREFIX):] for n in FEATURE_NAMES
                               if n.startswith(_RF_PREFIX)]


def _num(value: object, default: float = 0.0) -> float:
    """Coerce to a finite float, or `default` for None/non-numeric/NaN/inf."""
    try:
        out = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return out if math.isfinite(out) else default


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _clip_count(n: int) -> float:
    """A raw count, clipped at `_COUNT_CAP` and returned as a float."""
    if n < 0:
        n = 0
    return float(min(n, int(_COUNT_CAP)))


def _reason_family(reason: str) -> str:
    """Map one reason string to a family suffix; unmatched -> 'other'."""
    low = reason.lower()
    for key, family in REASON_FAMILY.items():
        if key in low:
            return family if family in _REASON_FAMILIES else "other"
    return "other"


def _request_ct_bucket(content_type: str) -> str | None:
    """Request content-type -> {json,form,xml,multipart,other}; None if absent."""
    ct = content_type.lower()
    if not ct:
        return None
    if "json" in ct:
        return "json"
    if "multipart" in ct:  # before "form" — multipart/form-data contains "form"
        return "multipart"
    if "form" in ct:
        return "form"
    if "xml" in ct:
        return "xml"
    return "other"


def _response_ct_bucket(content_type: str) -> str | None:
    """Response content-type -> {json,html,js,xml,text,other}; None if absent."""
    ct = content_type.lower()
    if not ct:
        return None
    if "json" in ct:
        return "json"
    if "html" in ct:  # before "text" — text/html contains "text"
        return "html"
    if "javascript" in ct or "ecmascript" in ct:  # before "text" — text/javascript
        return "js"
    if "xml" in ct:  # before "text" — text/xml
        return "xml"
    if "text" in ct:
        return "text"
    return "other"


def observation_features(envelope: dict) -> dict[str, float]:
    """Every FEATURE_NAME -> a finite float, computed purely from `envelope`.

    Missing or malformed keys are treated as absent (zero); this never raises.
    """
    env = _as_dict(envelope)
    obs = _as_dict(env.get("observation"))
    req = _as_dict(obs.get("request"))
    resp = _as_dict(obs.get("response"))
    base = _as_dict(obs.get("baseline"))
    reasons = _as_list(obs.get("reasons"))

    feat: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}

    # --- reason-family counts ---
    fam_counts: dict[str, int] = {fam: 0 for fam in _REASON_FAMILIES}
    for reason in reasons:
        fam = _reason_family(reason) if isinstance(reason, str) else "other"
        fam_counts[fam] += 1
    for fam, count in fam_counts.items():
        feat[_RF_PREFIX + fam] = _clip_count(count)

    # --- request structure ---
    body_keys = _as_list(req.get("body_keys"))
    feat["req_header_count"] = _clip_count(len(_as_list(req.get("header_names"))))
    feat["req_query_count"] = _clip_count(len(_as_list(req.get("query_names"))))
    feat["req_body_key_count"] = _clip_count(len(body_keys))
    feat["req_auth_present"] = 1.0 if req.get("auth_present") else 0.0
    feat["req_has_body"] = 1.0 if (body_keys or req.get("body_sha256")) else 0.0
    req_bucket = _request_ct_bucket(str(req.get("content_type") or ""))
    if req_bucket is not None:
        feat["req_ct_" + req_bucket] = 1.0

    # --- response structure ---
    status = int(_num(resp.get("status"), 0.0))
    if 200 <= status < 300:
        feat["resp_2xx"] = 1.0
    elif 300 <= status < 400:
        feat["resp_3xx"] = 1.0
    elif 400 <= status < 500:
        feat["resp_4xx"] = 1.0
    elif 500 <= status < 600:
        feat["resp_5xx"] = 1.0
    resp_bucket = _response_ct_bucket(str(resp.get("content_type") or ""))
    if resp_bucket is not None:
        feat["resp_ct_" + resp_bucket] = 1.0
    feat["resp_length_log"] = math.log1p(max(0.0, _num(resp.get("length"), 0.0)))
    feat["resp_json_key_count"] = _clip_count(len(_as_list(resp.get("json_keys"))))
    feat["resp_has_fingerprint"] = 1.0 if resp.get("fingerprint") else 0.0

    # --- baseline / rarity ---
    feat["base_obs_log"] = math.log1p(
        max(0.0, _num(base.get("endpoint_observations"), 0.0)))
    statuses = _as_dict(base.get("statuses"))
    status_keys = {str(k) for k in statuses}
    feat["base_status_seen"] = 1.0 if str(status) in status_keys else 0.0
    ctypes = _as_dict(base.get("content_types"))
    resp_ct_raw = str(resp.get("content_type") or "")
    ctype_keys = {str(k).lower() for k in ctypes}
    feat["base_ctype_seen"] = (
        1.0 if resp_ct_raw and resp_ct_raw.lower() in ctype_keys else 0.0)

    # --- signal-level ---
    attention = _as_dict(env.get("attention"))
    feat["sig_attention_norm"] = min(1.0, max(0.0, _num(attention.get("score"), 0.0) / 100.0))
    feat["sig_reason_count"] = _clip_count(len(reasons))
    feat["sig_hypothesis_count"] = _clip_count(len(_as_list(env.get("hypotheses"))))
    interrogation = _as_dict(env.get("interrogation"))
    feat["sig_lens_count"] = _clip_count(len(_as_list(interrogation.get("lenses"))))
    feat["sig_learned_hit"] = 1.0 if _as_list(env.get("learned")) else 0.0

    # Canonical order + a final finiteness guard.
    return {name: (feat[name] if math.isfinite(feat[name]) else 0.0)
            for name in FEATURE_NAMES}


def feature_list(envelope: dict) -> list[float]:
    """The feature vector as a plain list in FEATURE_NAMES order."""
    features = observation_features(envelope)
    return [features[name] for name in FEATURE_NAMES]
