"""Object-identifier co-occurrence graph — the BOLA "siblings / provenance" backbone.

Borrows Akto's value co-occurrence idea (their DependencyAnalyser stores response values
and links endpoints when a value recurs) but keeps Swarmie's redaction boundary: only a
NON-REVERSIBLE 12-hex hash of an id-like value is ever retained, and endpoints are named by
their structural ``(host, method, path_shape)`` key — never a raw path or a raw value. The
flow is always extract -> hash -> discard; no raw value is stored, persisted, or emitted.

It answers two questions a BOLA/IDOR hypothesis needs:
  * SIBLINGS  — which OTHER endpoints select an object with the same identifier
                ("resource 771 appears at GET /documents/{id} AND /download?document={id}");
  * PROVENANCE — did this request's identifier first appear in another endpoint's RESPONSE
                 (data flowed A.response -> B.request), so B may re-lookup without re-authorizing.

Stdlib only, deterministic, bounded. Nothing here references a target, product, or environment.
"""
from __future__ import annotations

import collections
import hashlib
import json
import re
from urllib.parse import parse_qs, urlsplit

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_NUMERIC = re.compile(r"^\d{4,}$")           # a 4+ digit integer id (small ints are too common)
_HEX = re.compile(r"^[0-9a-f]{12,}$", re.I)  # long hex handle / object id
_TOKENISH = re.compile(r"^[A-Za-z0-9_-]{12,}$")  # base64url-ish opaque id/token
_COMMON = {"true", "false", "null", "none", "undefined", "nan"}

_MAX_BODY_VALUES = 200   # cap flattened scalars per body
_MAX_DEPTH = 4
_DEFAULT_CAP = 100_000   # distinct id-hashes retained before oldest-first eviction


def is_id_like(value: object) -> bool:
    """True for values that plausibly SELECT an object (numeric/uuid/hex/opaque token)."""
    if not isinstance(value, str):
        value = str(value) if isinstance(value, int) else ""
    v = value.strip()
    if len(v) < 4 or len(v) > 200 or v.lower() in _COMMON:
        return False
    return bool(_UUID.match(v) or _NUMERIC.match(v) or _HEX.match(v) or _TOKENISH.match(v))


def value_hash(value: str) -> str:
    """Non-reversible 12-hex handle for an id-like value. The raw value is never kept."""
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:12]


def extract_request_ids(url: str) -> set[str]:
    """Id-like values from a request URL: path segments and query-string values."""
    out: set[str] = set()
    if not url:
        return out
    parts = urlsplit(url)
    for seg in (parts.path or "").split("/"):
        if is_id_like(seg):
            out.add(seg.strip())
    for _key, vals in parse_qs(parts.query or "").items():
        for v in vals:
            if is_id_like(v):
                out.add(v.strip())
    return out


def _flatten_scalars(obj, depth=0, out=None):
    if out is None:
        out = []
    if len(out) >= _MAX_BODY_VALUES or depth > _MAX_DEPTH:
        return out
    if isinstance(obj, dict):
        for v in obj.values():
            _flatten_scalars(v, depth + 1, out)
    elif isinstance(obj, list):
        for v in obj[:50]:
            _flatten_scalars(v, depth + 1, out)
    elif isinstance(obj, (str, int)):
        out.append(obj)
    return out


def extract_body_ids(body: str, content_type: str = "") -> set[str]:
    """Id-like scalar values from a JSON response body (bounded depth/count)."""
    if not body:
        return set()
    text = body.lstrip()
    if not (("json" in (content_type or "").lower()) or text[:1] in "{["):
        return set()
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return set()
    return {str(v).strip() for v in _flatten_scalars(parsed) if is_id_like(v)}


class ValueGraph:
    """Bounded id-hash -> {(endpoint, location)} index with sibling/provenance queries.

    ``endpoint`` is the structural ``(host, method, path_shape)`` tuple. ``location`` is
    "request" or "response". Only hashes and structural endpoint keys are stored.
    """

    def __init__(self, cap: int = _DEFAULT_CAP):
        self._cap = max(1, int(cap))
        self._idx: dict[str, set[tuple[str, str]]] = {}   # id_hash -> {(endpoint_str, location)}
        self._order: collections.deque[str] = collections.deque()

    @staticmethod
    def _ep(endpoint: tuple) -> str:
        return "\t".join(str(x) for x in endpoint)

    def record(self, id_values: set[str], endpoint: tuple, location: str) -> None:
        ep = self._ep(endpoint)
        for v in id_values:
            h = value_hash(v)
            slot = self._idx.get(h)
            if slot is None:
                if len(self._idx) >= self._cap:
                    self._evict()
                slot = self._idx[h] = set()
                self._order.append(h)
            slot.add((ep, location))

    def _evict(self) -> None:
        while self._order and len(self._idx) >= self._cap:
            old = self._order.popleft()
            self._idx.pop(old, None)

    def relate(self, id_values: set[str], endpoint: tuple) -> dict:
        """For this endpoint's id values, return other endpoints that share them.

        Returns ``{"siblings": {id_hash: [endpoint_tuple, ...]},
                   "origins":  {id_hash: [endpoint_tuple, ...]}}`` where *origins* is the
        subset seen in another endpoint's RESPONSE (data-flow into this request). The
        current endpoint is always excluded. Deterministic (sorted) output.
        """
        ep = self._ep(endpoint)
        siblings: dict[str, list] = {}
        origins: dict[str, list] = {}
        for v in id_values:
            h = value_hash(v)
            entries = self._idx.get(h)
            if not entries:
                continue
            others = sorted({e for (e, _loc) in entries if e != ep})
            if others:
                siblings[h] = [tuple(e.split("\t")) for e in others]
            resp = sorted({e for (e, loc) in entries if e != ep and loc == "response"})
            if resp:
                origins[h] = [tuple(e.split("\t")) for e in resp]
        return {"siblings": siblings, "origins": origins}
