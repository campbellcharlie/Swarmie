# jsdissect.py — FROZEN CONTRACT (ADR-0006)

Build `rqswarm_eval/perception/jsdissect.py`: Python 3.14, **stdlib only** (re, hashlib, json,
urllib.parse), pure, deterministic, never raises on any input. Mirror the style of
`rqswarm_eval/profile_adapter.py` (module-level compiled regexes + small pure functions).

## Public API
```
def dissect_js(text: str, base_url: str = "") -> dict
def value_hash(v: str) -> str           # sha256(v)[:12], reuse the exact shape from valuegraph.py
```
`dissect_js` returns EXACTLY these keys (always present; empty list/"" when none):
```
{
  "endpoints": [str, ...],   # API-ish absolute URLs + rooted paths found in string literals
  "params":    [str, ...],   # query/param NAMES referenced (from ?a=&b= and URLSearchParams/params keys)
  "graphql":   [str, ...],   # GraphQL operation names (query X / mutation X / operationName)
  "secrets":   [{"type": str, "hash": str, "context": str}, ...],   # TYPE + 12-hex hash + key-name; NEVER the raw value
  "sourcemap": str,          # the sourceMappingURL value, or ""
  "hosts":     [str, ...],   # distinct hostnames referenced
  "routes":    [str, ...],   # client route path patterns (best-effort; e.g. path:"/admin/:id")
}
```
All list values are sorted+deduped. Bound each list to <= 500 items. Truncate scanning text at
2_000_000 chars. Empty/non-str input -> all-empty result, no raise.

## Extraction rules (use these patterns; tune conservatively to avoid asset noise)
- **endpoints**: from quoted string literals, keep values that are (a) absolute
  `https?://<host>/<path>` OR (b) rooted paths `"/seg/seg..."` with >=2 path segments. DROP
  static assets (`\.(js|css|png|jpg|jpeg|gif|svg|webp|woff2?|ico|map|mp4)(\?|$)`), fragments,
  and pure template noise (`${...}` only). Keep paths containing `api|graphql|v\d|rest|rpc|
  service|internal|admin|user|account|auth|token|upload|download|export` OR any path with a
  `{...}`/`:param`/`%s` placeholder. Absolute URLs also contribute their host to `hosts`.
- **params**: names from `?k=`/`&k=` in extracted URLs, plus `searchParams.set('k'`,
  `params: { k: ... }`, `URLSearchParams({k:...})`.
- **graphql**: `\b(query|mutation|subscription)\s+([A-Za-z_]\w*)`, and `operationName["']?\s*[:=]\s*["'](\w+)`.
- **secrets** (TYPE + hash + context, NEVER raw): reuse the vendor prefixes from passive.py's
  `_JS_SECRET_PATTERNS` set (aws_access_key, slack_token, github_token, stripe_secret_key,
  google_api_key) PLUS generic assignment
  `(?i)\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password|
  bearer)\b["']?\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']` and JWT
  `eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`. For each hit emit
  `{"type": <family>, "hash": value_hash(<raw match value>), "context": <the key name or a
  <=24-char non-secret label>}`. The raw matched secret value MUST NOT appear anywhere in the
  returned dict (only its hash). Skip obvious placeholders (`YOUR_API_KEY`, `xxxx`, `example`,
  all-same-char).
- **sourcemap**: `//# sourceMappingURL=(\S+)` -> the URL (structural, not a secret).
- **hosts**: registrable hostnames from every absolute URL found.
- **routes**: best-effort — `path:\s*["'](/[^"']{1,80})["']` and react-router-ish `<Route ...
  path="/x/:id">`.

## Tests — `tests/test_jsdissect.py` (pytest, stdlib)
Cover, on hand-written JS strings: endpoint extraction (keeps `/api/v2/users/{id}`, drops
`/static/app.4f3.js`); param + graphql extraction; sourcemap; hosts. **Redaction invariant**:
a JS string containing `apiKey:"AKIAIOSFODNN7EXAMPLE"` and a JWT yields `secrets` with the right
`type`+`hash` and the raw key/JWT appear NOWHERE in `json.dumps(dissect_js(...))`. Determinism
(same input -> identical dict). Never-raises on `""`, `None`-ish, binary junk. Import only from
`rqswarm_eval.perception.jsdissect`.
