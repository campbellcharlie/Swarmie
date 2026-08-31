# ZAP passive-rule borrow-list for the passive signal engine

Goal: map OWASP ZAP's **passive** scan rules (analyze an already-captured
response; send no traffic) onto gaps in our passive HTTP signal engine, so the
high-value, cheap ones can be added without turning the sluice box into a
scanner.

**Constraints for every proposal below:** Python 3.14 **stdlib-only**
(`re`, `http.cookies`, `urllib.parse`, `base64`, `json` — all already imported
or trivially importable), fast (regex / header / structural checks only), and
**passive** (reads the hydrated pair; emits a hypothesis, never a verdict; no
raw values into the mailbox per boundary #6). A "signal family" here is a new
`reason` string added to `_REASON_WEIGHT` plus its append site, mirroring the
existing H1-H12 pattern.

Source of truth for the rule inventory: `zaproxy/zap-extensions` dirs
`addOns/pscanrules`, `pscanrulesBeta`, `pscanrulesAlpha`
(`Messages.properties`, verified 2026-08-29). Every ZAP `pscan` rule is passive
by construction, so nothing here needed excluding as "active" — the filtering
below is by **value**, not by attack/passive.

---

## What Swarmie already detects (baseline)

Compiled from `_REASON_WEIGHT` and the appended reason strings in
`rqswarm_eval/passive.py`:

- **Anomaly/baseline:** `new_status_for_endpoint`, `new_content_type_for_endpoint`,
  `response_length_outlier`, `status_spike_in_run`, `request_content_type_drift`,
  `outbound_request_size_spike`, `request_schema_expansion`, `auth_anomaly_in_sequence`,
  `mutating_method_amid_safe_run`, `state_changing_method`, `new_dynamic_endpoint`,
  `security_relevant_route`.
- **Cache:** `authenticated_cache_policy_contradiction` (auth response + cache HIT/Age
  despite `no-store`/`private` — *more* sophisticated than ZAP's cacheability rules).
- **CORS:** `wildcard_credentialed_cors` (ACAO `*` + credentials true).
- **Version / infra leak:** `version_disclosure_header` (version in Server/X-Powered-By),
  `internal_header_disclosure` (pod-ip/backend/instance/worker/debug-token header names),
  `internal_network_reference` (RFC1918 / `.internal`/`.corp`/`.lan` in body+headers),
  `api_description_exposure` (WADL/WSDL/OpenAPI/RAML).
- **Content-type mismatch:** `declared_json_actual_html`, `declared_html_actual_json`.
- **Redirect / SSRF / cred:** `open_redirect_to_external`, `ssrf_trigger_parameter`,
  `credential_in_query_string`.
- **JWT:** `jwt_sensitive_claim`, `jwt_in_url`.
- **Sec headers:** `missing_security_headers` — but **only** HSTS + CSP + X-Frame-Options,
  and **only** when >=2 are absent **and** the request is auth-bearing.
- **PII:** `pii_in_response` (email / SSN / card).
- **JS bundle intel:** `js_secret_literal`, `js_sourcemap_disclosure`,
  `js_endpoint_disclosure`, `js_auth_mechanism` (incl. web-storage token, oauth client_id,
  csrf-crumb logic).
- **Nuclei body signatures:** `sensitive_file_exposure` (.git/config, .env, private key,
  phpinfo, SQL dump, JVM heap dump, .DS_Store, directory listing), `secret_in_response`
  (AWS/GCP/Slack/GitHub/Stripe keys, PEM block), `exposed_management_panel`
  (Jenkins/Grafana/Kibana/phpMyAdmin/Prometheus/K8s/Actuator/Swagger/GraphQL Playground),
  `error_disclosure_in_body` (SQL errors, Django/Laravel debug, Express/Python traceback).
- **Exfil:** `encoded_outbound_blob`, `encoded_get_exfil`, `large_get_exfil_query`,
  `batch_payload_detected`.
- **Trust chain:** `client_trust_header`, `third_party_receives_auth_context_in_window`,
  `downstream_of_authenticated_host`.
- **HTTP version:** `http2_downgrade_surface`, `mixed_http_version_for_host`.
- **profile route/response vectors:** `route:injection`, `route:idor`, `route:xss-stored`,
  `route:graphql`, `resp:reflection`.
- **Learned lane:** `agent_injection_in_response`.

**The glaring structural gap: zero Set-Cookie analysis and zero HTML-body
element analysis** (script/form/comment/meta). That is where most of the cheap
ZAP value lives.

---

## Ranked borrow table

Ranked by value-to-Swarmie = novel x high-signal x cheap. `Coverage`: **no** =
not detected; **partial** = related reason exists but misses this case; **yes** =
effectively covered (listed only to justify skipping). **[TOP] = TOP 8, add first.**

| # | ZAP rule | Passively detects | Swarmie coverage | Proposed family | Cheap stdlib impl note |
|---|----------|-------------------|------------------|-----------------|------------------------|
| 1 [TOP] | CookieHttpOnly / CookieSecureFlag / CookieSameSite / CookieLooselyScoped | Session cookies set without `HttpOnly`, `Secure`, or `SameSite`, or scoped to a parent domain | **no** — no Set-Cookie parsing at all | `insecure_cookie_flags` | Parse `Set-Cookie` with `http.cookies.SimpleCookie`; flag missing flags on session-looking names (`sess`/`sid`/`auth`/`jwt`/`csrf`). Emit flag names only, never values. One parser subsumes 4 ZAP rules. |
| 2 [TOP] | JsoScanRule (Java Serialization Object) | Serialized Java object in body/param — `rO0AB` (base64) or magic bytes `AC ED 00 05` | **no** | `java_serialized_object` | `resp_body.startswith("rO0")` / `b"\xac\xed\x00\x05" in _bytes(...)`; also scan request body & cookies. Near-zero FP, deserialization-RCE surface — highest single-signal severity. |
| 3 [TOP] | InformationDisclosureSuspiciousComments | HTML/JS comments containing `TODO`,`FIXME`,`HACK`,`XXX`,`BUG`,`admin`,`password`,`backdoor`,`db`,`query` | **no** | `suspicious_comment` | Regex over `<!--...-->` and `/*...*/` // `//` comment spans for a wordlist. Pure developer-tell — aligns with the "who built this / human tell" standing questions. |
| 4 [TOP] | CrossDomainScriptInclusion + SubResourceIntegrity + PolyfillCdnScript | External `<script src=host>` with no `integrity=`; script from a known-bad/compromised CDN (polyfill.io et al.) | **no** (host-literal index exists but doesn't judge script trust) | `untrusted_script_include` | Regex `<script[^>]+src=` -> compare host vs page host, check for `integrity=`; static set of known-malicious CDN hosts. Supply-chain, full-page-privilege risk. |
| 5 [TOP] | ContentSecurityPolicyScanRule (policy weakness, not just presence) | CSP with `unsafe-inline`, `unsafe-eval`, wildcard `*` source, or missing `object-src`/`frame-ancestors`/`default-src` | **partial** — `missing_security_headers` only checks CSP *presence*, gated on auth+>=2 | `weak_csp_directive` | Split the CSP header on `;`, tokenize directives, match unsafe keywords. Turns a binary presence check into graded signal. No new hydration. |
| 6 [TOP] | HashDisclosureScanRule | Password/credential hashes in a response — bcrypt `$2[aby]$`, MD5/SHA hex, NTLM, `{SHA}`, crypt | **no** (JWT is separate) | `hash_disclosure` | Anchored regexes; require label proximity or field context to cut FP. Leaked hash = credential-material exposure; pairs with `secret_in_response`. |
| 7 [TOP] | InsecureAuthentication + InsecureFormLoad/Post + MixedContent | Basic/Digest auth or a password form over HTTP; HTTPS page loading/POSTing to `http://` | **no** | `insecure_transport_surface` | Check `url` scheme + `WWW-Authenticate: Basic/Digest`; regex `<form action="http:`, `type=password`, and `src=/href=http://` on an https page. Uses scheme already in `seed.url`. |
| 8 [TOP] | LinkTargetScanRule (reverse tabnabbing) + BigRedirectsScanRule | `target="_blank"` anchors without `rel="noopener/noreferrer"`; a 3xx whose body still carries content / multiple redirect HREFs (info leak) | **no** | `dom_link_hygiene` | Two cheap HTML regexes over the already-hydrated body; big-redirect = `300<=status<400` with `len(body) > N`. Low severity individually but ~free. |
| 9 | UserControlledOpenRedirect | A request param value reflected verbatim into the `Location` header | **partial** — `open_redirect_to_external` flags external Location but not param->Location *reflection* | (extend `open_redirect_to_external`) | Compare `Location` host/value against `param_names`/query values already parsed; add a `reflected` note. |
| 10 | SiteIsolationScanRule (COOP / COEP / CORP) | Missing `Cross-Origin-Opener/Embedder/Resource-Policy` (Spectre isolation) | **no** | `missing_isolation_headers` | Three header-name absence checks; scope to top-level HTML to avoid noise. Fold into the security-header lane. |
| 11 | CharsetMismatchScanRule | `Content-Type` charset != `<meta charset>` / XML encoding — MIME-sniff XSS surface | **no** | `charset_mismatch` | Compare header charset vs a `<meta charset=` regex in the body. Cheap; feeds the browser-parser lens. |
| 12 | SourceCodeDisclosureScanRule (beta) | Server-side source fragments in the response (`<?php`, `<%`, JSP/ASP scriptlets, `#!/usr/bin`) | **partial** — sensitive_file / js-sourcemap cover artifacts, not inline scriptlets | `source_code_disclosure` | Regex for scriptlet/shebang markers in a body served as `text/html`. High-signal recon. |
| 13 | Viewstate + InsecureJsfViewState | ASP.NET `__VIEWSTATE` without MAC / JSF ViewState unencrypted | **no** | `unprotected_viewstate` | Detect `__VIEWSTATE`/`javax.faces.ViewState` hidden inputs; base64-decode header bytes to check MAC presence. Niche but zero-FP where it fires. |
| 14 | InPageBannerInfoLeakScanRule | Server/version banner echoed in an **error page body** (not just the header) | **partial** — error bodies flagged, banner not extracted | (extend `error_disclosure_in_body`) | Add a server-banner regex to the error-body matcher; report the product/version token. |
| 15 | Base64DisclosureScanRule (alpha) | Base64-encoded data embedded **in a response** (may hide tokens/objects/PII) | **partial** — Swarmie decodes base64 in *requests/URLs* for exfil, not responses | `base64_blob_in_response` | Reuse `_B64_BLOB`; on a hit, peek-decode first bytes to classify (serialized object, JSON, PEM) — decode locally, emit category only. |
| 16 | CsrfCountermeasuresScanRule | State-changing `<form>` with no anti-CSRF hidden token | **partial** — has `state_changing_method` + js csrf logic, not form-token absence | `form_without_csrf_token` | On an HTML body with `<form method=post>`, check for a token-shaped hidden input; absence = signal. Pairs with the csrf-authz persona. |
| 17 | XChromeLoggerDataInfoLeak + XDebugToken | `X-ChromeLogger-Data`/`X-ChromePhp` (base64 server-side debug), Symfony `X-Debug-Token[-Link]` | **partial** — `internal_header_disclosure` catches `debug-token`, not XCOLD | (extend `internal_header_disclosure`) | Add these exact header names to `_INTERNAL_HEADER_RE`. One-line regex extension. |
| 18 | InformationDisclosureReferrerScanRule | Sensitive data (key/token/email/card) in the outbound `Referer` header | **no** | `sensitive_referer` | Run the cred/PII name+value checks against the `Referer` header value; leak-through-referrer is a real cross-origin exfil path. |
| 19 | InfoSessionIdUrlScanRule | Session ID in URL rewrite — `;jsessionid=`, `phpsessid=`, `sid=` in path/query | **partial** — `credential_in_query_string` covers `token`-ish names, misses session-rewrite forms | (extend `_CRED_PARAM_NAMES`) | Add `jsessionid`/`phpsessid`/`aspsessionid`/`cfid`/`cftoken` + a `;jsessionid=` path regex. |
| 20 | ContentTypeMissing + XContentTypeOptions | No `Content-Type` on a body-bearing response; missing `X-Content-Type-Options: nosniff` | **partial** — not in the auth-gated header lane individually | `mime_sniffing_surface` | Two header-absence checks; only emit on HTML/script/JSON bodies to bound noise. |
| 21 | PermissionsPolicyScanRule (beta) | Missing/deprecated `Permissions-Policy` (formerly `Feature-Policy`) | **no** | `missing_permissions_policy` | Header-absence check on top-level HTML. Fold into security-header lane; low weight. |
| 22 | FetchMetadataRequestHeadersScanRule (alpha) | Missing/invalid `Sec-Fetch-Site/Mode/Dest/User` on a request (resource-isolation posture) | **no** | `missing_fetch_metadata` | Request-header presence/value check. Low severity; useful as a modern-app maturity tell. |
| 23 | UserControlledCharset / HTMLAttributes / JavascriptEvent | A request param value reflected into a `<meta charset>`, an HTML attribute, or a JS event handler | **partial** — profile `resp:reflection` covers generic reflection, not these sinks | (extend reflection vector) | Where a param value appears inside `charset=`, an attribute, or `on*=`, tag the sink kind for the browser-parser persona. |
| 24 | FullPathDisclosureScanRule (alpha) | Full server filesystem path in a response (`/var/www/...`, `C:\inetpub\...`) | **partial** — error bodies leak paths, no dedicated detector | `full_path_disclosure` | Regex for absolute unix/windows paths in non-static bodies. Feeds the "internal identity leak" standing question. |
| 25 | ApplicationErrorScanRule / InformationDisclosureDebugErrors | Generic application/debug error text in body | **yes** — `error_disclosure_in_body` | — (skip) | Already covered; only broaden the marker list if corpus shows misses. |
| 26 | CrossDomainMisconfigurationScanRule | ACAO `*` (or reflected) even **without** credentials | **partial** — `wildcard_credentialed_cors` requires credentials=true | (widen CORS lane) | Emit a lower-weight `permissive_cors` when ACAO is `*`/reflected without credentials. Cheap, but higher FP — keep low weight. |
| 27 | DirectoryBrowsing / PII / InfoPrivateAddress / HeartBleed | Directory listing / card numbers / RFC1918 IPs / vulnerable OpenSSL banner | **yes** (first three) / niche | — (skip) | Directory-listing, PII, private-IP already covered. HeartBleed banner-version is a niche `version_disclosure` extension if ever needed. |
| 28 | TimestampDisclosure / ModernAppDetection / CacheControl / RetrievedFromCache / ZapVersion | Unix timestamps in body; SPA detection; simple cacheability; served-from-cache; ZAP self-version | low value / covered | — (skip) | Noisy or subsumed. Swarmie's `authenticated_cache_policy_contradiction` already beats the cache rules. Timestamp/ModernApp are high-FP, low-signal for an attention ranker. |

---

## TOP 8 — add these first

Chosen for **novel + high-signal + cheap + zero new hydration** (all operate on
the header set or the already-hydrated body):

1. **`insecure_cookie_flags`** — biggest structural gap. Swarmie parses zero
   `Set-Cookie` headers; a session cookie missing `HttpOnly`/`Secure`/`SameSite`
   is a direct, universally-understood security fact. One `http.cookies`
   parser retires four ZAP rules. Emit flag names only (boundary #6).
2. **`java_serialized_object`** — highest severity-per-line in the whole list.
   A two-branch check (`rO0` prefix / `\xac\xed\x00\x05` magic) with essentially
   no false positives, flagging a Java-deserialization RCE surface.
3. **`suspicious_comment`** — pure developer-tell that maps straight onto the
   engine's "who built this / human tell / internal-identity leak" standing
   questions. A comment wordlist regex over HTML/JS comment spans is cheap and
   frequently surfaces creds, internal hostnames, and dead admin routes.
4. **`untrusted_script_include`** — supply-chain. External `<script src>`
   without SRI, plus a static known-malicious-CDN host set (polyfill.io family).
   Directly answers "which third-party scripts execute with full page
   privileges." Swarmie already indexes script host literals — this judges them.
5. **`weak_csp_directive`** — upgrades the existing binary CSP-presence check
   into graded signal (`unsafe-inline`/`unsafe-eval`/`*`/missing `frame-ancestors`).
   No new data needed; just parse the header already in hand.
6. **`hash_disclosure`** — leaked bcrypt/MD5/SHA/NTLM hashes are credential
   material; complements `secret_in_response` and the secret-flow persona.
   Anchored regexes with field-context gating keep FP low.
7. **`insecure_transport_surface`** — Basic/Digest auth or a password form over
   HTTP, and mixed content on an HTTPS page. Uses the scheme already in
   `seed.url`; classic, unambiguous, and currently invisible to Swarmie.
8. **`dom_link_hygiene`** — reverse tabnabbing (`target=_blank` w/o
   `rel=noopener`) and big-redirect body leaks. Lowest severity of the eight but
   nearly free (two regexes on the hydrated body), and rounds out DOM-level
   coverage that the engine completely lacks today.

### Surprising gaps found

- **No cookie analysis whatsoever.** The engine has deep JWT, CORS, cache, and
  JS-bundle lanes but never parses `Set-Cookie` — the single cheapest,
  highest-consensus passive win, and four ZAP rules collapse into one parser.
- **No HTML-DOM lane.** Bodies are mined for secrets/errors/panels/JS-intel but
  never for **structural** HTML facts (script trust, form CSRF tokens, comments,
  link targets, mixed content). This is a whole cheap category ZAP mines and
  Swarmie doesn't.
- **Presence-only security headers.** `missing_security_headers` treats CSP as a
  checkbox and never inspects the policy — the *weak-policy* case (the one that
  actually matters) is unhandled, and it's free to add.
- **Swarmie already beats ZAP on caching.** `authenticated_cache_policy_contradiction`
  is more targeted than ZAP's whole Cacheable/CacheControl/RetrievedFromCache
  family — those are correctly *skipped*, not borrowed.

---

## Implementation notes (shared)

- All proposals slot into the existing `SignalEngine.header_reasons` (header
  lanes: #5,#7,#10,#17,#20,#21,#22) or `build_signal` (body lanes: #1-4,#6,#8,
  #11-16,#18,#23,#24) exactly like the current H1-H12 reasons — add a `reason`
  string + weight to `_REASON_WEIGHT` and one append site with a hypothesis dict.
- Stdlib modules needed, all already available: `re`, `http.cookies`
  (`SimpleCookie`), `urllib.parse` (`urlsplit`), `base64`, `json`. No new deps.
- Keep boundary #6: emit **flag names, header names, directive names, sink
  kinds, host names, comment keywords** — never cookie values, hash values,
  token values, or body excerpts.
- Weight guidance: `java_serialized_object` ~ 45 (RCE surface), cookie/CSP/hash
  ~ 25-35, script-include ~ 30, transport ~ 20, comments/link-hygiene ~ 10-15.
- Reuse existing precompiled patterns where possible (`_B64_BLOB` for #15,
  `_CRED_PARAM_NAMES` for #19, `_INTERNAL_HEADER_RE` for #17) to avoid new scans
  in the hot path.
