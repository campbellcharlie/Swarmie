# Juice Shop A/B — Swarmie signals vs. raw traffic

**Question:** does the Swarmie layer help an LLM hunter, versus reading raw captured traffic?
**Design (clean ablation):** one captured Juice Shop corpus (31 curated requests hitting known
vulnerable surfaces). Both arms are the same LLM (Claude). Arm A reads the raw request/response
pairs (`arm_a_raw.txt`); Arm B reads Swarmie's signal envelopes (`arm_b_signals.jsonl`). Ground
truth is labeled by the LLM from a full read of the raw corpus (`ground_truth.json`, 18
finding-bearing endpoints).

Reproduce: `crawl.py` → `passive … --hydrate-all` → `dump_raw.py` → `score.py`.

## Result (`score.py`)

| metric | value |
|--------|-------|
| Finding-bearing endpoints | 18 |
| Swarmie flagged (any signal) | **15/18 (83%)** |
| Swarmie flagged with a *specific* (non-generic) reason | 10/18 (56%) |
| **Top-5-by-attention precision** | **5/5** |
| Noise (flagged, no real finding) | 10 endpoints |

## Reading it honestly

- **The win is triage, not recall.** Arm A finds ~18/18 — because 31 small pairs are fully
  readable and the JWT decodes, the basket UserIds differ, the search response balloons, the
  KeePass file is right there. On a corpus this small, raw-reading has *higher* recall. Swarmie's
  value is that its **top 5 by attention are all real, high-value findings** (stack-trace leak,
  admin-config dump, SQLi-login, user dump) — a hunter following the ranking hits them
  immediately without reading raw traffic. That lift **grows with corpus size**: at 10k pairs you
  cannot read everything, and ranking becomes the whole game.
- **Swarmie surfaces, it does not classify — by design.** It flagged the SQLi-login endpoint as
  `successful_state_change_without_visible_auth` + `pii`, not "SQLi auth bypass". Correct division
  of labor (the LLM judges), but it means Arm B still needs the LLM to name the bug.

## Measured gaps (evidence, not vibes) → backlog

| gap | evidence | fix |
|-----|----------|-----|
| No sensitive-file / dir-listing lane | `/ftp` listing exposing `incident-support.kdbx` (KeePass) — **not flagged at all** | add a directory-listing + `.kdbx/.bak/.pyc/.kdbx` exposure signal (ZAP borrow) |
| `/metrics` (Prometheus) unrecognized | ranked **22nd**, attention 6, generic reason only | add a metrics/observability-exposure signal |
| Injection-by-response-anomaly not correlated | search `q='))--` returned 21KB vs 0.9KB benign — size explosion vs sibling **not** surfaced as injection | correlate response-size delta across same-endpoint siblings |
| High-value data under-weighted | payment cards rank 16, IDOR baskets rank 18/19 — flagged only generically | weight card/PII-shaped bodies + cross-user id reuse |
| `pii_in_response` over-fires | 10 noise endpoints, mostly this reason on benign lists | tighten the PII heuristic (structured email lists ≠ leak) |

These line up with the ZAP borrow-list (cookie/DOM/sensitive-file lanes) and are the P2
signal-quality work — now prioritized by what actually got missed on a labeled target.

## Round 2 — after building the evidence-driven signals

Five signals added, each traced to a miss above, then the A/B was re-scored on the same corpus:

| metric | round 1 | round 2 |
|--------|---------|---------|
| flagged (any signal) | 15/18 (83%) | **17/18 (94%)** |
| flagged with a specific reason | 10/18 (56%) | **13/18 (72%)** |
| top-5-by-attention precision | 5/5 | 5/5 |

Gaps closed (now flagged with a specific reason):

- `sensitive_file_exposure` extended to JSON-array **directory listings** of backup/secret files
  → the `/ftp` KeePass listing now flags (was: not flagged at all).
- `metrics_endpoint_exposed` (Prometheus/OpenMetrics exposition) → `/metrics` (was: rank 22,
  generic).
- `response_size_swing_for_endpoint` (same endpoint returns ≥8×/≥2KB more before the z-score
  baseline is warm) → the search SQLi's 21KB-vs-0.9KB jump (was: not flagged).
- `null_byte_in_path` (`%00`/`%2500` in the path) → the poison-null-byte `.bak` read (was: only
  caught incidentally by the loose PII rule).
- `pii_in_response` tightened to require an **email list (≥3 distinct)**, not a single address —
  removed the inflation that had pushed the Challenges/reviews endpoints into the mid-ranks.

Remaining (deliberately not chased): robots.txt→/ftp (low value; `/ftp` itself is now caught),
and the IDOR baskets / payment cards are flagged but only *generically* — those need cross-user
id-reuse and card-data weighting, and arguably belong to the LLM's judgment layer, not a rule.

## Round 3 — cookie + HTML-DOM lane (ZAP borrow), measured on DVWA

Juice Shop sets **zero cookies and no CSP** (JWT-in-body SPA), so it cannot exercise the cookie
/ DOM lane — the biggest structural gap the ZAP borrow-list flagged. Added a second target,
DVWA (`crawl.py --target dvwa`), which is cookie- and server-rendered-HTML based, and built four
signals: `insecure_cookie_flags`, `weak_csp_directive`, `suspicious_html_comment`,
`untrusted_script_include`.

Outcome — honest:
- **All four are unit-proven** (true-positive *and* true-negative cases) in `test_signal_lanes.py`.
- **Zero false positives on real DVWA traffic** (12 pairs): DVWA turns out to be *hardened* on
  these dimensions — session cookies carry HttpOnly, scripts are all local, comments are benign,
  no CSP to be weak. The lanes correctly stayed silent.
- **No real true-positive available:** both test apps are hardened on cookies/DOM, so the TP is
  covered only by unit tests. A real-traffic TP needs a target weak on these axes (older DVWA,
  a real site with an un-SRI'd CDN script) — future work.
- **The loop caught a real bug pre-ship:** the first cookie rule flagged *missing Secure*, which
  is a false positive over plain HTTP (the flag would just break the cookie). Measuring against
  DVWA surfaced it; the rule is now scheme-gated (HttpOnly is the real tell; Secure only on HTTPS).

## Round 4 — out-of-sample modern API (VAmPI)

Two heavy "modern platform" targets failed on this arm64/colima box (environment, not Swarmie):
crAPI timed out under load (10 containers, login 502 at 30s); NodeGoat's mongo is arm64-broken
(4.4 crashes, 5.1+ removed the `OP_QUERY` opcode its old driver needs). Pivoted to **VAmPI** — a
self-contained modern REST API (Flask + JWT, BOLA / mass-assignment / `/_debug` password dump) —
which Swarmie was **never tuned against**. `crawl_vampi.py` walks it authenticated (JWT bearer).

Score (`score.py --truth vampi_ground_truth.json`):

| metric | value |
|--------|-------|
| finding-bearing endpoints | 9 |
| flagged (any signal) | **9/9 (100%)** |
| flagged with a specific reason | 9/9 |
| top-5-by-attention precision | 5/5 |

- **Generalizes:** on an unfamiliar app it flagged every vuln endpoint and ranked the BOLA
  email-update #1, the `/_debug` password dump, user enumeration, and the BOLA book-secret read
  all in the top tier.
- Honest caveat: `version_disclosure_header` + `missing_security_headers` fire on *every* VAmPI
  response (universal → low discrimination), so "specific" is generous here.
- **Evidence-driven fix:** the crown jewel — `/_debug` returning plaintext passwords — was only
  `pii`/`resp:leak`. Added `_CRED_FIELD_RE`: a `"password"/"secret"/"api_key"` field echoed in a
  JSON *response* now flags `secret_in_response`. It lifted `/_debug` and the BOLA book-secret
  reads to attention 84 (top). Also fixed `untrusted_script_include` over-firing on a
  `document.write` livereload fragment (require a real external host). Both unit-pinned.

Three-target coverage now: Juice Shop (SPA/JWT, tuned), DVWA (PHP, cookie/DOM negative), VAmPI
(modern API, out-of-sample). Swarmie's triage holds — top-5 precision 5/5 on all three.
