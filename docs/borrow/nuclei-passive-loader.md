# Borrowing Nuclei matchers — passive-only, stdlib-only

**Status:** design + spec only. No change to `passive.py`, no new dependency, nothing sends a request.
**Goal:** let Swarmie ingest the *matcher* half of Nuclei templates and evaluate it against
already-captured HTTP responses, folding a match into the existing reason + hypothesis + attention
envelope. The request-generation half of every template (path, method, payloads) is discarded.

This is a generalisation of what `passive.py` already does by hand: `_PANEL_SIGS`, `_ENV_FILE_RE`,
`_sensitive_file_kind`, `_BODY_SECRET_PATTERNS`, and `_ERROR_BODY_RE` are hand-transcribed Nuclei
signatures. The design turns that manual transcription into a vetted, loadable data file.

---

## 1. What "passive-applicable" means here

Nuclei is an *active* scanner: a template crafts a request (`path`, `method`, `payloads`) and runs
`matchers` against the response. Swarmie never crafts the request. So only the **matcher block** is
reusable, and only when it can produce a truthful verdict from a response we happened to capture.

Two independent filters decide reuse:

**A. Structural passivity — is the matcher *evaluable* against a captured response?**
Include only matchers that read the response:

| Nuclei field | Include | Exclude |
|---|---|---|
| matcher `type` | `word`, `regex`, `binary`, `status`, `size` | `dsl` (expression lang, can read request/interactsh state), `xpath` (rare) |
| matcher `part` | `body`, `header`/`all_headers`/`header_name`, `response`/`raw`, `status_code`, `content_length` | `interactsh_protocol`, `interactsh_request` (OAST — only exist during an active interaction) |
| template shape | single request block, matcher-only logic | `payloads:` / `fuzzing:` / `attack:` (clusterbomb/battering-ram), multi-request `req-condition` chains referencing `_1`/`_2`, any `dns`/`network`/`ssl`/`headless`/`code`/`javascript`/`dast`/`workflows` block |

Modifiers we honour: `matchers-condition` (and/or), per-matcher `condition` (and/or), `negative`,
`case-insensitive`, `encoding: hex` (hex-decode a `word` before matching). Verified against the
engine's `SYNTAX-REFERENCE.md`.

**B. Effective passivity — will it *fire* on organically-captured traffic?**
Structural passivity is necessary but not sufficient. A `Server: nginx/1.2` banner matcher fires on
*any* response. A phpinfo/actuator/backup-file matcher only fires if that specific path was actually
browsed. So each compiled spec is tagged:

- `banner` — path-independent; the trigger content (a header, a version string, a security-header
  absence) can appear on arbitrary responses. Evaluate against every hydrated response.
- `path-coupled` — the trigger only appears if the template's request path was fetched. Evaluate only
  when the captured request path matches the template's `path_gate`. This reuses Swarmie's existing
  `_EXPOSURE_PATH` / `should_sample_body` philosophy — organic browsing *does* hit `/admin`, `/login`,
  `/.git/config`, so these still fire, just selectively.

Applying a path-coupled matcher to unrelated responses costs only false *negatives* (misses), never
false positives — but gating avoids wasted scans and keeps attention honest.

---

## 2. Loader: offline pre-compile, not a runtime YAML reader

The hard constraint (boundary #9): **Swarmie core is Python-3.14 stdlib-only — there is no `yaml`
module.** Two ways to bridge YAML → Swarmie:

**(a) Tiny runtime YAML-subset reader** inside `passive.py`. *Rejected.* YAML looks simple and isn't:
block scalars, flow sequences `["a","b"]`, quoted-escape rules, comments, anchors. A "subset" reader
robust enough to parse **untrusted third-party template files in the passive hot path** is more code
than it appears and a crash/DoS surface for the tailer, which must never fall over on bad input.
Violates KISS and the "read the actual implementation" rule — YAML edge cases are the classic footgun.

**(b) Offline pre-compile step → JSON spec that Swarmie loads with stdlib `json`.** RECOMMENDED.
A separate build tool (`tools/nuclei_compile.py`, *not* shipped in Swarmie core, free to depend on
PyYAML or the real Nuclei loader) reads vetted templates once and emits a single
`passive_signals.json`. At runtime Swarmie does `json.loads(...)` — pure stdlib.

Why (b) wins:

- **Resolves the no-yaml constraint cleanly:** YAML is *never parsed by Swarmie core*. It is parsed
  once, offline, by a tool allowed heavier deps; the runtime artifact is plain JSON. Full-fidelity
  parsing with zero reinvention.
- **The compile step is the vetting boundary** — exactly where filters A and B belong: drop
  active/dsl/interactsh/payload templates, hex-decode binaries, pre-compile + ReDoS-screen every
  regex (reject nested-quantifier catastrophes; compilation itself rejects invalid patterns), and
  dedup against Swarmie's built-in signatures so we don't double-count `.env`/DS_Store/actuator.
- **Fast + auditable at runtime:** pre-anchored JSON, a reviewable artifact checked into the repo,
  diffable when templates update. Mirrors how `passive.py` already ships *compiled* `re.compile`
  constants rather than parsing signatures live.
- **Cost** is a re-run of the compiler on template refresh — which is a feature: the human/CI vetting
  gate sits there, not in production.

This is the KISS posture: a model-free transform with a checkable output (compiler exits non-zero on a
malformed or non-passive template).

---

## 3. The passive-signal spec (runtime JSON contract)

`passive_signals.json` = `{ "version": 1, "signals": [ <spec>, ... ] }`. One `<spec>` per vetted
template:

```jsonc
{
  "id": "nginx-version",                 // template id
  "reason": "nuclei:version_disclosure:nginx-version",
                                         // flat reason string appended to envelope.reasons.
                                         // FORM: "nuclei:<family>:<id>" — embedding <family> lets
                                         // _build_interrogation() attach the right persona lens for
                                         // free (it scans reasons for family substrings), and lets
                                         // _REASON_WEIGHT carry a per-signal weight.
  "family": "version_disclosure",        // Swarmie hypothesis family; keys _PERSONA_QUESTIONS
  "severity": "info",                    // nuclei severity, verbatim
  "weight": 10,                          // int for the attention sum (see mapping below)
  "applicability": "banner",             // "banner" | "path-coupled"  (filter B)
  "path_gate": null,                     // null for banner; else compiled path constraint, e.g.
                                         //   {"kind":"suffix","values":["/.git/config"]}
                                         //   {"kind":"regex","pattern":"/actuator(/env)?$"}
  "condition": "and",                    // matchers-condition (and|or), default "or"
  "matchers": [
    { "type":"regex", "part":"header", "header":"server",
      "values":["nginx/[0-9.]+"], "condition":"or",
      "negative":false, "case_insensitive":false, "encoding":null },
    { "type":"status", "part":"status_code", "values":[200] }
  ],
  "hypothesis": {                        // pre-rendered; dropped verbatim into envelope.hypotheses
    "family":"version_disclosure",
    "statement":"Response matches Nuclei signature 'nginx-version' (severity info): a server/version banner is disclosed. Verify the disclosed version against known CVEs and patch latency.",
    "targets":["nginx-version"]
  }
}
```

**Normalisation the compiler applies** (so the runtime evaluator stays trivial):

- `part`: `all_headers`/`response`/`raw` → scan `resp_body + "\n" + raw_header_text` (the exact idiom
  `passive.py` already uses at the `_INTERNAL.search(...)` site). `header_name` (`server`, `x_powered_by`)
  → `resp_headers.get("<name>")`, translating `_`→`-`. `content_length` → the `size` lane.
- `binary`: hex strings decoded to `bytes`; evaluated with `bytes.find()` against the raw response
  body (`_bytes(row.get("response_body"))`) — same pattern as the existing `raw[4:8] == b"Bud1"` check.
- `size`/`content_length`: integer compare against `resp_length`.
- `word` + `encoding: hex`: hex-decoded to text at compile time.
- Regexes pre-validated (`re.compile`) and ReDoS-screened; stored as source strings, recompiled once
  at load and cached (Swarmie already keeps module-level compiled constants).

**Severity → weight** (aligned to the existing `_REASON_WEIGHT` scale where
`sensitive_file_exposure=50`, `version_disclosure_header=25`, `exposed_management_panel=30`):

| severity | weight |
|---|---|
| info | 10 |
| low | 15 |
| medium | 25 |
| high | 40 |
| critical | 50 |

**Extractor-only templates** (many token/key templates — e.g. AWS keys — have *no* `matchers` block,
only `extractors:`). These are a separate class: their regex is emitted into a `secret_regex` pool
that mirrors `_BODY_SECRET_PATTERNS` and feeds the existing `secret_in_response` reason, rather than
being forced into the matcher model.

### 3.1 How one loaded matcher becomes a Swarmie envelope reason + hypothesis

Take the `nginx-version` spec above. A new pure-function helper (design sketch, ~15 lines) is called
inside `build_signal` alongside the other body/header lanes:

```python
def _nuclei_reasons(specs, seed, resp_headers, raw_body):
    fired = []
    for s in specs:
        if s.applicability == "path-coupled" and not _path_gate_hit(s.path_gate, seed.path):
            continue
        if _eval_block(s, seed, resp_headers, raw_body):   # honours condition/negative/ci
            fired.append(s)
    return fired
```

For each fired spec, `build_signal` does exactly what every other lane does:

```python
for s in fired:
    reasons.append(s.reason)          # "nuclei:version_disclosure:nginx-version"
    hypotheses.append(s.hypothesis)   # {"family","statement","targets"}
```

Downstream, **unchanged** passive.py machinery picks it up:

- `_REASON_WEIGHT` is `.update()`-ed at load with `{s.reason: s.weight}`, so `raw_weight` and the
  `attention.score` already sum it — no change to the scoring code.
- `_build_interrogation(reasons, ...)` sees `"version_disclosure" in reason` and attaches the
  `dependency-latency` persona lens ("is this version affected by a known CVE… patch latency"). Free,
  because the family is embedded in the reason string.
- The envelope's `reasons`, `hypotheses`, `counterevidence`, `questions`, `interrogation`,
  `disposition` fields are produced by the existing code. The Nuclei signal is indistinguishable in
  shape from a native one — which is the point: **a hypothesis, never a finding** (boundary #4), and
  no raw values leave the mailbox (boundary #6 — only the template id and family are emitted).

Net new surface in `passive.py`: load the JSON once in `SignalEngine.__init__`, call
`_nuclei_reasons(...)` in `build_signal`. Everything else is the existing envelope pipeline.

---

## 4. How much of the corpus is passively usable

Counts from the repo's generated `TEMPLATES-STATS.md` (the README's numbers are staler — treat the
HTTP total as a **~9.3k–11.2k range, do not hardcode it**). Tag counts are a proxy for directory size;
a template carries several tags:

`http` ≈ 9.3k–11.2k total · `tech` 965 · `exposure` 1482 (+ `config` 324, `token` 226, `file` 392,
`logs` 65, `backup` 36) · `misconfig` 999 · `panel` 1615 · `default-login` 343 · `cve` 4431 /
`vuln` 6642 (heavily overlapping, mostly active) · `fuzzing` 12. `dns` 31 · `network` 280 · `ssl` 38 ·
`headless` 24 · `javascript` 129 · `code` 303 — all out of scope.

Tiered estimate of the **HTTP** corpus:

| Tier | ~share of http | What | Passive verdict |
|---|---|---|---|
| **A — banner / any-response** | **~10–15%** | tech/version banners, `Server`/`X-Powered-By` disclosure, internal-header leaks, CORS / security-header misconfigs | fire on arbitrary captured responses |
| **B — path-coupled but organically reachable** | **~15–25%** | exposures (config/token/file/logs/backup), exposed panels, actuator/env, framework error pages | fire when the browsed path hits them; gated by `path_gate` |
| **C — excluded** | **~60–70%** | active CVE/vuln payload templates, default-logins (POST creds), fuzzing/dast, dsl/interactsh, multi-request chains, non-HTTP protocols | not passively evaluable |

**Bottom line: roughly 25–40% of the HTTP corpus is passively applicable** (structural + effective),
with a high-confidence core around **~30%** dominated by `technologies/` and the `exposures/` family —
i.e. ~3,000–4,000 templates worth compiling, of which the pure path-independent "fires on anything"
banner subset is ~1,000–1,500. This is a lean, high-signal slice; the excluded 60–70% is exactly the
active-scanning surface Swarmie must never touch.

### Five real passive-applicable templates (paths verified 200, matcher blocks verbatim)

All five read only `body`/`header`/`status` from an already-captured response — none replay traffic.

1. **`http/technologies/nginx/nginx-version.yaml`** (`id: nginx-version`, severity **info**) —
   `matchers-condition: and`; `regex` on `part: header` `nginx/[0-9.]+` + `status: 200`.
   **applicability: banner** — pure `Server`-header version banner, no path dependency. The cleanest
   "fires on any response" case.

2. **`http/exposures/configs/phpinfo-files.yaml`** (`id: phpinfo-files`, severity **low**) —
   `and`; `word` on `part: body` `["PHP Extension","PHP Version"]` `condition: and` + `status: 200`.
   **applicability: path-coupled** — the body pair only appears on a `phpinfo()` page.

3. **`http/exposures/tokens/firebase-fcm-server-key-disclosure.yaml`**
   (`id: firebase-fcm-server-key-disclosure`, severity **medium**) — `and`; `regex` on `body`
   `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}` + `word` on `body` `["firebaseConfig","serverKey"]`
   `condition: or` + `status: 200`. **applicability: content-specific** (includes root `/`, so treat
   as banner-ish but body-gated) — fires only if the response body actually carries the key.

4. **`http/exposures/backups/zip-backup-files.yaml`** (`id: zip-backup-files`, severity **medium**) —
   `and`; `binary` on `body` with magic-byte list (`504B0304` zip, `1f8b` gzip,
   `53514c69746520666f726d6174203300` SQLite, `377ABCAF271C` 7z, …) `condition: or` + `regex` on
   `header` `application/[-\w.]+` + `status: 200`. **applicability: path-coupled** — meaningful only
   if an archive path was fetched. Demonstrates the `binary` (raw-bytes) lane.

5. **`http/misconfiguration/springboot/springboot-env.yaml`** (`id: springboot-env`, severity
   **low**) — `and`; `word` on `body` `["applicationConfig","activeProfiles"]` or; `word` on `body`
   `["server.port","local.server.port"]` or; `word` on `header` (actuator content-types) or;
   `status: 200`. **applicability: path-coupled** — fires only on an actuator `/env` response.
   Demonstrates multi-matcher `and` across body + header parts.

> Product names above (nginx, PHP, Firebase, Spring Boot) are citations of the public template IDs, not
> Swarmie targets. The compiled spec and the runtime evaluator name no target and hardcode no product —
> they carry only whatever templates the operator chooses to vet and compile in.

---

## 5. Boundaries honoured

- **Passive-only / zero requests** — only the matcher half is loaded; path/method/payloads are dropped
  at compile time. Nothing in the runtime path can emit a request (boundary #3).
- **stdlib-only** — runtime loads JSON with `json`; the YAML-parsing compiler is an offline tool, not
  Swarmie core (boundary #9).
- **No raw values leak** — envelopes carry only template `id` + `family` + pre-written statements;
  matched bytes/tokens are never emitted (boundary #6).
- **Hypothesis, not finding** — a fired Nuclei signal is one more `reasons`/`hypotheses` entry the LLM
  interrogates; it asserts nothing (boundary #4).
- **Lean** — one new offline tool + one JSON artifact + one ~15-line helper and a `_REASON_WEIGHT`
  update in `passive.py`. No new dependency, no change to scoring/interrogation/envelope code.
