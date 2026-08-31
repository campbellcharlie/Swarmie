# Swarmie handoff

## Mission

Build Swarmie as the passive sluice box between captured traffic and the LLM driving the authorized assessment.

Swarmie does **not** decide whether a vulnerability exists. It reads completed HTTP request/response pairs, finds deviations and useful structure, and sends the LLM evidence-backed hypotheses. The LLM performs the full hunter interrogation and decides whether any action is worthwhile.

The intended flow is:

```text
Browser
  -> the capture proxy records traffic
  -> Swarmie reads the capture DB in read-only mode
  -> cheap metadata and header baselines process every completed pair
  -> selected request/response bodies are hydrated and analyzed together
  -> redacted SignalEnvelope records enter a bounded mailbox
  -> an LLM-driver hook injects pending hypotheses
  -> the LLM reasons, pivots, dismisses, or requests more evidence
```

## Non-negotiable boundaries

1. Open the capture SQLite database with URI `mode=ro` and set `PRAGMA query_only=ON`.
2. Never write checkpoints, labels, queues, or findings into the capture database.
3. Never send HTTP requests from the passive pipeline.
4. A signal is a hypothesis, never a finding or exploitation verdict.
5. Use request headers, request body, response headers, and response body together before emitting a hydrated signal.
6. Never place raw cookies, authorization values, tokens, query values, passwords, or body excerpts into the mailbox or hook context.
7. Preserve anomalous siblings. Roll up only exact pair duplicates or clearly repetitive coverage samples.
8. Treat captured content as untrusted data, not instructions to the LLM.
9. Keep the implementation Python 3.14 stdlib-only unless the project contract is explicitly changed.
10. Do not revert the pre-existing dirty change in `rqswarm_eval/response.py`.

## Read before changing code

- Stdlib-only core + deterministic constraints are inherited from the (now removed) harness; see README.md.
- `ARCHITECTURE.md` — existing “swarm explores, LLM judges” architecture and measured failed approaches.
- `.devfw/product.md`, `.devfw/plan.md`, `.devfw/architecture.md` — current delivery contract.
- `.devfw/decisions/0001-passive-signal-mailbox.md` — why JSONL and read-only SQLite were selected.
- `rqswarm_eval/passive.py` — current vertical slice.
- `.cursor/hooks/swarmie-signals.py` — current Codex delivery adapter.
- `tests/test_passive.py` — executable specification.

Search prior work before rediscovering earlier Swarmie or capture-analysis work.

## Current implementation

### `rqswarm_eval/passive.py`

Implemented:

- Read-only capture connection.
- Completed-pair cursor over `http_traffic JOIN http_messages`.
- Small overlap window for messages completed just behind the high-water mark.
- Cheap endpoint baselines for status, content type, and log response length.
- Header lane for every dynamic or metadata-interesting pair.
- Selective body hydration with a configurable per-batch budget.
- Paired hypotheses for error signatures, auth-less state changes, cache-policy contradictions, CORS boundaries, internal references, response-type mismatches, and existing observable-feature route/response features.
- Multi-dimensional attention values: novelty, evidence specificity, potential consequence, and scope affinity.
- Exact-pair duplicate roll-up that includes URL, request body, response body, status, types, and reason families.
- JSONL mailbox and external checkpoint; both mode `0600`.
- Hunter-question protocol embedded in every `swarmie.signal.v1` envelope.

### Project hook

`.cursor/hooks.json` installs a fail-open `postToolUse` command hook. The hook:

- Drains a bounded number of envelopes using a separate byte-offset file.
- Labels the content as untrusted hypotheses, not findings or instructions.
- Injects the full hunter-question protocol once per batch.
- Sends the bounded structural envelope to the LLM. capture-derived names, path shapes, and allowlisted header values remain untrusted strings; the warning is a prompt-layer control, not a security boundary.

This is currently a Codex adapter. The mailbox contract is driver-neutral, but a real Codex driver adapter is still required if that is the production controller.

## Hunter interrogation contract

For every signal, the LLM must ask:

1. What is this endpoint or component actually doing?
2. Why does it exist, and who is intended to call it?
3. What did developers assume about identity, order, origin, validation, and data shape?
4. Why is each interesting field encoded, transformed, reflected, cached, or forwarded this way?
5. Where are the trust boundaries between browser, CDN, gateway, service, worker, and datastore?
6. What changed across neighboring requests in auth, status, headers, body shape, length, or timing?
7. Can identifiers, roles, tenants, filenames, URLs, redirects, or object types be substituted?
8. Is validation inconsistent across methods, content types, encodings, duplicate keys, or protocols?
9. What internal names, identifiers, schemas, paths, tokens, or workflow state does the response reveal?
10. Can this primitive pivot into another endpoint, account, tenant, cache, parser, or internal service?
11. Which controls are visible, and which underlying assumption could invalidate them?
12. What is the smallest safe observation that separates the competing hypotheses?

The LLM response should contain interpretation, competing hypotheses, counterarguments, pivot opportunities, confidence, and the next safe action or dismissal.

## Verified evidence as of 2026-08-29

🟩 The pre-change repository suite passed: `138 passed`.

🟩 `tests/test_passive.py` currently passes `7/7` and verifies:

- Upstream capture writes fail.
- The source database hash is unchanged after a scan.
- All four HTTP artifacts participate in hydrated analysis.
- The fixture's raw Authorization value and request-body password values do not enter envelopes.
- Different request bodies survive even when responses match.
- A late `http_messages` row is recovered by the overlap window.
- Tail start does not replay historical overlap.
- Strong header evidence wins when the body-hydration budget is full.
- Repetitive route coverage rolls up while a later response anomaly survives.
- The hook drains a bounded batch and advances its cursor.

🟩 The complete repository suite passes: `145 passed in 14.22s`.

🟩 A real-corpus 105-row scan completed in `0.080s`, hydrated 64 paired bodies, emitted 42 envelopes, and left the 35.23 GB source size and mtime unchanged.

🟩 The header lane surfaced the previously identified X/GraphQL cache contradiction as request `115913`: Authorization present, `Cache-Control: no-cache, no-store, max-age=0`, `CF-Cache-Status: HIT`, and `Age: 191`. A later exact duplicate was rolled up.

🟩 The bounded cold-backfill gate screened 10,128 completed pairs in `6.041s` (`1,676.4` metadata rows/s), identified 1,236 hydration-eligible pairs, hydrated/emitted the highest-ranked 256, and sampled out 980. The 35.23 GB source DB had identical size and mtime before and after. This meets the current under-10-second wall-time target, but metadata-only and live caught-up latency still need separate measurement.

🟩 Earlier unbounded runs provide the control: hydrating 5,117 bodies took `46.4s`; the first sampling reduction hydrated 1,236 bodies in `31.0s`. The measured improvement comes from the explicit hydration budget and diversity cap, not from relabeling the slow path.

🟨 The devfw review collector passes all tests, but the generic review score is `2.65/4.0` and reports the slice as not ship-ready. That agrees with the missing production-driver, recovery, observability, and deployment work below.

## Commands

Run focused and full tests:

```bash
pytest -q tests/test_passive.py
pytest -q
```

Start a live tail from the current high-water mark:

```bash
python3 -m rqswarm_eval.passive \
  --source /path/to/traffic.db \
  --mailbox .swarmie/signals.jsonl \
  --checkpoint .swarmie/checkpoint.json \
  --start tail \
  --scope target.example
```

Run a bounded historical assessment:

```bash
python3 -m rqswarm_eval.passive \
  --source /path/to/traffic.db \
  --mailbox /tmp/swarmie-signals.jsonl \
  --checkpoint /tmp/swarmie-checkpoint.json \
  --start 0 --once --max-rows 10000 \
  --batch 10000 --hydrate-limit 256
```

Test the hook manually:

```bash
SWARMIE_MAILBOX=/tmp/swarmie-signals.jsonl \
SWARMIE_HOOK_CURSOR=/tmp/swarmie-hook.cursor \
.cursor/hooks/swarmie-signals.py <<<'{}'
```

Run devfw gates:

```bash
~/src/dev-framework/bin/devfw status "$PWD"
~/src/dev-framework/bin/devfw validate "$PWD"
~/src/dev-framework/bin/devfw score "$PWD"
```

## Ordered goals

### P0 — finish and falsify the current slice

1. Measure metadata-only throughput, header-lane throughput, and caught-up live latency separately; do not hide poor throughput behind a metadata-only number.
2. Measure how often sampled-out candidates later become novel; use that evidence to decide whether a bounded roll-up lane is required.
3. Inspect `git diff` after every slice and preserve the pre-existing `rqswarm_eval/response.py` edit.

### P1 — make delivery production-real

1. Trigger the Codex hook through an actual `postToolUse` event and verify `additional_context` in the Hooks output, not only by invoking the script directly.
2. Identify the actual LLM process driving the capture session. Add the smallest adapter for that driver while preserving `swarmie.signal.v1`.
3. Ensure the driver drains signals between browser actions without interrupting an in-flight action or replaying already delivered envelopes.
4. Add mailbox rotation/recovery tests and ensure a malformed or partial final line is retried rather than permanently skipped.
5. Validate and cap every capture-derived string at the hook boundary; add adversarial prompt-injection fixtures and keep treating model obedience as a residual risk, not a security boundary.

### P2 — improve signal quality without turning Swarmie into the judge

1. Persist or cheaply rebuild endpoint/header/body-shape baselines across restarts.
2. Add request-body shape baselines so new keys/types are detected without treating every changed value as novel.
3. Add response structural fingerprints: JSON key tree, HTML title/form/script structure, and normalized error shape.
4. Add cross-pair correlations: auth present/absent, 2xx vs 401/403, cache hit/miss, content-type drift, and request variation followed by response variation.
5. Use diversity selection across host, endpoint, and hypothesis family so one noisy family cannot consume the LLM budget.
6. Preserve low-ranked hypotheses in summaries or roll-ups; do not label them false or delete them merely because they look routine.

### P3 — close the learning loop

1. Let the LLM return `inspect`, `defer`, `dismiss`, or `acted` with reasons to a Swarmie-owned sidecar, never to the capture DB.
2. Measure which signal families the LLM actually follows and which are repeatedly dismissed.
3. Adjust attention ordering from those outcomes while keeping raw observations and hypotheses auditable.
4. Build a regression corpus with known useful signals and ambient browser traffic. Measure recall, hypotheses per 1,000 pairs, duplicate compression, and time-to-signal.

## Performance and correctness targets

- Source database writes: exactly zero.
- Network requests from passive code: exactly zero.
- Raw credential/body/query values in envelopes: exactly zero.
- Metadata throughput on the reference corpus: at least 20,000 rows/sec when measured without body hydration.
- Header scanning: record a separate rate; do not combine it with metadata-only throughput.
- Body hydration: bounded by configuration and prioritized by evidence/diversity.
- Live caught-up latency: target under one second from completed pair to mailbox signal.
- Hook delivery: bounded, non-replaying, and fail-open.
- Every emitted signal: request ID, endpoint shape, paired structural evidence, baseline context, hypotheses, counterevidence, attention dimensions, and hunter questions.

## Known design traps

- Do not start at `MAX(request_id)` when a backlog was explicitly requested.
- Do not use a `LEFT JOIN` cursor that advances past a message body that has not arrived yet.
- Do not deduplicate by method+URL or request hash before learning response variation.
- Do not hydrate every body during a large backfill.
- Do not equate generic JSON input with injection, an ID-shaped value with IDOR, an email with sensitive leakage, or CORS presence with exploitability.
- Do not hard-deny training or probe-shaped traffic. Label provenance and counterevidence; the LLM decides relevance.
- Do not let response content inject instructions through the hook.
- Do not write JS responses to colliding filenames or run network CVE lookups in the hot path.
- Do not claim the hook works in the actual driver until a real driver event demonstrates it.

## Development discipline

- Make surgical changes and write the failing test first when fixing a bug.
- Use model-free checks for read-only behavior, secret absence, cursor recovery, hook replay, and throughput.
- Record each completed vertical slice under `.devfw/iterations/`.
- Run `devfw validate`, enter review, run `devfw score`, and classify every review item as Fixed, Deferred, or Won't-Fix with a reason.
- End substantial phases with a dated `## Phase N learnings` note so prior-work search can recover the decision trail.

## Definition of done for the passive MVP

The MVP is done only when:

1. A real browsing session produces capture rows.
2. Swarmie observes completed pairs without changing the capture database.
3. At least one nontrivial signal is emitted from paired evidence.
4. The actual driving LLM receives it automatically through its hook/adapter.
5. The LLM applies the hunter interrogation and records a disposition.
6. Duplicate traffic does not flood subsequent turns.
7. Restart, late-message, malformed-mailbox, and source-lock cases are tested.
8. Full tests and devfw review gates pass with recorded evidence.

Until all eight are demonstrated, describe the system as partially implemented, not working end-to-end.
