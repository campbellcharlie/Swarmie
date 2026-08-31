---
artifact: decision
version: 1
status: accepted
owners: []
last_updated: 2026-08-29
---

# ADR-0002 Learned lane: agent-prompt-injection in response bodies

## Context

Swarmie is a **symbolic** correlator: every family with a stable syntax (JWTs, `ghp_…`
tokens, headers, path shapes) is matched by rules in `passive.py`, and the LLM judges. Some
families are defined by **meaning, not shape** — the clearest is *agent-prompt-injection*:
text a target serves that would read as instructions to an LLM-driven client rather than as
data. No regex carries that (keyword filters are known to fail on distractors and multilingual
payloads), and it is exactly the residual risk CLAUDE.md P1.5 already flags ("add adversarial
prompt-injection fixtures; keep treating model obedience as a residual risk").

We do **not** turn Swarmie into a classifier. We add **one learned lane** behind the existing
`swarmie.signal.v1` envelope, keeping the three tiers distinct: symbolic recall (Swarmie) →
learned scoring (this lane) → judgment (LLM).

## Decision

A learned lane is an **out-of-process classifier sidecar** that Swarmie consults over a local
AF_UNIX socket. Swarmie core stays Python-3.14 **stdlib-only**; the model never lives in-process.

**Swarmie side (built):** `rqswarm_eval/learned_lane.py` — `LearnedLane.classify(text)` →
`Verdict | None`; wired into `SignalEngine.build_signal`; CLI `--injection-socket` /
`--injection-active` / `--injection-threshold` (env `SWARMIE_INJECTION_SOCKET`). Dormant unless
a socket is configured, so default behavior is unchanged.

**Sidecar side (to build):** any process that binds the socket and honors the wire contract.
It is **model-agnostic** — see "What provides the verdict" below.

### Wire contract (one request/response per connection, both length-prefixed)

```
request  = uint32-BE length + UTF-8 JSON
           {"v":1,"lane":"agent_injection","text":<str>,"meta":{"response_type":<str>}}
response = uint32-BE length + UTF-8 JSON
           {"v":1,"label":<str>,"score":<float 0..1>,"model":<str>,"spans":[[i,j],...]}
```

- `label` ∈ sidecar vocabulary; Swarmie's positive class is `"injection"`.
- `score` is **required**; a response without it fails open to dormant.
- `spans` are optional integer offsets into the submitted text — **operator-side only**, never
  placed in the mailbox.
- Swarmie caps `text` at 64 KiB and times out at 250 ms; a slow/dead/garbled sidecar fails open
  (that pair is simply un-annotated). The sidecar should answer in single-digit ms.

### Shadow vs. active (the `--injection-active` switch)

- **shadow (default):** the verdict *annotates* signals that emit for other reasons via a
  redacted `learned` block; it never appends a reason, never changes which signals emit, never
  moves attention ranking. This is *score-but-don't-act* — the mode for measuring the classifier
  against the deterministic baseline on live traffic.
- **active:** the verdict becomes a first-class `agent_injection_in_response` reason that can
  raise a signal on its own and contributes to attention weighting.

### Envelope addition

When (and only when) a verdict hits, the envelope carries:

```json
"learned": [{"lane":"agent_injection","label":"injection","score":0.97,"model":"…","shadow":true}]
```

No body text. No offsets. The classifier *reads* the untrusted body; only the verdict leaves.

## What provides the verdict (model-agnostic)

The contract needs a `{label, score}`, not a particular model. In increasing cost/accuracy:

1. **Heuristic classifier — no model, ship today.** Rules over known injection phrasings /
   hidden-instruction markers. Zero training; establishes the socket + measurement loop.
2. **Classical ML** (logistic regression / gradient boosting) over embeddings or features.
3. **Small encoder classifier** (BERT-class, ~22–185M) exported to **Core ML**, running on the
   Apple Neural Engine — the accuracy target, sub-ms on-device. This is a *discriminative
   classifier*, **not** a generative model; injection detection is discrimination, not generation.

Upgrade tiers only when measurement (below) shows the current tier's FP/FN is insufficient.

## Boundary rationale

- **#6 (no raw values in the mailbox):** the sidecar reads the body; only `label/score/model/
  shadow` enter the envelope. Verified by `test_..._without_leaking_body`.
- **#3 (no HTTP from the passive pipeline):** transport is AF_UNIX IPC in the same trust domain
  that already holds the hydrated body — not a network request.
- **#8 (captured content is untrusted):** the classifier is built to consume hostile text; its
  output is a hypothesis, never a finding.
- **#9 (stdlib-only core):** the model lives in the sidecar; `learned_lane.py` imports only
  `socket`/`struct`/`json`/`dataclasses`.

## Consequences

- Measurement plan: run **shadow mode** against BrowseSafe Bench + our own captured-traffic
  fixtures; record FP rate on benign envelopes before enabling active mode anywhere.
- Known limitation: shadow mode annotates only *already-hydrated* pairs, so it measures
  precision on the emitted set, not full recall. Recall measurement needs a hydrate-all pass.
- Cost: in active mode the lane calls the sidecar for every hydrated body (bounded by
  `--hydrate-limit`). Acceptable and configurable; dormant by default.
- The same lane is dual-use: the verdict is both a **defense** input (protect the driving LLM)
  and a **signal** (`agent_injection_in_response` = a target serving agent-injection content).
```
