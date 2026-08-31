---
artifact: decision
version: 1
status: accepted
owners: []
last_updated: 2026-08-30
---

# ADR-0003 ML perception spine (interest scoring) in front of the mailbox

## Context

Swarmie emits a `swarmie.signal.v1` envelope per interesting HTTP pair and ranks it by a
symbolic `attention.score` (reason weights, de-saturated, noise-dampened). That is good at
"this has a known tell" but has no notion of *statistical* interestingness — an observation
that is unusual relative to everything else seen, even when no single rule fires. The design
goal (see the ML-first perception discussion) is: **conventional ML continuously scores
thousands of observations as vectors; the scarce LLM only reasons about the top few.**

The Akto teardown (2026-08-30) confirmed the white space: Akto's "context analyzer" is
Bloom-filter value co-occurrence + threshold URL templatization + regex typing — **zero ML**.
So a learned/anomaly perception layer is a genuine fork, not a re-implementation.

Hard boundary (CLAUDE.md #9 + ADR-0002): Swarmie core stays **Python-3.14 stdlib-only**; any
model lives in an **out-of-process sidecar** over an AF_UNIX socket. The perception spine
follows the ADR-0002 learned-lane pattern exactly, extended for **batch** numeric scoring
(the whole point: score a step's worth of observations in one round-trip, keeping the LLM the
only scarce resource — "same load cost" means same judge budget, not same wall-clock).

## Decision

Add a perception spine, all new files, wired fail-open so a missing sidecar leaves behavior
byte-identical to today:

```
build_signal -> swarmie.signal.v1 envelope (attention.score)      [exists]
   -> perception/obs_features.observation_features(envelope)       [core, stdlib]  NEW
   -> InterestLane.score_batch([...vectors...])  --AF_UNIX-->      [core client]   NEW
        sidecar InterestScorer.score_batch(...)  (unsupervised)    [sidecar]       NEW
   -> perception/fuse.fuse_interest(attention, interest)           [core, stdlib]  NEW
   -> select_top_k(...) marks which signals earn LLM priority
   -> mailbox -> Stop-hook gate -> LLM                             [exists]
```

- **CPU lane first** (unsupervised anomaly + novelty over the numeric feature vector, stdlib
  only). GPU/MLX (embedding rarity) and ANE/Core ML (learned interest, once gate dispositions
  supply labels) are later lanes behind the *same* batch socket verb. This is the
  heterogeneous CPU/GPU/ANE fan-out from the design, staged.
- **Supervised comes after labels.** The first scorer is unsupervised because there are no
  labels yet; gate dispositions (`inspect/acted/pivot/dismiss/defer`) are the eventual training
  signal — "learn from labels, not blind search" (ARCHITECTURE.md).
- **No new capture reads, no new secrets.** Features derive purely from the already-built,
  already-redacted envelope. Only a float score returns from the sidecar.

## Increment plan

1. **This ADR — perception spine (interest scoring).** obs_features + InterestLane +
   InterestScorer + fuse + tests; wire into `PassiveTailer.step` and `sidecar/server.py`.
2. Borrow Akto's value-co-occurrence into the resource/identity **app-graph** (extends
   passive's existing investigation graph). Separate ADR.
3. Upgrade the flat per-vuln-class question lists into **directed investigation graphs** +
   explicit facts/hypotheses/questions in the ledger + "what else shares this assumption?".
4. GPU (MLX embedding) and ANE (Core ML learned) interest lanes behind the same socket verb.

## Consequences

- Perception is dormant unless `--interest-socket` is set; fail-open on any socket error.
- The frozen interface contract is `rqswarm_eval/perception/CONTRACT.md`.
- Determinism: features and fusion are pure; the unsupervised scorer updates its running
  baseline only *after* scoring a batch, so a score depends only on inputs seen before it.
