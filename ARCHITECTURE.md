# Swarm-explores / LLM-judges architecture

> Use swarms to explore a huge request-mutation space, use cheap
> models/algorithms to collapse redundant responses, and reserve the LLM for
> deciding which genuinely novel observations are worth pursuing.

> **Status note (removed):** the mutation-swarm / synthetic-oracle GA layer described in the
> component table below has been **removed** from the product (preserved at git tag
> `archive/experiment-harness`). This document is retained for the *measured findings* that
> justified that decision and for the swarm-explores / LLM-judges principle the passive engine
> still follows. Files like `evolve.py`, `executor.py`, `swarm_novelty.py`, and `swarm_tagger.py`
> no longer exist in the tree.

The LLM is **not** in the inner loop of every HTTP transaction. Cheap ML +
heuristics handle volume, dedup, and prioritization; the scarce frontier judge
handles strategy and verdicts.

```
Mutation swarm → 500 candidate requests → batch scheduler/LLM
  → execute 1–10 at a time → response normalization
  → similarity/anomaly filtering → discard redundant → rank interesting
  → LLM judge → choose next mutations/branches
```

## Component status (what is real vs. aspirational)

| stage | status | where |
|-------|--------|-------|
| Mutation swarm | 🟩 deterministic profiler; 🟨 genome policy exists but see finding #4 | `triage.py`, `profile_adapter.py`, `evolve.py` |
| 500 candidate requests | 🟩 candidates generated per captured request | `triage.py` |
| Batch scheduler / LLM picks 1–10 | 🟥 not built (needs live execution + authorization) | — |
| Execute 1–10 | 🟥 not built — dry-run only so far (nothing is sent) | (would be `executor.py` + an active sender, scoped) |
| Response normalization | 🟩 on captured responses | `response.py`, `sources.py` |
| Similarity / dedup | 🟩 shape-dedup; 🟥 TF-IDF novelty tried, failed (finding #2) | `triage.py`, `swarm_novelty.py` |
| Anomaly / value ranking | 🟩 value-weighted, host-aware | `triage.py` |
| LLM judge | 🟩 works — but only the *frontier* judge (me), not a local model | this session; `swarm_tagger.py` (local, failed #3) |
| Choose next mutations (feedback) | 🟥 not built | — |

## Measured findings (why the cheap-local path keeps failing)

1. **Deterministic regex + response analysis is the current strongest cheap signal.** It found the real leads (a media-server API-key exposure, an `alg:none` JWT, a CGI reflected-XSS). It's "just python + regex," and it wins so far.
2. **Unsupervised novelty (TF-IDF + kNN) is non-additive.** 0/20 overlap with the baseline; its top picks are structurally-weird tracking beacons, not vulns. Novelty ≠ vulnerability.
3. **A local 3B tagger is uncalibrated** — it mirrors the prompt (everything "low", or 40/50 confabulated "HIGH IDOR"). Not a reliable judge.
4. **The synthetic-fixture GA is starved.** Triggers require exact sha256-derived hidden field names (`f_09b3c9`) and `state_id` is constant, so blind mutation gets zero gradient. The fixtures are an unsolvable *test*, not a training *signal*. BDrome could evolve only because its match-fitness was free and dense; here the real fitness is the scarce judge, so **learn from labels, don't blind-search**.

## Decision: macOS-native, real ML/APIs (drop the toy-oracle GA)

- **Recall/dedup:** real embeddings (`nomic-embed-modernbert`, already in LM Studio; MLX on Apple Silicon) instead of TF-IDF.
- **Judge/tagger:** the Anthropic API (calibrated, built for semantic triage) — or a large local model via MLX (e.g. gpt-oss-20b) for fully offline. Not a 3B.
- **Learned member:** a supervised classifier (sklearn/MLX) trained on accumulated approve/dismiss verdicts on *real* traffic. The judge's labels are the fitness — active learning, not a GA.
- **Live execution + feedback loop:** authorization-gated; only against in-scope targets, rate-limited, non-destructive.

## Immediate next step (open)

Build the **real embedding-recall member** on the local nomic model (on-box, no API key), measured against the regex baseline like everything else — and/or wire the **Anthropic API as the calibrated tagger**. `evolve.py` is left as a documented dead-end (unsolvable-benchmark), not part of the path forward.
