# Learned-lane sidecar

The out-of-process classifier behind Swarmie's `agent_injection` learned lane. Swarmie core
(`rqswarm_eval`) stays Python-3.14 stdlib-only and talks to this over a local AF_UNIX socket;
the sidecar owns whatever produces the `{label, score}` verdict.

Wire contract: `rqswarm_eval/learned_lane.py` and `.devfw/decisions/0002-learned-injection-lane.md`.

## Tiers built

| tier | scorer | what it is | deps |
|------|--------|------------|------|
| 1 | `heuristic` | hand-weighted logistic over injection "tells" | **stdlib** |
| 3 | `coreml` | encoder classifier converted to Core ML, runs on the ANE | coremltools + transformers (separate venv) |

Tier 1 is the **baseline**; tier 3 is the **production candidate**. Tier 2 (a learned linear
model over the same features) was intentionally skipped — the baseline vs. the model is the
comparison that matters.

## Benchmark (72-example labeled corpus, `fixtures/injection_corpus.jsonl`)

```
tier  model                              precision  recall   F1     FP-rate  p50 latency
1     heuristic-v1                       0.80       0.97     0.875  0.25     0.04 ms
3     fmops/distilbert-prompt-injection  0.50       1.00     0.67   1.00     8.3  ms
3     testsavantai/…-defender-small-v0   0.80       0.89     0.84   0.22     2.8  ms   ← default
```

### Findings (why measurement is not optional)

1. **The Core ML conversion is faithful.** Converted-vs-source parity is ≤ 1e-5 (BERT) /
   3.6e-4 (DistilBERT) max probability delta. On-device inference is 2.8–8.3 ms p50. "It
   converted" is backed by "it agrees with the source model" — the convert script asserts this.
2. **Model choice dominates, and the popular one is miscalibrated for HTTP bodies.**
   `fmops/distilbert-prompt-injection` scores ordinary JSON/HTML/code as injection
   (`{"status":"ok"}` → 0.999), giving a **1.0 false-positive rate** — worse than the baseline.
   The default was switched to a BERT *defender* model that keeps FP-rate at 0.22.
3. **On this corpus the tier-1 heuristic (F1 0.875) edges the best model (0.84).** **Caveat:**
   72 synthetic examples, with the rules and the hard negatives authored by the same hand — so
   this is *not* evidence the heuristic wins in general. A real adversarial benchmark
   (BrowseSafe Bench: obfuscated, multilingual, novel phrasings the rules can't anticipate) is
   the next measurement. What the corpus *does* prove: the pipeline runs on-device, and the
   baseline is strong enough that a model must be measured against it, never assumed better.

## Run it

**Tier 1 — today, zero dependencies:**
```bash
python -m sidecar.server --scorer heuristic --socket /tmp/swm.sock
# then point Swarmie at it:
python -m rqswarm_eval.passive --source <db> --mailbox <mbox> \
    --injection-socket /tmp/swm.sock            # shadow mode (annotate only)
# add --injection-active to promote verdicts to first-class signals.
```

**Tier 3 — Core ML on the ANE (separate venv, since coremltools lags Python):**
```bash
python3.12 -m venv ~/.cache/swarmie-tier3-venv
~/.cache/swarmie-tier3-venv/bin/pip install "torch==2.7.0" "transformers==4.46.3" "coremltools>=9"
# convert (empirically resolves the injection label index + runs a parity check):
~/.cache/swarmie-tier3-venv/bin/python -m sidecar.convert_coreml --out sidecar/models/injection
# serve:
~/.cache/swarmie-tier3-venv/bin/python -m sidecar.server \
    --scorer coreml --model-dir sidecar/models/injection --socket /tmp/swm.sock
```

> Version pin matters: torch 2.13 + transformers v5 emit mask ops (`new_ones`, `__and__`)
> that coremltools 9 can't convert. The tested matrix (torch 2.7 / transformers 4.46) converts
> cleanly. `convert_coreml.py` also registers a `new_ones` op as a fallback.

**Benchmark any scorer against the corpus:**
```bash
python -m sidecar.bench --scorer heuristic --errors
~/.cache/swarmie-tier3-venv/bin/python -m sidecar.bench \
    --scorer coreml --model-dir sidecar/models/injection --errors
```

## Layout

```
sidecar/
  server.py            AF_UNIX harness — framing + Scorer dispatch
  features.py          shared injection-family features (tier 1)
  scorers/
    heuristic.py       tier 1
    coreml.py          tier 3 (lazy coremltools import)
  convert_coreml.py    HF classifier -> .mlpackage (+ empirical label resolve + parity check)
  bench.py             precision / recall / F1 / FP-rate / latency vs the corpus
  fixtures/…jsonl      labeled corpus (agnostic; includes hard negatives)
  models/              converted .mlpackage — gitignored (large, regenerable)
```
