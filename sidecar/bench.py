"""Benchmark a scorer against the labeled corpus.

The whole point of tiers: a model is only worth its complexity if it beats the tier-1
baseline on the *same* corpus. This prints precision / recall / F1 / false-positive-rate /
accuracy and p50-p95 latency, and (with --errors) the exact misclassified examples — so the
decision to keep or drop a tier is made on numbers, not vibes.

Stdlib for the heuristic scorer; the coreml scorer pulls its deps lazily, so run this under
the tier-3 venv when --scorer coreml.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .scorers import load_scorer


def load_corpus(path: str, split: str | None = None) -> list[dict]:
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    return [r for r in rows if split is None or r.get("split") == split]


def evaluate(scorer, rows: list[dict], threshold: float = 0.5) -> dict:
    tp = fp = tn = fn = 0
    latencies: list[float] = []
    for r in rows:
        t0 = time.perf_counter()
        res = scorer.score(r["text"])
        latencies.append((time.perf_counter() - t0) * 1000.0)
        pred = res.score >= threshold
        actual = r["label"] == "injection"
        tp += pred and actual
        fp += pred and not actual
        fn += (not pred) and actual
        tn += (not pred) and not actual
    n = len(rows) or 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    latencies.sort()
    return {
        "n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4), "accuracy": round((tp + tn) / n, 4),
        "latency_ms_p50": round(latencies[len(latencies) // 2], 3),
        "latency_ms_p95": round(latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))], 3),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark a learned-lane scorer")
    ap.add_argument("--scorer", default="heuristic", choices=["heuristic", "coreml"])
    ap.add_argument("--model-dir", help="path to the .mlpackage dir (coreml)")
    ap.add_argument("--corpus", default="sidecar/fixtures/injection_corpus.jsonl")
    ap.add_argument("--split", default=None, help="restrict to a split (train/eval)")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--errors", action="store_true", help="list misclassified examples")
    args = ap.parse_args(argv)

    kw = {}
    if args.scorer == "coreml":
        if not args.model_dir:
            ap.error("--model-dir is required for the coreml scorer")
        kw["model_dir"] = args.model_dir
    scorer = load_scorer(args.scorer, **kw)
    rows = load_corpus(args.corpus, args.split)
    metrics = {"scorer": args.scorer, "model": scorer.model_id, **evaluate(scorer, rows, args.threshold)}
    print(json.dumps(metrics, indent=2))
    if args.errors:
        for r in rows:
            res = scorer.score(r["text"])
            pred = res.score >= args.threshold
            if pred != (r["label"] == "injection"):
                tag = "FP" if pred else "FN"
                print(f"  [{tag} score={res.score:.3f}] {r['text'][:90]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
