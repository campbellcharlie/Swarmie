"""Compare Swarmie JSONL signal dumps on proxy quality metrics.

Usage:
    python3 -m rqswarm_eval.eval_corpus baseline.jsonl [variant.jsonl ...]

Metrics (no ground-truth labels required):
  signals        — total emitted
  score p50/p90  — differentiation proxy (wider = better)
  corr>=2        — % signals with >=2 independent reasons (converging evidence)
  unique_hosts   — distinct hosts in top-50 by score (diversity proxy)
  known_good     — presence of high-confidence reason families in any signal
  top_reasons    — most frequent reasons (top 10)
"""
from __future__ import annotations

import collections
import json
import math
import sys
from pathlib import Path


def load(path: str) -> list[dict]:
    signals = []
    for line in Path(path).read_text().splitlines():
        try:
            s = json.loads(line)
            if s.get("schema") == "swarmie.signal.v1":
                signals.append(s)
        except (ValueError, KeyError):
            pass
    return signals


def stats(signals: list[dict]) -> dict:
    if not signals:
        return {}

    scores = sorted(s.get("attention", {}).get("score", 0) for s in signals)
    n = len(scores)

    def pct(p):
        idx = max(0, min(n - 1, int(n * p / 100)))
        return scores[idx]

    reasons_per = [len(set(s.get("observation", {}).get("reasons", []))) for s in signals]
    corr2 = sum(1 for r in reasons_per if r >= 2) / n

    top50 = sorted(signals, key=lambda s: s.get("attention", {}).get("score", 0), reverse=True)[:50]
    unique_hosts_top50 = len({s.get("endpoint", {}).get("host", "") for s in top50})

    all_reasons: list[str] = []
    for s in signals:
        all_reasons.extend(s.get("observation", {}).get("reasons", []))
    reason_freq = collections.Counter(all_reasons).most_common(10)

    known_good_families = {
        "authenticated_cache_policy_contradiction", "server_error_response",
        "status_spike_in_run", "auth_anomaly_in_sequence",
        "third_party_receives_auth_context_in_window", "downstream_of_authenticated_host",
    }
    present_known = {r for r in all_reasons} & known_good_families

    return {
        "signals": n,
        "score_mean": round(sum(scores) / n, 1),
        "score_p25": round(pct(25), 1),
        "score_p50": round(pct(50), 1),
        "score_p75": round(pct(75), 1),
        "score_p90": round(pct(90), 1),
        "score_max": round(scores[-1], 1),
        "corr_ge2_pct": round(corr2 * 100, 1),
        "unique_hosts_top50": unique_hosts_top50,
        "known_good_present": sorted(present_known),
        "top_reasons": reason_freq,
    }


def _col(value, width=14) -> str:
    return str(value)[:width].ljust(width)


def compare(paths: list[str]) -> None:
    datasets = [(p, stats(load(p))) for p in paths]
    keys = [
        "signals", "score_mean", "score_p50", "score_p90", "score_max",
        "corr_ge2_pct", "unique_hosts_top50",
    ]
    header = _col("metric") + "  " + "  ".join(_col(Path(p).name, 20) for p, _ in datasets)
    print(header)
    print("-" * len(header))
    for k in keys:
        row = _col(k) + "  " + "  ".join(_col(str(s.get(k, "-")), 20) for _, s in datasets)
        print(row)

    print()
    for path, s in datasets:
        print(f"known_good [{Path(path).name}]: {s.get('known_good_present', [])}")

    print()
    for path, s in datasets:
        print(f"top reasons [{Path(path).name}]:")
        for reason, count in (s.get("top_reasons") or []):
            print(f"  {count:6d}  {reason}")
        print()


def main(argv=None) -> int:
    args = (argv or sys.argv)[1:]
    if not args:
        print(__doc__)
        return 1
    compare(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
