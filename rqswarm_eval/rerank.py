"""Rank-time re-scoring: corpus-rarity multiplier + dedup by lead shape.

The static attention weights are ground-truth-calibrated but *corpus-blind*: a reason that fires on
half of a given corpus (e.g. authenticated_cache_policy_contradiction ~50% on real browsing) still
carries its full weight and dominates the ranking, burying rarer, more specific findings. Rarity is
inherently corpus-relative, so it is applied HERE -- over a completed signal set -- not baked into
the per-signal emit score.

    effective_score(signal) = sum over its reasons of  weight[r] * rarity[r]
    rarity[r] = max(1.0, log2(N / count_r))     # a MULTIPLIER on the calibrated weight, never < 1

Then collapse signals that share a lead shape (method, host, path_shape, top-reason) to one
representative carrying a dup count, so a single repeated lead can't fill the top-K. Measured on
real captures: big re-rank where a corpus is noise-dominated, ~neutral where it is already good.
"""
from __future__ import annotations

import collections
import math


def _reasons(signal: dict) -> list[str]:
    return signal.get("observation", {}).get("reasons", []) or []


def reason_rarity(signals: list[dict]) -> dict[str, float]:
    """Per-corpus rarity multiplier for each reason: log2(N/count), floored at 1.0."""
    n = len(signals)
    if not n:
        return {}
    counts = collections.Counter(r for s in signals for r in set(_reasons(s)))
    return {r: max(1.0, math.log2(n / c)) for r, c in counts.items()}


def effective_score(signal: dict, rarity: dict[str, float], weights: dict[str, int]) -> float:
    return sum(weights.get(r, 0) * rarity.get(r, 1.0) for r in set(_reasons(signal)))


def lead_shape(signal: dict, weights: dict[str, int]) -> tuple:
    ep = signal.get("endpoint", {})
    top = max(_reasons(signal), key=lambda r: weights.get(r, 0), default="")
    return (ep.get("method", ""), ep.get("host", ""), ep.get("path_shape", ""), top)


def rerank(signals: list[dict], reference: list[dict] | None = None,
           weights: dict[str, int] | None = None, dedup: bool = True) -> list[dict]:
    """Order `signals` by rarity-adjusted score; rarity frequencies come from `reference` (default:
    `signals` itself — pass the full corpus when ranking only a pending subset). With dedup, collapse
    same-lead repeats to one representative carrying a `_dupes` count. Inputs are not mutated."""
    if weights is None:
        from .passive import _REASON_WEIGHT as weights  # lazy: keep this module import-light
    rarity = reason_rarity(reference if reference is not None else signals)
    ordered = sorted(signals, key=lambda s: -effective_score(s, rarity, weights))
    if not dedup:
        return ordered
    counts = collections.Counter(lead_shape(s, weights) for s in signals)
    out, taken = [], set()
    for s in ordered:
        k = lead_shape(s, weights)
        if k in taken:
            continue
        taken.add(k)
        rep = dict(s)
        rep["_dupes"] = counts[k]
        out.append(rep)
    return out
