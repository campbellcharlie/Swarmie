"""Fuse attention and interest into a single selection priority.

Two pure helpers the perception spine uses to turn per-observation scores into a
bounded work list. `fuse_interest` blends the deterministic attention score
(0..100) with the optional sidecar interest score (0..1) into a priority in
[0,1]; when interest is dormant (`None`) it falls back to attention alone, which
keeps the pipeline useful before the sidecar is wired. `select_top_k` picks the
highest-priority ids under a fractional budget bounded to a sane floor/ceiling.

Stdlib only, deterministic, pure. Nothing here references any target, product,
or environment.
"""
from __future__ import annotations

import math


def _clip01(x: float) -> float:
    """Clip to the closed unit interval; non-finite -> 0.0."""
    if not math.isfinite(x):
        return 0.0
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def fuse_interest(attention_0_100: float, interest_0_1: float | None,
                  *, w_attention: float = 0.6, w_interest: float = 0.4) -> float:
    """Blend attention (0..100) and interest (0..1) into a priority in [0,1].

    `interest_0_1 is None` is the dormant fallback: return `attention/100`
    clipped, ignoring the weights. Otherwise return the clipped weighted sum; the
    default weights sum to 1.0 so a well-formed blend already lands in [0,1], and
    the final clip guards against odd weights or out-of-range inputs.
    """
    attention = _clip01(attention_0_100 / 100.0)
    if interest_0_1 is None:
        return attention
    interest = _clip01(interest_0_1)
    return _clip01(w_attention * attention + w_interest * interest)


def select_top_k(scored: list[tuple], *, k_frac: float = 0.05, k_min: int = 3,
                 k_max: int = 50) -> set:
    """Return the ids of the top `ceil(k_frac*N)` entries of `scored`.

    `scored` is `[(id, priority), ...]`. The count is bounded to `[k_min, k_max]`
    and to `N`, so a small population still yields up to `k_min` ids (or all of
    them when `N < k_min`). Entries are ranked by higher priority, ties broken by
    id, making the selection fully deterministic.
    """
    n = len(scored)
    if n == 0:
        return set()
    k = math.ceil(k_frac * n)
    k = max(k_min, min(k, k_max))
    k = min(k, n)
    ordered = sorted(scored, key=lambda item: (-item[1], item[0]))
    return {item[0] for item in ordered[:k]}
