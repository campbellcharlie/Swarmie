"""Pluggable scorers behind the sidecar socket.

A scorer maps untrusted text -> a verdict. Every tier implements the same tiny interface
so the socket contract is identical regardless of what produces the score:

    tier 1  heuristic   stdlib rules                     (no model, no training)
    tier 3  coreml      encoder classifier on the ANE    (needs coremltools; separate venv)

Tier 1 is the baseline; tier 3 is the production candidate. They are benchmarked against
the same labeled corpus so the comparison is real.
"""
from __future__ import annotations

import dataclasses
from typing import Protocol, runtime_checkable


@dataclasses.dataclass(frozen=True)
class ScoreResult:
    label: str          # "injection" | "benign"
    score: float        # probability of the positive class, 0..1
    spans: list         # optional [[start, end], ...] offsets; operator-side only


@runtime_checkable
class Scorer(Protocol):
    model_id: str       # provenance string returned to Swarmie as "model"

    def score(self, text: str, *, response_type: str = "") -> ScoreResult: ...


def load_scorer(kind: str, **kw) -> Scorer:
    """Factory. Imports each tier lazily so tier-3 deps aren't required for tiers 1/2."""
    if kind == "heuristic":
        from .heuristic import HeuristicScorer
        return HeuristicScorer()
    if kind == "coreml":
        from .coreml import CoreMLScorer
        return CoreMLScorer(kw["model_dir"])
    if kind == "interest":
        from .interest import InterestScorer
        return InterestScorer()
    raise ValueError(f"unknown scorer {kind!r}")
