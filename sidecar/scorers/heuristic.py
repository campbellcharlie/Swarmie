"""Tier 1: heuristic scorer — stdlib rules, no model, no training.

Hand-weighted logistic over the shared injection families. Its job is to be the baseline
the learned tiers must beat; if a 20-line rule set ties the transformer on the bench, the
transformer isn't earning its complexity. Ships today with zero dependencies.
"""
from __future__ import annotations

import math

from ..features import feature_vector, iter_family_matches
from . import ScoreResult

# Hand-set family weights (tier 2 learns these instead). A single strong family (override,
# exfil, system_leak) crosses 0.5; a lone urgency/marker does not.
_FAMILY_W = {
    "override": 3.0, "role_switch": 2.0, "system_leak": 2.5, "exfil": 2.5,
    "redirect": 1.5, "hidden_marker": 0.8, "urgency": 0.7,
}
_SCALAR_W = {"url_count": 0.6, "code_fence": 0.3, "caps_ratio": 0.8, "length_norm": 0.0}
_BIAS = -1.6


class HeuristicScorer:
    model_id = "heuristic-v1"

    def score(self, text: str, *, response_type: str = "") -> ScoreResult:
        vec = feature_vector(text)
        z = _BIAS
        for name, w in _FAMILY_W.items():
            z += w * vec[name]
        for name, w in _SCALAR_W.items():
            z += w * vec[name]
        score = 1.0 / (1.0 + math.exp(-z))
        spans = [[s, e] for _, s, e in iter_family_matches(text)][:20]
        label = "injection" if score >= 0.5 else "benign"
        return ScoreResult(label=label, score=score, spans=spans)
