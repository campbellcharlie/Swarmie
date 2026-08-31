"""Interest scorer — unsupervised anomaly/novelty over perception feature vectors.

Companion to the perception spine's InterestLane. Where the injection scorers judge a single
untrusted string, this scorer judges *observation feature vectors* (see
`rqswarm_eval/perception/obs_features.py`) and answers a different question: "is this pair
worth the LLM's attention right now?" It never decides a verdict; it only ranks.

Three unsupervised signals are folded through a logistic into [0, 1]:

  * anomaly  — how far this vector sits from the running per-feature baseline, as the mean of
               clipped squared z-scores (Welford mean/variance); high = unusual;
  * novelty  — the fraction of baseline features this vector clears at running mean + 1 sigma;
  * prior    — a hand-weighted nudge from a few features that are interesting on their own
               (attention, a learned-lane hit, IDOR/leak/error/exfil/auth reason families).

The running baseline is updated with a batch only *after* that batch is scored, so a score
depends only on vectors seen strictly before it; the first-ever batch is scored on prior
alone. Deterministic, stdlib-only (math), no RNG, no training, no third-party imports.
"""
from __future__ import annotations

import math

# Prior weights: features worth attention regardless of how common they are. The rf_* counts
# are small integers; the 0..1 signals (attention, learned hit) carry the heaviest weights.
_PRIOR_W = {
    "sig_attention_norm": 2.0,
    "sig_learned_hit": 1.5,
    "rf_exfil": 1.5,
    "rf_idor": 1.2,
    "rf_leak": 1.2,
    "rf_error": 0.8,
    "rf_auth": 0.6,
}
_W_ANOMALY = 0.35   # anomaly is a mean of clipped z^2 in [0, _Z2_CAP]
_W_NOVELTY = 1.5    # novelty is a fraction in [0, 1]
_BIAS = -2.0        # an all-zero vector scores ~0.12, comfortably under 0.5
_Z2_CAP = 9.0       # clip each squared z-score at 3 sigma so one wild feature can't dominate


class InterestScorer:
    model_id = "interest-heuristic-v1"

    def __init__(self):
        # Per-feature running baseline, indexed by feature position and grown on demand.
        self._n: list[int] = []       # sample count per feature
        self._mean: list[float] = []  # running mean per feature
        self._m2: list[float] = []    # running sum of squared deltas (Welford)

    def score_batch(self, batch: list[list[float]], feature_names: list[str]) -> list[float]:
        if not batch:
            return []
        prior_idx = self._prior_indices(feature_names)
        scores = [self._score_one(vec, prior_idx) for vec in batch]
        for vec in batch:               # baseline update happens strictly AFTER scoring
            self._observe(vec)
        return scores

    # -- scoring -----------------------------------------------------------------------------
    def _score_one(self, vec: list[float], prior_idx: list[tuple[int, float]]) -> float:
        anomaly, novelty = self._anomaly_novelty(vec)
        z = _BIAS + self._prior(vec, prior_idx) + _W_ANOMALY * anomaly + _W_NOVELTY * novelty
        return 1.0 / (1.0 + math.exp(-_clip(z, -60.0, 60.0)))

    @staticmethod
    def _prior(vec: list[float], prior_idx: list[tuple[int, float]]) -> float:
        return sum(w * _at(vec, i) for i, w in prior_idx)

    def _anomaly_novelty(self, vec: list[float]) -> tuple[float, float]:
        z2_sum = 0.0
        exceed = 0
        considered = 0
        for i in range(min(len(vec), len(self._n))):
            n = self._n[i]
            if n < 2:                   # need >=2 samples before a variance exists
                continue
            std = math.sqrt(self._m2[i] / n)   # population std over seen samples
            if std <= 0.0:              # a constant feature is never anomalous
                continue
            considered += 1
            dev = _at(vec, i) - self._mean[i]
            z2_sum += min((dev / std) ** 2, _Z2_CAP)
            if dev > std:               # clears running mean + 1 sigma
                exceed += 1
        if considered == 0:
            return 0.0, 0.0
        return z2_sum / considered, exceed / considered

    # -- baseline ----------------------------------------------------------------------------
    def _observe(self, vec: list[float]) -> None:
        for i, raw in enumerate(vec):
            if i >= len(self._n):       # grow the baseline for a longer-than-seen vector
                self._n.append(0)
                self._mean.append(0.0)
                self._m2.append(0.0)
            x = _finite(raw)
            self._n[i] += 1
            delta = x - self._mean[i]
            self._mean[i] += delta / self._n[i]
            self._m2[i] += delta * (x - self._mean[i])

    @staticmethod
    def _prior_indices(feature_names: list[str]) -> list[tuple[int, float]]:
        out: list[tuple[int, float]] = []
        for name, w in _PRIOR_W.items():
            try:
                out.append((feature_names.index(name), w))
            except ValueError:
                continue                # tolerate a feature set that lacks this name
        return out


def _at(vec: list[float], idx: int) -> float:
    return _finite(vec[idx]) if 0 <= idx < len(vec) else 0.0


def _finite(raw) -> float:
    x = float(raw)
    return x if math.isfinite(x) else 0.0


def _clip(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x
