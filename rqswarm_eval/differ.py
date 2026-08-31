"""The compare node of the active-assessment loop.

Passive tap → cheap collapse → judge picks probes → active replay creates new
states → THIS compares those states → new signals feed back. Two oracles the
"no-response-anomaly" bugs need, that passive analysis can't provide:

- diff_authz: replay a victim's request as the attacker; did the attacker get
  the victim's object (BOLA/IDOR) or get properly denied? Authz bugs leave no
  anomaly in a single response -- only the A-vs-B comparison reveals them.
- diff_timing: paired baseline/probe timings sent concurrently; flag a
  jitter-robust delta (blind injection, user enumeration).

Pure stdlib, deterministic. The Observations come from the live capture half
(browser/replay); everything here is offline-testable.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass


@dataclass
class Obs:
    """One observed request outcome."""
    label: str
    status: int
    body: str = ""
    elapsed_ms: float | None = None


def _similarity(a: str, b: str) -> float:
    """Cheap token-set Jaccard, enough to tell 'same object' from 'different'."""
    ta, tb = set((a or "").split()), set((b or "").split())
    if not ta and not tb:
        return 1.0
    return len(ta & tb) / max(1, len(ta | tb))


def diff_authz(baseline: Obs, replay: Obs, victim_markers: list[str] | None = None) -> dict:
    """Classify an authorization differential.

    baseline = the victim's own request+response. replay = the SAME request sent
    with the attacker's identity. ``victim_markers`` are strings that should only
    appear in the victim's data (their email, id, token) -- their presence in the
    replay body is a confirmed cross-tenant leak.
    """
    markers = [m for m in (victim_markers or []) if m and m in (replay.body or "")]
    sim = _similarity(baseline.body, replay.body)
    if replay.status in (401, 403):
        verdict, severity = "scoped", "ok"                    # properly denied
    elif replay.status >= 500:
        verdict, severity = "error", "investigate"
    elif markers:
        verdict, severity = "bola-confirmed", "critical"      # attacker sees victim markers
    elif replay.status < 400 and sim >= 0.9:
        verdict, severity = "bola-likely", "high"             # attacker gets victim's object back
    elif replay.status < 400:
        verdict, severity = "rebound", "info"                 # served, but a different object
    else:
        verdict, severity = "blocked", "ok"
    return {
        "verdict": verdict, "severity": severity,
        "status": (baseline.status, replay.status),
        "leaked_markers": markers,
        "body_similarity": round(sim, 3),
    }


def diff_timing(pairs: list[tuple[float, float]], min_delta_ms: float = 25.0) -> dict:
    """Jitter-robust timing oracle over concurrently-sent (baseline_ms, probe_ms) pairs.

    Comparing *relative* deltas from paired concurrent sends cancels network
    jitter (Kettle's insight); absolute latency would not. Significant only if
    the median delta is positive, clears the jitter floor (MAD) by a margin, and
    exceeds ``min_delta_ms``.
    """
    deltas = [p - b for b, p in pairs if b is not None and p is not None]
    if len(deltas) < 3:
        return {"verdict": "insufficient", "n": len(deltas)}
    med = statistics.median(deltas)
    mad = statistics.median([abs(d - med) for d in deltas]) or 1e-6
    significant = med > 0 and med > 4 * mad and med > min_delta_ms
    return {
        "verdict": "timing-anomaly" if significant else "no-signal",
        "median_delta_ms": round(med, 1), "mad_ms": round(mad, 1), "n": len(deltas),
    }
