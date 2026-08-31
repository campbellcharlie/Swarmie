"""Tests for the active-loop compare node (authz + timing oracles)."""
from rqswarm_eval.differ import Obs, diff_authz, diff_timing


def test_bola_confirmed_by_marker():
    base = Obs("victim", 200, '{"user":"alice","ssn":"111-22-3333"}')
    replay = Obs("attacker-sends-victim-id", 200, '{"user":"alice","ssn":"111-22-3333"}')
    r = diff_authz(base, replay, victim_markers=["111-22-3333"])
    assert r["verdict"] == "bola-confirmed" and r["severity"] == "critical"
    assert r["leaked_markers"] == ["111-22-3333"]


def test_bola_likely_by_similarity():
    base = Obs("victim", 200, "order 4001 total 59 items shoes belt")
    replay = Obs("attacker", 200, "order 4001 total 59 items shoes belt")
    r = diff_authz(base, replay)
    assert r["verdict"] == "bola-likely" and r["severity"] == "high"


def test_scoped_when_denied():
    base = Obs("victim", 200, "secret")
    replay = Obs("attacker", 403, "forbidden")
    assert diff_authz(base, replay)["verdict"] == "scoped"


def test_rebound_when_different_object():
    base = Obs("victim", 200, "alice private profile email a@x.com phone 111")
    replay = Obs("attacker", 200, "bob other profile email b@y.com phone 999")
    assert diff_authz(base, replay)["verdict"] == "rebound"


def test_timing_anomaly_survives_jitter():
    # ~80ms consistent delta with small jitter -> flagged
    pairs = [(30, 112), (28, 108), (35, 118), (31, 111), (29, 109)]
    r = diff_timing(pairs)
    assert r["verdict"] == "timing-anomaly" and r["median_delta_ms"] >= 75


def test_timing_no_signal_under_jitter():
    # deltas dominated by noise, no consistent positive shift -> no signal
    pairs = [(30, 33), (28, 20), (35, 40), (31, 25), (29, 34)]
    assert diff_timing(pairs)["verdict"] == "no-signal"


def test_timing_insufficient_samples():
    assert diff_timing([(10, 20)])["verdict"] == "insufficient"
