"""Perception spine: obs_features, InterestScorer, InterestLane, and the fuse helpers.

All stdlib. The InterestLane test spins up a real bound AF_UNIX stub server (same wire
contract as `rqswarm_eval/perception/interest_lane.py`) so the client is exercised against
an actual socket, not a mock. Imports are confined to `rqswarm_eval.perception.*` and
`sidecar.scorers.interest`, per the frozen contract (ADR-0003).
"""
from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
import tempfile
import threading
import uuid

import pytest

from rqswarm_eval.perception.fuse import fuse_interest, select_top_k
from rqswarm_eval.perception.interest_lane import InterestLane, make_interest_lane
from rqswarm_eval.perception.obs_features import (
    FEATURE_NAMES,
    feature_list,
    observation_features,
)
from sidecar.scorers.interest import InterestScorer

_LEN = struct.Struct(">I")


def _sock_path() -> str:
    base = "/tmp" if os.path.isdir("/tmp") and os.access("/tmp", os.W_OK) else tempfile.gettempdir()
    return os.path.join(base, f"swm-il-{uuid.uuid4().hex[:12]}.sock")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("stub client closed mid-message")
        buf += chunk
    return bytes(buf)


@contextlib.contextmanager
def interest_stub(reply_fn):
    """A bound AF_UNIX stub speaking the interest wire contract.

    Reads one length-prefixed JSON request per connection and replies with
    `reply_fn(request)` (also length-prefixed JSON), letting each test shape the
    reply — a well-formed echo, a length-mismatched list, a non-list — to drive
    the client's fail-open branches.
    """
    path = _sock_path()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(8)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return  # socket closed on teardown
            with conn:
                try:
                    (n,) = _LEN.unpack(_recv_exact(conn, 4))
                    req = json.loads(_recv_exact(conn, n).decode("utf-8"))
                    body = json.dumps(reply_fn(req)).encode()
                    conn.sendall(_LEN.pack(len(body)) + body)
                except (OSError, ValueError, ConnectionError, struct.error):
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield path
    finally:
        srv.close()
        with contextlib.suppress(OSError):
            os.unlink(path)
        thread.join(timeout=1)


def _idor_leak_envelope() -> dict:
    return {
        "schema": "swarmie.signal.v1", "request_id": 42,
        "endpoint": {"method": "GET", "host": "app.test", "path_shape": "/api/o/{id}"},
        "observation": {
            "reasons": ["idor_substitution", "resp:leak"],
            "request": {"header_names": ["accept"], "auth_present": True,
                        "content_type": "application/json", "query_names": ["id"],
                        "body_keys": []},
            "response": {"status": 200, "content_type": "application/json",
                         "length": 128, "json_keys": ["id", "email"]},
            "baseline": {"endpoint_observations": 5, "statuses": {200: 5},
                         "content_types": {"application/json": 5}},
        },
        "attention": {"score": 80},
        "interrogation": {"lenses": [{"persona": "p", "ask": ["Q?"]}]},
    }


# ---------------------------------------------------------------- obs_features


def test_obs_features_is_deterministic_and_complete():
    env = _idor_leak_envelope()
    first = observation_features(env)
    second = observation_features(env)
    assert first == second                                   # same envelope -> identical vector
    assert set(first) == set(FEATURE_NAMES)                  # every canonical name present
    assert feature_list(env) == feature_list(env)
    assert len(feature_list(env)) == len(FEATURE_NAMES)      # list mirrors the frozen order
    assert all(isinstance(v, float) for v in first.values())


def test_obs_features_maps_idor_and_leak_reasons_and_attention():
    feat = observation_features(_idor_leak_envelope())
    assert feat["rf_idor"] >= 1.0
    assert feat["rf_leak"] >= 1.0
    assert feat["sig_attention_norm"] == pytest.approx(0.8)  # attention.score 80 / 100


# ---------------------------------------------------------------- InterestScorer


def _prior_vector(**named: float) -> list[float]:
    """A feature vector in FEATURE_NAMES order with the named features set."""
    vec = [0.0] * len(FEATURE_NAMES)
    for name, value in named.items():
        vec[FEATURE_NAMES.index(name)] = value
    return vec


def test_interest_scorer_scores_bounded_and_prior_beats_zero():
    scorer = InterestScorer()
    high = _prior_vector(sig_attention_norm=1.0, rf_leak=3.0)
    zero = [0.0] * len(FEATURE_NAMES)
    scores = scorer.score_batch([high, zero], FEATURE_NAMES)
    assert len(scores) == 2
    assert all(0.0 <= s <= 1.0 for s in scores)
    # First-ever batch scores on prior alone (baseline updated only after scoring).
    assert scores[0] > scores[1]


def test_interest_scorer_empty_batch():
    assert InterestScorer().score_batch([], FEATURE_NAMES) == []


# ---------------------------------------------------------------- InterestLane


def test_make_interest_lane_none_is_dormant():
    assert make_interest_lane(None) is None


def test_interest_lane_roundtrips_scores_from_a_bound_socket():
    batch = [[1.0, 2.0], [3.0, 4.0, 5.0]]

    def reply(req):
        return {"v": 1, "scores": [sum(vec) for vec in req["batch"]], "model": "stub"}

    with interest_stub(reply) as path:
        got = InterestLane(path).score_batch(batch, FEATURE_NAMES)
    assert got == pytest.approx([3.0, 12.0])


def test_interest_lane_missing_socket_fails_open():
    lane = InterestLane(_sock_path())          # nothing ever bound here
    assert lane.score_batch([[1.0, 2.0]], FEATURE_NAMES) is None


def test_interest_lane_length_mismatch_fails_open():
    def reply(req):
        # one extra score -> len(scores) != len(batch)
        return {"v": 1, "scores": [0.1] * (len(req["batch"]) + 1), "model": "stub"}

    with interest_stub(reply) as path:
        assert InterestLane(path).score_batch([[1.0]], FEATURE_NAMES) is None


def test_interest_lane_non_list_scores_fails_open():
    def reply(req):
        return {"v": 1, "scores": "not-a-list", "model": "stub"}

    with interest_stub(reply) as path:
        assert InterestLane(path).score_batch([[1.0]], FEATURE_NAMES) is None


# ---------------------------------------------------------------- fuse


def test_fuse_interest_dormant_fallback_and_lift():
    assert fuse_interest(80, None) == 0.8                    # interest dormant -> attention/100
    # A present interest score lifts priority above the attention-only fallback.
    assert fuse_interest(50, 1.0) > fuse_interest(50, None)


def test_select_top_k_floor_frac_and_determinism():
    # N below k_min -> floored at k_min (default 3), picking the highest priorities.
    small = [(i, i / 10.0) for i in range(5)]
    top_small = select_top_k(small)
    assert top_small == {4, 3, 2}
    assert select_top_k(small) == top_small                 # deterministic

    # Large N -> ceil(k_frac*N) within [k_min, k_max]; 0.05 * 200 = 10.
    large = [(i, i / 200.0) for i in range(200)]
    top_large = select_top_k(large, k_frac=0.05)
    assert len(top_large) == 10
    assert top_large == set(range(190, 200))

    # Ties broken by lower id when the budget is tight.
    tied = [(1, 0.5), (2, 0.5), (3, 0.1)]
    assert select_top_k(tied, k_frac=0.05, k_min=1) == {1}


# --- integration: PassiveTailer._score_interest wiring (hand-written glue) ---

def _mk_env(rid, attention, reasons=()):
    return {"schema": "swarmie.signal.v1", "request_id": rid,
            "attention": {"score": attention},
            "observation": {"reasons": list(reasons), "request": {},
                            "response": {"status": 200}, "baseline": {}}}


def test_score_interest_attaches_perception_and_topk():
    import types
    from rqswarm_eval.passive import PassiveTailer

    class _Lane:  # returns a score per vector, highest for the last envelope
        def score_batch(self, vectors, names):
            return [0.1 * (i + 1) for i in range(len(vectors))]

    envs = [_mk_env(1, 10), _mk_env(2, 20), _mk_env(3, 90, ["idor"])]
    stub = types.SimpleNamespace(interest_lane=_Lane())
    PassiveTailer._score_interest(stub, envs)
    for e in envs:
        assert "perception" in e
        p = e["perception"]
        assert 0.0 <= p["interest"] <= 1.0 and 0.0 <= p["priority"] <= 1.0
        assert isinstance(p["top_k"], bool)
    # at least one selected; the highest-priority id is among the top-k
    assert any(e["perception"]["top_k"] for e in envs)


def test_score_interest_fail_open_leaves_envelopes_untouched():
    import types
    from rqswarm_eval.passive import PassiveTailer

    class _DeadLane:
        def score_batch(self, vectors, names):
            return None  # dormant / erroring sidecar

    envs = [_mk_env(1, 10), _mk_env(2, 20)]
    stub = types.SimpleNamespace(interest_lane=_DeadLane())
    PassiveTailer._score_interest(stub, envs)
    assert all("perception" not in e for e in envs)  # byte-identical to symbolic pipeline

    # dormant lane (None) is also a no-op
    stub2 = types.SimpleNamespace(interest_lane=None)
    envs2 = [_mk_env(1, 10)]
    PassiveTailer._score_interest(stub2, envs2)
    assert "perception" not in envs2[0]
