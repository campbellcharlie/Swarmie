"""ADR-0004 value-graph: id extraction, co-occurrence, and the redaction boundary."""
from __future__ import annotations

import json

from rqswarm_eval.perception.valuegraph import (
    ValueGraph, extract_body_ids, extract_request_ids, is_id_like, value_hash,
)


def test_is_id_like():
    assert is_id_like("1234")                       # 4+ digit int
    assert is_id_like("550e8400-e29b-41d4-a716-446655440000")  # uuid
    assert is_id_like("deadbeefcafe0001")           # long hex
    assert is_id_like("aGVsbG8td29ybGQ_x")          # opaque token
    assert not is_id_like("12")                     # too short/common int
    assert not is_id_like("true")                   # common word
    assert not is_id_like("ab")                     # too short


def test_extract_request_ids_path_and_query():
    ids = extract_request_ids("http://x/api/users/1234/profile?ref=9999888877776666&page=2")
    assert "1234" in ids and "9999888877776666" in ids
    assert "2" not in ids and "profile" not in ids


def test_extract_body_ids_json_only():
    body = json.dumps({"id": 8181, "name": "bob", "nested": {"doc": "deadbeefcafe0001"}})
    ids = extract_body_ids(body, "application/json")
    assert "8181" in ids and "deadbeefcafe0001" in ids
    assert extract_body_ids("<html>1234</html>", "text/html") == set()  # non-json ignored


def test_value_hash_stable_and_non_reversible():
    h = value_hash("9999888877776666")
    assert h == value_hash("9999888877776666") and len(h) == 12
    assert "9999888877776666" not in h


def test_valuegraph_siblings_and_origin_exclude_self():
    g = ValueGraph()
    A = ("x", "GET", "/api/users/{id}/profile")
    B = ("x", "GET", "/api/orders/{id}")
    h = value_hash("1234")
    # self-exclusion: an id seen only at A gives A no siblings
    g.record({"1234"}, A, "request")
    assert g.relate({"1234"}, A) == {"siblings": {}, "origins": {}}
    # A's RESPONSE carried it, then B's request uses it -> data-flow A.response -> B.request
    g.record({"1234"}, A, "response")
    g.record({"1234"}, B, "request")
    relB = g.relate({"1234"}, B)
    assert relB["siblings"].get(h) == [A]         # A is a sibling of B
    assert relB["origins"].get(h) == [A]          # and the data-flow origin
    assert g.relate({"1234"}, A)["siblings"].get(h) == [B]  # co-occurrence is symmetric
    assert g.relate({"5555"}, B) == {"siblings": {}, "origins": {}}  # unknown id


def test_valuegraph_eviction_is_bounded():
    g = ValueGraph(cap=10)
    for i in range(50):
        g.record({f"{1000+i}"}, ("x", "GET", f"/e{i}"), "request")
    assert len(g._idx) <= 10


# --- the redaction boundary: no raw value may leave the process into an envelope ---

def _row(rid, url, host="x"):
    from urllib.parse import urlsplit
    return {
        "request_id": rid, "method": "GET", "host": host,
        "path": urlsplit(url).path, "url": url, "param_names": "ref",
        "status_code": 200, "response_length": 20, "content_type": "application/json",
        "request_headers": "GET / HTTP/1.1", "request_body": "",
        "response_headers": "content-type: application/json", "response_body": "{}",
    }


def test_shared_id_reason_and_no_raw_value_in_envelope():
    from rqswarm_eval.passive import SignalEngine
    eng = SignalEngine()
    secret_id = "9999888877776666"  # distinctive; appears only as a query VALUE
    r1 = _row(1, f"http://x/api/users/9001/profile?ref={secret_id}")
    r2 = _row(2, f"http://x/api/orders/9002?ref={secret_id}")
    eng.observe_metadata(r1); eng.observe_metadata(r2)   # primes the endpoint baselines
    e1 = eng.build_signal(r1, ["new_dynamic_endpoint"])
    e2 = eng.build_signal(r2, ["new_dynamic_endpoint"])
    assert e1 is not None and e2 is not None
    # the second endpoint sees the same query id -> BOLA sibling reason + hypothesis
    assert "idor_shared_object_id" in e2["observation"]["reasons"]
    assert any(h["family"] == "broken-object-level-authorization" for h in e2["hypotheses"])
    # REDACTION: the raw query value must appear in NEITHER envelope, anywhere.
    assert secret_id not in json.dumps(e1)
    assert secret_id not in json.dumps(e2)
    # the interrogation routes to the BOLA/trust-chain lens
    personas = {l["persona"] for l in e2["interrogation"]["lenses"]}
    assert "trust-chain" in personas


def test_hex_path_id_is_collapsed_not_leaked():
    """A 12+ char hex object id in a path segment collapses to {id} and never leaks raw.

    Regression for the ADR-0004 leak-hunt: path_shape's hex floor was 16, so 12-15 hex ids
    survived raw in envelope.endpoint.path_shape. Floor is now 12.
    """
    from rqswarm_eval.passive import SignalEngine
    eng = SignalEngine()
    r = _row(1, "http://x/api/obj/abcdef012345")
    eng.observe_metadata(r)
    env = eng.build_signal(r, ["new_dynamic_endpoint"])
    assert env is not None
    assert env["endpoint"]["path_shape"] == "/api/obj/{id}"
    assert "abcdef012345" not in json.dumps(env)


def test_secret_shaped_path_segments_collapse_route_names_survive():
    """Secret/token path segments collapse to {id}; unambiguous prefixes never eat route names."""
    from rqswarm_eval.sources import path_shape
    for seg in ["/x/AKIAIOSFODNN7EXAMPLE", "/pay/sk_live_0123456789abcdefghijklmn",
                "/gh/ghp_0123456789abcdefghij0123456789abcd", "/t/eyJhbGciOi.eyJzdWIi.abc123def",
                "/g/AIzaSyD0123456789abcdefghijklmnopqrstuv", "/c/cs_live_a1b2c3d4e5f6"]:
        assert path_shape(seg).endswith("/{id}"), seg
    for seg in ["/api/checkout", "/docs/documentation", "/user/skills", "/v1/orders"]:
        assert path_shape(seg) == seg, seg  # route names untouched


def test_secret_in_path_not_leaked_to_envelope():
    from rqswarm_eval.passive import SignalEngine
    eng = SignalEngine()
    secret = "AKIAIOSFODNN7EXAMPLE"
    r = _row(1, f"http://x/creds/{secret}/rotate")
    eng.observe_metadata(r)
    env = eng.build_signal(r, ["new_dynamic_endpoint"])
    assert env is not None
    assert env["endpoint"]["path_shape"] == "/creds/{id}/rotate"
    assert secret not in json.dumps(env)
