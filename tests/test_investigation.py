"""ADR-0005 investigation graphs: classify, machine-facts, build_signal wiring, gate."""
from __future__ import annotations

import json

from rqswarm_eval.perception.investigation import (
    build_investigation, classify, graph_for,
)


def test_classify_maps_reasons_to_class():
    assert classify(["idor_shared_object_id"]) == "bola"
    assert classify(["route:jwt", "resp:leak"]) == "broken_auth"
    assert classify(["route:injection"]) == "injection"
    assert classify(["resp:cors"]) == "cache"
    assert classify(["new_dynamic_endpoint"]) is None


def test_build_investigation_splits_facts_hypothesis_questions():
    inv = build_investigation("bola", {
        "selector_location": "path parameter",
        "id_predictability": "high (sequential-looking integer id)",
        "sibling_endpoints": ["GET x/api/orders/{id}"],
        "identity_source": "session cookie",
    })
    assert inv["vuln_class"] == "bola"
    assert inv["hypothesis"]
    # machine facts are answered; missing ones say "unknown (determine)"
    facts = inv["facts"]
    assert any("session cookie" == v for v in facts.values())
    assert any(v == ["GET x/api/orders/{id}"] for v in facts.values())
    # llm nodes are the open questions with allowed answers + next
    qids = {q["id"] for q in inv["questions"]}
    assert {"binding", "shared", "experiment"} <= qids
    assert inv["next_experiment"]                      # terminal node surfaced
    # facts and questions never overlap (the three are kept separate)
    q_asks = {q["ask"] for q in inv["questions"]}
    assert not (set(facts) & q_asks)


def test_build_investigation_unknown_when_ctx_missing():
    inv = build_investigation("injection", {})
    assert all(v == "unknown (determine)" for v in inv["facts"].values())
    assert inv["questions"]        # llm nodes still present


def test_graph_for_all_classes_defined():
    for cls in ("bola", "broken_auth", "injection", "cache"):
        assert graph_for(cls) is not None
    assert graph_for("nope") is None


# --- integration through build_signal ---

def _row(rid, url, headers="", host="x"):
    from urllib.parse import urlsplit
    return {
        "request_id": rid, "method": "GET", "host": host,
        "path": urlsplit(url).path, "url": url, "param_names": "ref",
        "status_code": 200, "response_length": 20, "content_type": "application/json",
        "request_headers": headers or "GET / HTTP/1.1", "request_body": "",
        "response_headers": "content-type: application/json", "response_body": "{}",
    }


def test_bola_signal_gets_investigation_with_siblings_and_no_leak():
    from rqswarm_eval.passive import SignalEngine
    eng = SignalEngine()
    secret = "9999888877776666"
    r1 = _row(1, f"http://x/api/users/9001/profile?ref={secret}", "GET /\r\ncookie: s=1")
    r2 = _row(2, f"http://x/api/orders/9002?ref={secret}", "GET /\r\ncookie: s=1")
    eng.observe_metadata(r1); eng.observe_metadata(r2)
    eng.build_signal(r1, ["route:idor"])
    e2 = eng.build_signal(r2, ["route:idor"])
    inv = e2["investigation"]
    assert inv["vuln_class"] == "bola"
    # "what else shares this assumption?" -> the sibling endpoint, by path_shape only
    sib_fact = next(v for k, v in inv["facts"].items() if "other endpoints" in k.lower())
    assert any("/api/users/{id}/profile" in s for s in sib_fact)
    assert inv["questions"]
    # REDACTION: no raw id value anywhere in the investigation block
    assert secret not in json.dumps(inv)


def test_gate_enforces_investigation_questions():
    from rqswarm_eval.gate import questions_for
    sig = {"interrogation": {"lenses": [{"persona": "p", "ask": ["lens q"]}]},
           "investigation": {"questions": [{"id": "binding", "ask": "graph q1"},
                                           {"id": "experiment", "ask": "graph q2"}]}}
    qs = questions_for(sig)
    assert "lens q" in qs and "graph q1" in qs and "graph q2" in qs


