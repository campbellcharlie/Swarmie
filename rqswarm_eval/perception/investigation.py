"""Directed vuln-class investigation graphs (ADR-0005).

A small decision GRAPH per vuln class replaces flat question lists so the LLM performs guided
investigation instead of re-deriving the process, and — the key economy — the machine ANSWERS
every node it can compute (id shape, sibling endpoints, auth source) so scarce LLM reasoning is
spent only on the genuinely-open nodes.

Node shape: ``{id, ask, kind: "machine"|"llm", fact?, answers?, next, terminal?}``
  * machine: ``fact`` names a key in the caller's ctx; build() fills it, or "unknown (determine)".
  * llm:     ``answers`` are the allowed responses, ``next`` the follow-up node ids.

``build_investigation`` returns a signal split into FACTS (machine), one HYPOTHESIS, and open
QUESTIONS (llm) — never collapsed, which is what keeps the reasoning honest. Only structural
facts flow in (siblings as path_shape, id *type* not value); no raw value or path.

Stdlib only, deterministic, pure. Nothing here names a target, product, or environment.
"""
from __future__ import annotations

# Reason substring -> primary vuln class (ordered; first match wins). Substrings match the
# reason strings passive.py emits (idor_*, route:idor, route:injection, resp:reflection, ...).
REASON_CLASS: list[tuple[str, str]] = [
    ("idor", "bola"),
    ("jwt", "broken_auth"), ("credential", "broken_auth"), ("cleartext_auth", "broken_auth"),
    ("injection", "injection"), ("reflection", "injection"), ("null_byte", "injection"),
    ("cors", "cache"), ("cache", "cache"),
]


def classify(reasons) -> str | None:
    """The primary vuln class for a signal's reasons, or None if no graph applies."""
    for r in reasons:
        rl = str(r).lower()
        for key, cls in REASON_CLASS:
            if key in rl:
                return cls
    return None


_GRAPHS: dict[str, dict] = {
    "bola": {
        "hypothesis": ("An object is selected by a client-controlled identifier; one handler may "
                       "look it up directly without the ownership check the others enforce (BOLA)."),
        "nodes": [
            {"id": "selector", "kind": "machine", "fact": "selector_location",
             "ask": "What input selects the protected object?", "next": ["predictable"]},
            {"id": "predictable", "kind": "machine", "fact": "id_predictability",
             "ask": "Is the identifier predictable / enumerable?", "next": ["siblings"]},
            {"id": "siblings", "kind": "machine", "fact": "sibling_endpoints",
             "ask": "Which other endpoints select an object with this same identifier?",
             "next": ["identity"]},
            {"id": "identity", "kind": "machine", "fact": "identity_source",
             "ask": "What establishes the caller's identity?", "next": ["binding"]},
            {"id": "binding", "kind": "llm",
             "ask": "What binds this object to the authenticated identity — implicit session "
                    "state, or an explicit ownership check?",
             "answers": ["session_implied", "explicit_check", "unknown"], "next": ["shared"]},
            {"id": "shared", "kind": "llm",
             "ask": "Do the sibling endpoints appear to enforce that same ownership check, or "
                    "could one skip it?",
             "answers": ["same", "one_may_skip", "no_siblings", "unknown"], "next": ["experiment"]},
            {"id": "experiment", "kind": "llm",
             "ask": "What is the smallest safe observation that separates secure ownership "
                    "checking from direct object lookup?",
             "answers": [], "next": [], "terminal": True},
        ],
    },
    "broken_auth": {
        "hypothesis": ("Identity rests on a token/cookie whose trust, freshness, or scope may not "
                       "be re-validated consistently across the request path."),
        "nodes": [
            {"id": "token", "kind": "machine", "fact": "token_type",
             "ask": "Which artifact carries identity here?", "next": ["reuse"]},
            {"id": "reuse", "kind": "machine", "fact": "token_reuse",
             "ask": "Is the same identity artifact reused across endpoints/hosts?",
             "next": ["trust"]},
            {"id": "trust", "kind": "llm",
             "ask": "What does the server appear to TRUST to establish identity — a signature it "
                    "verifies, or a claim/header it accepts as given?",
             "answers": ["verified_signature", "trusted_claim", "unknown"], "next": ["reeval"]},
            {"id": "reeval", "kind": "llm",
             "ask": "Is identity established once and reused, or re-evaluated per request / per "
                    "downstream service?",
             "answers": ["once", "per_request", "unknown"], "next": ["experiment"]},
            {"id": "experiment", "kind": "llm",
             "ask": "What minimal observation would show identity is accepted without being "
                    "re-verified (stale/duplicated/forwarded trust)?",
             "answers": [], "next": [], "terminal": True},
        ],
    },
    "injection": {
        "hypothesis": ("User-controlled input may reach a backend interpreter, and validation may "
                       "differ across content-types, methods, or encodings."),
        "nodes": [
            {"id": "surface", "kind": "machine", "fact": "input_surface",
             "ask": "Which input surface carries user data?", "next": ["reaches"]},
            {"id": "reaches", "kind": "llm",
             "ask": "Does that input plausibly reach a backend interpreter (SQL, template, "
                    "command, deserializer), or is it inert?",
             "answers": ["reaches_interpreter", "inert", "unknown"], "next": ["validation"]},
            {"id": "validation", "kind": "llm",
             "ask": "Is validation consistent across content-types, methods, duplicate keys, and "
                    "encodings, or does one path escape while another does not?",
             "answers": ["consistent", "inconsistent", "unknown"], "next": ["experiment"]},
            {"id": "experiment", "kind": "llm",
             "ask": "What safe differential (e.g. boolean-true vs boolean-false payload) would "
                    "distinguish an interpreter reacting from inert echoing?",
             "answers": [], "next": [], "terminal": True},
        ],
    },
    "cache": {
        "hypothesis": ("A response may be cached on a key that omits an input affecting its "
                       "content, letting one client's request influence another's response."),
        "nodes": [
            {"id": "policy", "kind": "machine", "fact": "cache_policy",
             "ask": "What cache directives and hit/miss state did the response carry?",
             "next": ["userspecific"]},
            {"id": "userspecific", "kind": "machine", "fact": "user_specific",
             "ask": "Does the response appear user-specific (auth present)?", "next": ["key"]},
            {"id": "key", "kind": "llm",
             "ask": "What does the cache key include vs exclude — is there an input that changes "
                    "content but may not change the key?",
             "answers": ["key_covers_inputs", "gap_exists", "unknown"], "next": ["experiment"]},
            {"id": "experiment", "kind": "llm",
             "ask": "What minimal observation would show one request can influence what another "
                    "client receives (poisoning/deception)?",
             "answers": [], "next": [], "terminal": True},
        ],
    },
}

_EMPTY = (None, "", [], {})


def graph_for(vuln_class: str) -> dict | None:
    return _GRAPHS.get(vuln_class)


def build_investigation(vuln_class: str, ctx: dict) -> dict | None:
    """Instantiate a class graph for one signal: fill machine facts from ctx, collect llm
    questions, and return the FACTS / HYPOTHESIS / QUESTIONS split (never collapsed)."""
    graph = _GRAPHS.get(vuln_class)
    if graph is None:
        return None
    ctx = ctx or {}
    facts: dict[str, object] = {}
    questions: list[dict] = []
    next_experiment = ""
    for node in graph["nodes"]:
        if node["kind"] == "machine":
            val = ctx.get(node.get("fact", ""))
            facts[node["ask"]] = val if val not in _EMPTY else "unknown (determine)"
        else:
            questions.append({
                "id": node["id"], "ask": node["ask"],
                "answers": list(node.get("answers", [])), "next": list(node.get("next", [])),
            })
            if node.get("terminal"):
                next_experiment = node["ask"]
    return {
        "vuln_class": vuln_class,
        "hypothesis": graph["hypothesis"],
        "facts": facts,
        "questions": questions,
        "next_experiment": next_experiment,
    }
