"""Dry-run triage: capture DB -> swarm expansion -> candidate vuln vectors.

Reads a captured-traffic DB (any supported HTTP-capture proxy; see ``sources``), profiles
each request with the observable-feature profiler (``profile_adapter``), and
turns each testable surface into a *candidate vuln vector* -- a hypothesis worth
a human/judge decision, NOT a confirmed finding.

DRY-RUN by construction: this module imports no transport and opens no socket.
It never sends a request anywhere. It only reads your own captured traffic and
writes cards + a hash-chained ledger for the judge to rank. A routing flag is a
*hypothesis*, never proof -- confirmation requires an authorized verification
probe against an in-scope host, which is a separate, later step.
"""
from __future__ import annotations

import argparse
import json
import os
import re

from .profile_adapter import profile_request, route_features
from .ledger import Ledger
from .response import analyze_response, redact_text
from .sources import Seed, body_skeleton, iter_seeds, path_shape, redact_headers

# Well-known vector categories keyed by profiler route token. Each is (title,
# why-it-is-a-hypothesis, a NON-DESTRUCTIVE test to confirm-or-dismiss).
_VECTORS: dict[str, tuple[str, str, str]] = {
    "route:idor": (
        "IDOR / broken object-level authorization",
        "An object id in the request may not be ownership-checked.",
        "Re-request with an adjacent / another-account id you are authorized to hold; compare authz outcome.",
    ),
    "route:injection": (
        "Server-side injection (SQL / NoSQL / command)",
        "User-controlled JSON input reaches a backend interpreter.",
        "Send boolean-true vs boolean-false and error-marker payloads per field; diff the responses.",
    ),
    "route:jwt": (
        "JWT trust / algorithm confusion",
        "A JWT is presented and may be weakly validated.",
        "Resend with alg:none and with tampered claims; check whether it is still accepted.",
    ),
    "route:xxe": (
        "XXE / XML external entity",
        "An XML body is parsed server-side.",
        "Declare a benign local external entity; observe whether it resolves.",
    ),
    "route:graphql": (
        "GraphQL abuse",
        "A GraphQL endpoint is exposed.",
        "Run an introspection query; test aliased/nested amplification and field-level authz.",
    ),
    "route:file-attack": (
        "Malicious file upload",
        "A multipart file upload is accepted.",
        "Vary content-type / extension / filename (path traversal); check server handling.",
    ),
    "route:xss-stored": (
        "Reflected / stored XSS",
        "A url or form parameter may render in an HTML context.",
        "Insert a unique inert marker; check reflection and persistence in later responses.",
    ),
    "route:websocket-injection": (
        "WebSocket message injection",
        "A WebSocket upgrade is present.",
        "Fuzz message frames for unvalidated command / query handling.",
    ),
}

_NOTABLE_HEADER = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token")

# --- value weighting -------------------------------------------------------
# What each signal is worth, plus a demotion (NOT exclusion -- everything is
# still fair game) for known ad/analytics networks so first-party error/leak/
# injection findings outrank a tracking pixel that merely reflects an origin.
_ROUTE_VALUE = {
    "resp:error": 6, "resp:leak": 5, "route:injection": 5, "route:idor": 5,
    "route:xxe": 5, "route:file-attack": 4, "route:graphql": 3,
    "resp:reflection": 2, "resp:cors": 2, "route:jwt": 0, "route:xss-stored": 0,
}
_AD_NETWORK = (
    "doubleclick", "doubleverify", "pubmatic", "rubiconproject", "adsrvr", "gumgum",
    "adnxs", "criteo", "casalemedia", "openx", "33across", "indexexchange", "adform",
    "teads", "sharethrough", "smartadserver", "yieldmo", "taboola", "outbrain",
    "unrulymedia", "marphezis", "lhmos", "adnml", "singular.net", "moatads",
    "adsafeprotected", "serving-sys", "2mdn", "sonobi", "amazon-adsystem",
    "googleads", "googleadservices", "googlesyndication", "adobedc", "quantummetric",
    "intentiq", "optable", "scorecardresearch", "smaato", "improvedigital",
    "recaptcha", "gstatic", "posthog", "segment.", "amplitude", "mixpanel",
    "hotjar", "fullstory", "adsystem", "adservice",
)

# --- precision filter: signal-QUALITY cut only (not host/scope) --------------
# This is dry-run theorizing, so every host is fair game. We only drop things
# that aren't a real *signal*: id-shaped values that are telemetry envelope
# fields, version markers, or JS object-paths rather than actual parameters.
# id-shaped params that are telemetry envelope fields, not object references.
_TELEMETRY_ID = {
    "__hsi", "__rev", "__spin_r", "__spin_t", "__spin_b", "jazoest", "fb_dtsg",
    "ai.device.id", "ai.operation.id", "ai.session.id", "ai.user.id",
    "ai.cloud.role", "id", "v", "_",
}
# Routes that are actionable on their own; jwt/xss-stored are annotations only.
# resp:* routes come from the captured response (reflection/error/leak/cors) and
# are strong signals in their own right.
_ACTIONABLE = {
    "route:idor", "route:injection", "route:xxe", "route:graphql",
    "route:file-attack", "route:websocket-injection",
    "resp:reflection", "resp:error", "resp:leak", "resp:cors",
}
_OBJREF = re.compile(
    r"(_id$|^id$|esiid|serial|account|order|site|user|customer|tenant|invoice|doc|file|record|uuid)",
    re.I,
)


def _precision_keep(card: dict) -> dict | None:
    """Apply the signal-quality cut. Returns a filtered card, or None to drop it.

    Host-agnostic (every host is fair game for theorizing). Keeps IDOR only when
    an id param actually looks like an object reference -- not a telemetry field,
    a version marker, or a dotted JS object-path -- and keeps a card only if it
    retains an *actionable* route after filtering.
    """
    routes = set(card["routes"])
    real_ids = [p for p in card["id_params"]
                if p.lower() not in _TELEMETRY_ID and "." not in p and _OBJREF.search(p)]
    if not real_ids:
        routes.discard("route:idor")
    routes.discard("route:xss-stored")  # mechanical on API/JSON traffic
    if not (routes & _ACTIONABLE):
        return None
    kept = [r for r in card["routes"] if r in routes]
    out = dict(card)
    out["routes"] = kept
    out["vectors"] = [v for v in card["vectors"] if v["route"] in routes]
    out["id_params"] = real_ids or card["id_params"]
    return out


def _card_score(routes, profile, signals, host, auth_present) -> int:
    """Value-weighted, host-aware score.

    Sums per-signal value, rewards leaks/data on an id-scoped endpoint (BOLA/EDE)
    and authed state-bearing surfaces, and demotes (does not exclude) known
    ad/analytics origins so real first-party findings rank above them.
    """
    real_id = any("." not in p for p in profile.get("id_params", []))
    s = sum(_ROUTE_VALUE.get(r, 1) for r in routes)
    if signals.get("is_data_response") and real_id:
        s += 3
    if signals.get("sensitive_in_response") and real_id:
        s += 2                                    # leak on an id-scoped endpoint -> BOLA/EDE
    if auth_present and (set(routes) & {"route:injection", "route:idor", "resp:leak", "resp:error"}):
        s += 2
    if any(a in host for a in _AD_NETWORK):
        s -= 7
    return max(s, 1)


def _response_vectors(signals: dict, profile: dict) -> list[dict]:
    """Vectors that only the captured RESPONSE can reveal."""
    out = []
    if signals["reflected_params"]:
        out.append({
            "route": "resp:reflection",
            "title": "Reflected input (XSS / SSTI / injection)",
            "hypothesis": f"request value(s) echoed in the response: {signals['reflected_params']}",
            "targets": signals["reflected_params"],
            "nondestructive_test": "resend with a unique inert marker; confirm it renders unencoded in the response context.",
        })
    if signals["error_signature"]:
        out.append({
            "route": "resp:error",
            "title": "Server error / stack leak (injection surface)",
            "hypothesis": f"response leaks an error signature: {signals['error_signature']!r}",
            "targets": profile.get("input_surfaces"),
            "nondestructive_test": "vary one input to a malformed value; compare the error against baseline.",
        })
    if signals["sensitive_in_response"]:
        out.append({
            "route": "resp:leak",
            "title": "Sensitive data in response (excessive-data-exposure / BOLA)",
            "hypothesis": f"response body carries {signals['sensitive_in_response']}",
            "targets": profile.get("id_params"),
            "nondestructive_test": "if id-scoped, request an id you do not own and compare what is exposed.",
        })
    if signals.get("cors_allow_origin"):
        out.append({
            "route": "resp:cors",
            "title": "Permissive CORS",
            "hypothesis": f"ACAO={signals['cors_allow_origin']} credentials={signals.get('cors_credentials', False)}",
            "targets": ["Origin"],
            "nondestructive_test": "replay with a foreign Origin; check whether it is reflected with credentials.",
        })
    return out


def build_card(seed: Seed) -> dict | None:
    """Expand one captured request/response PAIR into candidate vectors.

    Uses both the request shape (profile/routes) and the captured response
    (reflection, error/stack leaks, sensitive-data exposure, CORS). Returns None
    only when neither side exposes a testable surface.
    """
    req = {"method": seed.method, "url": seed.url,
           "headers": seed.headers, "body": seed.body}
    profile = profile_request(req)
    routes = route_features(profile)
    signals = analyze_response(seed)
    rvectors = _response_vectors(signals, profile)
    if not routes and not rvectors:
        return None

    vectors = []
    for r in routes:
        title, why, test = _VECTORS.get(r, (r, "Routed surface.", "Manual review."))
        vectors.append({
            "route": r, "title": title, "hypothesis": why,
            "targets": profile.get("id_params") or profile.get("input_surfaces"),
            "nondestructive_test": test,
        })
    vectors += rvectors
    all_routes = routes + [v["route"] for v in rvectors]

    redacted = redact_headers(seed.headers)
    sec_headers = {}
    if signals.get("cors_allow_origin"):
        sec_headers["access-control-allow-origin"] = signals["cors_allow_origin"]
    if signals.get("missing_sec_headers"):
        sec_headers["missing"] = signals["missing_sec_headers"]
    if signals.get("weak_set_cookie"):
        sec_headers["weak_set_cookie"] = signals["weak_set_cookie"]
    auth_present = any(k.lower() in ("authorization", "cookie") for k in seed.headers)

    return {
        "seed_request_id": seed.request_id,
        "host": seed.host,
        "method": seed.method,
        "path_shape": path_shape(seed.path),
        "content_type": profile.get("request_content_type", ""),
        "input_surfaces": profile.get("input_surfaces", []),
        "id_params": profile.get("id_params", []),
        "jwt_present": profile.get("jwt_present", False),
        "graphql": profile.get("graphql", False),
        "custom_headers": profile.get("custom_headers", []),
        "notable_headers": [h for h in _NOTABLE_HEADER if h in {k.lower() for k in seed.headers}],
        "body_keys": body_skeleton(seed.body, seed.content_type),
        "routes": all_routes,
        "vectors": vectors,
        "response": signals,
        "pair": {
            "request": {
                "method": seed.method, "url": seed.url,
                "headers": redacted, "body_keys": body_skeleton(seed.body, seed.content_type),
            },
            "response": {
                "status": signals["status"],
                "content_type": signals["resp_content_type"],
                "length": signals["resp_length"],
                "security_headers": sec_headers,
                "excerpt": redact_text(seed.resp_body),
            },
        },
        "auth_present": auth_present,
        "score": _card_score(all_routes, profile, signals, seed.host.lower(), auth_present),
    }


def run_triage(db_path: str, scan: int, top: int, out_dir: str,
               precision: bool = False, dedup: bool = False) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    ledger = Ledger(os.path.join(out_dir, "triage.jsonl"))
    cards: list[dict] = []
    index: dict[tuple, dict] = {}
    scanned = 0
    for seed in iter_seeds(db_path, limit=(scan or None)):
        scanned += 1
        card = build_card(seed)
        if card is None:
            continue
        if precision:
            card = _precision_keep(card)
            if card is None:
                continue
        if dedup:
            key = (card["host"], card["method"], card["path_shape"], tuple(card["routes"]))
            if key in index:
                index[key]["dupes"] = index[key].get("dupes", 1) + 1
                continue
            card["dupes"] = 1
            index[key] = card
        cards.append(card)
        ledger.append({
            "kind": "proposal", "trial_id": "triage", "condition": "T1-triage",
            "seed": seed.request_id, "fixture_id": card["path_shape"],
            "family": ",".join(card["routes"]), "split": "live-capture",
            "candidate_id": f"seed-{seed.request_id}",
            "generator_family": "profile+routes",
            "destination": "NONE (dry-run: nothing sent)",
            "transaction": None, "evidence": None, "payload": card,
        })
    cards.sort(key=lambda c: (-c["score"], c["seed_request_id"]))
    with open(os.path.join(out_dir, "triage_cards.json"), "w", encoding="utf-8") as fh:
        json.dump(cards, fh, indent=2)
    route_counts: dict[str, int] = {}
    for c in cards:
        for r in c["routes"]:
            route_counts[r] = route_counts.get(r, 0) + 1
    return {
        "scanned": scanned,
        "with_surface": len(cards),
        "top": cards[:top],
        "route_counts": dict(sorted(route_counts.items(), key=lambda kv: -kv[1])),
        "hosts": sorted({c["host"] for c in cards}),
        "out_dir": out_dir,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="rqswarm_eval.triage",
        description="Dry-run: expand a capture DB into candidate vuln vectors (nothing is sent).",
    )
    ap.add_argument("--source", required=True, help="path to an http_traffic capture .db")
    ap.add_argument("--scan", type=int, default=500, help="max requests to read (0 = all)")
    ap.add_argument("--top", type=int, default=25, help="how many ranked cards to print")
    ap.add_argument("--out", default="runs", help="output directory for cards + ledger")
    ap.add_argument("--precision", action="store_true", help="apply the judge noise-cut")
    ap.add_argument("--dedup", action="store_true", help="collapse identical vector shapes")
    args = ap.parse_args(argv)

    summary = run_triage(args.source, args.scan, args.top, args.out,
                         precision=args.precision, dedup=args.dedup)
    print(f"scanned={summary['scanned']}  with_testable_surface={summary['with_surface']}  "
          f"hosts={len(summary['hosts'])}")
    print("routes:", summary["route_counts"])
    print(f"cards -> {os.path.join(summary['out_dir'], 'triage_cards.json')}   "
          f"ledger -> {os.path.join(summary['out_dir'], 'triage.jsonl')}")
    print("\nTOP CANDIDATE VECTORS (dry-run hypotheses, not confirmed findings):")
    for c in summary["top"]:
        routes = ",".join(r.replace("route:", "") for r in c["routes"])
        print(f"  [{c['score']:>2}] {c['method']:6} {c['host']}{c['path_shape']}  ->  {routes}"
              f"  | ids={c['id_params']} jwt={c['jwt_present']} auth={c['auth_present']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
