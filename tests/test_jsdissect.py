"""Executable specification for ``rqswarm_eval.perception.jsdissect`` (ADR-0006).

Covers the contract's Tests section on hand-written JS strings: endpoint keep/drop,
param + graphql + sourcemap + host extraction, the REDACTION invariant (a planted AWS
key and JWT surface as ``{type, hash}`` while the raw values appear NOWHERE in
``json.dumps`` of the result), determinism, and never-raises on empty / non-string /
binary junk. Imports are confined to the module under test, per the frozen contract.
"""
from __future__ import annotations

import json

import pytest

from rqswarm_eval.perception.jsdissect import dissect_js, value_hash

# --- planted secrets (the redaction invariant is the load-bearing test) ----------
PLANTED_AWS = "AKIAIOSFODNN7EXAMPLE"
PLANTED_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# A single fixture bundle exercising every extractor at once.
FIXTURE_JS = """
const users = "https://api.example.com/api/v2/users/{id}";
const orders = "/api/v2/orders?status=open&limit=20";
const bundle = "/static/app.4f3.js";          // static asset -> dropped
const apiBundle = "/api/bundle.min.js";        // api keyword but asset -> dropped
const marketing = "/help/home";                // no keyword/placeholder -> dropped
fetch("https://cdn.assets.io/logo.png");       // host kept, not an endpoint
searchParams.set('token', value);
const cfg = { params: { userId: 1, region: "us" } };
const gq = query GetUser { name }
subscription OnMessage { body }
const op = { operationName: "DoThing" };
const router = [{ path: "/admin/:id" }];
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const jwt = "%s";
//# sourceMappingURL=main.4f3a.js.map
""" % PLANTED_JWT


@pytest.fixture(scope="module")
def result() -> dict:
    return dissect_js(FIXTURE_JS, base_url="https://target.test")


# --- shape -----------------------------------------------------------------------

def test_returns_exact_key_set(result):
    assert set(result) == {
        "endpoints", "params", "graphql", "secrets", "sourcemap", "hosts", "routes"
    }


def test_empty_input_has_all_keys_empty():
    assert dissect_js("") == {
        "endpoints": [], "params": [], "graphql": [],
        "secrets": [], "sourcemap": "", "hosts": [], "routes": [],
    }


# --- endpoints -------------------------------------------------------------------

def test_endpoint_keeps_api_path_with_placeholder(result):
    assert "https://api.example.com/api/v2/users/{id}" in result["endpoints"]
    assert "/api/v2/orders" in result["endpoints"]


def test_endpoint_drops_static_asset(result):
    # A plain static bundle, an api-keyworded static bundle, and a keywordless
    # marketing path must all be excluded.
    for dropped in ("/static/app.4f3.js", "/api/bundle.min.js", "/help/home"):
        assert dropped not in result["endpoints"]


def test_query_values_never_retained_in_endpoint(result):
    # The endpoint is stored structurally; ?status=open must not ride along.
    assert all("status=open" not in e for e in result["endpoints"])


# --- params ----------------------------------------------------------------------

def test_params_from_query_searchparams_and_block(result):
    params = set(result["params"])
    assert {"status", "limit"} <= params          # from ?status=&limit=
    assert "token" in params                      # from searchParams.set('token'
    assert {"userId", "region"} <= params         # from params: { ... }


# --- graphql ---------------------------------------------------------------------

def test_graphql_ops_and_operation_name(result):
    gql = set(result["graphql"])
    assert {"GetUser", "OnMessage", "DoThing"} <= gql


# --- sourcemap -------------------------------------------------------------------

def test_sourcemap(result):
    assert result["sourcemap"] == "main.4f3a.js.map"


def test_sourcemap_empty_when_absent():
    assert dissect_js('var x = "/api/v2/things/{id}";')["sourcemap"] == ""


# --- hosts -----------------------------------------------------------------------

def test_hosts_distinct_and_include_base_and_asset_hosts(result):
    hosts = set(result["hosts"])
    assert "api.example.com" in hosts             # from an endpoint URL
    assert "cdn.assets.io" in hosts               # from a dropped-asset URL
    assert "target.test" in hosts                 # from base_url


# --- routes ----------------------------------------------------------------------

def test_routes(result):
    assert "/admin/:id" in result["routes"]


# --- REDACTION invariant (the reason this module exists) -------------------------

def test_secrets_report_type_and_hash_for_aws_and_jwt(result):
    by_type = {s["type"]: s for s in result["secrets"]}
    assert "aws_access_key" in by_type
    assert "jwt" in by_type
    assert by_type["aws_access_key"]["hash"] == value_hash(PLANTED_AWS)
    assert by_type["jwt"]["hash"] == value_hash(PLANTED_JWT)
    # Every secret entry carries exactly the three redacted fields.
    for s in result["secrets"]:
        assert set(s) == {"type", "hash", "context"}
        assert len(s["hash"]) == 12


def test_raw_secret_values_absent_from_serialized_result(result):
    blob = json.dumps(result)
    assert PLANTED_AWS not in blob
    assert PLANTED_JWT not in blob
    # A JWT fragment must not survive either.
    assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in blob


def test_raw_secret_absent_even_when_secret_is_the_only_content():
    d = dissect_js('const k = "%s";' % PLANTED_AWS)
    assert PLANTED_AWS not in json.dumps(d)
    assert any(s["type"] == "aws_access_key" for s in d["secrets"])


def test_placeholder_secrets_are_skipped():
    d = dissect_js('apiKey: "YOUR_API_KEY_HERE"; token = "xxxxxxxxxxxxxxxx";')
    assert d["secrets"] == []


# --- determinism -----------------------------------------------------------------

def test_determinism_identical_dicts():
    a = dissect_js(FIXTURE_JS, base_url="https://target.test")
    b = dissect_js(FIXTURE_JS, base_url="https://target.test")
    assert a == b
    assert json.dumps(a) == json.dumps(b)


def test_lists_are_sorted_and_deduped():
    js = (
        'a="https://B.com/api/x/{id}"; b="https://a.com/api/x/{id}"; '
        'c="https://B.com/api/x/{id}";'
    )
    r = dissect_js(js)
    for key in ("endpoints", "params", "graphql", "hosts", "routes"):
        assert r[key] == sorted(r[key])
        assert len(r[key]) == len(set(r[key]))
    assert r["hosts"] == ["a.com", "b.com"]       # lowercased + deduped


# --- never raises ----------------------------------------------------------------

EMPTY = {
    "endpoints": [], "params": [], "graphql": [],
    "secrets": [], "sourcemap": "", "hosts": [], "routes": [],
}


@pytest.mark.parametrize(
    "bad",
    ["", None, 12345, 3.14, b"\x00\x01\x02", ["not", "a", "string"], {"k": "v"}],
)
def test_never_raises_on_non_string(bad):
    assert dissect_js(bad) == EMPTY


def test_never_raises_on_binary_junk():
    junk = bytes(range(256)).decode("latin1") * 40
    out = dissect_js(junk)
    assert set(out) == set(EMPTY)                 # well-formed shape, no exception


def test_never_raises_on_unterminated_and_nested_noise():
    for weird in ('const x = "unterminated', "`${a}${b}` + '/'", "//# sourceMappingURL="):
        out = dissect_js(weird)
        assert set(out) == set(EMPTY)


def test_hidden_endpoint_scope_filter():
    """_hidden_js_endpoints keeps first-party app routes, drops cross-domain CDN/library refs."""
    from rqswarm_eval.passive import SignalEngine
    eng = SignalEngine()
    eng.baselines[("shop.example.com", "GET", "/cart")] = type("B", (), {})()
    declared = [
        "/account-settings/payments/${o.TABS.DONATIONS}",   # first-party route -> keep
        "/api/v3/checkout",                                 # first-party -> keep
        "https://api.example.com/api/orders/{id}",          # same reg-domain -> keep
        "https://cdn.jsdelivr.net/npm/rive@1/rive.wasm",    # cross-domain lib -> drop
        "https://unpkg.com/x@1/y.wasm",                     # drop
        "https://github.com/a/core-js/blob/v3/LICENSE",     # drop
        "/cart",                                            # observed -> not hidden
    ]
    out = eng._hidden_js_endpoints(declared, "shop.example.com")
    assert "/api/v3/checkout" in out
    assert "https://api.example.com/api/orders/{id}" in out
    assert any("payments" in o for o in out)
    assert not any("jsdelivr" in o or "unpkg" in o or "LICENSE" in o for o in out)  # noise dropped
    assert "/cart" not in out                               # observed, not hidden
