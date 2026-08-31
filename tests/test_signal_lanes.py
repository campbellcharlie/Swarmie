"""Signal lanes added from the Juice Shop A/B misses.

Each test pins one evidence-driven addition: the corpus that motivated it is in
eval/juiceshop/. Direct-engine tests (no DB) — the same style as test_learned_lane.
"""
from __future__ import annotations

from rqswarm_eval.passive import SignalEngine


def _meta_row(*, path, method="GET", status=200, length=100, content_type="application/json"):
    return {
        "request_id": 1, "method": method, "host": "app.test", "path": path,
        "url": f"https://app.test{path}", "query": path.split("?", 1)[1] if "?" in path else "",
        "param_count": 0, "param_names": "", "status_code": status,
        "response_length": length, "content_type": content_type,
    }


def _body_row(resp_body: bytes, *, path="/x", content_type="application/json", status=200):
    return {
        "request_id": 1, "method": "GET", "host": "app.test", "path": path,
        "url": f"https://app.test{path}", "query": "", "param_count": 0, "param_names": "",
        "status_code": status, "response_length": len(resp_body), "content_type": content_type,
        "request_headers": "", "request_body": b"",
        "response_headers": f"Content-Type: {content_type}\r\n", "response_body": resp_body,
    }


def _reasons(engine, row):
    engine.observe_metadata(row)
    env = engine.build_signal(row, ["new_dynamic_endpoint"])
    return env["observation"]["reasons"] if env else []


def test_sensitive_directory_listing_flags_backup_and_vault_files():
    eng = SignalEngine()
    body = b'["quarantine","legal.md","incident-support.kdbx","package.json.bak","eastere.gg"]'
    assert "sensitive_file_exposure" in _reasons(eng, _body_row(body, path="/ftp"))
    # an ordinary JSON array of non-sensitive names does not fire
    eng2 = SignalEngine()
    assert "sensitive_file_exposure" not in _reasons(eng2, _body_row(b'["apple","orange","lemon"]', path="/list"))


def test_metrics_endpoint_exposed_flags_prometheus_exposition():
    eng = SignalEngine()
    body = (b"# HELP http_requests_total Total requests\n# TYPE http_requests_total counter\n"
            b"http_requests_total 42\n# HELP up 1\n# TYPE up gauge\n# HELP mem bytes\n# TYPE mem gauge\n")
    assert "metrics_endpoint_exposed" in _reasons(eng, _body_row(body, path="/metrics", content_type="text/plain"))


def test_response_size_swing_fires_on_second_hit_not_the_tenth():
    eng = SignalEngine()
    eng.observe_metadata(_meta_row(path="/rest/products/search", length=921))
    reasons = eng.observe_metadata(_meta_row(path="/rest/products/search", length=21581))
    assert "response_size_swing_for_endpoint" in reasons
    # a proportionate second response does not trip it
    eng2 = SignalEngine()
    eng2.observe_metadata(_meta_row(path="/api/list", length=3000))
    assert "response_size_swing_for_endpoint" not in eng2.observe_metadata(_meta_row(path="/api/list", length=3200))


def test_null_byte_in_path_flags_poison_null_byte():
    eng = SignalEngine()
    assert "null_byte_in_path" in eng.observe_metadata(_meta_row(path="/ftp/package.json.bak%2500.md"))
    eng2 = SignalEngine()
    assert "null_byte_in_path" not in eng2.observe_metadata(_meta_row(path="/ftp/legal.md"))


def test_pii_requires_an_email_list_not_a_single_address():
    # one address in prose is not a leak
    eng = SignalEngine()
    single = b'{"contact":"Reach support at help@example.com for assistance."}'
    assert "pii_in_response" not in _reasons(eng, _body_row(single))
    # a list of distinct addresses (an enumeration/dump) is
    eng2 = SignalEngine()
    dump = b'[{"email":"a@x.test"},{"email":"b@x.test"},{"email":"c@x.test"}]'
    assert "pii_in_response" in _reasons(eng2, _body_row(dump))


# ---- cookie + HTML-DOM lane (ZAP borrow) ------------------------------------------------

def _header_reasons(engine, resp_headers):
    row = {"request_id": 1, "method": "GET", "host": "app.test", "path": "/",
           "url": "https://app.test/", "status_code": 200, "timestamp": "",
           "request_headers": "", "response_headers": resp_headers}
    return engine.header_reasons(row)


def test_insecure_cookie_flags_on_bare_session_cookie():
    assert "insecure_cookie_flags" in _header_reasons(SignalEngine(), "Set-Cookie: PHPSESSID=abc; path=/\r\n")
    # a fully-flagged session cookie is fine
    assert "insecure_cookie_flags" not in _header_reasons(
        SignalEngine(), "Set-Cookie: sid=x; HttpOnly; Secure; SameSite=Strict\r\n")
    # a non-session cookie is not the finding
    assert "insecure_cookie_flags" not in _header_reasons(SignalEngine(), "Set-Cookie: theme=dark; path=/\r\n")


def test_weak_csp_directive_flags_unsafe_inline_but_not_strict():
    assert "weak_csp_directive" in _header_reasons(
        SignalEngine(), "Content-Security-Policy: default-src 'self' 'unsafe-inline'\r\n")
    assert "weak_csp_directive" not in _header_reasons(
        SignalEngine(), "Content-Security-Policy: default-src 'self'; script-src 'self'\r\n")


def test_suspicious_html_comment_flags_developer_tells():
    eng = SignalEngine()
    body = b"<html><!-- TODO: remove hard-coded admin password before release --></html>"
    assert "suspicious_html_comment" in _reasons(eng, _body_row(body, content_type="text/html"))
    eng2 = SignalEngine()
    benign = b"<html><!-- Copyright 2026, SPDX-License-Identifier: MIT --></html>"
    assert "suspicious_html_comment" not in _reasons(eng2, _body_row(benign, content_type="text/html"))


def test_untrusted_script_include_requires_external_src_without_integrity():
    eng = SignalEngine()
    body = b'<html><script src="https://cdn.example.net/lib.js"></script></html>'
    assert "untrusted_script_include" in _reasons(eng, _body_row(body, content_type="text/html"))
    # SRI-protected external script is fine; a local script is fine
    eng2 = SignalEngine()
    ok = b'<html><script src="https://cdn.example.net/lib.js" integrity="sha384-x"></script></html>'
    assert "untrusted_script_include" not in _reasons(eng2, _body_row(ok, content_type="text/html"))
    eng3 = SignalEngine()
    local = b'<html><script src="/static/app.js"></script></html>'
    assert "untrusted_script_include" not in _reasons(eng3, _body_row(local, content_type="text/html"))


# ---- evidence-driven adds from the VAmPI / NodeGoat rounds ------------------------------

def test_credential_field_in_json_response_flags_secret():
    # a JSON response echoing password fields (e.g. a /_debug user dump) is a secret exposure
    eng = SignalEngine()
    body = b'{"users":[{"username":"a","password":"pass1"},{"username":"b","password":"pass2"}]}'
    assert "secret_in_response" in _reasons(eng, _body_row(body))
    # a benign user list without credential fields does not fire
    eng2 = SignalEngine()
    assert "secret_in_response" not in _reasons(eng2, _body_row(b'{"users":[{"username":"a","email":"a@x.test"}]}'))


def test_untrusted_script_ignores_document_write_fragment():
    # a dev livereload injected via document.write yields a 'http://' fragment, not a real
    # external host — must not fire (this over-fired 11/12 on NodeGoat before the fix)
    eng = SignalEngine()
    frag = b'<html><script>document.write("<script src=\'http://" + h + ":35729/livereload.js\'></" + "script>");</script></html>'
    assert "untrusted_script_include" not in _reasons(eng, _body_row(frag, content_type="text/html"))


# ---- scale-test fixes (283k-corpus retune) ----------------------------------------------

def _hdr_row(url, *, req_headers="", query="", path="/", host="10.20.30.1"):
    return {"request_id": 1, "method": "GET", "host": host, "path": path, "url": url,
            "query": query, "status_code": 200, "timestamp": "",
            "request_headers": req_headers, "response_headers": ""}


def test_cleartext_auth_material_flags_auth_over_http_only():
    hr = lambda **k: SignalEngine().header_reasons(_hdr_row(**k))
    # Authorization over plaintext http:// fires
    assert "cleartext_auth_material" in hr(url="http://10.20.30.1/api", req_headers="Authorization: Bearer x\r\n")
    # apikey in the query over http fires (the Servarr case)
    assert "cleartext_auth_material" in hr(url="http://10.20.30.8:8080/api/v1/records?apikey=abc12345",
                                           query="apikey=abc12345", path="/api/v1/records")
    # stok in the path over http fires (the router case)
    assert "cleartext_auth_material" in hr(url="http://10.20.30.1/cgi-bin/luci/;stok=deadbeef",
                                           path="/cgi-bin/luci/;stok=deadbeef")
    # the SAME auth over HTTPS is not a cleartext finding
    assert "cleartext_auth_material" not in hr(url="https://10.20.30.1/api", req_headers="Authorization: Bearer x\r\n")


def test_credential_reused_across_endpoints_fires_on_third_endpoint():
    eng = SignalEngine()
    key = "apikey=5252984ec88e47b08fab1df5ce77c28e"

    def obs(path):
        return eng.observe_metadata({
            "request_id": 1, "method": "GET", "host": "10.20.30.8", "path": path.split("?")[0],
            "url": f"http://10.20.30.8{path}", "query": path.split("?", 1)[1] if "?" in path else "",
            "param_count": 1, "param_names": "apikey", "status_code": 200,
            "response_length": 100, "content_type": "application/json"})

    obs(f"/api/v1/records?{key}")
    obs(f"/api/v3/movie?{key}")
    third = obs(f"/api/v3/config?{key}")
    assert "credential_reused_across_endpoints" in third


def test_noise_factor_dampens_beacons_and_labs_not_real_targets():
    from rqswarm_eval.passive import _noise_factor
    assert _noise_factor("rt.pubmatic.com", "/translator") <= 0.2        # ad host
    assert _noise_factor("example.com", "/openrtb2/auction") <= 0.2      # beacon path
    assert _noise_factor("academy.hackthebox.com", "/module/1") == 0.4   # training platform
    assert _noise_factor("www.some-gov-site.gov", "/api/documents") == 1.0  # real third party
    assert _noise_factor("10.20.30.8", "/api/v1/records") == 1.0            # internal host stays full weight


def test_internal_network_reference_validates_octets():
    from rqswarm_eval.passive import _INTERNAL
    # minified-JS numeric literals that look like 10.x but have octets > 255 must NOT match
    assert not _INTERNAL.search("10.386.748.748")
    assert not _INTERNAL.search("10.669.606.225")
    assert not _INTERNAL.search("192.168.999.1")
    # genuine RFC-1918 addresses and internal hostnames still match
    assert _INTERNAL.search("10.20.30.8")
    assert _INTERNAL.search("192.168.1.1")
    assert _INTERNAL.search("172.16.5.4")
    assert _INTERNAL.search("db.internal")


def test_google_api_key_is_publishable_not_secret():
    eng = SignalEngine()
    body = b'{"config":{"apiKey":"AIza' + b'A' * 35 + b'"}}'
    r = _reasons(eng, _body_row(body))
    assert "publishable_client_key" in r
    assert "secret_in_response" not in r  # AIza is a restricted client key, not a secret


def _post_body_row(body: bytes, *, ct="application/octet-stream", path="/v1/events"):
    return {"request_id": 1, "method": "POST", "host": "api.vendor.test", "path": path,
            "url": f"https://api.vendor.test{path}", "query": "", "param_count": 0, "param_names": "",
            "status_code": 200, "response_length": 2, "content_type": "application/json",
            "request_headers": f"Content-Type: {ct}\r\n", "request_body": body,
            "response_headers": "", "response_body": b"{}"}


def test_encrypted_outbound_blob_flags_high_entropy_not_json():
    import os
    eng = SignalEngine()
    row = _post_body_row(os.urandom(4096))
    eng.observe_metadata(row)
    env = eng.build_signal(row, ["state_changing_method"])
    assert "encrypted_outbound_blob" in env["observation"]["reasons"]
    # a same-size JSON body is structured, low-entropy -> does not fire
    eng2 = SignalEngine()
    row2 = _post_body_row(b'{"event":"click","x":1}' * 200)
    eng2.observe_metadata(row2)
    env2 = eng2.build_signal(row2, ["state_changing_method"])
    assert "encrypted_outbound_blob" not in env2["observation"]["reasons"]


def test_precise_reason_overrides_beacon_noise_dampener():
    # a /v1/events beacon path would normally be dampened x0.2 — but a real finding on it must not be
    import os
    from rqswarm_eval.passive import _noise_factor, _PRECISE_OVERRIDE
    assert _noise_factor("api.vendor.test", "/v1/events") == 0.2   # path looks like a beacon
    assert "encrypted_outbound_blob" in _PRECISE_OVERRIDE
    eng = SignalEngine()
    row = _post_body_row(os.urandom(4096))         # encrypted_outbound_blob on a beacon path
    eng.observe_metadata(row)
    env = eng.build_signal(row, ["state_changing_method"])
    assert env["attention"]["score"] >= 40         # undampened (would be ~11 if the 0.2 applied)


def _nav_row(host):
    # a genuine top-level navigation to `host` — Sec-Fetch marks the browsing context, so this
    # records host's registrable domain as one the user actually visited (first-party).
    return {"request_id": 1, "method": "GET", "host": host, "path": "/",
            "url": f"https://{host}/", "query": "", "param_count": 0, "param_names": "",
            "status_code": 200, "response_length": 100, "content_type": "text/html",
            "request_headers": "Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n",
            "request_body": b"", "response_headers": "", "response_body": b"<html></html>"}


def test_opaque_body_to_navigated_site_is_first_party_not_exfil():
    # The iframe-isolation trick makes referer/origin/sec-fetch all report same-origin for an
    # embedded collector, so the only tell is whether the user ever navigated to the recipient.
    import os
    blob = os.urandom(4096)
    # recipient the user never navigated to -> third-party exfil, high-weight encrypted_outbound_blob
    third = SignalEngine()
    third.observe_metadata(_post_body_row(blob))
    env3 = third.build_signal(_post_body_row(blob), ["state_changing_method"])
    assert "encrypted_outbound_blob" in env3["observation"]["reasons"]
    assert "opaque_outbound_body" not in env3["observation"]["reasons"]
    # same blob, but the user navigated to the recipient's registrable domain first -> first-party
    first = SignalEngine()
    first.header_reasons(_nav_row("www.vendor.test"))   # records vendor.test as navigated
    first.observe_metadata(_post_body_row(blob))
    env1 = first.build_signal(_post_body_row(blob), ["state_changing_method"])
    assert "opaque_outbound_body" in env1["observation"]["reasons"]
    assert "encrypted_outbound_blob" not in env1["observation"]["reasons"]
    # first-party telemetry ranks below third-party exfil
    assert env1["attention"]["score"] < env3["attention"]["score"]


def _redirect_row(location, query="", host="app.test"):
    return {"request_id": 1, "method": "GET", "host": host, "path": "/go",
            "url": f"https://{host}/go?{query}", "query": query, "param_count": 1,
            "param_names": "", "status_code": 302, "response_length": 0, "content_type": "text/html",
            "request_headers": "", "request_body": b"",
            "response_headers": f"Location: {location}\r\n", "response_body": b""}


def test_open_redirect_needs_an_attacker_controlled_destination():
    # A cross-domain 3xx alone is not an open redirect — designed SSO/CDN hops do it constantly.
    # This fired on Wikimedia's CentralAutoLogin -> auth.wikimedia.org and ranked #1 on a clean browse.
    hr = lambda **k: SignalEngine().header_reasons(_redirect_row(**k))
    assert "open_redirect_to_external" not in hr(
        location="https://auth.wikimedia.org/checkLoggedIn", query="type=script&usesul3=1")
    # target echoed from a request parameter -> genuinely attacker-influencable
    assert "open_redirect_to_external" in hr(
        location="https://evil.example/cb", query="next=https://evil.example/cb")
    assert "open_redirect_to_external" in hr(
        location="https://evil.example/cb", query="returnTo=%2F%2Fevil.example%2Fcb")
    # same-domain redirect is never this signal
    assert "open_redirect_to_external" not in hr(
        location="https://app.test/home", query="next=https://app.test/home")
