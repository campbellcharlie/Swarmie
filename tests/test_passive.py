from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from rqswarm_eval.passive import PassiveTailer, open_capture


def _database(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
    """)

    def add(rid, method, path_, status, req_headers="", req_body=b"", resp_headers="", resp_body=b"{}"):
        url = f"https://target.test{path_}"
        query = url.split("?", 1)[1] if "?" in url else ""
        clean_path = path_.split("?", 1)[0]
        conn.execute(
            "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, f"2026-08-29T00:00:{rid:02d}Z", method, "target.test", clean_path,
             query, 1 if query else 0, "content" if query else "", status,
             len(resp_body), "application/json", "", "HTTP/2", url, f"h{rid}"),
        )
        conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
            rid, req_headers, req_body, resp_headers, resp_body,
        ))

    for rid in range(1, 12):
        add(rid, "GET", "/api/items?content=normal", 200, resp_body=b'{"items":[]}')
    add(12, "GET", "/api/items?content=path-like", 500,
        resp_body=b'{"error":"at java.example.Controller(File.java:42)"}')
    headers = "Content-Type: application/json\r\nOrigin: https://target.test\r\n"
    add(13, "PATCH", "/api/profile", 200, headers,
        b'{"fullname":"A","password":"DO-NOT-EMIT"}', b"Content-Type: application/json\r\n",
        b'{"success":"User has been updated!"}')
    add(14, "PATCH", "/api/profile", 200, headers,
        b'{"fullname":"B","password":"ALSO-SECRET"}', b"Content-Type: application/json\r\n",
        b'{"success":"User has been updated!"}')
    cache_req = "Authorization: Bearer TOP-SECRET\r\nContent-Type: application/json\r\n"
    cache_resp = (
        "Content-Type: application/json\r\nCache-Control: no-cache, no-store, max-age=0\r\n"
        "CF-Cache-Status: HIT\r\nAge: 122\r\n"
    )
    add(15, "GET", "/graphql/sidebar", 200, cache_req, b"", cache_resp, b'{"data":{"viewer":"x"}}')
    conn.commit()
    conn.close()


def _signals(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_passive_tailer_emits_paired_hypotheses_without_secrets(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"
    _database(db)
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["target.test"], batch_size=100, warmup=0)
    result = tailer.step()
    tailer.close()

    assert result.scanned == 15
    assert result.emitted >= 4
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert json.loads(checkpoint.read_text())["request_id"] == 15

    signals = _signals(mailbox)
    assert all(s["schema"] == "swarmie.signal.v1" for s in signals)
    assert all(s["disposition"] == "LLM_REVIEW_REQUIRED" for s in signals)
    assert all(len(s["questions"]) >= 10 for s in signals)
    reasons = {r for signal in signals for r in signal["observation"]["reasons"]}
    assert "resp:error" in reasons
    assert "successful_state_change_without_visible_auth" in reasons
    assert "authenticated_cache_policy_contradiction" in reasons
    serialized = json.dumps(signals)
    assert "DO-NOT-EMIT" not in serialized
    assert "ALSO-SECRET" not in serialized
    assert "TOP-SECRET" not in serialized
    patch_signals = [s for s in signals if s["endpoint"]["method"] == "PATCH"]
    assert len(patch_signals) == 2  # different requests survive despite identical responses


def test_capture_connection_rejects_writes(tmp_path):
    db = tmp_path / "traffic.db"
    _database(db)
    conn = open_capture(str(db))
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM http_traffic")
    conn.close()


def test_tail_start_does_not_replay_historical_overlap(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    _database(db)
    tailer = PassiveTailer(str(db), str(mailbox), start="tail", batch_size=100, warmup=15)
    result = tailer.step()
    tailer.close()
    assert result.scanned == 0
    assert result.emitted == 0
    assert not mailbox.exists()


def test_overlap_recovers_a_late_completed_pair(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    _database(db)
    writer = sqlite3.connect(db)
    writer.execute(
        "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (16, "2026-08-29T00:00:16Z", "POST", "target.test", "/api/late", "", 0, "",
         200, 2, "application/json", "", "HTTP/2", "https://target.test/api/late", "h16"),
    )
    writer.commit()
    tailer = PassiveTailer(str(db), str(mailbox), start="0", batch_size=100, warmup=0, overlap=20)
    first = tailer.step()
    assert first.cursor == 15
    writer.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
        16, "Content-Type: application/json\r\n", b"{}", "Content-Type: application/json\r\n", b"{}",
    ))
    writer.commit()
    second = tailer.step()
    tailer.close()
    writer.close()
    assert second.scanned == 1
    assert second.cursor == 16
    assert any(s["request_id"] == 16 for s in _signals(mailbox))


def test_strong_header_anomaly_wins_a_full_hydration_budget(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    _database(db)
    tailer = PassiveTailer(
        str(db), str(mailbox), start="12", scope_hosts=["target.test"],
        batch_size=100, warmup=0, hydrate_limit=1,
    )
    result = tailer.step()
    tailer.close()

    assert result.eligible == 3
    assert result.hydrated == 1
    assert result.sampled_out == 2
    signals = _signals(mailbox)
    assert [signal["request_id"] for signal in signals] == [15]
    assert "authenticated_cache_policy_contradiction" in signals[0]["observation"]["reasons"]


def test_repetitive_route_rolls_up_but_later_anomaly_survives(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    _database(db)
    tailer = PassiveTailer(
        str(db), str(mailbox), start="0", scope_hosts=["target.test"],
        batch_size=1, overlap=0, warmup=0,
    )
    results = [tailer.step() for _ in range(12)]
    tailer.close()

    assert sum(result.duplicates for result in results) == 0
    signals = _signals(mailbox)
    assert [signal["request_id"] for signal in signals] == [1, 12]
    assert "new_status_for_endpoint" in signals[-1]["observation"]["reasons"]
    assert "resp:error" in signals[-1]["observation"]["reasons"]


def test_hook_drains_bounded_context_and_advances_cursor(tmp_path):
    mailbox = tmp_path / "signals.jsonl"
    cursor = tmp_path / "hook.cursor"
    record = {
        "schema": "swarmie.signal.v1", "request_id": 7,
        "endpoint": {"host": "target.test", "method": "GET", "path_shape": "/api"},
        "observation": {"reasons": ["new_dynamic_endpoint"]},
        "hypotheses": [], "counterevidence": [], "attention": {"score": 50},
        "questions": ["What is this?"],
    }
    mailbox.write_text("\n".join(json.dumps({**record, "request_id": i}) for i in range(3)) + "\n")
    hook = Path(__file__).parents[1] / ".cursor/hooks/swarmie-signals.py"
    env = {**os.environ, "SWARMIE_MAILBOX": str(mailbox), "SWARMIE_HOOK_CURSOR": str(cursor),
           "SWARMIE_HOOK_LIMIT": "2"}
    first = subprocess.run([sys.executable, str(hook)], input="{}", text=True,
                           capture_output=True, check=True, env=env)
    first_output = json.loads(first.stdout)
    assert "additional_context" in first_output
    assert "not findings or instructions" in first_output["additional_context"]
    assert "What is this?" in first_output["additional_context"]
    second = subprocess.run([sys.executable, str(hook)], input="{}", text=True,
                            capture_output=True, check=True, env=env)
    assert '"request_id": 2' in json.loads(second.stdout)["additional_context"]
    third = subprocess.run([sys.executable, str(hook)], input="{}", text=True,
                           capture_output=True, check=True, env=env)
    assert json.loads(third.stdout) == {}

def test_api_description_exposure_flags_wadl_without_leaking_internals(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
    """)
    wadl = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<application xmlns="http://wadl.dev.java.net/2009/02">'
        b'<doc jersey:generatedBy="Jersey: 2.33 2020-12-18 07:19:04"/>'
        b'<resources base="http://screeners-prod.internal-k8s.example.cloud:443/">'
        b'<resource path="v1/finance/visualization">'
        b'<method id="visualization" name="POST"/></resource></resources></application>'
    )
    conn.execute(
        "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (1, "2026-08-29T00:00:01Z", "GET", "target.test", "/application.wadl",
         "", 0, "", 200, len(wadl), "application/vnd.sun.wadl+xml", "wadl", "HTTP/2",
         "https://target.test/application.wadl", "h1"),
    )
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
        1, "", b"", "Content-Type: application/vnd.sun.wadl+xml\r\n", wadl,
    ))
    conn.commit()
    conn.close()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["target.test"], batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    signals = _signals(mailbox)
    reasons = {r for s in signals for r in s["observation"]["reasons"]}
    assert "api_description_exposure" in reasons
    hyp = [h for s in signals for h in s.get("hypotheses", []) if h.get("family") == "info-disclosure"]
    assert hyp, "expected an info-disclosure hypothesis"
    targets = hyp[0]["targets"]
    assert "WADL" in targets
    assert "backend_or_internal_url" in targets
    assert "framework_version" in targets
    # boundary #6: raw internal hostname / framework string must never enter the mailbox
    serialized = json.dumps(signals)
    assert "internal-k8s.example.cloud" not in serialized
    assert "Jersey: 2.33" not in serialized

def test_js_intel_flags_secrets_paths_auth_without_leaking_values(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
    """)
    js = (
        b'var cfg={apiKey:"AKIAIOSFODNN7EXAMPLE",client_id:"705819728788-abcdef.apps"};'
        b'fetch("/api/v2/user/profile");fetch("/oauth/token");fetch("/internal/admin/flush");'
        b'localStorage.setItem("auth_token",t);var crumb=getCrumb();'
        b'\n//# sourceMappingURL=/static/app.min.js.map\n'
    )
    conn.execute(
        "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (1, "2026-08-29T00:00:01Z", "GET", "target.test", "/static/app.min.js",
         "", 0, "", 200, len(js), "application/javascript", "js", "HTTP/2",
         "https://target.test/static/app.min.js", "h1"),
    )
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
        1, "", b"", "Content-Type: application/javascript\r\n", js,
    ))
    conn.commit()
    conn.close()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["target.test"], batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    signals = _signals(mailbox)
    reasons = {r for s in signals for r in s["observation"]["reasons"]}
    assert "js_secret_literal" in reasons
    assert "js_endpoint_disclosure" in reasons
    assert "js_sourcemap_disclosure" in reasons
    assert "js_auth_mechanism" in reasons
    hyp = [h for s in signals for h in s.get("hypotheses", []) if h.get("family") == "js-intel"]
    assert hyp, "expected a js-intel hypothesis"
    targets = hyp[0]["targets"]
    assert any(t.startswith("secret:") and "aws_access_key" in t for t in targets)
    assert any(t == "path:/oauth/token" for t in targets)  # query-stripped path shape is fine
    # boundary #6: the raw secret value must never enter the mailbox
    serialized = json.dumps(signals)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized

def test_infra_graph_records_backend_and_framework_from_wadl(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
    """)
    wadl = (
        b'<?xml version="1.0"?><application xmlns="http://wadl.dev.java.net/2009/02">'
        b'<doc jersey:generatedBy="Jersey: 2.33 2020-12-18"/>'
        b'<resources base="http://screeners-prod.internal-k8s.example.cloud:443/">'
        b'<resource path="v1/finance/visualization"><method name="POST"/></resource>'
        b'</resources></application>'
    )
    conn.execute(
        "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (1, "2026-08-29T00:00:01Z", "GET", "target.test", "/application.wadl",
         "", 0, "", 200, len(wadl), "application/vnd.sun.wadl+xml", "wadl", "HTTP/2",
         "https://target.test/application.wadl", "h1"),
    )
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
        1, "", b"", "Content-Type: application/vnd.sun.wadl+xml\r\n", wadl,
    ))
    conn.commit()
    conn.close()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["target.test"], batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    graph = json.loads((tmp_path / "signals.jsonl.graph.json").read_text())
    nodes = graph["nodes"]
    assert "host:target.test" in nodes
    assert "backend:screeners-prod.internal-k8s.example.cloud" in nodes
    assert any(n.startswith("framework:Jersey") for n in nodes)
    rels = {(e["from"], e["rel"], e["to"]) for e in graph["edges"]}
    assert ("host:target.test", "served_by", "backend:screeners-prod.internal-k8s.example.cloud") in rels
    assert any(r[0] == "host:target.test" and r[1] == "framework" for r in rels)
    # the host node carries the signal reason for pivoting
    assert "api_description_exposure" in nodes["host:target.test"]["reasons"]


def test_graph_persists_cross_domain_embed_edges(tmp_path):
    # The embedding structure - a first-party page pulling in a third-party collector - is the
    # relational signal point-detection cannot see; it must survive into the persisted sidecar.
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
    """)

    def add(rid, host, path, referer):
        conn.execute(
            "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, f"2026-08-29T00:00:{rid:02d}Z", "POST", host, path, "", 0, "",
             200, 2, "application/json", "", "HTTP/2", f"https://{host}{path}", f"h{rid}"))
        conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
            rid, f"Referer: {referer}\r\n", b"", "Content-Type: application/json\r\n", b"{}"))

    add(1, "collector.other", "/collect", "https://page.test/")   # cross-domain -> embed edge
    add(2, "assets.page.test", "/app.js", "https://page.test/")   # same registrable domain -> not
    conn.commit()
    conn.close()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    graph = json.loads((tmp_path / "signals.jsonl.graph.json").read_text())
    rels = {(e["from"], e["rel"], e["to"]) for e in graph["edges"]}
    assert ("host:page.test", "embeds", "host:collector.other") in rels
    # a same-registrable-domain asset load is not a third-party embed
    assert not any(r[1] == "embeds" and r[2] == "host:assets.page.test" for r in rels)


def test_graph_clusters_by_shared_ip_and_response_fingerprint(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT,
            ip_address TEXT, fingerprint TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
    """)

    def add(rid, host, path, ip, fp):
        conn.execute(
            "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, f"2026-08-29T00:00:{rid:02d}Z", "GET", host, path, "", 0, "",
             500, 3, "application/json", "", "HTTP/2", f"https://{host}{path}", f"h{rid}", ip, fp),
        )
        conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
            rid, "", b"", "Content-Type: application/json\r\n", b'{"e":1}',
        ))

    # two hostnames behind one IP; two distinct a.test endpoints return the same error shape
    add(1, "a.test", "/api/users/1", "203.0.113.9", "ERRTPL")
    add(2, "a.test", "/api/orders/2", "203.0.113.9", "ERRTPL")
    add(3, "b.test", "/api/x/3", "203.0.113.9", "ZZZ")
    conn.commit()
    conn.close()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["a.test", "b.test"], batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    graph = json.loads((tmp_path / "signals.jsonl.graph.json").read_text())
    nodes, edges = graph["nodes"], graph["edges"]
    rels = {(e["from"], e["rel"], e["to"]) for e in edges}

    # shared IP: both hostnames resolve to one ip node (shared-infra cluster)
    assert nodes.get("ip:203.0.113.9", {}).get("type") == "ip"
    assert ("host:a.test", "resolves_to", "ip:203.0.113.9") in rels
    assert ("host:b.test", "resolves_to", "ip:203.0.113.9") in rels

    # shared fingerprint: two DIFFERENT a.test endpoint families share one response shape
    assert nodes.get("fingerprint:ERRTPL", {}).get("type") == "response_shape"
    responds = [e for e in edges if e["rel"] == "responds_as" and e["to"] == "fingerprint:ERRTPL"]
    assert len({e["from"] for e in responds}) >= 2  # oracle: many endpoints, one shape

def test_header_signals_trust_and_internal_disclosure_and_tech_graph(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
    """)
    # request carries a client-controllable trust header; response leaks a pod IP + reveals Envoy
    req = ("GET /api/data HTTP/1.1\r\nHost: t.test\r\nCookie: s=1\r\n"
           "X-Original-URL: /admin\r\nX-Forwarded-Host: evil.test\r\n")
    resp = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: nginx/1.19\r\n"
            "X-Backend-Pod-IP: 10.1.2.3\r\nX-Envoy-Upstream-Service-Time: 4\r\n"
            "Via: 1.1 google, 1.1 varnish\r\n")
    conn.execute(
        "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (1, "2026-08-29T00:00:01Z", "GET", "t.test", "/api/data", "", 0, "",
         200, 2, "application/json", "", "HTTP/2", "https://t.test/api/data", "h1"),
    )
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)",
                 (1, req, b"", resp, b'{"ok":1}'))
    conn.commit()
    conn.close()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["t.test"], batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    signals = _signals(mailbox)
    reasons = {r for s in signals for r in s["observation"]["reasons"]}
    assert "client_trust_header" in reasons
    assert "internal_header_disclosure" in reasons
    hyps = [h for s in signals for h in s.get("hypotheses", [])]
    trust = [h for h in hyps if h.get("family") == "request-tampering"]
    assert trust and "x-original-url" in trust[0]["targets"]
    leak = [h for h in hyps if h.get("family") == "info-disclosure" and "x-backend-pod-ip" in h.get("targets", [])]
    assert leak, "expected pod-ip disclosure hypothesis"
    # boundary #6: the leaked pod-IP VALUE must not enter the mailbox
    serialized = json.dumps(signals)
    assert "10.1.2.3" not in serialized
    assert "/admin" not in serialized  # trust-header value withheld too

    graph = json.loads((tmp_path / "signals.jsonl.graph.json").read_text())
    techs = {n.split(":", 1)[1] for n, d in graph["nodes"].items() if d["type"] == "technology"}
    assert "nginx" in techs and "Envoy" in techs
    proxies = {n.split(":", 1)[1] for n, d in graph["nodes"].items() if d["type"] == "proxy"}
    assert "varnish" in proxies and "google" in proxies

def test_http2_downgrade_surface_activates_from_alpn_probe(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
        CREATE TABLE raw_socket_traffic (
            id INTEGER PRIMARY KEY, timestamp TEXT, tool TEXT, target_host TEXT,
            target_port INTEGER, protocol TEXT, alpn_negotiated TEXT
        );
    """)
    # an operator ALPN probe recorded that t.test negotiates HTTP/2
    conn.execute("INSERT INTO raw_socket_traffic (target_host, alpn_negotiated) VALUES (?,?)",
                 ("t.test", "h2"))
    # yet a response carries a hop-by-hop header HTTP/2 forbids -> H1 backend behind H2 frontend
    resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
    conn.execute(
        "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (1, "2026-08-29T00:00:01Z", "GET", "t.test", "/api/x", "", 0, "",
         200, 2, "application/json", "", "HTTP/2", "https://t.test/api/x", "h1"),
    )
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)",
                 (1, "GET /api/x HTTP/1.1\r\nHost: t.test\r\nCookie: s=1\r\n", b"", resp, b'{"ok":1}'))
    conn.commit()
    conn.close()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["t.test"], batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    reasons = {r for s in _signals(mailbox) for r in s["observation"]["reasons"]}
    assert "http2_downgrade_surface" in reasons


def test_alpn_lane_dormant_without_raw_socket_table(tmp_path):
    # the common case: no raw_socket_traffic table at all -> lane no-ops, no crash
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    _database(db)
    tailer = PassiveTailer(str(db), str(mailbox), start="0", scope_hosts=["target.test"],
                           batch_size=100, warmup=0)
    tailer.step()  # must not raise despite the missing table
    tailer.close()
    reasons = {r for s in _signals(mailbox) for r in s["observation"]["reasons"]}
    assert "http2_downgrade_surface" not in reasons

def test_nuclei_borrowed_response_signatures(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE http_traffic (
            request_id INTEGER PRIMARY KEY, timestamp TEXT, method TEXT, host TEXT,
            path TEXT, query TEXT, param_count INTEGER, param_names TEXT,
            status_code INTEGER, response_length INTEGER, content_type TEXT,
            extension TEXT, protocol TEXT, url TEXT, request_hash TEXT
        );
        CREATE TABLE http_messages (
            request_id INTEGER PRIMARY KEY, request_headers TEXT, request_body BLOB,
            response_headers TEXT, response_body BLOB
        );
    """)

    def add(rid, path, ctype, body):
        conn.execute(
            "INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, f"2026-08-29T00:00:{rid:02d}Z", "GET", "t.test", path, "", 0, "",
             200, len(body), ctype, "", "HTTP/2", f"https://t.test{path}", f"h{rid}"),
        )
        conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)",
                     (rid, "", b"", f"Content-Type: {ctype}\r\n", body))

    add(1, "/.env", "text/plain",
        b"APP_ENV=production\nAPP_KEY=base64:ZZZ\nDB_PASSWORD=sup3rs3cret\n")
    add(2, "/config.json", "application/json",
        b'{"note":"deploy","key":"AKIAIOSFODNN7EXAMPLE","gh":"ghp_' + b"a" * 36 + b'"}')
    add(3, "/oops", "text/html",
        b"<html><body>Django tried these URL patterns, in this order: URLconf defined</body></html>")
    add(4, "/login", "text/html", b"<html><head><title>Grafana</title></head></html>")
    conn.commit()
    conn.close()

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["t.test"], batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    signals = _signals(mailbox)
    reasons = {r for s in signals for r in s["observation"]["reasons"]}
    assert "sensitive_file_exposure" in reasons
    assert "secret_in_response" in reasons
    assert "error_disclosure_in_body" in reasons
    assert "exposed_management_panel" in reasons

    hyps = [h for s in signals for h in s.get("hypotheses", [])]
    assert any(".env file" in h.get("targets", []) for h in hyps)
    assert any("aws_access_key" in h.get("targets", []) and "github_token" in h.get("targets", []) for h in hyps)
    assert any("Grafana" in h.get("targets", []) for h in hyps)

    # boundary #6: secret values and env secrets must never enter the mailbox
    serialized = json.dumps(signals)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "sup3rs3cret" not in serialized
    assert "ghp_" not in serialized

    # panel feeds the tech graph
    graph = json.loads((tmp_path / "signals.jsonl.graph.json").read_text())
    techs = {n.split(":", 1)[1] for n, d in graph["nodes"].items() if d["type"] == "technology"}
    assert "Grafana" in techs

def test_envelope_carries_signal_aware_interrogation(tmp_path):
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    checkpoint = tmp_path / "checkpoint.json"
    _database(db)  # includes a 500 error, a reflected/cache-contradiction, PATCH state-changes

    tailer = PassiveTailer(str(db), str(mailbox), checkpoint=str(checkpoint), start="0",
                           scope_hosts=["target.test"], batch_size=100, warmup=0)
    tailer.step()
    tailer.close()

    signals = _signals(mailbox)
    assert signals
    for s in signals:
        intr = s.get("interrogation")
        assert intr, "every envelope must carry an interrogation block"
        assert intr["lenses"], "at least one persona lens"
        assert len(intr["standing"]) >= 6              # operator's recurring investigative frames
        assert len(intr["blindspots"]) >= 8            # should-have-asked / persona-signature angles
        assert len(intr["temporal"]) >= 6              # dating/provenance/latency/archive/context ladder
        assert any("patch latency" in q for q in intr["temporal"])  # CVE-latency rung present
        assert "DISPROVE" in intr["falsify"]           # falsification frame present
        assert "neighbours" in intr["pivot"].lower()   # graph-pivot provocation present
        assert "fan-out" in intr["impact"].lower()      # impact provocation present
        # lenses carry concrete questions
        assert all(l["ask"] for l in intr["lenses"])

    # signal-aware: a cache-contradiction signal gets the cache-keying lens; a state-change gets csrf-authz
    cache_sig = [s for s in signals if "authenticated_cache_policy_contradiction" in s["observation"]["reasons"]]
    if cache_sig:
        personas = {l["persona"] for l in cache_sig[0]["interrogation"]["lenses"]}
        assert "cache-keying" in personas
    patch_sig = [s for s in signals if s["endpoint"]["method"] == "PATCH"]
    if patch_sig:
        personas = {l["persona"] for l in patch_sig[0]["interrogation"]["lenses"]}
        assert "csrf-authz" in personas

    # agnostic: no environment/target names anywhere in the interrogation scaffolding
    # (canary tokens are fictional placeholders — the repo carries no real target brand)
    blob = json.dumps([s["interrogation"] for s in signals])
    for banned in ("acmecorp", "paranoid", "contoso", "examplebrand"):
        assert banned not in blob.lower()
