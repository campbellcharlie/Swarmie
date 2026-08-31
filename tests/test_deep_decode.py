"""Recursive multi-codec decode with a meaningfulness gate (extends the encoded-blob signals).

deep_decode walks urldecode/base64/hex/gzip/zlib to a bounded depth, keeping a layer only when it
is meaningful (container magic, or printable + low-entropy). A JSON verdict requires a real
json.loads, so printable-but-invalid decodes (the classic ``{ghD`` false positive) are reported as
text, not JSON. It returns only the codec chain + terminal classification -- never decoded bytes.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import sqlite3
import zlib
from pathlib import Path

from rqswarm_eval.passive import PassiveTailer, deep_decode


def test_unwraps_base64_gzip_json():
    payload = json.dumps({"user": "x", "device": "y", "ts": 123, "beh": [1, 2, 3]}).encode()
    got = deep_decode(base64.b64encode(gzip.compress(payload)))
    assert got == {"chain": ["base64", "gzip"], "terminal": "json", "json_keys": 4}


def test_unwraps_zlib_and_plain_base64():
    payload = json.dumps({"a": 1, "b": 2}).encode()
    assert deep_decode(base64.b64encode(zlib.compress(payload)))["chain"] == ["base64", "zlib"]
    assert deep_decode(base64.b64encode(payload)) == {"chain": ["base64"], "terminal": "json", "json_keys": 2}


def test_json_verdict_requires_real_json_loads():
    # hex of a printable-but-invalid-JSON string: starts with '{' yet json.loads fails.
    blob = b"7b6768446f6573206e6f742070617273652061732a4a534f4e21"  # "{ghDoes not parse as*JSON!"
    got = deep_decode(blob)
    assert got is not None and got["terminal"] == "text" and got["json_keys"] is None


def test_encrypted_blob_stays_opaque():
    # random bytes: base64 decodes to noise (high entropy, not printable) -> nothing is kept.
    assert deep_decode(base64.b64encode(os.urandom(600))) is None


def _db_with_blob_post(path: Path, body_text: str) -> None:
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
    host = "collector.third-party.test"
    conn.execute("INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        1, "2026-08-31T00:00:01Z", "POST", host, "/rum", "", 0, "",
        200, 2, "text/plain", "", "HTTP/2", f"https://{host}/rum", "h1"))
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
        1, "Content-Type: text/plain\r\n", body_text.encode(),
        "Content-Type: application/json\r\n", b"{}"))
    conn.commit()
    conn.close()


def test_encoded_blob_decoded_end_to_end_and_redacted(tmp_path):
    # a large base64(gzip(json)) blob whose values must never reach the mailbox.
    payload = {f"field_{i}": f"SENTINEL_VALUE_{os.urandom(4).hex()}" for i in range(40)}
    payload["marker"] = "DO_NOT_LEAK_THIS"
    blob = base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()
    assert len(blob) >= 500  # clears the _B64_BLOB floor

    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    _db_with_blob_post(db, blob)

    tailer = PassiveTailer(str(db), str(mailbox), start="0", batch_size=100, warmup=0, hydrate_all=True)
    tailer.step()
    tailer.close()

    text = mailbox.read_text()
    signals = [json.loads(l) for l in text.splitlines()]
    reasons = {r for s in signals for r in s["observation"]["reasons"]}
    assert "encoded_blob_decoded" in reasons
    # the decoded structure is reported...
    assert any("JSON (41 fields)" in json.dumps(s) for s in signals)
    # ...but boundary #6: no decoded value or the raw blob ever appears.
    assert "DO_NOT_LEAK_THIS" not in text
    assert "SENTINEL_VALUE_" not in text
    assert blob not in text
