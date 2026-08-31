"""Regression: mojibaked binary bodies must not fool the opaque-body detector.

Some capture proxies store a binary request/response body as ``UTF-8(latin-1-decode(bytes))``
-- every byte >= 0x80 is re-encoded as a 2-byte UTF-8 sequence. A gzip body whose true magic
is ``1f 8b 08`` lands on disk (and in ``_raw_req``) as ``1f c2 8b 08``. That round-trip both
hides the container magic and *deflates* measured Shannon entropy (the repeated ``c2/c3`` lead
bytes are low-entropy), so the opaque/encrypted-body detector -- gated on
``_shannon_entropy(_raw_req[:16384]) >= 7.2`` -- silently misses a whole class of real bodies.

``unmojibake`` inverts the round-trip when (and only when) the bytes are a UTF-8 encoding of an
all-latin-1 string; genuine binary (invalid UTF-8) and ordinary text are left untouched.
"""
from __future__ import annotations

import gzip
import json
import os
import sqlite3
from pathlib import Path

from rqswarm_eval.passive import PassiveTailer, _bytes, _shannon_entropy, unmojibake


def _true_and_mojibaked() -> tuple[bytes, bytes]:
    """A realistic captured gzip body and the mojibaked form a proxy would persist."""
    true_body = gzip.compress(os.urandom(6000))
    assert true_body[:3] == b"\x1f\x8b\x08" and len(true_body) >= 2048
    # latin-1 decode -> str (what the DB text_factory yields) -> _bytes re-encodes as UTF-8.
    mojibaked = _bytes(true_body.decode("latin-1"))
    assert mojibaked[:4] == b"\x1f\xc2\x8b\x08" and mojibaked != true_body
    return true_body, mojibaked


def test_mojibake_inverts_the_opaque_entropy_gate():
    """The bug, stated as a measurement: the same body crosses the 7.2 gate in opposite directions."""
    true_body, mojibaked = _true_and_mojibaked()
    assert _shannon_entropy(true_body[:16384]) >= 7.2          # true body is opaque/high-entropy
    assert _shannon_entropy(mojibaked[:16384]) < 7.2           # mojibake deflates it below the gate


def test_unmojibake_recovers_true_body_and_is_safe_otherwise():
    true_body, mojibaked = _true_and_mojibaked()
    restored = unmojibake(mojibaked)
    assert restored == true_body                               # exact round-trip
    assert restored[:3] == b"\x1f\x8b\x08"                     # gzip magic re-exposed
    assert _shannon_entropy(restored[:16384]) >= 7.2           # entropy restored above the gate
    # safety: genuine binary is invalid UTF-8 -> untouched; ASCII text -> unchanged; idempotent.
    assert unmojibake(true_body) == true_body
    assert unmojibake(b"user=bob&pw=secret") == b"user=bob&pw=secret"
    assert unmojibake(restored) == restored


def _db_with_mojibaked_post(path: Path, body: bytes) -> None:
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
        200, 2, "application/octet-stream", "", "HTTP/2", f"https://{host}/rum", "h1"))
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
        1, "Content-Type: application/octet-stream\r\n", body,
        "Content-Type: application/json\r\n", b"{}"))
    conn.commit()
    conn.close()


def test_mojibaked_gzip_post_is_flagged_opaque_end_to_end(tmp_path):
    """Through the real tailer: a mojibaked-gzip POST to a third party must still surface as an
    opaque/encrypted outbound blob (it silently didn't, before unmojibake)."""
    _true_body, mojibaked = _true_and_mojibaked()
    db = tmp_path / "traffic.db"
    mailbox = tmp_path / "signals.jsonl"
    _db_with_mojibaked_post(db, mojibaked)

    tailer = PassiveTailer(str(db), str(mailbox), start="0", batch_size=100,
                           warmup=0, hydrate_all=True)
    tailer.step()
    tailer.close()

    signals = [json.loads(l) for l in mailbox.read_text().splitlines()]
    reasons = {r for s in signals for r in s["observation"]["reasons"]}
    assert "encrypted_outbound_blob" in reasons or "opaque_outbound_body" in reasons
