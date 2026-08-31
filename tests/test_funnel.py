"""#3: per-detector / per-stage funnel attribution on the StepResult and the CLI summary."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from rqswarm_eval.passive import PassiveTailer


def _db(path: Path) -> None:
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
    host = "app.test"
    # an authed request whose response contradicts its cache policy -> a strong metadata reason,
    # plus a server error on another endpoint.
    conn.execute("INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        1, "2026-08-31T00:00:01Z", "GET", host, "/api/me", "", 0, "",
        200, 20, "application/json", "", "HTTP/2", f"https://{host}/api/me", "h1"))
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
        1, "Authorization: Bearer T\r\n", b"",
        "Content-Type: application/json\r\nCache-Control: no-store\r\nCF-Cache-Status: HIT\r\nAge: 99\r\n",
        b'{"x":1}'))
    conn.execute("INSERT INTO http_traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        2, "2026-08-31T00:00:02Z", "GET", host, "/boom", "", 0, "",
        500, 20, "application/json", "", "HTTP/2", f"https://{host}/boom", "h2"))
    conn.execute("INSERT INTO http_messages VALUES (?,?,?,?,?)", (
        2, "\r\n", b"", "Content-Type: application/json\r\n", b'{"e":1}'))
    conn.commit()
    conn.close()


def test_stepresult_carries_reason_and_stage_attribution(tmp_path):
    db = tmp_path / "t.db"
    mailbox = tmp_path / "s.jsonl"
    _db(db)
    tailer = PassiveTailer(str(db), str(mailbox), start="0", batch_size=100, warmup=0, hydrate_all=True)
    step = tailer.step()
    tailer.close()

    # per-stage timing is present and non-negative
    assert set(step.stage_us) == {"metadata", "body_hydrate"}
    assert all(v >= 0 for v in step.stage_us.values())

    # per-detector counts equal the reasons actually emitted into the mailbox
    signals = [json.loads(l) for l in mailbox.read_text().splitlines()]
    emitted = [r for s in signals for r in s["observation"]["reasons"]]
    assert step.reason_counts and sum(step.reason_counts.values()) == len(emitted)
    for r in set(emitted):
        assert step.reason_counts[r] == emitted.count(r)


def test_cli_summary_has_a_count_ordered_reason_funnel(tmp_path):
    db = tmp_path / "t.db"
    _db(db)
    proc = subprocess.run(
        [sys.executable, "-m", "rqswarm_eval.passive", "--source", str(db),
         "--mailbox", str(tmp_path / "s.jsonl"), "--checkpoint", str(tmp_path / "c.json"),
         "--start", "0", "--once", "--hydrate-all"],
        capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1]))
    summary = json.loads(proc.stdout)
    funnel = summary["reason_funnel"]
    assert isinstance(funnel, list) and funnel and all(len(pair) == 2 for pair in funnel)
    counts = [c for _, c in funnel]
    assert counts == sorted(counts, reverse=True)          # most-frequent first, not alphabetical
    assert "stage_us" in summary and "metadata" in summary["stage_us"]
