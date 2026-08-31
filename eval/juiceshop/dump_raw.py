"""Dump the captured traffic as readable raw request/response pairs — the Arm A input.

Arm A (baseline) gets exactly this: the same traffic Swarmie saw, but unprocessed. No
signals, no ranking, no interrogation — just the rows. This is what "Claude with raw traffic
and no Swarmie" reads when hunting, so the A/B isolates the Swarmie layer's contribution.
"""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def dump(db: str, out: Path, body_cap: int = 1200) -> int:
    conn = sqlite3.connect(f"file:{Path(db).resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT t.request_id, t.method, t.url, t.status_code, t.content_type, t.response_length,
               m.request_headers, m.request_body, m.response_headers, m.response_body
        FROM http_traffic t JOIN http_messages m USING(request_id) ORDER BY t.request_id
    """).fetchall()
    lines: list[str] = []
    for r in rows:
        lines.append(f"===== #{r['request_id']}  {r['method']} {r['url']}  -> {r['status_code']} "
                     f"({r['content_type']}, {r['response_length']}B) =====")
        req_body = bytes(r["request_body"] or b"").decode("utf-8", "replace")
        if req_body.strip():
            lines.append(f"REQUEST BODY: {req_body[:body_cap]}")
        resp = bytes(r["response_body"] or b"").decode("utf-8", "replace")
        lines.append(f"RESPONSE: {resp[:body_cap]}")
        lines.append("")
    out.write_text("\n".join(lines))
    conn.close()
    return len(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Dump capture DB to readable raw pairs (Arm A input)")
    ap.add_argument("--db", default="eval/juiceshop/juiceshop.db")
    ap.add_argument("--out", default="eval/juiceshop/arm_a_raw.txt")
    args = ap.parse_args(argv)
    n = dump(args.db, Path(args.out))
    print(f"wrote {n} pairs to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
