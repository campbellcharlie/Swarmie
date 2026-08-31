"""Bulk triage: run the dry-run pipeline across every capture DB, then aggregate.

Enumerates non-empty ``http_traffic`` databases matched by capture globs (set
``$SWARMIE_CAPTURE_GLOBS`` to a colon-separated list, and/or pass ``--glob``),
runs precision+dedup triage on each (nothing is sent), and writes one cross-corpus
``SUMMARY.json`` plus a ranked shortlist for the judge. Per-corpus cards +
hash-chained ledgers land under ``runs/triage/<name>/``.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sqlite3

from .triage import run_triage

def _capture_globs(extra) -> list[str]:
    """Capture-DB glob patterns: $SWARMIE_CAPTURE_GLOBS (colon-separated) plus any --glob."""
    env = [g for g in os.environ.get("SWARMIE_CAPTURE_GLOBS", "").split(":") if g]
    return env + list(extra or [])


def discover(globs) -> list[tuple[str, str]]:
    """Return (tag, db_path) for every matched DB with a non-empty http_traffic table."""
    paths: list[str] = []
    for pat in globs:
        paths += glob.glob(os.path.expanduser(pat), recursive=True)
    found: list[tuple[str, str]] = []
    for db in sorted(set(paths)):
        try:
            c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            has = c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='http_traffic'"
            ).fetchone()
            n = c.execute("SELECT COUNT(*) FROM http_traffic").fetchone()[0] if has else 0
            c.close()
        except sqlite3.Error:
            n = 0
        if n:
            base = os.path.basename(db)
            parent = os.path.basename(os.path.dirname(db))
            tag = parent if base in ("traffic.db", "capture.db") and parent else (
                base[:-3] if base.endswith(".db") else base)
            found.append((tag, db))
    return found


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="rqswarm_eval.triage_all")
    ap.add_argument("--out", default="runs/triage", help="root output dir")
    ap.add_argument("--cap", type=int, default=0, help="max requests per DB (0 = all)")
    ap.add_argument("--shortlist", type=int, default=40, help="global shortlist size")
    ap.add_argument("--glob", action="append",
                    help="capture-DB glob (repeatable); also reads $SWARMIE_CAPTURE_GLOBS")
    args = ap.parse_args(argv)

    dbs = discover(_capture_globs(args.glob))
    if not dbs:
        print("no capture DBs found; set $SWARMIE_CAPTURE_GLOBS or pass --glob '<pattern>'")
        return 1
    os.makedirs(args.out, exist_ok=True)
    per_db: list[dict] = []
    all_cards: list[dict] = []
    route_totals: dict[str, int] = {}

    for tag, db in dbs:
        safe = tag.replace(":", "_").replace("/", "_")
        out = os.path.join(args.out, safe)
        summary = run_triage(db, args.cap, 5, out, precision=True, dedup=True)
        cards = json.load(open(os.path.join(out, "triage_cards.json"), encoding="utf-8"))
        for c in cards:
            c["corpus"] = tag
            all_cards.append(c)
            for r in c["routes"]:
                route_totals[r] = route_totals.get(r, 0) + 1
        per_db.append({
            "corpus": tag,
            "scanned": summary["scanned"],
            "survivors": summary["with_surface"],
            "routes": summary["route_counts"],
            "top_hosts": summary["hosts"][:5],
        })
        print(f"  {tag:42} scanned={summary['scanned']:>7}  survivors={summary['with_surface']:>4}")

    all_cards.sort(key=lambda c: (-c["score"], c["corpus"], c["seed_request_id"]))
    shortlist = [{
        "corpus": c["corpus"], "score": c["score"], "method": c["method"],
        "host": c["host"], "path_shape": c["path_shape"], "routes": c["routes"],
        "id_params": c["id_params"], "jwt": c["jwt_present"], "auth": c["auth_present"],
        "dupes": c.get("dupes", 1),
    } for c in all_cards[:args.shortlist]]

    result = {
        "corpora": len(dbs),
        "total_scanned": sum(p["scanned"] for p in per_db),
        "total_survivors": len(all_cards),
        "route_totals": dict(sorted(route_totals.items(), key=lambda kv: -kv[1])),
        "per_db": sorted(per_db, key=lambda p: -p["survivors"]),
        "shortlist": shortlist,
    }
    with open(os.path.join(args.out, "SUMMARY.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"\ncorpora={result['corpora']}  total_scanned={result['total_scanned']:,}  "
          f"total_survivors={result['total_survivors']}")
    print("route_totals:", result["route_totals"])
    print(f"\nCROSS-CORPUS SHORTLIST (precision-filtered, deduped; dry-run hypotheses):")
    for c in shortlist[:25]:
        routes = ",".join(r.replace("route:", "") for r in c["routes"])
        print(f"  [{c['score']:>2}] {c['corpus']:24} {c['method']:5} {c['host']}{c['path_shape']}"
              f"  -> {routes}  ids={c['id_params'][:3]} auth={c['auth']} x{c['dupes']}")
    print(f"\nSUMMARY.json -> {os.path.join(args.out, 'SUMMARY.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
