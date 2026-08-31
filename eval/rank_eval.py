"""Reproducible before/after eval for the rank-time rarity re-ranker (#2), over real captures.

Runs the passive engine over each capture DB, then compares the STATIC attention order against the
rarity-adjusted order produced by ``rqswarm_eval.rerank`` (the same code the gate uses). Reports, per
corpus: how much of the top-K changes, the Spearman correlation between reason frequency and static
weight (the discrimination baseline -- weak/near-zero means common reasons rank as high as rare ones),
and the two top-K views so the re-rank can be eyeballed. No labels needed; this measures
discrimination on real traffic, not precision against an oracle.

Usage:
    python3 -m eval.rank_eval <capture.db> [<capture.db> ...] [--k 8]
    # or set $SWARMIE_CAPTURE_GLOBS and pass no paths.
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import os
import subprocess
import sys
import tempfile

from rqswarm_eval.passive import _REASON_WEIGHT
from rqswarm_eval.rerank import rerank, reason_rarity, effective_score


def _spearman(xs, ys):
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(v):
            j = i
            while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for k in range(i, j + 1):
                r[order[k]] = (i + j) / 2 + 1
            i = j + 1
        return r
    n = len(xs)
    if n < 3:
        return float("nan")
    rx, ry = ranks(xs), ranks(ys)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    den = math.sqrt(sum((rx[i] - mx) ** 2 for i in range(n)) * sum((ry[i] - my) ** 2 for i in range(n)))
    return num / den if den else float("nan")


def _emit(db):
    with tempfile.TemporaryDirectory() as d:
        mb = os.path.join(d, "s.jsonl")
        subprocess.run([sys.executable, "-m", "rqswarm_eval.passive", "--source", db, "--mailbox", mb,
                        "--checkpoint", os.path.join(d, "c.json"), "--start", "0", "--once",
                        "--batch", "80000", "--hydrate-limit", "2500"], capture_output=True, text=True)
        return [json.loads(l) for l in open(mb)] if os.path.exists(mb) else []


def _label(db):
    return os.path.basename(os.path.dirname(db)) if db.endswith("traffic.db") else os.path.basename(db)


def _line(s, rarity):
    ep = s["endpoint"]
    top = max(s["observation"]["reasons"],
              key=lambda r: _REASON_WEIGHT.get(r, 0) * rarity.get(r, 1.0), default="-")
    dup = f" x{s['_dupes']}" if s.get("_dupes", 1) > 1 else ""
    return f"{ep['method']:4} {ep['host'][:30]:30}{ep['path_shape'][:20]:20} <{top}>{dup}"


def evaluate(db, k=8):
    sigs = _emit(db)
    name = _label(db)
    if len(sigs) < 10:
        print(f"\n{name}: only {len(sigs)} signals (skip)")
        return
    n = len(sigs)
    freq = collections.Counter(r for s in sigs for r in set(s["observation"]["reasons"]))
    weighted = [(freq[r] / n, _REASON_WEIGHT[r]) for r in freq if _REASON_WEIGHT.get(r, 0) > 0]
    rho = _spearman([f for f, _ in weighted], [w for _, w in weighted])

    rarity = reason_rarity(sigs)
    static = sorted(sigs, key=lambda s: -s["attention"]["score"])
    rare = rerank(sigs, dedup=True)                      # rarity + dedup (presentation view)
    top_static = {id(s) for s in static[:k]}
    top_rare = {id(s) for s in rare[:k]}
    churn = len(top_static ^ top_rare) // 2

    print(f"\n=== {name}: {n} signals · rho(freq,weight)={rho:+.3f} · top-{k} changed {churn}/{k} ===")
    print(" STATIC (by attention):")
    for s in static[:k]:
        print("   ", _line(s, {}))
    print(" RARITY + dedup:")
    for s in rare[:k]:
        print("   ", _line(s, rarity))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dbs", nargs="*", help="capture DB paths (default: $SWARMIE_CAPTURE_GLOBS)")
    ap.add_argument("--k", type=int, default=8)
    args = ap.parse_args(argv)
    dbs = args.dbs
    if not dbs:
        import glob
        for pat in os.environ.get("SWARMIE_CAPTURE_GLOBS", "").split(":"):
            if pat:
                dbs += glob.glob(os.path.expanduser(pat), recursive=True)
    if not dbs:
        print("no DBs; pass paths or set $SWARMIE_CAPTURE_GLOBS", file=sys.stderr)
        return 1
    for db in dbs:
        evaluate(db, args.k)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
