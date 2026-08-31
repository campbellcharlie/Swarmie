"""Score Swarmie's signals (Arm B) against the labeled ground truth.

Both arms are the same LLM (me), and Arm A can read all 31 raw pairs, so raw recall is not the
interesting axis — TRIAGE is. This scores what Swarmie actually contributes:

  * endpoint recall  — of the request_ids that carry a real finding, how many did Swarmie flag?
  * strong recall    — how many did it flag with a NON-generic reason (not just new_dynamic /
                       missing_security_headers, which fire almost everywhere)?
  * ranking quality  — precision@k when the hunter follows Swarmie's attention order
  * misses           — finding-bearing endpoints Swarmie flagged weakly or not at all
  * noise            — flagged endpoints that carry no real finding
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

# reasons that fire on almost every dynamic endpoint -> not evidence of a specific finding
_GENERIC = {"new_dynamic_endpoint", "missing_security_headers", "auth_anomaly_in_sequence"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", default="eval/juiceshop/ground_truth.json")
    ap.add_argument("--signals", default="eval/juiceshop/arm_b_signals.jsonl")
    args = ap.parse_args(argv)

    findings = json.loads(Path(args.truth).read_text())["findings"]
    gt = {}  # request_id -> worst severity + labels
    for f in findings:
        gt.setdefault(f["request_id"], []).append(f)

    sig = {}  # request_id -> {attention, reasons}
    for line in Path(args.signals).read_text().splitlines():
        s = json.loads(line)
        rid = s["request_id"]
        prev = sig.get(rid)
        cur = {"attention": s["attention"]["score"], "reasons": s["observation"]["reasons"]}
        if prev is None or cur["attention"] > prev["attention"]:
            sig[rid] = cur

    ranked = sorted(sig.items(), key=lambda kv: -kv[1]["attention"])
    rank_of = {rid: i + 1 for i, (rid, _) in enumerate(ranked)}

    flagged = strong = 0
    rows = []
    for rid in sorted(gt):
        s = sig.get(rid)
        has = s is not None
        non_generic = has and bool(set(s["reasons"]) - _GENERIC)
        flagged += has
        strong += non_generic
        sev = sorted(gt[rid], key=lambda f: ["low", "med", "high", "crit"].index(f["severity"]))[-1]
        rows.append((rid, sev["severity"], has, non_generic,
                     rank_of.get(rid), s["attention"] if has else 0, gt[rid][0]["finding"]))

    # top-5 precision: of Swarmie's 5 highest-attention endpoints, how many carry a real finding?
    top5 = [rid for rid, _ in ranked[:5]]
    top5_hits = sum(1 for rid in top5 if rid in gt)
    noise = [rid for rid in sig if rid not in gt]

    print(f"Ground-truth finding-bearing endpoints: {len(gt)}")
    print(f"Swarmie flagged (any signal):           {flagged}/{len(gt)}  ({flagged/len(gt):.0%})")
    print(f"Swarmie flagged with specific reason:   {strong}/{len(gt)}  ({strong/len(gt):.0%})")
    print(f"Top-5-by-attention precision:           {top5_hits}/5")
    print(f"Noise (flagged, no real finding):       {len(noise)} endpoints -> req {sorted(noise)}")
    print()
    print(f"{'req':>4} {'sev':>4} {'flag':>4} {'spec':>4} {'rank':>4} {'att':>6}  finding")
    for rid, sev, has, ng, rk, att, name in sorted(rows, key=lambda r: -(r[5] or 0)):
        print(f"{rid:>4} {sev:>4} {'Y' if has else '·':>4} {'Y' if ng else '·':>4} "
              f"{rk if rk else '-':>4} {att:>6}  {name[:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
