"""Rank-time rarity multiplier + lead dedup (#2), and its wiring into the gate's check order."""
from __future__ import annotations

import json

from rqswarm_eval.rerank import reason_rarity, effective_score, lead_shape, rerank
import rqswarm_eval.gate as gate

W = {"common": 20, "rare": 15, "mid": 10}


def _sig(rid, reasons, host="h", path="/x", method="GET", score=0):
    return {"request_id": rid, "attention": {"score": score},
            "endpoint": {"method": method, "host": host, "path_shape": path},
            "observation": {"reasons": reasons}, "interrogation": {}}


def test_reason_rarity_is_log2_of_inverse_frequency():
    sigs = [_sig(i, ["common"]) for i in range(15)] + [_sig(99, ["rare"])]
    r = reason_rarity(sigs)
    assert r["common"] == 1.0                      # 15/16 -> log2(~1.07) floored to 1.0
    assert abs(r["rare"] - 4.0) < 1e-9             # 1/16 -> log2(16) = 4


def test_rarity_flips_a_common_high_weight_below_a_rare_one():
    sigs = [_sig(i, ["common"]) for i in range(15)] + [_sig(99, ["rare"])]
    # static: common (20) outranks rare (15)
    assert sorted(sigs, key=lambda s: -W[s["observation"]["reasons"][0]])[0]["request_id"] != 99
    # rarity: rare 15*log2(16)=60 beats common 20*1=20 -> the rare signal is now first
    ranked = rerank(sigs, weights=W, dedup=False)
    assert ranked[0]["request_id"] == 99


def test_dedup_collapses_same_lead_with_a_count():
    sigs = [_sig(i, ["common"], host="dup.host", path="/same") for i in range(4)] + \
           [_sig(50, ["rare"], host="other", path="/z")]
    ranked = rerank(sigs, weights=W, dedup=True)
    leads = [lead_shape(s, W) for s in ranked]
    assert len(leads) == len(set(leads))                    # every survivor is a distinct lead
    dup_rep = next(s for s in ranked if s["endpoint"]["host"] == "dup.host")
    assert dup_rep["_dupes"] == 4


def test_rerank_does_not_mutate_inputs():
    sigs = [_sig(1, ["common"]), _sig(2, ["rare"])]
    rerank(sigs, weights=W, dedup=True)
    assert all("_dupes" not in s for s in sigs)             # dedup annotates copies only


def test_default_weights_come_from_the_engine_table():
    # smoke: no explicit weights -> pulls _REASON_WEIGHT from passive, still orders sanely
    sigs = [_sig(i, ["resp:cors"]) for i in range(9)] + [_sig(99, ["cleartext_auth_material"])]
    assert rerank(sigs, dedup=False)[0]["request_id"] == 99


def test_gate_check_orders_by_rarity(tmp_path, capsys):
    mb = tmp_path / "mb.jsonl"
    disp = tmp_path / "d.jsonl"; disp.write_text("")
    # a common reason on many signals, one rare-reason signal that should surface first
    lines = [_sig(i, ["resp:cors"], host=f"h{i}", path=f"/p{i}", score=2) for i in range(12)]
    lines.append(_sig(999, ["credential_reused_across_endpoints"], host="hz", path="/z", score=55))
    mb.write_text("\n".join(json.dumps(s) for s in lines))

    rc = gate.main(["check", "--mailbox", str(mb), "--dispositions", str(disp), "--limit", "5"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2 and out["pending"] == 13
    assert out["must_answer_each"][0]["request_id"] == 999   # the rare, high-value lead is first
