"""The response gate: no Swarmie signal may be silently ignored."""
import json
from pathlib import Path

from rqswarm_eval.gate import pending, questions_for, VERDICTS


def _mailbox(tmp, ids):
    p = tmp / "mb.jsonl"
    p.write_text("\n".join(json.dumps({
        "request_id": i, "endpoint": {"method": "GET", "host": "h", "path_shape": "/"},
        "observation": {"reasons": ["x"]}, "attention": {"score": 10}, "interrogation": {},
    }) for i in ids))
    return str(p)


def test_gate_blocks_until_every_signal_is_answered(tmp_path):
    mb = _mailbox(tmp_path, [1, 2, 3])
    dp = str(tmp_path / "d.jsonl")
    assert len(pending(mb, dp)) == 3            # nothing answered yet
    Path(dp).write_text(json.dumps({"request_id": 1, "verdict": "dismiss", "reason": "benign"}) + "\n")
    assert len(pending(mb, dp)) == 2
    # an empty reason does NOT count — that is the silent-ignore this gate prevents
    with open(dp, "a") as f:
        f.write(json.dumps({"request_id": 2, "verdict": "dismiss", "reason": ""}) + "\n")
    assert len(pending(mb, dp)) == 2
    for i in (2, 3):
        with open(dp, "a") as f:
            f.write(json.dumps({"request_id": i, "verdict": "inspect", "reason": "looked"}) + "\n")
    assert pending(mb, dp) == []                 # all answered -> gate clears


def test_verdict_vocabulary():
    assert {"inspect", "acted", "pivot", "dismiss", "defer"} == VERDICTS


def test_scan_self_registers_its_mailbox_with_the_gate(tmp_path, monkeypatch):
    # The gate used to read one hand-configured path, so a scan into a NEW mailbox was invisible
    # to it and the Stop hook read "clear" while hundreds of signals sat un-answered. A run must
    # arm the gate on the mailbox it actually wrote, without anyone remembering to point at it.
    import rqswarm_eval.passive as P

    swarmie = tmp_path / ".swarmie"
    swarmie.mkdir()
    monkeypatch.setattr(P, "__file__", str(tmp_path / "pkg" / "passive.py"))
    # tmp_path lives under the OS temp dir, which registration now deliberately skips; point the
    # temp dir elsewhere so this exercises the ordinary (non-transient) mailbox path.
    monkeypatch.setattr(P.tempfile, "gettempdir", lambda: str(tmp_path / "not-here"))

    mailbox = tmp_path / "run.jsonl"
    mailbox.write_text("")
    P._register_mailbox(mailbox)

    registered = json.loads((swarmie / "mailboxes.json").read_text())
    assert str(mailbox.resolve()) in registered

    P._register_mailbox(mailbox)  # idempotent — no duplicate entries
    assert json.loads((swarmie / "mailboxes.json").read_text()) == registered


def test_registration_is_dormant_without_an_active_investigation(tmp_path, monkeypatch):
    # No .swarmie/ in the checkout -> no live investigation -> stay silent (don't create state).
    import rqswarm_eval.passive as P

    monkeypatch.setattr(P, "__file__", str(tmp_path / "pkg" / "passive.py"))
    P._register_mailbox(tmp_path / "run.jsonl")
    assert not (tmp_path / ".swarmie").exists()


def _asking_mailbox(tmp, path="m2.jsonl"):
    """A signal that asks two interrogation questions."""
    mb = tmp / path
    mb.write_text(json.dumps({
        "schema": "swarmie.signal.v1", "request_id": 7,
        "endpoint": {"method": "POST", "host": "h.test", "path_shape": "/x"},
        "observation": {"reasons": ["state_changing_method"]},
        "attention": {"score": 50},
        "interrogation": {"lenses": [{"persona": "p", "ask": ["Q one?", "Q two?"]}]},
    }) + "\n")
    return str(mb)


def test_verdict_without_answers_does_not_satisfy_the_gate(tmp_path):
    # A verdict alone is a yes/no that discards the reasoning; the signal's questions are the point.
    mb = _asking_mailbox(tmp_path)
    dp = tmp_path / "d2.jsonl"
    dp.write_text(json.dumps({"request_id": 7, "verdict": "dismiss", "reason": "looks fine"}) + "\n")
    assert len(pending(mb, str(dp))) == 1

    # partial answers are still incomplete
    dp.write_text(json.dumps({"request_id": 7, "verdict": "dismiss", "reason": "looks fine",
                              "answers": [{"question": "Q one?", "answer": "because x"}]}) + "\n")
    assert len(pending(mb, str(dp))) == 1

    # an empty answer string does not count as answered
    dp.write_text(json.dumps({"request_id": 7, "verdict": "dismiss", "reason": "looks fine",
                              "answers": [{"question": "Q one?", "answer": "because x"},
                                          {"question": "Q two?", "answer": "   "}]}) + "\n")
    assert len(pending(mb, str(dp))) == 1

    # every question answered -> clear
    dp.write_text(json.dumps({"request_id": 7, "verdict": "dismiss", "reason": "looks fine",
                              "answers": [{"question": "Q one?", "answer": "because x"},
                                          {"question": "Q two?", "answer": "because y"}]}) + "\n")
    assert pending(mb, str(dp)) == []


def test_questions_for_collects_lens_asks_without_duplicates():
    sig = {"interrogation": {"lenses": [{"ask": ["a?", "b?"]}, {"ask": ["b?", "c?"]}]}}
    assert questions_for(sig) == ["a?", "b?", "c?"]
    assert questions_for({}) == []


def test_repeat_disposition_unions_answers_instead_of_overwriting(tmp_path):
    # Re-scanning one corpus into a new mailbox (or an id collision across capture DBs) used to
    # let the LAST disposition silently replace a more complete earlier one, so a fully answered
    # signal could flip back to un-answered. Answers must accumulate by question.
    mb = _asking_mailbox(tmp_path)
    dp = tmp_path / "d3.jsonl"
    dp.write_text(
        json.dumps({"request_id": 7, "verdict": "dismiss", "reason": "first pass",
                    "answers": [{"question": "Q one?", "answer": "a1"},
                                {"question": "Q two?", "answer": "a2"}]}) + "\n"
        + json.dumps({"request_id": 7, "verdict": "inspect", "reason": "second pass",
                      "answers": [{"question": "Q one?", "answer": "revised"}]}) + "\n")
    assert pending(mb, str(dp)) == []


def test_dispositions_union_across_several_ledgers(tmp_path):
    # The unit of work is the signal, not the file it was scanned into.
    mb = _asking_mailbox(tmp_path)
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    a.write_text(json.dumps({"request_id": 7, "verdict": "dismiss", "reason": "r",
                             "answers": [{"question": "Q one?", "answer": "a1"}]}) + "\n")
    b.write_text(json.dumps({"request_id": 7, "verdict": "dismiss", "reason": "r",
                             "answers": [{"question": "Q two?", "answer": "a2"}]}) + "\n")
    assert len(pending(mb, str(a))) == 1          # neither ledger alone is complete
    assert pending(mb, [str(a), str(b)]) == []    # together they are


def test_transient_temp_mailboxes_do_not_arm_the_gate(tmp_path, monkeypatch):
    # pytest tmp_path scans and scratch runs are throwaway; registering them buried the gate under
    # dozens of 1-6 signal artifacts, which trains the operator to ignore it.
    import rqswarm_eval.passive as P

    (tmp_path / ".swarmie").mkdir()
    monkeypatch.setattr(P, "__file__", str(tmp_path / "pkg" / "passive.py"))
    monkeypatch.setattr(P.tempfile, "gettempdir", lambda: str(tmp_path))

    P._register_mailbox(tmp_path / "scratch.jsonl")
    assert not (tmp_path / ".swarmie" / "mailboxes.json").exists()


# --- #5: the gate's own self-test (a fail-open gate can't otherwise be told from a quiet one) ---

def test_selftest_passes_on_healthy_machinery():
    import rqswarm_eval.gate as G
    ok, notes = G._selftest()
    assert ok is True
    assert all(n.startswith("ok:") for n in notes) and len(notes) == 5
    assert G._handle_selftest(None) == 0


def test_selftest_catches_the_silent_fail_open(monkeypatch):
    """The exact failure the selftest exists for: a gate that never reports anything pending
    (fail-open / broken channel) must be caught, not read as 'clear'."""
    import rqswarm_eval.gate as G
    monkeypatch.setattr(G, "pending", lambda *a, **k: [])   # gate silently blocks nothing
    ok, notes = G._selftest()
    assert ok is False
    assert any("FAIL" in n and "pending" in n for n in notes)
    assert G._handle_selftest(None) == 1


def test_selftest_catches_broken_question_extraction(monkeypatch):
    import rqswarm_eval.gate as G
    monkeypatch.setattr(G, "questions_for", lambda s: [])   # loses the signal's questions
    ok, _ = G._selftest()
    assert ok is False
