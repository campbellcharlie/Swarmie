"""Swarmie response gate — no emitted signal may be ignored.

Every signal Swarmie writes to the mailbox must carry a disposition before a turn is allowed to
end: a verdict, a non-empty reason, AND an answer to every interrogation question that signal
asked. A verdict on its own is a yes/no that throws away the reasoning — the whole point of a
signal is the questions it raises, so answering them is the disposition. A Stop hook runs `check`;
if anything is un-answered it blocks and lists the exact questions still owed. `record` appends
a disposition with its answers.

Disposition verdicts: inspect (looked, pursuing) | acted (took a safe action) | pivot (spawned a
new thread) | dismiss (benign, with the reason) | defer (parked, with why). "dismiss" still
requires a reason — silently dropping a signal is exactly what this gate exists to prevent.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

VERDICTS = {"inspect", "acted", "pivot", "dismiss", "defer"}


def _signals(mailbox: str) -> dict[int, dict]:
    out: dict[int, dict] = {}
    p = Path(mailbox)
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        if line.strip():
            s = json.loads(line)
            out[int(s["request_id"])] = s
    return out


def questions_for(signal: dict) -> list[str]:
    """The signal's own interrogation questions — what it is asking the analyst to determine.

    A verdict alone is a yes/no that discards the reasoning; the point of a signal is the
    questions it raises, so a disposition is only complete when each one has been answered.
    """
    out: list[str] = []
    for lens in signal.get("interrogation", {}).get("lenses", []):
        for q in lens.get("ask", []):
            if q not in out:
                out.append(q)
    # ADR-0005: the investigation graph's open (llm) nodes are questions too.
    for q in signal.get("investigation", {}).get("questions", []):
        ask = q.get("ask") if isinstance(q, dict) else None
        if ask and ask not in out:
            out.append(ask)
    return out


def _dispositions(paths: str | list[str]) -> dict[int, dict]:
    """Union of one or more disposition ledgers. A signal answered anywhere counts as answered:
    the unit of work is the signal, not the file it happened to be scanned into."""
    done: dict[int, dict] = {}
    for path in ([paths] if isinstance(paths, str) else paths):
        p = Path(path)
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            if d.get("verdict") not in VERDICTS or not (d.get("reason") or "").strip():
                continue
            rid = int(d["request_id"])
            prev = done.get(rid)
            if prev is None:
                done[rid] = d
                continue
            # Same request id seen again — re-scans of one corpus, or (across capture DBs) a
            # genuine id collision. Overwriting silently dropped a more complete answer set, so
            # union the answers by question and keep the latest verdict/reason.
            merged = {a.get("question"): a for a in (prev.get("answers") or [])}
            merged.update({a.get("question"): a for a in (d.get("answers") or [])})
            done[rid] = {**d, "answers": list(merged.values())}
    return done


def _answered(signal: dict, disp: dict | None) -> bool:
    """Complete only when every question the signal asked carries a non-empty answer."""
    if disp is None:
        return False
    asked = questions_for(signal)
    if not asked:
        return True
    answers = disp.get("answers") or []
    by_question = {a.get("question"): str(a.get("answer", "")).strip() for a in answers}
    if all(q in by_question for q in asked):
        return all(by_question[q] for q in asked)
    # Older records predate question text being stored; fall back to positional coverage.
    return (len(answers) >= len(asked)
            and all(str(a.get("answer", "")).strip() for a in answers[:len(asked)]))


def pending(mailbox: str, dispositions: str | list[str]) -> list[dict]:
    sigs = _signals(mailbox)
    done = _dispositions(dispositions)
    return [s for rid, s in sigs.items() if not _answered(s, done.get(rid))]


def _handle_check(args) -> int:
    pend = pending(args.mailbox, args.dispositions)
    if not pend:
        print(json.dumps({"pending": 0, "status": "clear"}))
        return 0
    # Order by the corpus-rarity-adjusted score (rank-time #2): a reason that fires on half the
    # corpus stops dominating, so rarer/more-specific pending signals surface within --limit. Rarity
    # frequencies come from the whole mailbox, not just the pending subset. Dedup is deliberately
    # OFF here: the gate must keep every pending signal individually accountable, and collapsing
    # same-lead repeats would hide signals that still owe a disposition.
    from .rerank import rerank
    ranked = rerank(pend, reference=list(_signals(args.mailbox).values()), dedup=False)
    must = [{
        "request_id": s["request_id"], "attention": s["attention"]["score"],
        "endpoint": f'{s["endpoint"]["method"]} {s["endpoint"]["host"]}{s["endpoint"]["path_shape"]}',
        "reasons": s["observation"]["reasons"],
        "answer_each_question": questions_for(s),
    } for s in ranked[:args.limit]]
    print(json.dumps({"pending": len(pend), "status": "BLOCKED",
                      "must_answer_each": must}, indent=2))
    return 2


def _handle_record(args) -> int:
    if args.verdict not in VERDICTS:
        print(f"verdict must be one of {sorted(VERDICTS)}", file=sys.stderr)
        return 1
    if not args.reason.strip():
        print("reason is required — a signal cannot be dismissed silently", file=sys.stderr)
        return 1
    answers = []
    for pair in args.answer or []:
        q, sep, a = pair.partition("::")
        if not sep or not a.strip():
            print("--answer must be 'question::answer' with a non-empty answer", file=sys.stderr)
            return 1
        answers.append({"question": q.strip(), "answer": a.strip()})
    with open(args.dispositions, "a") as f:
        f.write(json.dumps({"request_id": int(args.request_id), "verdict": args.verdict,
                            "reason": args.reason, "answers": answers}) + "\n")
    print(json.dumps({"recorded": int(args.request_id), "verdict": args.verdict,
                      "answers": len(answers)}))
    return 0


def _selftest() -> tuple[bool, list[str]]:
    """Exercise the real check path end-to-end on a synthetic signal, so a silently-broken gate is
    distinguishable from a legitimately-quiet one. The gate fails OPEN (a crash reads as 'clear'),
    so 'no block' alone proves nothing; this proves the machinery — signal parsing, question
    extraction, disposition union, and the answered/pending logic — actually works right now."""
    import tempfile
    notes: list[str] = []
    ok = True

    def check(cond: bool, msg: str) -> None:
        nonlocal ok
        ok = ok and bool(cond)
        notes.append(("ok:   " if cond else "FAIL: ") + msg)

    signal = {
        "schema": "swarmie.signal.v1", "request_id": 1, "attention": {"score": 42},
        "endpoint": {"method": "POST", "host": "selftest.invalid", "path_shape": "/x"},
        "observation": {"reasons": ["selftest_probe"]},
        "interrogation": {"lenses": [{"persona": "selftest", "ask": ["Q1?", "Q2?"]}]},
    }
    check(questions_for(signal) == ["Q1?", "Q2?"], "questions_for extracts the signal's questions")
    with tempfile.TemporaryDirectory() as d:
        mbox, disp, empty = (str(Path(d) / n) for n in ("m.jsonl", "d.jsonl", "e.jsonl"))
        Path(mbox).write_text(json.dumps(signal) + "\n")
        Path(empty).write_text("")
        check(len(pending(mbox, disp)) == 1, "un-answered signal is pending (gate would BLOCK)")
        check(pending(empty, disp) == [], "empty mailbox reads clear (quiet, not broken)")
        Path(disp).write_text(json.dumps({
            "request_id": 1, "verdict": "dismiss", "reason": "selftest",
            "answers": [{"question": "Q1?", "answer": "a"}]}) + "\n")
        check(len(pending(mbox, disp)) == 1, "a partially-answered signal stays pending")
        Path(disp).write_text(json.dumps({
            "request_id": 1, "verdict": "dismiss", "reason": "selftest",
            "answers": [{"question": "Q1?", "answer": "a"}, {"question": "Q2?", "answer": "b"}]}) + "\n")
        check(pending(mbox, disp) == [], "a fully-answered signal clears")
    return ok, notes


def _handle_selftest(args) -> int:
    ok, notes = _selftest()
    print(json.dumps({"selftest": "ok" if ok else "BROKEN", "checks": notes}, indent=2))
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Swarmie signal response gate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--mailbox", required=True)
    c.add_argument("--dispositions", required=True, action="append",
                   help="disposition ledger (repeatable; unioned)")
    c.add_argument("--limit", type=int, default=25)
    c.set_defaults(fn=_handle_check)
    r = sub.add_parser("record")
    r.add_argument("--dispositions", required=True)
    r.add_argument("--request-id", required=True)
    r.add_argument("--verdict", required=True)
    r.add_argument("--reason", required=True)
    r.add_argument("--answer", action="append",
                   help="'question::answer' for one of the signal's questions (repeatable)")
    r.set_defaults(fn=_handle_record)
    s = sub.add_parser("selftest", help="verify the gate machinery end-to-end (0=ok, 1=broken)")
    s.set_defaults(fn=_handle_selftest)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
