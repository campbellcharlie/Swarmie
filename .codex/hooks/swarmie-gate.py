#!/usr/bin/env python3
"""Stop hook — refuse to end the turn while any Swarmie signal is un-answered.

Covers EVERY mailbox any scan in this checkout has written (`.swarmie/mailboxes.json`, which
`rqswarm_eval.passive` self-registers on emit), plus a hand-configured one in `.swarmie/gate.json`
if present. The single-configured-path version was bypassable by accident: a fresh scan into a new
mailbox was invisible to the gate, so it read "clear" while hundreds of signals sat un-answered.
The operator does not get to choose which signals count.

Dormant only when `.swarmie/` itself is absent (no live investigation in this checkout).
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / ".swarmie"


LEDGER = ROOT / "dispositions.jsonl"


def _targets() -> list[tuple[str, str]]:
    """(mailbox, dispositions) for every mailbox this checkout knows about.

    Dispositions are looked up in a shared ledger as well as the mailbox's own paired file: the
    unit of work is a SIGNAL, not a file, so answering a signal once also covers a re-scan of the
    same corpus into a different mailbox. gate.check unions every --dispositions passed to it.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(mailbox: str, disp: str = "") -> None:
        if not mailbox or mailbox in seen or not Path(mailbox).exists():
            return
        seen.add(mailbox)
        out.append((mailbox, disp or mailbox + ".dispositions.jsonl"))

    cfg = ROOT / "gate.json"
    if cfg.exists():
        try:
            c = json.loads(cfg.read_text())
            add(c.get("mailbox", ""), c.get("dispositions") or "")
        except (OSError, ValueError):
            pass
    reg = ROOT / "mailboxes.json"
    if reg.exists():
        try:
            for m in json.loads(reg.read_text()):
                add(m)
        except (OSError, ValueError):
            pass
    return out


def main() -> int:
    try:
        json.load(sys.stdin)  # consume the Stop-hook payload (unused)
    except Exception:
        pass
    if not ROOT.is_dir():
        return 0  # gate inactive — no live investigation

    blocked = []
    for mailbox, disp in _targets():
        proc = subprocess.run(
            [sys.executable, str(REPO / "rqswarm_eval" / "gate.py"),
             "check", "--mailbox", mailbox, "--dispositions", disp,
             "--dispositions", str(LEDGER), "--limit", "15"],
            capture_output=True, text=True)
        if proc.returncode == 2:
            blocked.append((mailbox, disp, proc.stdout))

    if not blocked:
        return 0
    detail = "\n".join(
        f"--- mailbox: {m}\n    record with --dispositions {d}\n{body}" for m, d, body in blocked)
    print(json.dumps({
        "decision": "block",
        "reason": ("Swarmie response gate: signals are UN-ANSWERED across "
                   f"{len(blocked)} mailbox(es). You do not have the right to ignore them. "
                   "Disposition every one via `python3 -m rqswarm_eval.gate record "
                   "--dispositions <path> --request-id <id> "
                   "--verdict inspect|acted|pivot|dismiss|defer --reason '<why>'` "
                   "before ending the turn.\n" + detail)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
