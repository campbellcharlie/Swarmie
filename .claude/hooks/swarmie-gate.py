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


def _run_gate(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(REPO / "rqswarm_eval" / "gate.py"), *args],
                          capture_output=True, text=True)


def main() -> int:
    # `--selftest`: verify the gate machinery itself (a fail-open gate can't otherwise be told
    # apart from a quiet one). Runs before reading the Stop payload so it works when invoked by hand.
    if "--selftest" in sys.argv[1:]:
        proc = _run_gate("selftest")
        sys.stdout.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        return proc.returncode
    try:
        json.load(sys.stdin)  # consume the Stop-hook payload (unused)
    except Exception:
        pass
    if not ROOT.is_dir():
        return 0  # gate inactive — no live investigation

    blocked, broken = [], []
    for mailbox, disp in _targets():
        proc = _run_gate("check", "--mailbox", mailbox, "--dispositions", disp,
                         "--dispositions", str(LEDGER), "--limit", "15")
        if proc.returncode == 2:
            blocked.append((mailbox, disp, proc.stdout))
        elif proc.returncode != 0:
            # A crashed gate returns neither 0 (clear) nor 2 (blocked). Fail-open would read that
            # as clear and silently un-gate the turn — a broken channel is not a quiet one. Surface it.
            broken.append((mailbox, (proc.stderr or proc.stdout or "gate exited nonzero").strip()[:400]))

    if not blocked and not broken:
        return 0
    parts = []
    if blocked:
        parts.append(f"{len(blocked)} mailbox(es) have UN-ANSWERED signals — you do not have the "
                     "right to ignore them; disposition every one via `python3 -m rqswarm_eval.gate "
                     "record --dispositions <path> --request-id <id> --verdict "
                     "inspect|acted|pivot|dismiss|defer --reason '<why>'`")
    if broken:
        parts.append(f"{len(broken)} mailbox(es) FAILED the gate self-check — the gate could not "
                     "verify them, which is NOT the same as clear; fix it (`python3 "
                     f"{Path(__file__).resolve()} --selftest`) before ending")
    detail = "\n".join(f"--- BLOCKED mailbox: {m}\n    record with --dispositions {d}\n{body}"
                       for m, d, body in blocked)
    detail += "\n" + "\n".join(f"--- BROKEN mailbox: {m}\n    {err}" for m, err in broken)
    print(json.dumps({"decision": "block",
                      "reason": "Swarmie response gate: " + "; ".join(parts) + ".\n" + detail}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
