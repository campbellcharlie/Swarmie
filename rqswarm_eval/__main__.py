"""`python -m rqswarm_eval` — pointer to the passive signal-engine tools.

Swarmie is a passive HTTP signal sluice; each tool is run directly. See README.md.
"""
from __future__ import annotations

_TOOLS = {
    "passive": "tail a capture DB, emit swarmie.signal.v1 hypotheses into a mailbox",
    "triage": "one-shot triage of a capture DB into candidate vuln vectors",
    "triage_all": "triage across multiple capture DBs",
    "gate": "response gate: check/record dispositions for emitted signals",
    "eval_corpus": "score a mailbox against a labelled corpus",
}


def main() -> int:
    print("Swarmie — passive HTTP signal engine. Run a tool directly:\n")
    for name, desc in _TOOLS.items():
        print(f"  python3 -m rqswarm_eval.{name} --help\n      {desc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
