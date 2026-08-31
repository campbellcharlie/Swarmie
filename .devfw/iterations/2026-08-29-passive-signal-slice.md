---
artifact: iteration
version: 1
status: completed
last_updated: 2026-08-29
---

# Passive signal slice

## Outcome

Added a read-only completed-pair tailer, bounded hydration/ranking, redacted `swarmie.signal.v1` mailbox, and a bounded Codex hook adapter. Swarmie emits hypotheses and counterevidence; the LLM remains the decision-maker.

## Model-free evidence

- `pytest -q`: 145 passed in 14.22 seconds.
- `pytest -q tests/test_passive.py`: 7 passed.
- 10,128-pair reference scan: 6.041 seconds; 1,236 eligible; 256 hydrated/emitted; 980 sampled out.
- Source DB stat before/after: `35232026624 1787959295` both times.
- `python3 -m py_compile` and `git diff --check` passed.

## Remaining boundary

The `.cursor` hook is a verified script adapter, not proof that the production Claude driver receives live signals. That integration remains the next delivery slice.
