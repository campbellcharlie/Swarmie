---
artifact: decision
version: 1
status: accepted
owners: []
last_updated: 2026-08-30
---

# ADR-0005 Directed vuln-class investigation graphs + machine-pre-answered facts

## Context

Today a signal carries flat question lists (`_PERSONA_QUESTIONS` -> `interrogation.lenses`).
The LLM re-derives the investigation process each time, and — worse — is asked things the
machine already knows ("is the id sequential?", "do other endpoints use this id?"). The design
goal (ML-first perception thread) is **use the LLM to answer questions, not analyse traffic**:
give each vuln class a small decision GRAPH, have the machine answer every node it can compute,
and spend LLM reasoning only on the genuinely-open nodes.

## Decision

`rqswarm_eval/perception/investigation.py` (stdlib): per-class investigation graphs for `bola`,
`broken_auth`, `injection`, `cache`. Each node is `{id, ask, kind: machine|llm, fact?, answers?,
next, terminal?}`:
  * `machine` nodes name a `fact` key resolved from a ctx the engine computes (selector
    location, id predictability, **sibling endpoints from the ADR-0004 value-graph**, identity
    source, input surface, cache headers, token type);
  * `llm` nodes carry allowed `answers` and `next` node ids — the branch the LLM chooses.

`build_investigation(vuln_class, ctx)` returns a signal cleanly split into **facts**
(machine-answered), one **hypothesis**, and open **questions** (llm nodes) plus a terminal
`next_experiment` — the three are never collapsed, which is what keeps the reasoning honest.

Wired into `build_signal`: a signal's reasons classify to a vuln class (`classify`); if a graph
exists, the engine assembles ctx from what it already knows and attaches `envelope["investigation"]`.
The flat `interrogation` stays for classes without a graph (back-compat). `gate.py` also requires
an answer to every `investigation.questions[*].ask`, so the graph's open nodes are enforced like
the persona questions.

"What else shares this assumption?" is concrete here: the `bola` graph's `siblings` fact lists —
by `path_shape` only — every other endpoint the value-graph saw select the same object identifier.

## Consequences

- Additive: no existing envelope field changes; `investigation` appears only for classified signals.
- Redaction unchanged: ctx carries only structural facts (siblings as path_shape, id *type* not
  value); a test asserts no raw id reaches the investigation block.
- Follow-up: richer ctx for auth/injection/cache; answer-conditioned `next` traversal enforced by
  the gate (v1 lists next ids but does not yet branch on the answer).
