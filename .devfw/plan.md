---
artifact: plan
version: 1
status: approved
owners: []
last_updated: 2026-08-29
---

# Plan

## Milestones

1. Define the signal-envelope and hunter-question contract. 2. Implement the adaptive read-only tailer and endpoint baselines. 3. Add the LLM delivery hook. 4. Validate against fixtures and the captured corpus.

## Vertical Slices

The first slice reads completed pairs, emits deterministic envelopes to JSONL, and lets a post-tool hook inject a bounded batch into LLM context.

## Acceptance Criteria

No capture mutation; all four request/response artifacts participate in hydrated analysis; exact duplicates roll up without deleting anomalous siblings; envelopes include hypotheses, counterevidence, dimensions, and hunter questions; tests and corpus benchmark pass.

## Dependencies

Python stdlib (`sqlite3`, `json`, `hashlib`, `statistics`) and the existing `sources`, `response`, and profile-adapter modules.

## Risks

Mixed passive/probe traffic can distort novelty, late message rows can be skipped by a naive cursor, and a hook can flood context. Provenance labels, overlap reads, and bounded delivery address these risks.

## Release Strategy

Ship as an opt-in `rqswarm_eval.passive` command and project hook. It is reversible by stopping the process or removing the hook entry.

## Open Questions

The production driver must choose its mailbox location and whether high-attention signals can interrupt between browser actions.
