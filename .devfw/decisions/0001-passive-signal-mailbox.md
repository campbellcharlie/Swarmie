# ADR 0001: Passive signal mailbox

## Decision

Read the capture DB with SQLite `mode=ro`, maintain baselines in memory, and append redacted `SignalEnvelope` records to a JSONL sidecar. A project `postToolUse` hook drains a bounded batch into LLM context.

## Why

The capture database remains untouched, JSONL is auditable, and the delivery mechanism does not couple Swarmie to one LLM SDK.

## Consequences

Checkpoint and hook offsets are separate plain files. Advisory locks and bounded records are required. A socket transport can be added later without changing envelopes.
