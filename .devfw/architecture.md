---
artifact: architecture
version: 1
status: approved
owners: []
last_updated: 2026-08-29
---

# Architecture

## System Context

A browser generates traffic, the capture proxy records it, Swarmie reads completed pairs, and the driving LLM receives hypotheses through a project hook.

## Technology Choices

Python 3.14 stdlib and SQLite URI `mode=ro`; JSONL is the mailbox format because it is inspectable, append-only, and independent of the capture database.

## Data Model

`SignalEnvelope` contains request ID, endpoint shape, redacted pair features, baseline deltas, hypotheses, counterevidence, attention dimensions, recurrence, and hunter questions.

## API and Integration Design

`python -m rqswarm_eval.passive` tails or backfills a capture DB. `.cursor/hooks/swarmie-signals.py` drains a bounded mailbox batch and returns `additional_context`.

## Background Jobs and Workflows

The tailer drains backlog without sleeping, polls only when caught up, rereads a small overlap for late messages, and checkpoints outside the source database.

## Security Model

Source connections set `mode=ro` and `query_only`; emitted material contains names, hashes, categories, and bounded signatures but no credentials or raw bodies.

## Observability

The CLI reports scanned, hydrated, emitted, duplicate, cursor, and throughput counters. Every envelope points back to a capture request ID.

## Performance Budgets

Metadata processing target is at least 20,000 rows/second on the reference corpus. Body hydration is capped and reserved for candidate representatives.

## Data Lifecycle

The source remains untouched. Mailbox and checkpoint files are operator-owned sidecars that may be rotated; the hook keeps a separate byte offset.

## Dependencies and Risks

Late or incomplete pairs require overlap reads. File-mailbox concurrency requires advisory locking. Hook support varies by LLM driver.

## Open Questions

A Unix socket may replace JSONL once the capture proxy exposes a stable event interface.
