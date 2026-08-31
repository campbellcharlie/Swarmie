---
artifact: ux
version: 1
status: approved
owners: []
last_updated: 2026-08-29
---

# UX

## Personas and Jobs

The LLM needs compact evidence and questions; the operator needs read-only guarantees, progress counters, and reproducible request IDs.

## Journey Overview

Start tailer, browse through the capture proxy, receive a bounded signal block after tool activity, inspect the cited pair, then choose whether to act.

## Primary Flows

Live tail from the current high-water mark; bounded historical backfill; hook delivery; manual inspection by request ID.

## Information Architecture

Signals are grouped by endpoint and hypothesis family while preserving the anomalous representative and recurrence count.

## Empty Loading and Error States

An empty mailbox produces no injected context. Locked or incomplete capture rows are retried. Malformed sidecar lines are skipped and counted.

## Content Strategy

Use neutral language: observation, hypothesis, counterevidence, and questions. Never call a signal a confirmed finding.

## Accessibility Notes

CLI and hook output are plain text/JSON with explicit labels and no color-only meaning.

## Open Questions

The preferred maximum number of signals per LLM turn remains configurable.
