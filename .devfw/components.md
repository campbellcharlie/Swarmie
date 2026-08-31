---
artifact: components
version: 1
status: approved
owners: []
last_updated: 2026-08-29
---

# Components

## Inventory

Read-only source, endpoint baseline engine, signal envelope, JSONL mailbox, checkpoint, passive CLI, and post-tool hook.

## State Matrix

Tailer states are backlog, caught-up, locked/retry, and stopped. Signal states are new, rolled-up duplicate, delivered, and pending.

## Accessibility Contract

Every signal includes a descriptive hypothesis and evidence fields rather than icons alone.

## Responsive Behavior

Batch size, hydration budget, body cap, poll interval, and hook delivery count are configurable.

## Instrumentation Hooks

CLI counters expose throughput and disposition; the Codex `postToolUse` hook injects pending signal context.

## Open Questions

Driver-native event delivery can be added behind the same envelope schema.
