---
artifact: product
version: 1
status: approved
owners: []
last_updated: 2026-08-29
---

# Product

## Problem

An LLM driving a browsing session cannot inspect hundreds of thousands of HTTP exchanges recorded by the capture proxy. Swarmie must passively reduce that stream into evidence-backed hypotheses without deciding whether a vulnerability exists.

## Users

The primary user is the authorized security-testing LLM. Human operators need auditable request identifiers and control over source, scope, and delivery.

## Outcomes

Completed request/response pairs are baselined, unusual pairs become compact signal envelopes, and a project hook supplies those envelopes to the LLM for hunter-style evaluation.

## Constraints

The capture SQLite database is always read-only. The implementation is Python 3.14 stdlib-only, emits no network requests, redacts values, and preserves hypotheses rather than silently judging them false.

## Non-Goals

Swarmie does not exploit targets, confirm vulnerabilities, choose active probes, or write findings into capture databases.

## Success Metrics

Unit tests prove read-only access, paired evidence, baseline deltas, duplicate roll-up, and hook delivery. A corpus benchmark must process metadata at tens of thousands of rows per second.

## Open Questions

The capture driver may later consume a socket instead of the initial append-only mailbox; the envelope contract should remain stable.
