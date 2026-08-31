---
artifact: decision
version: 1
status: accepted
owners: []
last_updated: 2026-08-30
---

# ADR-0004 Object-identifier co-occurrence graph (BOLA siblings / provenance)

## Context

The Akto teardown (2026-08-30) showed their whole "context analyzer" is value co-occurrence:
store every response value in a Bloom filter, and when a value recurs in a later request,
link the two endpoints. That data-flow graph is what powers their BOLA/business-logic tests —
and it is exactly the "app world model" box in ADR-0003's roadmap (increment 2). Swarmie
already had lighter relational graphs (referer edges, hashed credential reuse); this adds the
missing piece a BOLA/IDOR hypothesis needs: **which other endpoints select the same object,
and did this identifier originate in another endpoint's response.**

Boundary: Swarmie never puts raw values or raw paths in the mailbox (CLAUDE.md #6). Akto stores
raw values; we cannot. So we store only a **non-reversible hash** of each id-like value and the
**structural** `(host, method, path_shape)` endpoint key — the same discipline as the existing
`seen_credentials` reuse detector.

## Decision

`rqswarm_eval/perception/valuegraph.py` (stdlib core): extract id-like values (numeric ≥4,
uuid, long hex, opaque token) from request URLs (path + query) and hydrated JSON response
bodies; index `value_hash -> {(endpoint, location)}`, bounded with oldest-first eviction. Query
it for **siblings** (other endpoints sharing an id) and **origins** (endpoints where the id was
seen in a RESPONSE — data flowed into this request).

Wired into `SignalEngine.build_signal`: for each signal, relate the request's ids against prior
observations, then record this pair's request + response ids. On a hit:
  * add a redacted reason — `idor_id_from_response` (provenance, stronger) or
    `idor_shared_object_id` (co-occurrence). Both contain `idor`, so `_build_interrogation`
    routes them to the trust-chain (BOLA) lens automatically, and `_REASON_WEIGHT` gives them
    attention weight (12 / 8);
  * add a `broken-object-level-authorization` hypothesis naming the sibling/origin endpoints by
    **path_shape only**;
  * accumulate a hashed edge that the tailer drains into the operator investigation graph as
    `object:<hash>` nodes with `references` and `data_flow` edges (never the mailbox).

## Consequences

- **Redaction is a tested invariant:** `tests/test_valuegraph.py` asserts a distinctive raw
  query id never appears anywhere in either emitted envelope.
- Scope of this increment: co-occurrence is computed in `build_signal` (interesting pairs), not
  the high-volume metadata path — a deliberate perf/surface trade-off. Broadening the index to
  all metadata rows (URL/query ids for every pair) is a future enhancement.
- Only hashes + structural keys are stored, in memory and in the persisted graph; nothing raw
  is retained.

- **Leak-hunt fix (this increment):** an adversarial verify pass found that `path_shape`
  (`sources._ID_SEG`) collapsed hex path segments only at length >=16, so 12-15 char hex object
  ids survived RAW inside `envelope.endpoint.path_shape` (and now the graph endpoint nodes). The
  floor was lowered 16 -> 12, which is safe (a 12+ all-hex segment is never a real route word)
  and also de-fragments hex-id endpoints for co-occurrence.
- **Known residual (pre-existing, product-wide — NOT introduced here):** opaque *non-hex* path
  segments (base64url slugs / share tokens / secret-shaped values like `cs_live_...`, `AKIA...`)
  are still not collapsed by `path_shape`, so they appear raw in `endpoint.path_shape` for EVERY
  signal, independent of this feature. The obvious "collapse `[A-Za-z0-9_-]{12,}`" fix is WRONG —
  it eats route names ("documentation"). Correct fixes are cardinality-based collapse (Akto's
  ">=N distinct values at a position" rule) or an unambiguous secret-PREFIX redactor for
  path_shape; tracked as a follow-up, not this increment's scope.
