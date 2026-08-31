---
artifact: decision
version: 1
status: accepted
owners: []
last_updated: 2026-08-30
---

# ADR-0006 JS-bundle dissection (endpoints, secrets, sourcemaps, hidden surface)

## Context

Measured on the live multi-site browse: **996 JS responses captured, only 6 dissected** — JS
scores attention ~0 (treated as a static asset) and is sampled out. That throws away the
single richest recon source: SPA bundles enumerate dozens of API routes, hidden params,
hardcoded keys, and sourcemaps, most never exercised by a normal browse. Today Swarmie only
scans JS for ~6 vendor secret prefixes + `sourceMappingURL` + host-indexing.

## Decision

Add `rqswarm_eval/perception/jsdissect.py` (stdlib, pure, deterministic): `dissect_js(text,
base_url) -> {endpoints, params, graphql, secrets, sourcemap, hosts, routes}`. It runs on
**every hydrated JS bundle regardless of attention**, and a signal is emitted **only when
intel is found** (so 996 boring bundles don't flood the mailbox).

Redaction (boundary #6): a `secret` is reported as `{type, hash(12-hex), context}` — the KEY
name and a non-reversible hash, **never the raw value**. Endpoints/params/routes/hosts/
sourcemap are structural strings and are emitted as-is.

The crown-jewel output is the **hidden-surface cross-reference**: endpoints declared in JS but
**never observed in traffic** = undiscovered attack surface. The engine accumulates JS-declared
endpoints and diffs them against observed endpoint keys, feeding both into the value/
investigation graph as new nodes to probe.

## Consequences

- New `js_intel` reasons: `js_secret_literal` (typed+hashed), `js_endpoints_declared`,
  `js_hidden_endpoint`, `js_sourcemap_disclosure`, `js_graphql_ops`.
- JS pairs are hydrated + dissected even at attention 0; signal only if intel found.
- Redaction is a tested invariant (a planted raw secret must not appear in the js_intel block).
- Follow-up: fetch+unminify sourcemaps; generic high-entropy hunting tuning.
