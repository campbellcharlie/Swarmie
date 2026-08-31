# Deprecated-but-live endpoint discovery

**Goal.** Find endpoints the current front-end no longer references but the backend still
serves. Orphaned routes are prime targets: they often keep an older stack's weaker auth and
validation while nobody watches them.

## Why they exist

Redesigns and migrations drop features, swap partners, and rewrite the API client. The
*front-end* stops calling an endpoint the moment the new bundle ships. The *backend* route
usually stays up far longer — deprecating a live service is a separate, slower decision, and
sometimes never happens. That gap is the opportunity.

## Method

1. **Get two surfaces to compare.**
   - *Old surface:* dissect the historical bundles (see
     [bundle history reconstruction](bundle-history-reconstruction.md)) — the endpoints the
     app declared some months/years ago.
   - *Current surface:* dissect today's bundles from a fresh capture.
2. **Compute the set difference, globally.** `old_endpoints − current_endpoints` = present
   then, absent from the current front-end now. Do it across the *union* of all chunks, not
   per-chunk, so an endpoint that merely moved between bundles isn't a false "removed."
3. **Filter to real routes.** Drop JSON-schema tokens, license URLs, asset paths, and
   template-builder noise. Keep API-shaped paths and third-party integration URLs.
4. **Categorize the result.**
   - *Deprecated first-party API paths* — the high-value set; candidates for liveness probing.
   - *Dropped third-party integrations* — analytics/ad/embed partners the redesign cut
     (useful context, lower direct value).

## The critical caveat

"Absent from current JS" means **no longer *referenced***, not **decommissioned**. This is
the same property as the bundles themselves (unreferenced but still served). So the output
is a set of *candidate* orphaned endpoints — you must **probe** to know which still answer.

## Liveness probing (active — authorization required)

This step *sends requests to the target*, so it is separate from the passive pipeline and
run only under authorization.

1. **Recover the real base host and call shape from the old source**, don't guess. The
   URL-construction code near the endpoint literal tells you the base host and required
   path segments / params (region, query, count, …). Guessing risks fabricating a URL.
2. **Probe for a status, not an exploit.** A `200` with a real body = live and functional.
   A `4xx/5xx` from the application tier (not a CDN error page, not `404`/DNS failure) still
   means the **route exists** — it's live, your request was just malformed or unauthorized.
3. **Interpret the result honestly.** "Still 200" is a liveness fact, not a vulnerability. It
   becomes interesting when a deprecated route answers with weaker checks than the current
   stack — that is the thing to investigate next, deliberately.

If the target rate-limits or blocks a plain client, see
[authenticated session probing](authenticated-session-probing.md) — the fix is usually a
real session, not a spoofed header.
