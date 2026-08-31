# JS dissection & hidden-endpoint cross-reference

**Goal.** Pull the machine-readable structure out of a site's JavaScript bundles —
endpoints, GraphQL operations, parameters, auth mechanisms, source-map references — and
flag the endpoints the front-end *declares* but that were **never seen in traffic**. Those
are undiscovered attack surface.

## Why it works

A single-page app ships its API client in JS. Every route it can call is a string (or a
string-builder) in a bundle, whether or not the user's session happened to exercise it.
Traffic capture shows you what *was* called; the bundle shows you what *can be* called. The
difference is the interesting part.

## Method

1. **Dissect each JS body** into structured fields:
   - `endpoints` — path/URL literals and obvious builders;
   - `graphql` — operation names / persisted-query ids;
   - `params` — query/body parameter names;
   - `auth` — bearer/oauth/cookie mechanism hints;
   - `sourcemap` — `//# sourceMappingURL=` references (see below);
   - `hosts` — hostnames referenced as literals.

2. **Cross-reference against observed traffic.** Canonicalize every declared endpoint to a
   path shape and subtract the set of path shapes actually observed. What remains is
   *declared-but-never-observed*: `js_hidden_endpoint`.

3. **Scope-filter the result.** Raw dissection is noisy — it will surface library/CDN paths
   and third-party trackers. Keep only first-party surface:
   - drop cross-domain absolute URLs (a bundle on `cdn.example.net` referencing
     `some-tracker.example.com` is not the target's surface);
   - drop library/asset paths (`/node_modules/`, license files, well-known CDN prefixes);
   - attribute relative paths to the bundle's own registrable domain;
   - optionally restrict to an explicit in-scope domain set.

## Two failure modes to design around

**Attribution error (relative paths).** A relative endpoint gets attributed to the *page /
bundle host*, but a shared bundle served on one property can target a *different* base host
at runtime (e.g. a shared nav component that calls a different back-end). Treat a relative
path found in a shared/vendor bundle as "some first-party surface," and confirm the real
base host from the surrounding URL-construction code before asserting which host owns it.
Watch for batch-envelope sub-requests too: a string like `{uri:"/x", method:"GET"}` inside
a batch POST body is a sub-request target, not a top-level fetch path.

**Secrets leaking through structural fields.** Redaction must cover *every* emitted string,
not just an obvious `secrets` list. A token embedded in a path (`/reset/<jwt>`) will leak
verbatim through the `endpoints`/`routes`/`hosts`/`sourcemap` fields unless you scrub
vendor-key / JWT / long-hex / high-entropy substrings from all of them. Redact the whole
output, then emit.

## Source maps

If bundles ship source maps (or leave `sourceMappingURL` pointing at a live `.map`), they
recover original module structure and paths for the **current** bundles — depth, not
history. Flag their presence (`js_sourcemap_disclosure`); fetch/parse them only as a
separate, authorized step.

## Output is a hypothesis

A hidden endpoint is a *lead*, not a finding. Many are template builders (`/quote/${sym}`),
dev-only branches, or feature-flagged. The value is a ranked list of "surface the UI knows
about but this session didn't touch," to be probed deliberately.
