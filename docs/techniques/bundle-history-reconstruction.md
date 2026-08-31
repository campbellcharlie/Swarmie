# JS-bundle change-history reconstruction

**Goal.** Recover how a site's JavaScript — and therefore its declared API/endpoint surface
— changed over months or years, even though the bundles are content-hashed and immutable.

## The problem

Modern builds ship **content-hashed immutable** bundles: `Header.<hash>.js`,
`/assets/immutable/chunk.<hash>.js`. That hash *is* the version. When the code changes, the
filename changes. So a single bundle URL has no history to diff — it is one frozen content
forever, and web archives usually never crawled those deep, dynamically-imported hashed
URLs at all.

## The two facts that make history recoverable

1. **Web archives densely capture the HTML pages** (not the hashed bundles). Each snapshot's
   HTML lists the bundle URLs that were live on that date.
2. **CDNs retain old immutable artifacts.** Old deploys' cached pages must keep working, so
   an old hash typically still serves (HTTP 200) from the live host — present, just
   unreferenced. *(Verified empirically in one study: a set of 15-month-old hashed bundles
   were all still live; retention is real but not guaranteed indefinitely — always test.)*

## Method

```
web-archive CDX  ->  monthly HTML snapshots of a stable page
                        |
        parse each snapshot's HTML -> hashed bundle URLs live on that date
                        |
        group URLs by logical module id (filename minus the content hash)
                        |
        fetch each distinct version LIVE from the CDN (content-addressed cache)
                        |
        diff consecutive versions per module  ->  real code change history
```

1. **Enumerate snapshots.** Query the archive's CDX index for the stable HTML page over the
   window, one per month, 200s only.
2. **Extract bundle URLs** from each archived HTML (`<script src>` and friends), stripping
   the archive's rewrite prefix.
3. **Group by logical id.** `name-<moduleid>.<contenthash>.js` → keep `name-<moduleid>`, drop
   the content hash. Same logical id at a different content hash = a change to that module.
4. **Fetch versions live.** Pull each distinct historical hash from the live CDN with a
   browser-like client (see [authenticated session probing](authenticated-session-probing.md)
   for why a plain client may be edge-blocked). Cache by URL hash.
5. **Diff.** Token-normalize minified JS (break on `,` `;` `{`) so a diff sees structural
   changes, then diff consecutive versions per module.
6. **Optionally re-dissect per date.** Run [JS dissection](js-dissection-hidden-endpoints.md)
   on every version to produce a *structured endpoint/GraphQL-op surface timeline* — "this
   endpoint first appears on date X" — rather than raw token diffs.

Reference implementation: `tools/js_history.py` in this repo (standalone, stdlib-only, sends
outbound HTTP so it lives outside the passive engine).

## Caveats & artifacts

- **Stack migrations flap.** If a site is mid-migration between two front-end stacks,
  snapshots alternate between them; a snapshot that caught the *other* stack looks like
  "everything removed then re-added." Skip snapshots whose (filtered) bundle set is empty so
  they don't register as phantom churn.
- **SPA-injected chunks aren't in the static HTML.** If bundles load via `import()` rather
  than `<script src>`, the archived HTML won't list them — for that stack, your own current
  capture is `t0` and you diff forward.
- **Retention isn't forever.** Old hashes age out eventually; measure, don't assume.
- **Template builders are noisy.** Dissected "endpoints" include client route-builders
  (`/item/${id}`); treat them as leads, not literal paths.
