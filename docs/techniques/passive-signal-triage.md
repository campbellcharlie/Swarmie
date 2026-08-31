# Passive signal triage

**Goal.** Turn a pile of already-captured HTTP request/response pairs into a small set of
evidence-backed hypotheses worth a human's attention — without generating any traffic and
without leaking secrets.

## Why passive-first

Active scanners are loud, touch the target, and drown you in findings that are mostly
"the scanner poked something." Reading traffic that a normal browsing session already
produced is quiet, reversible, and grounded in what the application actually does. The
analyzer's job is not to decide a vuln exists — it is to notice deviations and useful
structure and hand them up as questions.

## Pipeline shape

```
instrumented browser  ->  recording proxy  ->  read-only capture store (SQLite)
                                                     |
                                     analyzer reads completed pairs (mode=ro)
                                                     |
       cheap metadata + header baselines over EVERY pair (no body fetch)
                                                     |
             a bounded, ranked subset gets its bodies hydrated + analyzed
                                                     |
                    redacted hypotheses -> bounded mailbox (JSONL)
                                                     |
                       an LLM reasons, pivots, dismisses, or asks for more
```

The browser/proxy/store are interchangeable; the analyzer only needs a table of completed
pairs it can open read-only.

## How it works

1. **Baseline everything cheaply.** For each `(host, method, path_shape)` keep a running
   baseline: status mix, content types, response-length distribution, request-size
   distribution, auth-state window. This is metadata-only — no body reads — so it scales to
   every pair. Deviations (new status, length outlier, auth flip, cache-policy
   contradiction on an authed response) become *reasons*.

2. **Hydrate a bounded subset.** Fetching bodies is expensive and noisy, so gate it: a pair
   is body-hydrated only if it already has reasons, hits an interesting/exposure path, or is
   sampled for coverage. Diversity caps stop one chatty host from eating the budget. (See
   [bundle history](bundle-history-reconstruction.md) for why JS bundles need a *wider*
   per-host budget than ordinary endpoints.)

3. **Analyze request + response together.** Never judge a response without its request —
   headers, body, and params together decide whether a deviation is interesting.

4. **Emit a hypothesis, not a verdict.** Each emitted record carries: the structural
   envelope (method, host, redacted `path_shape`), the reasons that fired, a vuln-class
   hypothesis, and interrogation questions that force the reader to reason about *this*
   signal. It is explicitly a hypothesis.

## Redaction discipline (the load-bearing rule)

Everything that leaves the analyzer is structural:

- **Paths** become `path_shape` — query stripped, and id-like / secret-shaped segments
  collapsed to a placeholder (`/orders/{id}`, not `/orders/8fkS...`).
- **Values** become a category + a short hash, never the value.
- **Secrets** (API keys, JWTs, high-entropy tokens) are detected to *classify* the signal,
  then dropped — the token itself is never emitted, in any field, including structural ones
  like endpoint lists or host lists.

If a value could identify a user, a session, or a secret, it does not appear downstream.
This is what makes it safe to feed the output to an LLM or paste into a report.

## Ranking

Reasons carry weights; the ranked queue floats the strongest deviations up. Be aware that
generic-but-common reasons (e.g. cache noise) can out-rank rarer, higher-value structural
findings — a deterministic first-party/scope filter on the surface is often the missing
discriminator, not more ranking.

## Caveats

- Sampling luck matters: if bodies aren't hydrated, symbolic detectors can't fire. Tune the
  hydration budget to the site's shape (one-CDN sites need special handling).
- Baselines need warm-up; very-low-observation endpoints produce weaker signals.
- The analyzer sees only what was captured. Coverage of the app during capture bounds
  everything downstream.
