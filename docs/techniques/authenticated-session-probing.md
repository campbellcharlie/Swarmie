# Getting past anti-automation: session, not User-Agent

**Goal.** When a plain HTTP client can't reach an endpoint that a browser reaches fine,
diagnose *which* wall you hit and use the cheapest thing that actually clears it — usually a
real authenticated session, not a spoofed header.

## Diagnose the wall by its status code

Different defenses fail differently. Read the response before reacting:

| Symptom | Likely wall | What actually clears it |
|---|---|---|
| `403` + block page, only for `curl/x.y` UA | **User-Agent sniff** at the edge | A browser-like `User-Agent` header |
| `403`/challenge HTML, JS/interstitial | **Bot challenge** (fingerprint/JS) | A real browser engine (not header spoofing) |
| `429 Too Many Requests`, same for browser-UA *and* default-UA | **Per-IP rate limit / anti-automation** | Slower rate, a valid session cookie, or a different path in |
| `401`/`{error: invalid cookie}` | **Missing session/consent context** | The real session's cookies + any required token/crumb |
| TLS handshake oddities, works in browser only | **TLS/JA-style fingerprinting** | A client with a real browser TLS fingerprint |

The trap: assuming "it blocks curl" means "it blocks the curl *User-Agent*." Confirm by
sending the **same request with a browser UA** *and* with the default UA. If both get the
same `429`, the User-Agent was never the gate — it's rate/session based, and swapping the UA
string wastes effort.

## The reliable unlock: reuse a real session

Most consumer sites gate sensitive endpoints on a valid consent/auth **session**, not on a
header. The robust approach is to make the request from inside a real, already-authenticated
browsing context:

```
authenticated browser (real engine, real TLS, holds the session cookies)
        -> through the recording proxy
        -> top-level navigation to the endpoint URL  (no CORS on a navigation)
        -> read the response body / status from the capture
```

Because it is the *same* engine, TLS fingerprint, and cookie jar the site already trusts,
consent/rate walls that reject a bare client let it straight through. Top-level navigation
(rather than `fetch`) sidesteps CORS, so a JSON endpoint renders its body directly.

## Practical notes

- **Cookies must be fresh and correctly scoped.** Some sessions are device/session-bound and
  won't transfer; re-import from a live logged-in browser rather than reusing stale exports.
- **A `curl` retry-with-backoff won't beat a persistent per-IP limit** — it just re-hits the
  same wall slower. Change the *path in* (session), not the patience.
- **This is active.** You are sending requests to the target. Do it only under authorization,
  and probe for liveness/status — not for exploitation — unless the engagement scope allows
  more.
- **Redaction still applies.** Session cookies and tokens used to get in never get written
  into notes, mailboxes, or reports.
