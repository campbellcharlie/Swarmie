# Investigation Techniques

Method notes for the passive/observational recon workflows built around Swarmie.
Each doc describes **how a technique works and why**, so it can be reapplied to any
authorized target — not a record of any particular engagement.

## Host-disclosure policy (read before adding a doc)

These documents are **methodology only**. They MUST NOT contain:

- any real target host, domain, subdomain, or IP address;
- any endpoint path, parameter name, cookie name, or bundle filename that uniquely
  identifies a real target;
- screenshots, response bodies, or captures tied to a real host.

Use synthetic placeholders everywhere: `example.com`, `cdn.example.net`,
`api.example.org`, `<target>`, `<cdn-host>`, `<api-host>`, `/v1/<service>/<resource>`.
When adding or editing a doc, re-read the diff and scrub anything that would let a
reader recover which host was studied. The techniques are the deliverable; the targets
are not.

## Index

| Doc | Technique |
|-----|-----------|
| [passive-signal-triage.md](techniques/passive-signal-triage.md) | Read captured traffic read-only, baseline it, emit redacted hypotheses; the LLM judges |
| [js-dissection-hidden-endpoints.md](techniques/js-dissection-hidden-endpoints.md) | Dissect JS bundles for endpoints/ops/secrets; flag declared-but-never-observed surface |
| [bundle-history-reconstruction.md](techniques/bundle-history-reconstruction.md) | Reconstruct a year of JS change history via web-archive HTML + live-CDN retention |
| [deprecated-endpoint-liveness.md](techniques/deprecated-endpoint-liveness.md) | Diff old vs current JS surface, then probe the "gone from UI" endpoints for liveness |
| [authenticated-session-probing.md](techniques/authenticated-session-probing.md) | Get past anti-automation with a real session instead of guessing at a User-Agent |

## Non-negotiable safety rails (apply to every technique here)

1. **Passive path never sends HTTP.** Traffic analysis reads a completed capture; it
   does not generate requests. Active probing (liveness, session probing) is a separate,
   clearly-labeled step, run only with authorization for the target.
2. **Open capture stores read-only** (`mode=ro`, `PRAGMA query_only=ON`). Never write
   analysis state back into the capture DB.
3. **No raw secrets leave the analyzer.** Only structural categories, counts, hashes, and
   query-stripped path shapes enter any mailbox, report, or LLM context — never raw
   cookies, tokens, authorization values, query values, passwords, or body excerpts.
4. **A signal is a hypothesis, not a finding.** The analyzer surfaces evidence and
   questions; a human/LLM decides whether anything is real or worth acting on.
