"""Passive HTTP-capture tailer: completed HTTP pairs -> LLM hypothesis signals.

The capture database is opened read-only.  Swarmie ranks *attention*, never
vulnerability truth, and emits only redacted structure plus request identifiers.
"""
from __future__ import annotations

import argparse
import base64
import calendar as _calendar
import collections
import dataclasses
import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, parse_qs, unquote_plus

from .learned_lane import make_lane
from .perception.obs_features import FEATURE_NAMES, feature_list
from .perception.interest_lane import make_interest_lane
from .perception.fuse import fuse_interest, select_top_k
from .perception.valuegraph import ValueGraph, extract_request_ids, extract_body_ids, is_id_like
from .perception.investigation import classify, build_investigation
from .perception.jsdissect import dissect_js
from .sources import Seed, body_skeleton, parse_headers, path_shape
from .triage import build_card, _AD_NETWORK  # reuse the ad-network host denylist for noise dampening


HUNTER_QUESTIONS = [
    "What is this endpoint or component actually doing?",
    "Why does it exist, and who is intended to call it?",
    "What did the developers assume about identity, order, origin, validation, and data shape?",
    "Why is each interesting field encoded, transformed, reflected, cached, or forwarded this way?",
    "Where are the trust boundaries between browser, CDN, gateway, service, worker, and datastore?",
    "What changed across neighboring requests in auth, status, headers, body shape, length, or timing?",
    "Can identifiers, roles, tenants, filenames, URLs, redirects, or object types be substituted?",
    "Is validation inconsistent across methods, content types, encodings, duplicate keys, or protocols?",
    "What internal names, identifiers, schemas, paths, tokens, or workflow state does the response reveal?",
    "Can this primitive pivot into another endpoint, account, tenant, cache, parser, or internal service?",
    "Which controls are visible, and which underlying assumption could invalidate them?",
    "What is the smallest safe observation that separates the competing hypotheses?",
]

# Adversarial-persona interrogation, keyed by signal family. Each entry is a researcher lens
# and the sharp questions that lens asks. Swarmie attaches the ones matching a signal's reasons
# to PUSH the driving LLM toward the right line of questioning per signal — it never answers them.
# Lenses are vuln-class reasoning styles (parser gaps, trust chains, browser sinks); they are
# environment-agnostic and name no target.
_PERSONA_QUESTIONS: dict[str, tuple[str, list[str]]] = {
    "encrypted_outbound_blob": ("data-exfiltration", [
        "What is in this opaque body — a device/behavioral fingerprint, harvested storage, or exfiltrated data?",
        "Who is the recipient, is it first- or third-party, and did the user consent to what leaves?",
    ]),
    "opaque_outbound_body": ("data-exfiltration", [
        "This opaque body goes to a site the user navigated to — first-party telemetry, or a first-party "
        "endpoint relaying to a third party?",
        "Does the volume and entropy of what leaves match what this feature plausibly needs?",
    ]),
    "reflection": ("browser-parser", [
        "What is the reflection context — HTML body, attribute, JS string, URL, or CSS? Only an executing context is XSS.",
        "Does the same reflected value also reach a template engine (SSTI) or JSON that is later rendered as HTML?",
    ]),
    "xss": ("browser-parser", [
        "Which parser renders this — an executable context, or inert JSON/text?",
        "Is output encoding contextual and consistent, or does one path escape while another does not?",
    ]),
    "idor": ("trust-chain", [
        "Is the object id user-scoped or a global/content id? Substitute a neighbour id and diff the response.",
        "Is the response identity-gated, or does the same content return regardless of who asks?",
        "Is there an older API version of this route that lacks the authz control?",
    ]),
    "injection": ("parser-gap", [
        "Does user input reach a backend interpreter (SQL, template, command, deserializer)?",
        "Is validation consistent across content-types, methods, duplicate keys, and encodings?",
    ]),
    "graphql": ("scope-expander", [
        "Is introspection enabled, and do errors leak 'Did you mean' field suggestions?",
        "Is query depth/complexity bounded, or are batching/aliasing abuse paths open?",
    ]),
    "cors": ("trust-boundary", [
        "Does ACAO reflect an arbitrary Origin or is it a fixed allowlist? Is credentials=true paired with a reflected/wildcard origin?",
        "Could a permissive preflight be cached and reused against a stricter endpoint?",
    ]),
    "open_redirect": ("url-parser", [
        "Is the redirect target reflected from a request parameter, or a fixed server-side value?",
        "Can a URL pass the allowlist yet resolve to a different host (backslash, encoding, userinfo, IPv6)?",
    ]),
    "ssrf": ("url-parser", [
        "Does the fetch validator parse the URL the same way the HTTP client does? Where is the gap?",
        "Does any representation of an internal host (decimal/hex/octal/IPv6/short) slip past the filter?",
    ]),
    "http2_downgrade": ("spec-gap", [
        "How many parsers sit in the path, and do front-end and back-end disagree on framing?",
        "Does an h2 request that downgrades to invalid h1 change how the body is framed (smuggling)?",
    ]),
    "mixed_http_version": ("spec-gap", [
        "Which endpoints negotiate a different HTTP version, and does that expose a distinct backend/parser?",
    ]),
    "cache": ("cache-keying", [
        "What does the cache key include vs exclude? Can two 'different' requests map to one key (poisoning/deception)?",
    ]),
    "credential": ("secret-flow", [
        "Where does this secret/token flow — audience-locked, short-lived, same-origin, or replayable/cross-host?",
        "Does it end up logged (URL/query) or readable by JS (non-HttpOnly cookie)?",
    ]),
    "jwt": ("token-trust", [
        "What are the claims — an identity/role/scope claim, or an audience-locked ephemeral token?",
        "Is the same token reused across requests (replay), and are alg and signature enforced?",
    ]),
    "version_disclosure": ("dependency-latency", [
        "Is the disclosed version affected by a known CVE, and — dated against the disclosure — how long has "
        "the vulnerable version been carried (their patch latency)?",
        "Is this version pinned or frozen, implying the same neglect extends across the dependency tree?",
    ]),
    "agent_injection": ("prompt-injection", [
        "Does this response reach an LLM/agent sink, and would the flagged content read as instructions rather than data?",
        "Is an attacker planting agent-injection in content the target serves, or is the target's own benign text tripping the classifier?",
        "What would the embedded instruction achieve — exfiltrate the agent's context, redirect its next action, or poison downstream state?",
    ]),
    "api_description_exposure": ("scope-expander", [
        "What does this schema unlock — internal hostnames, framework+version (CVE lead), hidden params, other endpoints?",
        "Are non-production environments or older API versions named in it?",
    ]),
    "internal_header_disclosure": ("scope-expander", [
        "What internal identifier does this reveal (pod/host/instance/worker), and what topology does it imply?",
    ]),
    "sensitive_file_exposure": ("scope-expander", [
        "Does the exposed artifact reveal source, config, credentials, or history that unlocks further surface?",
    ]),
    "metrics_endpoint": ("observability-exposure", [
        "What do these metrics leak — internal hostnames, queue depths, user/tenant counts, build info?",
        "Is the endpoint authenticated, and does it confirm reachability of other internal services?",
    ]),
    "response_size_swing": ("injection", [
        "Why did the same endpoint return a far larger body — did input break out of a filter/WHERE and dump more rows?",
        "Compare the small and large responses: what extra records or fields appeared, and were they scope-bound?",
    ]),
    "null_byte_in_path": ("input-validation", [
        "What extension filter is the NUL byte bypassing, and what artifact does the truncated path actually serve?",
        "Does the server decode %00 once or twice, and can the same trick reach source, config, or backups?",
    ]),
    "insecure_cookie": ("session-security", [
        "Is this a session/auth cookie, and does the missing HttpOnly/Secure/SameSite make it stealable via XSS, sniffing, or CSRF?",
        "What does holding this cookie authorize, and is it scoped/rotated or long-lived?",
    ]),
    "weak_csp": ("xss-defense", [
        "Does unsafe-inline/eval or a wildcard source make the CSP non-protective against injected script?",
        "Is there a reflected/stored sink on this origin that the weak CSP would fail to contain?",
    ]),
    "suspicious_html_comment": ("developer-tells", [
        "What does the comment reveal — a credential, a hidden endpoint, an admin path, a disabled control, an assumption?",
        "Does the tell point at surface not linked from the app (debug routes, staging, TODO'd auth checks)?",
    ]),
    "untrusted_script": ("supply-chain", [
        "Who controls this third-party origin, and what would injected script there reach — tokens, DOM, forms on this page?",
        "Is the dependency pinned/SRI-protected anywhere, or is every page trusting it implicitly?",
    ]),
    "secret_in_response": ("secret-flow", [
        "Is the secret live/privileged, what does it authorize, and where else is it valid?",
    ]),
    "error_disclosure": ("error-as-docs", [
        "What framework, version, file paths, or query does the stack trace reveal, and does it hint at SSTI/SQLi?",
    ]),
    "client_trust_header": ("trust-boundary", [
        "Does the app honour this client-set header (X-Forwarded-*/X-Original-URL)? Does it change routing, authz, or cache?",
    ]),
    "state_chang": ("csrf-authz", [
        "Is this mutation protected by an unpredictable token AND same-origin checks, and does that token live somewhere leakable?",
    ]),
    "third_party_receives_auth": ("trust-chain", [
        "What identity or token crosses to the third party, and could it be leveraged in a different context?",
    ]),
}
# Falsification frame (assume-benign default): the discipline that keeps a signal a hypothesis.
_FALSIFY_FRAME = (
    "Default to the BENIGN explanation. For any vuln class you weigh, first name the innocent "
    "reading that must be eliminated (cache-hit vs auth-bypass, stale-object vs IDOR, "
    "gateway-strips-header vs service-trusts-it, reflection-in-JSON vs reflection-in-HTML), then "
    "state the single observation that would DISPROVE it. Never treat one un-falsified signal as a finding."
)
# Standing questions — asked on EVERY signal regardless of family. These are the recurring
# investigative frames that turn a signal into a story: unexpectedness, architecture & flow,
# provenance/authorship, developer tells, internal-identity leakage, black-box reconstruction,
# impact, and the whole-picture read. They complement the per-signal persona lenses above and
# push the driving LLM to always widen from "is this a vuln" to "what does this reveal, and so what".
_STANDING_QUESTIONS = [
    "What is unexpected here — where does this converge with, or diverge from, the rest of the traffic?",
    "What is this host actually serving, and what flows in and out? Trace it to its backend — what is "
    "adjacent, and what do the overlaps, edges, and seams between hosts reveal?",
    "Who built this? What frameworks, build tools, and OSS are bundled, and do comments, author fields, "
    "source maps, internal repo/host references, or naming conventions fingerprint the team, their stack, "
    "or the sources they lean on?",
    "What idiosyncratic names, parameters, structures, or repeated habits are a human tell — and where do "
    "those same patterns predict the next weakness?",
    "Does anything leak internal identity — developer emails, internal hostnames, repo paths, environment "
    "names, or employee-attributable code?",
    "What can an outsider reconstruct from this alone, or folded with its neighbours — and does that depth "
    "come from design, or from a leak that should be closed?",
    "If this is real, what does it let an outsider DO, what would the business lose, and what does it cost "
    "to close? (attacker-capability x consequence / fix-cost)",
    "Folded with everything else observed, what does this say about the team's technology choices, maturity, "
    "and the eras layered into their stack?",
]
# Questions the operator tends NOT to ask but should — the elite-researcher signature angles and
# the classic blind spots (business logic, auth mechanics, implied-but-unseen surface, second-order
# effects, resource limits, client-side trust, supply chain, parser/cache gaps, AI surfaces). Kept in
# every envelope so the interrogation never narrows to only the obvious. Generic; names no target.
_BLINDSPOT_QUESTIONS = [
    "What is the intended workflow, and what breaks if steps run out of order, are skipped, replayed, or "
    "run concurrently (race / TOCTOU)?",
    "What endpoints or features are IMPLIED but not yet observed — admin variants, older or unversioned "
    "APIs, mobile or internal-only routes, feature flags?",
    "How is a session established and torn down — token lifecycle, fixation, concurrent sessions, "
    "logout/rotation invalidation — and is any authorization decision made client-side?",
    "Beyond object IDs: are function-level and tenant/role boundaries enforced server-side, or only hidden "
    "in the UI (BOLA/BFLA)?",
    "Where does input get STORED and rendered LATER, possibly in a different context or by a different user "
    "(second-order injection, stored XSS)?",
    "What is unbounded — recursion depth, batch/array size, query complexity, upload size — and is anything "
    "actually rate-limited?",
    "What does the client trust that it should not — postMessage handlers, DOM sinks, client-side routing, "
    "or a token decoded in-browser to gate access?",
    "Which third-party scripts execute with full page privileges, and what happens to the app if one is "
    "compromised or swapped?",
    "Do any two systems in the path disagree about parsing, cache-keying, or URL interpretation — and can "
    "that gap be forced?",
    "If any surface is an AI / agent / tool-use endpoint: can instructions be injected, tools abused, or the "
    "model's output trusted as a security control?",
    "What here is valuable enough for an attacker to monetize, and what would the team NOT be logging — so an "
    "attack would be invisible?",
]
# Temporal / archaeological ladder — the dating, provenance-depth, patch-latency, archive-persistence, and
# external-correlation rungs. These push the LLM past "what is this" into "how old is it, is it reused,
# is it abandoned, how slow do they patch, is it permanently archived, and what does its timeline mean".
_TEMPORAL_QUESTIONS = [
    "How old is this artifact — date it from copyright years, framework/library versions, or deprecated "
    "patterns — and which era of the stack does it belong to?",
    "Is this ancient code reused inside newer construction (an old library or snippet bundled into a modern "
    "build)? Reused old material carries old bugs forward.",
    "Is this layer maintained or abandoned — a control present in form but dead in function, an endpoint no "
    "longer updated, a dependency frozen years ago?",
    "If a version is exposed here: is that version affected by a known CVE, and — dated against the "
    "disclosure — how long has the vulnerable version been carried (their patch latency)?",
    "If this is a leak or an internal name, assume it is preserved in a public archive (Wayback, source-code "
    "search) and cannot be un-published — does the real fix require rotation rather than removal?",
    "What does the artifact's build hash or chunk name imply about release cadence and when this feature "
    "shipped — does the timeline expose sprint rhythm or freeze windows?",
    "Pair any datable change with what was happening in the industry or the org at that time (framework "
    "waves, layoffs, acquisitions, the supply-chain-security climate) — does the correlation reveal an "
    "un-announced event or a lasting character trait?",
]


def _build_interrogation(reasons: list[str], host: str, seen_families: set) -> dict:
    """Signal-aware persona questions + falsify frame + graph-pivot + impact provocation.
    Pure prompt scaffolding derived from the profile persona methodology — asks, never answers."""
    lenses: dict[str, list[str]] = {}
    for r in reasons:
        for fam, (persona, qs) in _PERSONA_QUESTIONS.items():
            if r.startswith(fam) or fam in r:
                bucket = lenses.setdefault(persona, [])
                for q in qs:
                    if q not in bucket:
                        bucket.append(q)
    if not lenses:
        lenses["scope-expander"] = [
            "What hidden surface does this endpoint imply — older versions, admin variants, sibling routes?",
        ]
    families = sorted({fam for (k, fam) in seen_families if k and k[0] == host})[:6]
    neigh = f" Same-host endpoint families already seen: {families}." if families else ""
    return {
        "lenses": [{"persona": p, "ask": qs} for p, qs in lenses.items()],
        "standing": _STANDING_QUESTIONS,
        "blindspots": _BLINDSPOT_QUESTIONS,
        "temporal": _TEMPORAL_QUESTIONS,
        "falsify": _FALSIFY_FRAME,
        "pivot": ("Pull the graph neighbours of this host — endpoints sharing its backend, "
                  "response-shape fingerprint, or referer edges — and interrogate those next." + neigh),
        "impact": ("Assess reconstruction fan-out: what does this signal plus its neighbours let an "
                   "outsider rebuild, and what would that be worth? Depth is reach, not the single fact."),
    }


_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_STATIC_TYPES = ("image/", "font/", "audio/", "video/", "text/css")
# Types the learned (agent-injection) lane must NOT scan. The classifier answers "would an agent
# reading this be steered by it?", so it belongs on content an agent consumes as instructions -
# HTML, JSON, plain text. Minified JS bundles are code dense with imperative tokens, and on real
# browsing traffic they produced a 92% false-positive class (69/75 fires were JS). JS is still
# hydrated for the symbolic detectors (js_secret_literal, js_sourcemap_disclosure, script tracing).
_LANE_SKIP_TYPES = _STATIC_TYPES + (
    "text/javascript", "application/javascript", "application/x-javascript",
    "text/x-javascript", "application/ecmascript", "text/ecmascript",
)
_INTERESTING_PATH = re.compile(
    r"(?:^|/)(?:api|admin|auth|account|user|graphql|upload|download|export|import|"
    r"callback|webhook|debug|internal|private|config|swagger|openapi|metrics|token|"
    r"session|oauth|sso|billing|payment|invoice|report)(?:/|$)", re.I,
)
# Paths whose response is worth hydrating for body-signature scanning (exposed files,
# panels) even when metadata is unremarkable — mirrors how a scanner prioritizes targets.
_EXPOSURE_PATH = re.compile(
    r'(?i)(?:\.env\b|\.git/|\.svn/|\.ds_store|/actuator|heapdump|phpinfo|\.sql\b|\.bak\b'
    r'|\.backup\b|wp-config|id_rsa|/swagger|/openapi|/login\b|/admin\b|/dashboard\b'
    r'|/grafana|/kibana|/jenkins|/phpmyadmin|/prometheus|/console\b|/manage\b)')
# Octet 0-255 — without this, minified JS numeric literals like 10.386.748.748 false-match.
_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_INTERNAL = re.compile(
    r"\b(?:10\." + _OCT + r"\." + _OCT + r"\." + _OCT +
    r"|172\.(?:1[6-9]|2\d|3[01])\." + _OCT + r"\." + _OCT +
    r"|192\.168\." + _OCT + r"\." + _OCT +
    r"|[\w-]+\.(?:internal|corp|intranet|lan))\b", re.I,
)
_PROBE = re.compile(
    r"(?:\.\./|%2e%2e|\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|"
    r"<script\b|\$\{|\{\{[^}]+\}\})", re.I,
)
_TELEMETRY = re.compile(r"(?:^|/)(?:collect(?:or)?|log|logs|events?|stats|metrics|envelope|trace)(?:/|$)", re.I)
# Matches a contiguous base64 string of 500+ chars — opaque data blob in a request body.
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{500,}={0,2}")
# URL-safe base64 or high-density alphanum segment in path/query (80+ chars, no slashes).
_B64_IN_URL = re.compile(r"[A-Za-z0-9_\-]{80,}")
# 10+ consecutive percent-encoded octets — bulk URL-encoded payload.
_PCT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2}){10,}")
# Hostname quoted as a string literal in JS source — used to trace which script originates traffic.
_HOST_LITERAL = re.compile(r"""["']([a-z0-9][a-z0-9.\-]{2,}[a-z0-9]\.[a-z]{2,6})["']""", re.I)
_JS_TYPES = {"application/javascript", "text/javascript", "application/x-javascript"}
# JS bundles are the richest dissection surface (hidden endpoints, GraphQL ops, secrets), and a
# single shared CDN host serves hundreds of DISTINCT bundles. Each is its own path_shape, so
# baseline.count==1 forever and the per-(host,type) "sample once" cap collapses them to a single
# dissection. Give JS a per-host budget of this many DISTINCT bundles before the periodic cap.
_JS_PER_HOST_CAP = 24
# JS bundle intelligence. Every pattern is matched to CLASSIFY only — raw secret values,
# tokens, and query strings are never emitted (boundary #6); only categories, counts, and
# query-stripped path shapes (structural, like endpoint.path) reach the mailbox.
_JS_SECRET_PATTERNS = (
    ("aws_access_key", re.compile(r'\b(?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b')),
    ("slack_token", re.compile(r'\bxox[baprs]-[0-9A-Za-z-]{10,}')),
    ("github_token", re.compile(r'\bgh[pusor]_[A-Za-z0-9]{36}\b')),
    ("stripe_secret_key", re.compile(r'\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b')),
    ("private_key_block", re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY')),
    ("secret_assignment", re.compile(
        r'''(?i)(?:bearer|api[_-]?key|apikey|access[_-]?token|client[_-]?secret|'''
        r'''app[_-]?secret|auth[_-]?token|private[_-]?key)["']?\s*[:=]\s*["'][^"']{8,}["']''')),
)
# High-precision secret patterns scanned in ANY response body (Nuclei file/keys borrow).
# Excludes the fuzzy secret_assignment (kept JS-only) to avoid false positives on prose.
_BODY_SECRET_PATTERNS = tuple(p for p in _JS_SECRET_PATTERNS if p[0] != "secret_assignment")
# Publishable client keys — designed to live in client JS (referrer/API-restricted), not secrets.
# Detected so the judge can check restrictions, but weighted low; NOT counted as secret exposure.
_PUBLISHABLE_KEY_PATTERNS = (
    ("google_api_key", re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    ("google_oauth_client", re.compile(r'\b\d+-[a-z0-9]{32}\.apps\.googleusercontent\.com\b')),
)


def _shannon_entropy(data: bytes) -> float:
    """Bits/byte: ~8 for encrypted/compressed, ~4-5 for text/JSON, ~6 for base64. Empty -> 0."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
# Nuclei exposure/error/panel matchers — the body IS the artifact, or reveals internals.
_PRIVKEY_RE = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY')
_ENV_FILE_RE = re.compile(
    r'(?mi)^(?:APP_KEY|APP_ENV|APP_DEBUG|APP_URL|DB_PASSWORD|DB_HOST|DB_DATABASE'
    r'|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|SECRET_KEY|MAIL_PASSWORD)\s*=')
_ERROR_BODY_RE = re.compile(
    r'(?i)(you have an error in your SQL syntax|ORA-0[0-9]{4}|Warning: (?:pg|mysql|mysqli)_'
    r'|<b>Fatal error</b>|<b>Parse error</b>|failed to open stream:|Uncaught exception'
    r'|Whoops[,!] There was an error|URLconf defined|Django tried these URL patterns'
    r'|NotFoundError: Not Found|at Function\.handle|Traceback \(most recent call last\)'
    r'|Microsoft OLE DB Provider|System\.Data\.SqlClient\.)')
_PANEL_SIGS = (
    ("Jenkins", re.compile(r'Sign in \[Jenkins\]|Dashboard \[Jenkins\]')),
    ("Grafana", re.compile(r'<title>Grafana</title>')),
    ("Kibana", re.compile(r'<title>(?:Kibana|Elastic)</title>')),
    ("phpMyAdmin", re.compile(r'name="pma_username"|/pmahomme/|alt="phpMyAdmin')),
    ("Prometheus", re.compile(r'<title>Prometheus Time Series')),
    ("Kubernetes Dashboard", re.compile(r'Kubernetes Dashboard</title>')),
    ("Spring Boot Actuator", re.compile(r'"_links":.*?"health"', re.S)),
    ("GraphQL Playground", re.compile(r'<title>GraphQL playground</title>')),
    ("Swagger UI", re.compile(r'<title>Swagger UI</title>|id="swagger-ui')),
)
_JS_ENDPOINT_RE = re.compile(
    r'''["'](/(?:api|v\d+|graphql|internal|admin|oauth|auth|account|user|gateway|rpc)'''
    r'''/[A-Za-z0-9/_\-.{}]{2,60})["']''')
_JS_SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=(\S+)')
_JS_AUTH_PATTERNS = (
    ("token_in_web_storage", re.compile(
        r'''(?i)(?:local|session)Storage\.setItem\(\s*["'][^"']*(?:token|auth|jwt|session|bearer)''')),
    ("oauth_client_id", re.compile(r'''(?i)client_id["']?\s*[:=]\s*["'][0-9A-Za-z._\-]{8,}''')),
    ("csrf_crumb_logic", re.compile(
        r'''(?i)(?:get_?crumb\s*\(|crumb["']?\s*[:=]|csrf[_-]?token["']?\s*[:=]|xsrf[_-]?token["']?\s*[:=])''')),
)
# JWT: three URL-safe base64 segments separated by dots (no raw values go to the mailbox).
_JWT_RE = re.compile(r'\b([A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b')
# PII patterns for response body scanning (deliberately conservative to reduce FP).
_EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
_SSN_RE = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
_CARD_RE = re.compile(r'\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6011\d{12})\b')
# Parameter names that suggest a server-side fetch surface (H1 — SSRF trigger).
# Intentionally narrow: broad names like 'url', 'src', 'href', 'target' fire on
# tracking pixels and ad networks and produce too much ambient noise.
_SSRF_PARAM_NAMES = frozenset({
    "redirecturl", "redirect_url", "redirecturi", "redirect_uri",
    "returnurl", "return_url", "goto", "fetch",
    "webhookurl", "webhook_url", "webhook",
    "endpoint", "callback", "callbackurl", "callback_url",
    "next_hop", "forward", "forwardurl", "forward_url",
    "proxyurl", "proxy_url",
})
# Parameter names that suggest a credential is in the URL (H2 — credential exposure).
_CRED_PARAM_NAMES = frozenset({
    "token", "api_key", "apikey", "key", "secret", "access_token", "accesstoken",
    "password", "passwd", "pwd", "auth", "bearer", "authorization",
    "client_secret", "private_key", "api_secret", "session_token",
})
# Security response headers whose absence matters on auth-bearing requests.
_SEC_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options")
# JWT claims that warrant elevated attention.
_JWT_SENSITIVE_CLAIMS = frozenset({
    "admin", "role", "roles", "scope", "scopes", "permissions", "groups",
    "priv", "privilege", "superuser", "is_admin", "is_superuser", "acl",
})
# H9: client-controllable trust/routing headers — ACL-bypass, cache-poison, and SSRF
# primitives when the app honors them. Presence on a request is the probe surface.
_CLIENT_TRUST_HEADERS = frozenset({
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-server",
    "x-original-url", "x-rewrite-url", "x-real-ip", "x-host", "x-originating-ip",
    "x-remote-addr", "x-remote-ip", "forwarded", "x-http-method-override",
    "x-method-override", "x-original-referer",
})
# H10: response header NAMES that leak a genuinely sensitive internal identifier — pod/host
# IPs, backend/instance names, worker PIDs, debug tokens. Common infra-timing/CDN headers
# (x-envoy-upstream-service-time, x-served-by) are deliberately excluded: they are captured
# as technology nodes instead, not flagged as leaks. Matched on the name; values not emitted.
_INTERNAL_HEADER_RE = re.compile(
    r'(?i)(pod[-_]?ip|[-_]backend|[-_]instance|worker[-_](?:pid|id|ip|name)\b'
    r'|debug-worker|debug-token|server-ip|host-ip|node-id|[-_]hostname)')
# Hop-by-hop headers HTTP/2 forbids on a response — their presence on an h2-negotiated host
# marks an HTTP/1 backend behind an HTTP/2 frontend (H2-downgrade smuggling surface).
_HOPBYHOP_HEADERS = ("connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection")
# H7: what an exposed API-description document leaks. Matched for classification only;
# raw values are never emitted (boundary #6) — only the categories they fall into.
_API_DESC_LEAK = re.compile(
    r'(?:base|location)\s*=\s*"([^"]+)"'      # WADL base= / WSDL soap:address location=
    r'|generatedBy\s*=\s*"([^"]+)"'           # Jersey/framework fingerprint
    r'|"url"\s*:\s*"(https?://[^"]+)"'         # OpenAPI servers[].url
)
_REASON_WEIGHT: dict[str, int] = {
    "authenticated_cache_policy_contradiction": 60,
    "server_error_response": 50,
    "new_status_for_endpoint": 45,
    "new_content_type_for_endpoint": 40,
    "third_party_receives_auth_context_in_window": 40,
    "resp:leak": 35,
    "wildcard_credentialed_cors": 35,
    "status_spike_in_run": 35,
    "batch_payload_detected": 35,
    "request_content_type_drift": 30,
    "resp:reflection": 30,
    "internal_network_reference": 30,
    "declared_json_actual_html": 30,
    "request_schema_expansion": 25,
    "auth_anomaly_in_sequence": 25,
    "version_disclosure_header": 25,
    "route:injection": 25,
    "route:idor": 25,
    "declared_html_actual_json": 20,
    "successful_state_change_without_visible_auth": 20,
    "route:xss-stored": 20,
    "downstream_of_authenticated_host": 20,
    "mutating_method_amid_safe_run": 18,
    "state_changing_method": 15,
    "route:graphql": 15,
    "security_relevant_route": 15,
    "encoded_outbound_blob": 15,
    "encoded_get_exfil": 30,
    "large_get_exfil_query": 20,
    "resp:cors": 10,
    "new_dynamic_endpoint": 10,
    # H1: SSRF — parameter name suggests server-side fetch surface
    "ssrf_trigger_parameter": 30,
    # H2: Credential in URL — token/key/secret in query string; gets logged
    "credential_in_query_string": 45,
    # H3: Open redirect — 3xx to external domain
    "open_redirect_to_external": 40,
    # H4: JWT with sensitive privilege claims
    "jwt_sensitive_claim": 40,
    "jwt_in_url": 15,
    # H5: Missing critical security headers on auth-bearing response
    "missing_security_headers": 10,
    # H6: PII patterns in response body
    "pii_in_response": 35,
    # H7: API-description doc exposed (WADL/WSDL/OpenAPI) — schema + internal host/version leak
    "api_description_exposure": 35,
    # H8: JS bundle intelligence — secrets, endpoint disclosure, source maps, auth mechanism
    "js_secret_literal": 45,
    "js_sourcemap_disclosure": 25,
    "js_endpoint_disclosure": 20,
    "js_auth_mechanism": 15,
    # H9/H10: header-derived signals
    "client_trust_header": 30,
    "internal_header_disclosure": 25,
    # H11: HTTP-version signals (populated once an ALPN probe fills raw_socket_traffic)
    "http2_downgrade_surface": 40,
    "mixed_http_version_for_host": 20,
    # H12: Nuclei-borrowed response-body-signature detections
    "sensitive_file_exposure": 50,
    "secret_in_response": 45,
    "exposed_management_panel": 30,
    "error_disclosure_in_body": 25,
    # Evidence-driven adds (Juice Shop A/B misses): a directory listing that names backup/secret
    # files, an exposed metrics endpoint, and a same-endpoint response-size swing (injection tell).
    "metrics_endpoint_exposed": 35,
    "response_size_swing_for_endpoint": 20,
    "null_byte_in_path": 40,
    # Cookie + HTML-DOM lane (ZAP borrow — Swarmie's biggest structural gap).
    "insecure_cookie_flags": 25,
    "weak_csp_directive": 20,
    "suspicious_html_comment": 15,
    "untrusted_script_include": 20,
    # Learned lane (agent-prompt-injection in a response body). Only counts toward attention
    # in active mode — in shadow mode the reason is never appended (see build_signal).
    "agent_injection_in_response": 35,
}
# Recalibrated from the 283k-corpus scale test — the LLM judge measured 42% of the top-100 by
# attention as noise. Floor the broad low-precision families (they co-occur on ordinary SPA/API/
# media traffic); lift the rare high-precision ones that actually led to findings.
_REASON_WEIGHT.update({
    "state_changing_method": 5, "successful_state_change_without_visible_auth": 6,
    "mutating_method_amid_safe_run": 6, "resp:reflection": 8, "resp:cors": 2, "resp:leak": 12,
    "route:xss-stored": 4, "route:injection": 10, "route:idor": 10, "route:graphql": 2,
    "new_dynamic_endpoint": 2, "new_content_type_for_endpoint": 15, "new_status_for_endpoint": 15,
    "status_spike_in_run": 12, "version_disclosure_header": 10, "weak_csp_directive": 10,
    "wildcard_credentialed_cors": 15, "ssrf_trigger_parameter": 10, "encoded_get_exfil": 12,
    "large_get_exfil_query": 8, "downstream_of_authenticated_host": 8,
    "third_party_receives_auth_context_in_window": 12,
    "secret_in_response": 55, "error_disclosure_in_body": 42, "insecure_cookie_flags": 32,
    "exposed_management_panel": 40, "cleartext_auth_material": 60,
    "credential_reused_across_endpoints": 55, "publishable_client_key": 5, "encrypted_outbound_blob": 55,
    "opaque_outbound_body": 18,
    "idor_shared_object_id": 8, "idor_id_from_response": 12,
})
# Noise detection (283k-corpus scale test): ad-tech/RTB/analytics beacons and training/lab
# platforms are structurally-recognizable third-party noise. Detection drives an attention
# dampener directly — no host allowlist or per-envelope tag needed.
_BEACON_PATH = re.compile(
    r"(?:^|/)(?:hb|openrtb|rtb|bid|bidder|prebid|auction|usersync|setuid|getuid|pagead|adx|imp|"
    r"impression|pixel|beacon|collect|track(?:ing)?|events?|metrics?|telemetry|rum|csp[-_]?report|"
    r"translator|monitoring|analytics|gtag|batch|log)\d*(?:/|$|\.|\?)", re.I)
_PRACTICE_HOST = re.compile(
    r"(?:hackthebox|juice-?shop|web-security-academy|portswigger|testfire\.net|dvwa|vulnweb|"
    r"tryhackme|pentesterlab|hackazon)", re.I)


def _noise_factor(host: str, path: str) -> float:
    """Attention multiplier for structurally-recognizable third-party noise. Ad/RTB/analytics
    beacons carry huge encoded blobs and wildcard CORS by design (the exfil/idor reasons are false
    positives there); training platforms should rank below real targets."""
    h = (host or "").lower()
    if any(a in h for a in _AD_NETWORK) or _BEACON_PATH.search(path or ""):
        return 0.2
    if _PRACTICE_HOST.search(h):
        return 0.4
    return 1.0


# Reasons strong enough that the ad/beacon/lab noise dampener must NOT apply — a beacon-shaped
# path (e.g. /v1/events) that also carries one of these is a real finding, not telemetry noise.
_PRECISE_OVERRIDE = frozenset({
    "encrypted_outbound_blob", "secret_in_response", "cleartext_auth_material",
    "credential_reused_across_endpoints", "credential_in_query_string", "error_disclosure_in_body",
    "exposed_management_panel", "sensitive_file_exposure", "null_byte_in_path",
    "internal_network_reference", "metrics_endpoint_exposed", "jwt_sensitive_claim",
})


_WINDOW_SIZE = 20


def _epoch_bucket(ts: str, window: int = 30) -> int:
    try:
        clean = ts.split(".")[0].rstrip("Z").replace("T", " ")
        return _calendar.timegm(time.strptime(clean, "%Y-%m-%d %H:%M:%S")) // window
    except (ValueError, OverflowError):
        return 0


def _base_domain(host: str) -> str:
    parts = host.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _referer_host(headers: dict[str, str]) -> str:
    ref = headers.get("referer", "")
    if not ref:
        return ""
    try:
        return urlsplit(ref).netloc.lower().split(":")[0]
    except Exception:
        return ""


def _base_type(value: str | None) -> str:
    return (value or "").split(";", 1)[0].strip().lower()


def _bytes(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", "replace")


def _text(value) -> str:
    return _bytes(value).decode("utf-8", "replace")


def _lower_headers(raw) -> dict[str, str]:
    return {k.lower(): v for k, v in parse_headers(_text(raw)).items()}


def _tech_from_headers(resp: dict[str, str]) -> list[str]:
    """Fingerprint server/framework/mesh technologies from response headers for the graph."""
    out: list[str] = []
    def add(t: str) -> None:
        t = t.strip()
        if t and t not in out:
            out.append(t)
    add((resp.get("server") or "").split("/")[0].strip())
    add((resp.get("x-powered-by") or "").split("/")[0].strip())
    if any(k.startswith("x-envoy") for k in resp):
        add("Envoy")
    if "x-served-by" in resp or "x-varnish" in resp:
        add("Fastly/Varnish")
    if "x-aspnet-version" in resp or "x-aspnetmvc-version" in resp:
        add("ASP.NET")
    if "x-drupal-cache" in resp or "x-generator" in resp:
        add((resp.get("x-generator") or "Drupal").split(" ")[0])
    return out[:6]


# Backup/secret/credential file extensions that shouldn't be reachable by clients — used to
# flag a directory-listing body that enumerates them (e.g. a .kdbx vault or a .bak of config).
_SENSITIVE_FILE_EXT = re.compile(
    r"\.(?:kdbx?|kdb|keystore|jks|bak|backup|old|orig|swp|sql|dump|pyc|pem|key|p12|pfx|ppk|"
    r"ovpn|env|crt|htpasswd)(?:\b|$)", re.I)
# Developer "tells" left in HTML/JS comments — leak intent, credentials, or hidden surface.
_SUSPICIOUS_COMMENT = re.compile(
    r"(?i)\b(?:todo|fixme|hack|xxx|bug|password|passwd|secret|api[_-]?key|apikey|token|"
    r"backdoor|debug|username|admin(?:istrator)?|do not|remove before|internal only|"
    r"deprecated|temporary|for now|not secure)\b")
# Session-ish cookie name fragments — a session cookie missing HttpOnly/Secure is the finding.
_SESSION_COOKIE = ("sess", "sid", "token", "auth", "jwt", "csrf")
# External <script src=...> without Subresource Integrity.
_SCRIPT_SRC = re.compile(r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', re.I)
# A credential/secret FIELD echoed in a JSON response body (a plaintext password dump, etc.).
_CRED_FIELD_RE = re.compile(
    r'"(?:password|passwd|pwd|secret|api[_-]?key|private[_-]?key|access[_-]?token|client[_-]?secret)"'
    r'\s*:\s*"[^"]{2,}"', re.I)


def _sensitive_file_kind(text: str, content_type: str, raw: bytes) -> str:
    """Return a label if the response body IS a sensitive exposed artifact (Nuclei borrow)."""
    if "repositoryformatversion" in text and "[core]" in text:
        return ".git/config"
    # JSON array of filenames (a REST-style directory listing) that names backup/secret files.
    if text[:1] == "[" and _SENSITIVE_FILE_EXT.search(text[:8192]):
        try:
            arr = json.loads(text)
        except (ValueError, TypeError):
            arr = None
        if isinstance(arr, list) and any(isinstance(x, str) and _SENSITIVE_FILE_EXT.search(x) for x in arr):
            return "directory listing of sensitive files"
    if _ENV_FILE_RE.search(text):
        return ".env file"
    if _PRIVKEY_RE.search(text):
        return "private key file"
    if "PHP Version" in text and ("PHP Extension" in text or "phpinfo()" in text):
        return "phpinfo() output"
    low = text.lower()
    if not content_type.startswith("text/html") and "create table" in low and (
            "insert into" in low or "drop table" in low):
        return "SQL dump"
    if raw[:13] == b"JAVA PROFILE ":
        return "JVM heap dump"
    if raw[4:8] == b"Bud1":
        return ".DS_Store"
    if ("Directory Listing For" in text or "Index of /" in text) and "<a href=" in text:
        return "directory listing"
    return ""


def _error_category(marker: str) -> str:
    m = marker.lower()
    if "sql" in m or m.startswith("ora-") or "olé db" in m or "ole db" in m or "sqlclient" in m \
            or "pg_" in m or "mysql" in m:
        return "SQL error"
    if "urlconf" in m or "django" in m:
        return "Django debug page"
    if "whoops" in m:
        return "Laravel debug page"
    if "function.handle" in m or "notfounderror" in m:
        return "Express stack trace"
    if "traceback" in m:
        return "Python traceback"
    return "framework error / stack trace"


def _json_keys(raw) -> list[str]:
    try:
        value = json.loads(_text(raw))
    except (ValueError, TypeError):
        return []
    if isinstance(value, dict):
        return sorted(str(k) for k in value)[:40]
    return ["[]"] if isinstance(value, list) else []


@dataclasses.dataclass
class EndpointBaseline:
    count: int = 0
    statuses: collections.Counter = dataclasses.field(default_factory=collections.Counter)
    content_types: collections.Counter = dataclasses.field(default_factory=collections.Counter)
    log_sum: float = 0.0
    log_sumsq: float = 0.0
    min_len: int = 0
    max_len: int = 0
    # Request-side baseline: tracks outbound body size and content-type.
    req_body_count: int = 0
    req_log_sum: float = 0.0
    req_log_sumsq: float = 0.0
    req_content_types: collections.Counter = dataclasses.field(default_factory=collections.Counter)

    def compare(self, status: int, content_type: str, length: int) -> list[str]:
        reasons: list[str] = []
        if self.count and status not in self.statuses:
            reasons.append("new_status_for_endpoint")
        if self.count and content_type and content_type not in self.content_types:
            reasons.append("new_content_type_for_endpoint")
        if self.count >= 10:
            mean = self.log_sum / self.count
            variance = max(0.0, self.log_sumsq / self.count - mean * mean)
            if variance > 1e-9:
                z = abs(math.log1p(max(0, length)) - mean) / math.sqrt(variance)
                if z >= 3.0:
                    reasons.append(f"response_length_outlier_z={z:.1f}")
        # Low-observation size swing: the same endpoint returning a dramatically larger body
        # than it has before (>=8x, >=2KB) is a data-amplification tell (e.g. an injection that
        # broke out of a WHERE clause and dumped the table). Fires before the z-score baseline
        # is warm, so it catches the second hit, not the tenth.
        if self.count >= 1 and length >= 2048 and self.max_len > 0:
            lo = max(1, min(length, self.min_len or length))
            if max(length, self.max_len) >= 8 * lo:
                reasons.append("response_size_swing_for_endpoint")
        return reasons

    def add(self, status: int, content_type: str, length: int) -> None:
        self.count += 1
        self.statuses[status] += 1
        if content_type:
            self.content_types[content_type] += 1
        value = math.log1p(max(0, length))
        self.log_sum += value
        self.log_sumsq += value * value
        self.min_len = length if self.min_len == 0 else min(self.min_len, length)
        self.max_len = max(self.max_len, length)

    def compare_request(self, req_content_type: str, req_body_len: int) -> list[str]:
        reasons: list[str] = []
        if self.req_body_count >= 1 and req_content_type and req_content_type not in self.req_content_types:
            reasons.append("request_content_type_drift")
        if self.req_body_count >= 10 and req_body_len > 0:
            mean = self.req_log_sum / self.req_body_count
            variance = max(0.0, self.req_log_sumsq / self.req_body_count - mean * mean)
            if variance > 1e-9:
                z = abs(math.log1p(req_body_len) - mean) / math.sqrt(variance)
                if z >= 3.0:
                    reasons.append(f"outbound_request_size_spike_z={z:.1f}")
        return reasons

    def add_request(self, req_content_type: str, req_body_len: int) -> None:
        if req_body_len > 0:
            self.req_body_count += 1
            if req_content_type:
                self.req_content_types[req_content_type] += 1
            v = math.log1p(req_body_len)
            self.req_log_sum += v
            self.req_log_sumsq += v * v


_DECL_PLACEHOLDER = re.compile(r"\{[^/}]*\}|:[A-Za-z_]\w*|%s")


# Declared-endpoint noise: library/CDN/asset references that are never the target's own API.
_NONTARGET_PATH = re.compile(r"/node_modules/|/blob/|/LICENSE\b|\.wasm\b|/core-js|(?:unpkg|jsdelivr|cdnjs)\b", re.I)


def _reg_domain(host: str) -> str:
    """Rough registrable domain (last two labels). Good enough to tell first-party from a
    cross-domain CDN/library reference (api.x.com and x.com share 'x.com')."""
    host = (host or "").lower().split(":")[0]
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _canon_path(p: str) -> str:
    """Canonicalize a path so a JS-declared endpoint and an observed path_shape compare:
    drop scheme/host/query, collapse placeholders/ids to {x}, lowercase, drop empty segs."""
    path = urlsplit(p).path or (p if p.startswith("/") else "")
    path = _DECL_PLACEHOLDER.sub("{x}", path)
    return "/" + "/".join(s for s in path.split("/") if s).lower()


class SignalEngine:
    """In-memory endpoint baselines and exact-pair roll-up."""

    def __init__(self, scope_hosts: Iterable[str] = (), lane=None, full_coverage: bool = False):
        self.scope_hosts = {h.lower() for h in scope_hosts if h}
        # Full-coverage mode disables the per-(host,type) body-sampling cap: every non-static
        # pair is hydrated. For bounded assessments and eval corpora where sampling luck would
        # otherwise distort which signals surface. Off in normal high-volume tailing.
        self.full_coverage = full_coverage
        # Optional learned lane (out-of-process classifier). None = dormant; symbolic
        # detectors are unaffected. See rqswarm_eval/learned_lane.py for the wire contract.
        self.lane = lane
        self.baselines: dict[tuple[str, str, str], EndpointBaseline] = {}
        self.seen_pairs: collections.Counter[str] = collections.Counter()
        self.seen_endpoint_families: set[tuple[tuple[str, str, str], str]] = set()
        self.coverage_seen: set[tuple[str, str]] = set()
        # Distinct JS bundles hydrated per host (dissection budget; see _JS_PER_HOST_CAP).
        self.js_host_budget: collections.Counter[str] = collections.Counter()
        # Per-host sliding windows for sequential anomaly detection.
        # Each entry: {"status": int, "length": int, "method": str}
        self.host_windows: dict[str, collections.deque] = {}
        # Per-host auth-state windows for auth-flip detection (populated in header_reasons).
        self.host_auth_windows: dict[str, collections.deque] = {}
        # Cross-host relationship graph: hosts that have carried explicit Authorization headers,
        # keyed to the 30s time buckets in which auth was seen.
        self.host_auth_buckets: dict[str, set] = collections.defaultdict(set)
        # (src_host, dst_host) → Referer-linked co-occurrence count across the session.
        self.referer_graph: collections.Counter = collections.Counter()
        # Infra facts drained by the tailer into the operator-side investigation graph.
        # Holds raw backend hostnames/framework strings recovered from schema docs — these
        # belong to the operator sidecar, never the (redacted) mailbox envelope.
        self.infra_edges: list[dict] = []
        # host -> set of negotiated ALPN values (e.g. {"h2","http/1.1"}), loaded by the tailer
        # from raw_socket_traffic when an operator ALPN probe has populated it. Empty = dormant.
        self.host_alpn: dict[str, set] = {}
        # Per-endpoint request body key sets: detects schema expansion in outbound payloads.
        self.endpoint_req_key_sets: dict[tuple, set] = {}
        # hostname → set of JS source URLs that contain that hostname as a string literal.
        # Built during body hydration of JS responses; used to trace traffic back to source code.
        self.script_host_index: dict[str, set] = collections.defaultdict(set)
        # fingerprint(hashed credential value) -> set of (host, path) for cross-request reuse.
        self.seen_credentials: dict[str, set] = {}
        # Registrable domains the user actually NAVIGATED to (top-level document navigations).
        # A cross-site embedded collector (e.g. a fraud/fingerprint iframe) posts to a domain that
        # is NEVER in this set - the tell that separates third-party exfil from first-party
        # telemetry, which referer/origin/sec-fetch all report as same-origin for an isolated iframe.
        self.navigated_domains: set[str] = set()
        # Object-identifier co-occurrence graph (ADR-0004): hashes only, structural
        # endpoint keys only; no raw value or raw path is retained. Edges drained by the
        # tailer into the operator investigation graph.
        self.value_graph = ValueGraph()
        self.dataflow_edges: list[dict] = []

    @staticmethod
    def endpoint_key(row: dict) -> tuple[str, str, str]:
        return (
            (row.get("host") or "").lower(),
            (row.get("method") or "GET").upper(),
            path_shape(row.get("path") or urlsplit(row.get("url") or "").path or "/"),
        )

    def _window_reasons(self, host: str, status: int, length: int, method: str) -> list[str]:
        """Detect anomalies relative to a per-host sliding window; always updates the window."""
        window = self.host_windows.setdefault(host, collections.deque(maxlen=_WINDOW_SIZE))
        reasons: list[str] = []
        if len(window) >= 8:
            statuses = [e["status"] for e in window]
            dominant = max(set(statuses), key=statuses.count)
            if statuses.count(dominant) / len(statuses) >= 0.85 and status != dominant:
                reasons.append("status_spike_in_run")

            lengths = [e["length"] for e in window if e["length"] > 0]
            if len(lengths) >= 6 and length > 0:
                mean = sum(lengths) / len(lengths)
                variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
                if variance > 0:
                    z = abs(length - mean) / variance ** 0.5
                    if z >= 6.0:
                        reasons.append(f"local_length_outlier_z={z:.1f}")

            methods = [e["method"] for e in window]
            safe_frac = sum(1 for m in methods if m in _SAFE_METHODS) / len(methods)
            if safe_frac >= 0.8 and method not in _SAFE_METHODS:
                reasons.append("mutating_method_amid_safe_run")

        window.append({"status": status, "length": length, "method": method})
        return reasons

    def observe_metadata(self, row: dict, warmup: bool = False) -> list[str]:
        key = self.endpoint_key(row)
        baseline = self.baselines.setdefault(key, EndpointBaseline())
        status = int(row.get("status_code") or 0)
        content_type = _base_type(row.get("content_type"))
        length = int(row.get("response_length") or 0)
        method = key[1]
        host = key[0]
        path = key[2]
        # Window is always updated (including warmup) so it reflects real history.
        window_reasons = self._window_reasons(host, status, length, method)
        reasons = [] if warmup else baseline.compare(status, content_type, length) + window_reasons
        first = baseline.count == 0
        params = int(row.get("param_count") or 0)
        dynamic = bool(content_type) and not content_type.startswith(_STATIC_TYPES)
        if not warmup:
            if status >= 500:
                reasons.append("server_error_response")
            if method not in _SAFE_METHODS and (
                host in self.scope_hosts or first or reasons or baseline.count % 32 == 0
            ) and not (_TELEMETRY.search(path) and not first and not reasons):
                reasons.append("state_changing_method")
            if first and dynamic and (
                _INTERESTING_PATH.search(path)
                or method not in _SAFE_METHODS
                or (host in self.scope_hosts and (params or "json" in content_type))
            ):
                reasons.append("new_dynamic_endpoint")
            elif first and _INTERESTING_PATH.search(path):
                reasons.append("security_relevant_route")
            # GET-based data exfiltration: encoded payloads in URL path or query string.
            if not warmup and method in _SAFE_METHODS:
                query = row.get("query") or ""
                raw_path = row.get("path") or ""
                query_len = len(query)
                params = int(row.get("param_count") or 0)
                if (query_len > 400 and params >= 5) or _PCT_RUN.search(query):
                    reasons.append("large_get_exfil_query")
                if _B64_IN_URL.search(raw_path) or _B64_IN_URL.search(query):
                    reasons.append("encoded_get_exfil")
            # Poison null byte: an encoded NUL truncates the path to bypass an extension filter
            # (e.g. /secret.bak%00.md served as secret.bak). A clear attack signature.
            if not warmup and "%00" in (row.get("path") or "").replace("%2500", "%00"):
                reasons.append("null_byte_in_path")
            # H1: SSRF trigger parameter — param name suggests server-side fetch surface.
            # H2: Credential in URL — sensitive key/token/secret in query string gets logged.
            param_names_str = row.get("param_names") or ""
            if param_names_str:
                pnames = {p.strip().lower() for p in param_names_str.split(",") if p.strip()}
                if pnames & _SSRF_PARAM_NAMES:
                    reasons.append("ssrf_trigger_parameter")
                if pnames & _CRED_PARAM_NAMES:
                    reasons.append("credential_in_query_string")
                    # Cross-request correlation: fingerprint the credential value (hashed, never
                    # stored raw) and flag when the same one recurs across multiple endpoints.
                    for _k, _vals in parse_qs(row.get("query") or "").items():
                        if _k.lower() not in _CRED_PARAM_NAMES:
                            continue
                        for _v in _vals:
                            if len(_v) < 8:
                                continue
                            _fp = hashlib.sha256(_v.encode()).hexdigest()[:16]
                            _seen = self.seen_credentials.setdefault(_fp, set())
                            _seen.add((host, path))
                            if len(_seen) >= 3 and "credential_reused_across_endpoints" not in reasons:
                                reasons.append("credential_reused_across_endpoints")
        baseline.add(status, content_type, length)
        return list(dict.fromkeys(reasons))

    def header_reasons(self, row: dict) -> list[str]:
        req = _lower_headers(row.get("request_headers"))
        resp = _lower_headers(row.get("response_headers"))
        reasons: list[str] = []
        host = (row.get("host") or "").lower()
        # Record genuine top-level navigations (Sec-Fetch marks the browsing context). A third
        # party embedded via iframe/script is never navigated to, so its registrable domain stays
        # out of this set even though its own requests look same-origin.
        if req.get("sec-fetch-dest") == "document" and req.get("sec-fetch-mode") == "navigate" and host:
            self.navigated_domains.add(_base_domain(host))
        auth = bool(req.get("authorization") or req.get("cookie"))
        auth_window = self.host_auth_windows.setdefault(host, collections.deque(maxlen=_WINDOW_SIZE))
        if len(auth_window) >= 8:
            majority_auth = sum(auth_window) > len(auth_window) / 2
            if majority_auth != auth:
                reasons.append("auth_anomaly_in_sequence")
        auth_window.append(auth)

        # Track hosts bearing explicit Authorization headers (not just cookies) by time bucket.
        # Cookie-only auth is too noisy for relationship graph purposes.
        explicit_auth = bool(req.get("authorization"))
        bucket = _epoch_bucket(row.get("timestamp") or "")
        if explicit_auth and bucket:
            self.host_auth_buckets[host].add(bucket)

        # Cross-domain Referer analysis: detect when a third-party destination receives
        # context from a session where the referring host had authenticated traffic.
        ref_host = _referer_host(req)
        if ref_host and ref_host != host and _base_domain(ref_host) != _base_domain(host):
            self.referer_graph[(ref_host, host)] += 1
            if ref_host in self.host_auth_buckets:
                if bucket and bucket in self.host_auth_buckets[ref_host]:
                    reasons.append("third_party_receives_auth_context_in_window")
                elif not explicit_auth:
                    reasons.append("downstream_of_authenticated_host")

        # Outbound request size baseline (uses LENGTH(request_body) from the header lane query).
        req_body_len = int(row.get("req_body_len") or 0)
        req_content_type = _base_type(req.get("content-type"))
        baseline = self.baselines.get(self.endpoint_key(row))
        if baseline:
            reasons.extend(baseline.compare_request(req_content_type, req_body_len))
            baseline.add_request(req_content_type, req_body_len)

        cache_control = resp.get("cache-control", "").lower()
        cache_state = (resp.get("x-cache", "") + " " + resp.get("cf-cache-status", "")).upper()
        if auth and ("no-store" in cache_control or "private" in cache_control) and (
            "HIT" in cache_state or resp.get("age")
        ):
            reasons.append("authenticated_cache_policy_contradiction")
        acao = resp.get("access-control-allow-origin", "")
        if "*" in acao and resp.get("access-control-allow-credentials", "").lower() == "true":
            reasons.append("wildcard_credentialed_cors")
        if re.search(r"/\d+(?:\.\d+)+", resp.get("server", "") + " " + resp.get("x-powered-by", "")):
            reasons.append("version_disclosure_header")

        # Insecure session cookie: a session-ish Set-Cookie missing HttpOnly (XSS-stealable), or
        # missing Secure on an HTTPS origin (sniffable). Missing Secure over plain HTTP is not a
        # finding (the flag would just stop the cookie working), so it is scheme-gated. Parse the
        # raw header text — the lower-cased dict collapses duplicate Set-Cookie lines.
        is_https = (row.get("url") or "").lower().startswith("https")
        for line in _text(row.get("response_headers")).split("\n"):
            ls = line.strip()
            if not ls.lower().startswith("set-cookie:"):
                continue
            cookie = ls.split(":", 1)[1].strip()
            name = cookie.split("=", 1)[0].strip().lower()
            low = cookie.lower()
            if any(frag in name for frag in _SESSION_COOKIE) and (
                    "httponly" not in low or (is_https and "secure" not in low)):
                reasons.append("insecure_cookie_flags")
                break

        # Weak CSP directive — upgrades the presence-only missing-header check: a CSP that
        # allows unsafe-inline/unsafe-eval or a wildcard script/default source barely protects.
        csp = resp.get("content-security-policy", "").lower()
        if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp
                    or re.search(r"(?:default|script)-src[^;]*\*", csp)):
            reasons.append("weak_csp_directive")

        # Cleartext auth material: auth (Authorization / session cookie / apikey|token|stok in the
        # URL) carried over plaintext HTTP — sniffable and log/referer-leakable. The LLM-alone scale
        # run's crown jewel (router stok, Servarr keys over http) that Swarmie had no detector for.
        if (row.get("url") or "").lower().startswith("http://"):
            loc = ((row.get("query") or "") + " " + (row.get("path") or "")).lower()
            if req.get("authorization") or req.get("cookie") or any(
                    t in loc for t in ("apikey=", "api_key=", "access_token=", "token=", "stok=",
                                       "auth=", "sessionid=", "session=", "secret=", "password=")):
                reasons.append("cleartext_auth_material")

        # H3: Open redirect — a 3xx to another domain is only a finding when the DESTINATION is
        # attacker-influencable. Flagging every cross-domain 3xx made this the #1 signal on a
        # clean browse by matching designed SSO hops (Wikimedia CentralAutoLogin -> auth.wikimedia
        # .org), CDN and consent-flow redirects. Require the target to echo a request parameter.
        status_code = int(row.get("status_code") or 0)
        location = resp.get("location", "")
        if 300 <= status_code < 400 and location:
            try:
                loc_host = urlsplit(location).netloc.lower().split(":")[0]
                if loc_host and loc_host != host and _base_domain(loc_host) != _base_domain(host):
                    query = unquote_plus((row.get("query") or "").lower())
                    # the redirect target (host, or a full/scheme-relative URL) came from input
                    if loc_host in query or any(
                            m in query for m in ("=http://", "=https://", "=//")):
                        reasons.append("open_redirect_to_external")
            except Exception:
                pass

        # H5: Missing critical security headers on auth-bearing, non-static responses.
        # Scoped to auth context to suppress near-universal noise on public pages.
        resp_ct = _base_type(row.get("content_type"))
        if auth and not resp_ct.startswith(_STATIC_TYPES):
            missing = sum(1 for h in _SEC_HEADERS if h not in resp)
            if missing >= 2:
                reasons.append("missing_security_headers")

        # H9: client-controllable trust/routing headers on the request — ACL-bypass,
        # cache-poisoning, and SSRF probe surface (names only; values never emitted).
        if _CLIENT_TRUST_HEADERS & set(req):
            reasons.append("client_trust_header")
        # H10: response header names that leak internal infrastructure.
        if any(_INTERNAL_HEADER_RE.search(name) for name in resp):
            reasons.append("internal_header_disclosure")
        # H11: HTTP-version tells — active only once an operator ALPN probe has populated
        # host_alpn from raw_socket_traffic; dormant (no-op) on purely passive captures.
        alpn = self.host_alpn.get(host)
        if alpn:
            if len(alpn) > 1:
                reasons.append("mixed_http_version_for_host")
            if "h2" in alpn and any(h in resp for h in _HOPBYHOP_HEADERS):
                reasons.append("http2_downgrade_surface")
        # Technologies fingerprinted from response headers feed the investigation graph
        # (host -> runs -> technology), the same way the WADL gave us the Jersey node.
        for tech in _tech_from_headers(resp):
            self.infra_edges.append({"kind": "technology", "host": host, "tech": tech})

        return reasons

    def graph_summary(self, top_n: int = 40) -> dict:
        """Return the top cross-domain Referer edges and auth-bearing hosts seen so far."""
        edges = [
            {"src": src, "dst": dst, "count": count}
            for (src, dst), count in self.referer_graph.most_common(top_n)
        ]
        auth_hosts = sorted(self.host_auth_buckets.keys())
        return {"referer_edges": edges, "auth_bearing_hosts": auth_hosts}

    def should_sample_body(self, row: dict) -> bool:
        content_type = _base_type(row.get("content_type"))
        if content_type.startswith(_STATIC_TYPES):
            return False
        if self.full_coverage:
            return True
        # Exposure/panel-suggestive paths are always worth a body scan, regardless of the
        # per-(host,type) coverage cap — the body-signature lanes emit only on a real match.
        if _EXPOSURE_PATH.search(row.get("path") or ""):
            return True
        baseline = self.baselines[self.endpoint_key(row)]
        host = self.endpoint_key(row)[0]
        interval = 8 if host in self.scope_hosts else 32
        coverage_key = (host, content_type or "(empty)")
        # A distinct JS bundle (first sighting) is worth dissecting even after this host has
        # already spent its per-(host,type) "once", up to a per-host budget — otherwise a CDN
        # host serving 800 bundles gets exactly one read (ADR-0006 hidden-endpoint blind spot).
        if content_type in _JS_TYPES and baseline.count == 1:
            if self.js_host_budget[host] < _JS_PER_HOST_CAP:
                self.js_host_budget[host] += 1
                return True
        if baseline.count == 1 and coverage_key not in self.coverage_seen:
            self.coverage_seen.add(coverage_key)
            return True
        return baseline.count % interval == 0

    def _hidden_js_endpoints(self, declared: list[str], bundle_host: str = "") -> list[str]:
        """JS-declared endpoints whose canonical path was NEVER observed in traffic — the
        undiscovered attack surface (ADR-0006). Scope-filtered: cross-domain third-party
        (library/CDN) references and asset/lib paths are dropped so only the target's own
        first-party surface surfaces; with --scope set, restrict to in-scope domains.
        Declared strings are already redacted by dissect_js, so they are safe to emit."""
        if not declared:
            return []
        observed = {_canon_path(k[2]) for k in self.baselines}
        bdom = _reg_domain(bundle_host)
        scope_doms = {_reg_domain(h) for h in self.scope_hosts} if self.scope_hosts else set()
        hidden = []
        for ep in declared:
            if _NONTARGET_PATH.search(ep):
                continue
            if "://" in ep:  # absolute URL: drop cross-domain third-party (CDN/lib/tracker)
                edom = _reg_domain(urlsplit(ep).netloc)
                if edom and bdom and edom != bdom:
                    continue
                eff = edom
            else:            # relative path: same-origin app route, attributed to the bundle host
                eff = bdom
            if scope_doms and eff and eff not in scope_doms:
                continue
            c = _canon_path(ep)
            if c and c != "/" and c not in observed:
                hidden.append(ep)
        return sorted(set(hidden))[:40]

    def _investigation_for(self, reasons, url, req_headers, resp_headers, request_type,
                           req_ids, sibling_shapes):
        """Assemble the machine-known ctx for a signal's vuln class and build its investigation
        graph (ADR-0005). Only structural facts flow in — siblings as path_shape, id TYPE not
        value — so no raw value or path enters the investigation block."""
        cls = classify(reasons)
        if cls is None:
            return None
        parts = urlsplit(url or "")
        if any(is_id_like(v) for _k, vals in parse_qs(parts.query or "").items() for v in vals):
            selector = "query parameter"
        elif any(is_id_like(s) for s in (parts.path or "").split("/")):
            selector = "path parameter"
        else:
            selector = ""
        pred = ""
        for v in req_ids:
            if v.isdigit():
                pred = "high (sequential-looking integer id)"
                break
            pred = ("low (uuid)" if (len(v) == 36 and v.count("-") == 4)
                    else "medium (opaque token)")
        auth = req_headers.get("authorization", "")
        cookie = req_headers.get("cookie", "")
        if auth.lower().startswith("bearer"):
            identity = "bearer token"
        elif auth:
            identity = "authorization header"
        elif cookie:
            identity = "session cookie"
        else:
            identity = "none observed"
        is_jwt = "eyj" in auth.lower() or any("jwt" in str(r).lower() for r in reasons)
        token_type = "jwt" if is_jwt else identity
        token_reuse = ("reused across endpoints"
                       if "credential_reused_across_endpoints" in reasons else "")
        if "json" in request_type:
            surface = "json request body"
        elif parts.query:
            surface = "query parameters"
        elif "form" in request_type:
            surface = "form fields"
        else:
            surface = ""
        cc = resp_headers.get("cache-control", "")
        hit = resp_headers.get("x-cache") or resp_headers.get("cf-cache-status") or ""
        cache_policy = (f"cache-control={cc or 'none'}; hit-state={hit or 'none'}"
                        if (cc or hit) else "")
        ctx = {
            "selector_location": selector, "id_predictability": pred,
            "sibling_endpoints": sibling_shapes, "identity_source": identity,
            "token_type": token_type, "token_reuse": token_reuse,
            "input_surface": surface, "cache_policy": cache_policy,
            "user_specific": "yes (authenticated request)" if (auth or cookie) else "",
        }
        return build_investigation(cls, ctx)

    def build_signal(self, row: dict, metadata_reasons: list[str]) -> dict | None:
        req_headers = _lower_headers(row.get("request_headers"))
        resp_headers = _lower_headers(row.get("response_headers"))
        req_body = _text(row.get("request_body"))
        resp_body = _text(row.get("response_body"))
        request_type = req_headers.get("content-type", "")
        response_type = _base_type(row.get("content_type") or resp_headers.get("content-type"))
        seed = Seed(
            request_id=int(row["request_id"]), method=(row.get("method") or "GET").upper(),
            url=row.get("url") or "", host=row.get("host") or "", path=row.get("path") or "/",
            headers=parse_headers(_text(row.get("request_headers"))), body=req_body,
            content_type=request_type, status=int(row.get("status_code") or 0),
            resp_headers=parse_headers(_text(row.get("response_headers"))), resp_body=resp_body,
            resp_content_type=response_type, resp_length=int(row.get("response_length") or len(resp_body)),
        )
        key = self.endpoint_key(row)
        card = build_card(seed)
        hypotheses = []
        reasons = list(metadata_reasons)

        # Large high-entropy (encrypted/opaque) outbound body: data leaving the browser that is
        # deliberately unreadable to a proxy/user — e.g. an encrypted device+behavioral fingerprint
        # POSTed to a third-party risk vendor. No baseline needed; one such POST is the signal.
        _raw_req = _bytes(row.get("request_body"))
        if len(_raw_req) >= 2048 and not _base_type(request_type).startswith(
                ("image/", "audio/", "video/", "multipart/")):
            if req_body.lstrip()[:1] not in "{[" and _shannon_entropy(_raw_req[:16384]) >= 7.2:
                # Third-party recipient = a registrable domain the user never navigated to (an
                # embedded collector). That is the exfil case and outranks first-party telemetry,
                # which posts opaque bodies to its own site (a navigated domain) - same size and
                # entropy, but benign by comparison. The iframe-isolation trick makes referer/
                # origin/sec-fetch useless here; the navigated-domain set is what survives it.
                recipient = _base_domain(key[0])
                if recipient in self.navigated_domains:
                    reasons.append("opaque_outbound_body")
                    hypotheses.append({
                        "family": "data-exfiltration",
                        "statement": (f"A {len(_raw_req)}-byte opaque/encrypted body is POSTed to {key[0]}, "
                                      "a site the user navigated to (first-party). Likely telemetry; "
                                      "confirm it is not harvesting more than the user consented to."),
                        "targets": ["outbound payload contents", "collection scope"],
                    })
                else:
                    reasons.append("encrypted_outbound_blob")
                    hypotheses.append({
                        "family": "data-exfiltration",
                        "statement": (f"A {len(_raw_req)}-byte high-entropy (opaque/encrypted) body is being "
                                      f"POSTed to {key[0]} — a third party the user never navigated to, "
                                      "unreadable to inspection. Verify what it collects and why it leaves."),
                        "targets": ["outbound payload contents", "third-party recipient", "collection scope"],
                    })

        # Learned lane (dormant unless an out-of-process classifier sidecar is wired). It
        # READS the untrusted response body over a local AF_UNIX socket and returns only a
        # label+score verdict: the raw body never enters the mailbox (boundary #6) and a unix
        # socket is IPC, not an HTTP request (boundary #3). Active -> a first-class reason that
        # can raise a signal and weigh attention; shadow -> annotate-only, never altering which
        # signals emit or how they rank (score-but-don't-act, for measuring against the baseline).
        lane_verdict = None
        # A NUL byte means the body is binary (font, wasm, protobuf, image) whatever the declared
        # type - a .woff2 served as application/octet-stream slipped past the type gate on the live
        # drive and was scanned as agent-readable text. Content sniffing, not a type allowlist.
        _lane_binary = b"\x00" in _bytes(row.get("response_body"))[:4096]
        if (self.lane is not None and resp_body and not _lane_binary
                and not response_type.startswith(_LANE_SKIP_TYPES)):
            lane_verdict = self.lane.classify(resp_body, response_type=response_type)
            if lane_verdict and lane_verdict.hit and self.lane.active:
                reasons.append("agent_injection_in_response")
                hypotheses.append({
                    "family": "agent-injection",
                    "statement": "The response body matches a learned agent-prompt-injection signature; "
                                 "content later rendered to an LLM-driven client may carry embedded instructions.",
                    "targets": ["downstream LLM/agent consumer", "content-rendering sink"],
                })
        if card:
            for vector in card["vectors"]:
                # H8: xss-stored is too broad on telemetry/logging endpoints — suppress there.
                if vector["route"] == "route:xss-stored" and _TELEMETRY.search(key[2]):
                    continue
                family_key = (key, vector["route"])
                if family_key in self.seen_endpoint_families and vector["route"].startswith("route:"):
                    continue
                self.seen_endpoint_families.add(family_key)
                hypotheses.append({
                    "family": vector["route"], "statement": vector["hypothesis"],
                    "targets": vector.get("targets") or [],
                })
                reasons.append(vector["route"])

        auth_present = bool(req_headers.get("authorization") or req_headers.get("cookie"))
        status = seed.status
        if seed.method not in _SAFE_METHODS and 200 <= status < 300 and not auth_present:
            reasons.append("successful_state_change_without_visible_auth")
            hypotheses.append({
                "family": "auth-boundary",
                "statement": "A state-changing request succeeded without a visible Cookie or Authorization header.",
                "targets": body_skeleton(req_body, request_type),
            })

        cache_control = resp_headers.get("cache-control", "").lower()
        cache_state = (resp_headers.get("x-cache", "") + " " + resp_headers.get("cf-cache-status", "")).upper()
        if auth_present and ("no-store" in cache_control or "private" in cache_control) and (
            "HIT" in cache_state or resp_headers.get("age")
        ):
            reasons.append("authenticated_cache_policy_contradiction")
            hypotheses.append({
                "family": "cache-boundary",
                "statement": "An authenticated response reports a cache hit or Age despite restrictive cache directives.",
                "targets": ["cache key", "authorization variance", "response personalization"],
            })

        acao = resp_headers.get("access-control-allow-origin", "")
        credentials = resp_headers.get("access-control-allow-credentials", "").lower() == "true"
        counterevidence: list[str] = []
        if "*" in acao and credentials:
            reasons.append("wildcard_credentialed_cors")
            hypotheses.append({
                "family": "cors-boundary",
                "statement": "The response combines wildcard-like origin permission with credentialed CORS.",
                "targets": ["Origin", "credential mode"],
            })
            counterevidence.append("Browsers reject a literal wildcard ACAO for credentialed reads; malformed multi-origin syntax may also be rejected.")
        if req_headers.get("origin") and acao == req_headers.get("origin"):
            counterevidence.append("The allowed origin exactly matches the captured request Origin and may be an intentional allowlist.")

        if _INTERNAL.search(resp_body + "\n" + _text(row.get("response_headers"))):
            reasons.append("internal_network_reference")
            hypotheses.append({
                "family": "internal-disclosure",
                "statement": "The response contains an internal network address or hostname.",
                "targets": ["response field context", "possible SSRF destinations"],
            })

        declared = response_type
        prefix = resp_body.lstrip()[:32].lower()
        if declared == "application/json" and prefix.startswith(("<html", "<!doctype")):
            reasons.append("declared_json_actual_html")
        if declared == "text/html" and prefix.startswith(("{", "[")):
            reasons.append("declared_html_actual_json")

        probe_text = (row.get("url") or "") + "\n" + req_body
        if _PROBE.search(probe_text):
            counterevidence.append("The request shape resembles an active probe; it may be prior testing rather than organic browser behavior.")

        # Outbound payload analysis: detect data aggregation and packaging patterns.
        if req_body and seed.method not in _SAFE_METHODS:
            req_ct = _base_type(request_type)
            if req_ct in ("application/json", "text/plain", ""):
                try:
                    parsed_req = json.loads(req_body)
                    if isinstance(parsed_req, list) and len(parsed_req) >= 5:
                        n = len(parsed_req)
                        reasons.append(f"batch_payload_detected_n={n}")
                        hypotheses.append({
                            "family": "data-aggregation",
                            "statement": (
                                f"The request body is a JSON array of {n} items — this endpoint receives "
                                "aggregated/batched data. Compromising this collector may yield broader "
                                "data access than attacking the primary site."
                            ),
                            "targets": ["array item schema", "new fields vs prior sends", "compression", "auth on this endpoint"],
                        })
                    # Request schema expansion: new top-level keys not seen before for this endpoint.
                    req_keys = set(_json_keys(req_body))
                    if req_keys and isinstance(parsed_req, dict):
                        seen = self.endpoint_req_key_sets.setdefault(key, set())
                        new_keys = req_keys - seen
                        if new_keys and seen:
                            reasons.append("request_schema_expansion")
                            hypotheses.append({
                                "family": "schema-expansion",
                                "statement": f"This endpoint's request body has new keys not seen in prior sends: {sorted(new_keys)[:8]}.",
                                "targets": sorted(new_keys)[:8],
                            })
                        seen.update(req_keys)
                except (ValueError, TypeError):
                    pass
            # Encoded blob: large opaque base64 string in POST body suggests packaged/obfuscated data.
            if _B64_BLOB.search(req_body):
                reasons.append("encoded_outbound_blob")
                hypotheses.append({
                    "family": "encoded-payload",
                    "statement": "The request body contains a large base64-encoded blob — may be compressed or obfuscated data being forwarded to a third party.",
                    "targets": ["blob decode", "compression format", "inner schema"],
                })

        # H4: JWT sensitive claims — decode JWT payload from URL/request body; flag privilege claims.
        # Raw token values are never placed in the envelope; only the claim names are reported.
        probe_for_jwt = (seed.url or "") + "\n" + (req_body or "")[:4096]
        jwt_match = _JWT_RE.search(probe_for_jwt)
        if jwt_match:
            try:
                payload_b64 = jwt_match.group(0).split(".")[1]
                pad = (-len(payload_b64)) % 4
                payload_b64 += "=" * pad
                jwt_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                if isinstance(jwt_payload, dict):
                    sensitive = [k for k in jwt_payload if str(k).lower() in _JWT_SENSITIVE_CLAIMS]
                    if sensitive:
                        reasons.append("jwt_sensitive_claim")
                        hypotheses.append({
                            "family": "jwt-claims",
                            "statement": f"JWT payload contains sensitive authorization claims: {sensitive[:8]}. Verify whether these claims can be manipulated or are validated server-side.",
                            "targets": sensitive[:8],
                        })
                    elif "sub" in jwt_payload or "iss" in jwt_payload:
                        reasons.append("jwt_in_url")
            except Exception:
                pass

        # H6: PII patterns in response body — email addresses and SSNs.
        # Only scan first 32KB; phone patterns excluded (too noisy on general browsing).
        if resp_body and not response_type.startswith(_STATIC_TYPES):
            body_sample = resp_body[:32768]
            pii_types = []
            # A single email in prose is not a leak; a *list* of distinct addresses is an
            # enumeration/dump. Card and SSN patterns are specific enough to fire on any hit.
            if len(set(_EMAIL_RE.findall(body_sample))) >= 3:
                pii_types.append("email-list")
            if _SSN_RE.search(body_sample):
                pii_types.append("ssn")
            if _CARD_RE.search(body_sample):
                pii_types.append("card")
            if pii_types:
                reasons.append("pii_in_response")
                hypotheses.append({
                    "family": "data-exposure",
                    "statement": f"Response body contains apparent PII patterns ({', '.join(pii_types)}). Verify whether this endpoint is expected to return this data and whether it is scoped to the requesting identity.",
                    "targets": pii_types,
                })

            # H12: Nuclei-borrowed response-body signatures — exposed artifacts, leaked
            # secrets, framework errors, management panels. Values/excerpts never emitted.
            sample = resp_body[:65536]
            file_kind = _sensitive_file_kind(sample, response_type, _bytes(row.get("response_body")))
            if file_kind:
                reasons.append("sensitive_file_exposure")
                hypotheses.append({
                    "family": "exposure",
                    "statement": f"Response body appears to be an exposed {file_kind}. "
                    "Verify it should be reachable by clients.",
                    "targets": [file_kind],
                })
            if response_type not in _JS_TYPES:  # JS bodies are covered by js_secret_literal
                secret_kinds = {n for n, pat in _BODY_SECRET_PATTERNS if pat.search(sample)}
                if any(not any(pk.search(m.group(0)) for _, pk in _PUBLISHABLE_KEY_PATTERNS)
                       for m in _CRED_FIELD_RE.finditer(sample)):
                    secret_kinds.add("credential field")  # skip publishable-key values
                secret_kinds = sorted(secret_kinds)
                if any(pat.search(sample) for _, pat in _PUBLISHABLE_KEY_PATTERNS):
                    reasons.append("publishable_client_key")
                if secret_kinds:
                    reasons.append("secret_in_response")
                    hypotheses.append({
                        "family": "exposure",
                        "statement": "Response body exposes secret material: " + "/".join(secret_kinds)
                        + ". Values are not emitted — retrieve the response to review.",
                        "targets": secret_kinds,
                    })
            err = _ERROR_BODY_RE.search(sample)
            if err:
                cat = _error_category(err.group(0))
                reasons.append("error_disclosure_in_body")
                hypotheses.append({
                    "family": "info-disclosure",
                    "statement": f"Response body contains a {cat}, which typically leaks framework, "
                    "file paths, or query structure. Excerpt not emitted.",
                    "targets": [cat],
                })
            panels = [name for name, pat in _PANEL_SIGS if pat.search(sample)]
            if panels:
                reasons.append("exposed_management_panel")
                hypotheses.append({
                    "family": "exposure",
                    "statement": "Response resembles an exposed management panel: " + ", ".join(panels)
                    + ". Confirm whether it requires authentication.",
                    "targets": panels,
                })
                for p in panels:  # panels are technologies too — feed the graph
                    self.infra_edges.append({"kind": "technology", "host": key[0], "tech": p})

            # Prometheus/OpenMetrics exposition served to clients — an internal /metrics endpoint
            # that should not be world-readable; it leaks counters, runtime shape, and hostnames.
            if response_type.startswith("text/plain") and sample.count("# HELP") >= 3 and "# TYPE" in sample:
                reasons.append("metrics_endpoint_exposed")
                hypotheses.append({
                    "family": "observability-exposure",
                    "statement": "Response is a Prometheus/OpenMetrics exposition, typically an "
                    "internal metrics endpoint that should not be reachable by clients.",
                    "targets": ["internal counters", "runtime topology"],
                })

            # HTML-DOM lane: developer tells in comments, and external scripts without SRI.
            if response_type == "text/html":
                if any(_SUSPICIOUS_COMMENT.search(c) for c in re.findall(r"<!--(.*?)-->", sample, re.S)):
                    reasons.append("suspicious_html_comment")
                    hypotheses.append({
                        "family": "info-disclosure",
                        "statement": "An HTML/JS comment contains a developer tell (TODO / credential / "
                        "admin / debug marker). Excerpt not emitted — retrieve to review.",
                        "targets": ["source comment"],
                    })
                for m in _SCRIPT_SRC.finditer(sample):
                    if re.match(r"(?:https?:)?//[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}", m.group(1), re.I) and "integrity=" not in m.group(0).lower():
                        reasons.append("untrusted_script_include")
                        hypotheses.append({
                            "family": "supply-chain",
                            "statement": "External script included without Subresource Integrity — a "
                            "compromised third-party host could inject code into this page.",
                            "targets": ["third-party script origin"],
                        })
                        break

        # H7: API-description documents (WADL/WSDL/OpenAPI/RAML) returned to clients.
        # They enumerate methods and parameters, and commonly leak internal backend
        # hostnames and framework versions — recon disclosure. Detect by content-type,
        # or by an OpenAPI/Swagger body signature served as generic JSON.
        if resp_body:
            head = resp_body[:4096]
            schema_kind = ""
            if "wadl" in response_type:
                schema_kind = "WADL"
            elif "wsdl" in response_type:
                schema_kind = "WSDL"
            elif "raml" in response_type:
                schema_kind = "RAML"
            elif "openapi" in response_type or "swagger" in response_type:
                schema_kind = "OpenAPI"
            elif response_type == "application/json" and '"paths"' in head and ('"openapi"' in head or '"swagger"' in head):
                schema_kind = "OpenAPI"
            if schema_kind:
                exposes: list[str] = []
                backends: list[str] = []
                frameworks: list[str] = []
                for m in _API_DESC_LEAK.finditer(resp_body[:16384]):
                    url_val = m.group(1) or m.group(3)
                    if url_val:
                        if "backend_or_internal_url" not in exposes:
                            exposes.append("backend_or_internal_url")
                        netloc = urlsplit(url_val if "//" in url_val else "//" + url_val).netloc.split("@")[-1]
                        host_only = netloc.split(":")[0]
                        if host_only and host_only != key[0] and host_only not in backends:
                            backends.append(host_only)
                    if m.group(2):
                        if "framework_version" not in exposes:
                            exposes.append("framework_version")
                        if m.group(2) not in frameworks:
                            frameworks.append(m.group(2))
                # Operator-graph facts (raw values) — sidecar only, never the mailbox.
                for b in backends[:5]:
                    self.infra_edges.append({"kind": "served_by", "host": key[0],
                                             "backend": b, "via": schema_kind})
                for fw in frameworks[:3]:
                    self.infra_edges.append({"kind": "framework", "host": key[0], "framework": fw})
                reasons.append("api_description_exposure")
                detail = f" and exposing {', '.join(exposes)}" if exposes else ""
                hypotheses.append({
                    "family": "info-disclosure",
                    "statement": f"Endpoint returns a {schema_kind} API-description document, enumerating methods and parameters{detail}. Verify whether this schema should be reachable by clients.",
                    "targets": [schema_kind] + exposes,
                })

        # Script source tracing + JS intel: index host literals, and mine the bundle for
        # secrets, endpoint/path disclosure, exposed source maps, and auth-mechanism hints.
        script_url = seed.url
        if response_type in _JS_TYPES:
            js = resp_body[:262144]  # cap scan at 256KB of JS
            for m in _HOST_LITERAL.finditer(js[:131072]):
                ref = m.group(1).lower()
                if ref != key[0] and "." in ref:
                    self.script_host_index[ref].add(script_url)
            js_intel: list[str] = []
            secret_kinds = sorted({name for name, pat in _JS_SECRET_PATTERNS if pat.search(js)})
            if any(pat.search(js) for _, pat in _PUBLISHABLE_KEY_PATTERNS):
                reasons.append("publishable_client_key")
                js_intel.append("publishable-key")
            if secret_kinds:
                reasons.append("js_secret_literal")
                js_intel.append("secret:" + "/".join(secret_kinds))
            endpoints = sorted({m.group(1) for m in _JS_ENDPOINT_RE.finditer(js)})
            if len(endpoints) >= 3:
                reasons.append("js_endpoint_disclosure")
                js_intel.append(f"endpoints:{len(endpoints)}")
            if _JS_SOURCEMAP_RE.search(js):
                reasons.append("js_sourcemap_disclosure")
                js_intel.append("sourcemap")
            auth_kinds = sorted({name for name, pat in _JS_AUTH_PATTERNS if pat.search(js)})
            if auth_kinds:
                reasons.append("js_auth_mechanism")
                js_intel.append("auth:" + "/".join(auth_kinds))
            # Consolidated dissection (ADR-0006): params / GraphQL / routes + hidden surface.
            _intel = dissect_js(resp_body, seed.url)
            if _intel["params"]:
                js_intel.append(f"params:{len(_intel['params'])}")
            if _intel["graphql"]:
                reasons.append("js_graphql_ops")
                js_intel.append("graphql:" + ",".join(_intel["graphql"][:6]))
            if _intel["routes"]:
                js_intel.append(f"routes:{len(_intel['routes'])}")
            _hidden = self._hidden_js_endpoints(_intel["endpoints"], key[0])
            if _hidden:
                reasons.append("js_hidden_endpoint")
                js_intel.append(f"hidden-endpoints:{len(_hidden)}")
                hypotheses.append({
                    "family": "attack-surface",
                    "statement": (f"JS bundle declares {len(_hidden)} endpoint(s) not seen in "
                                  "observed traffic — undiscovered surface to enumerate and authz-test."),
                    "targets": _hidden[:12],
                })
            if js_intel:
                targets = list(js_intel)
                if len(endpoints) >= 3:
                    targets += ["path:" + p for p in endpoints[:8]]
                hypotheses.append({
                    "family": "js-intel",
                    "statement": "JavaScript bundle exposes " + "; ".join(js_intel)
                    + ". Secret values are not emitted — retrieve the bundle to review specifics.",
                    "targets": targets,
                })
        source_scripts = sorted(self.script_host_index.get(key[0], set()))[:5]

        # Enrich header-derived reasons with the specific (non-sensitive) header NAMES.
        if "client_trust_header" in reasons:
            trust_names = sorted(_CLIENT_TRUST_HEADERS & set(req_headers))
            hypotheses.append({
                "family": "request-tampering",
                "statement": "Request carries client-controllable trust/routing header(s): "
                + ", ".join(trust_names) + ". If the app honors them this is an ACL-bypass, "
                "cache-poisoning, or SSRF primitive. Values withheld.",
                "targets": trust_names,
            })
        if "internal_header_disclosure" in reasons:
            leaked = sorted(n for n in resp_headers if _INTERNAL_HEADER_RE.search(n))
            hypotheses.append({
                "family": "info-disclosure",
                "statement": "Response leaks internal-infrastructure header(s): " + ", ".join(leaked)
                + " (pod IP / backend / instance / worker / mesh). Verify these are not client-facing.",
                "targets": leaked,
            })

        reasons = list(dict.fromkeys(reasons))
        if not reasons:
            return None
        hypotheses = list({json.dumps(h, sort_keys=True): h for h in hypotheses}.values())
        baseline = self.baselines[key]
        req_hash = hashlib.sha256(_bytes(row.get("request_body"))).hexdigest()
        resp_hash = hashlib.sha256(_bytes(row.get("response_body"))).hexdigest()
        url_hash = hashlib.sha256((row.get("url") or "").encode()).hexdigest()
        pair_sig = hashlib.sha256(json.dumps([
            key, status, request_type, response_type, url_hash, req_hash, resp_hash, sorted(reasons),
        ], sort_keys=True).encode()).hexdigest()
        self.seen_pairs[pair_sig] += 1
        if self.seen_pairs[pair_sig] > 1:
            return None

        # Object-identifier co-occurrence (ADR-0004): does this request's id also select an
        # object at OTHER endpoints (siblings), or did it first appear in another endpoint's
        # response (data-flow)? Only hashes + structural endpoint keys are used — no raw
        # value or raw path enters the index, the mailbox, or the graph.
        _req_ids = extract_request_ids(seed.url)
        _rel = self.value_graph.relate(_req_ids, key)
        self.value_graph.record(_req_ids, key, "request")
        self.value_graph.record(extract_body_ids(resp_body, response_type), key, "response")
        if _rel["origins"]:
            reasons.append("idor_id_from_response")
        elif _rel["siblings"]:
            reasons.append("idor_shared_object_id")
        if _rel["siblings"] or _rel["origins"]:
            _sib_eps = sorted({ep for eps in _rel["siblings"].values() for ep in eps})
            _org_eps = sorted({ep for eps in _rel["origins"].values() for ep in eps})
            _shapes = [f"{m} {h}{ps}" for (h, m, ps) in (_org_eps or _sib_eps)][:6]
            hypotheses.append({
                "family": "broken-object-level-authorization",
                "statement": (
                    f"An object identifier used here also appears at {len(_sib_eps)} other "
                    f"endpoint(s)" + (" and first appeared in another endpoint's response"
                    if _org_eps else "") + f": {_shapes}. If each handler looks the object up "
                    "directly, one may skip the ownership check the others enforce — verify "
                    "authorization independently at each."),
                "targets": ["object ownership check", "each sibling handler"],
            })
            for _h, _eps in {**_rel["siblings"], **_rel["origins"]}.items():
                self.dataflow_edges.append({
                    "id_hash": _h, "this": [key[0], key[1], key[2]],
                    "others": [[e[0], e[1], e[2]] for e in _eps],
                    "provenance": _h in _rel["origins"],
                })

        # Directed investigation graph for this signal's vuln class (ADR-0005): machine
        # facts filled from what the engine knows, incl. the value-graph siblings
        # ("what else shares this assumption?"); llm nodes stay open for the gate.
        _sib_shapes = sorted({f"{m} {h}{ps}"
                              for eps in {**_rel["siblings"], **_rel["origins"]}.values()
                              for (h, m, ps) in eps})
        _inv = self._investigation_for(reasons, seed.url, req_headers, resp_headers,
                                       request_type, _req_ids, _sib_shapes)

        weights = []
        for r in reasons:
            w = _REASON_WEIGHT.get(r, 0)
            if r.startswith("response_length_outlier_z=") or r.startswith("outbound_request_size_spike_z="):
                try:
                    w += min(50, int(float(r.split("=")[1])) * 5)
                except (ValueError, IndexError):
                    pass
            elif r.startswith("batch_payload_detected_n="):
                try:
                    w += _REASON_WEIGHT["batch_payload_detected"] + min(25, int(r.split("=")[1]) // 2)
                except (ValueError, IndexError):
                    pass
            weights.append(w)
        # De-saturate: strongest reason dominates, each further reason adds a halving fraction, so
        # a pile of low-precision reasons cannot outrank one high-precision reason. Then dampen
        # structurally-recognizable third-party noise (ad/RTB/analytics beacons, training labs).
        weights.sort(reverse=True)
        score = sum(w * (0.5 ** i) for i, w in enumerate(weights))
        # The ad/beacon/lab dampener applies only when nothing high-precision is present.
        if not (set(reasons) & _PRECISE_OVERRIDE):
            score *= _noise_factor(key[0], row.get("path") or "")
        attention = round(min(100.0, score), 1)

        selected_response_headers = {
            name: resp_headers[name] for name in (
                "content-type", "cache-control", "age", "x-cache", "cf-cache-status",
                "access-control-allow-origin", "access-control-allow-credentials", "server",
                "x-powered-by", "via",
            ) if name in resp_headers
        }
        envelope = {
            "schema": "swarmie.signal.v1",
            "request_id": seed.request_id,
            "endpoint": {"host": key[0], "method": key[1], "path_shape": key[2],
                         "ip_address": (row.get("ip_address") or "")},
            "observation": {
                "reasons": reasons,
                "request": {
                    "header_names": sorted(req_headers)[:60], "auth_present": auth_present,
                    "content_type": _base_type(request_type),
                    "query_names": sorted(filter(None, (row.get("param_names") or "").split(",")))[:40],
                    "body_keys": body_skeleton(req_body, request_type),
                    "body_sha256": req_hash,
                },
                "response": {
                    "status": status, "content_type": response_type,
                    "length": seed.resp_length, "headers": selected_response_headers,
                    "json_keys": _json_keys(row.get("response_body")), "body_sha256": resp_hash,
                    "fingerprint": (row.get("fingerprint") or ""),
                },
                "baseline": {
                    "endpoint_observations": baseline.count,
                    "statuses": dict(baseline.statuses.most_common(8)),
                    "content_types": dict(baseline.content_types.most_common(8)),
                },
            },
            "hypotheses": hypotheses,
            "counterevidence": counterevidence,
            "attention": {
                "score": attention,
            },
            "source_scripts": source_scripts,
            "questions": HUNTER_QUESTIONS,
            "interrogation": _build_interrogation(reasons, key[0], self.seen_endpoint_families),
            "disposition": "LLM_REVIEW_REQUIRED",
        }
        if lane_verdict is not None and lane_verdict.hit:
            # Redacted verdict only (label/score/model/shadow) — never the body text.
            envelope["learned"] = [lane_verdict.as_signal(shadow=not self.lane.active)]
        if _inv is not None:
            envelope["investigation"] = _inv
        return envelope


_META_SELECT = """
SELECT t.request_id,t.timestamp,t.method,t.host,t.path,t.query,t.param_count,t.param_names,
       t.status_code,t.response_length,t.content_type,t.extension,t.protocol,t.url,t.request_hash
FROM http_traffic t JOIN http_messages m USING(request_id)
"""


def open_capture(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _append_jsonl(path: Path, records: list[dict]) -> None:
    if not records:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        payload = b"".join((json.dumps(r, sort_keys=True) + "\n").encode() for r in records)
        while payload:
            payload = payload[os.write(fd, payload):]
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _save_checkpoint(path: Path | None, source: str, cursor: int) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({"schema": 1, "source": str(Path(source).resolve()), "request_id": cursor}) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        payload = data.encode()
        while payload:
            payload = payload[os.write(fd, payload):]
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)


def _register_mailbox(mailbox: Path) -> None:
    """Self-arm the response gate on whatever mailbox this run actually wrote.

    The gate previously read one hand-configured path, so a new scan into a new mailbox was simply
    invisible to it — the operator could (and did) run a fresh scan and the Stop hook stayed clear
    all day. Every run now registers its own mailbox, so the gate covers what was actually emitted
    instead of what someone remembered to point it at. Sidecar only: never the capture DB.
    """
    root = Path(__file__).resolve().parent.parent / ".swarmie"
    if not root.is_dir():
        return  # no active investigation in this checkout -> stay dormant
    # Mailboxes under the OS temp dir are transient by construction (pytest tmp_path, scratch
    # runs). Registering them buried the gate under dozens of 1-6 signal test artifacts, which
    # is noise that trains the operator to ignore the gate - the opposite of the point.
    try:
        if mailbox.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()):
            return
    except (OSError, ValueError):
        pass
    reg = root / "mailboxes.json"
    try:
        known = json.loads(reg.read_text()) if reg.exists() else []
    except (OSError, ValueError):
        known = []
    path = str(mailbox.resolve())
    if path in known:
        return
    known.append(path)
    tmp = reg.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(sorted(known), indent=2))
    os.chmod(tmp, 0o600)
    os.replace(tmp, reg)


@dataclasses.dataclass
class StepResult:
    scanned: int = 0
    eligible: int = 0
    hydrated: int = 0
    emitted: int = 0
    duplicates: int = 0
    sampled_out: int = 0
    cursor: int = 0
    caught_up: bool = False


class PassiveTailer:
    def __init__(self, source: str, mailbox: str, *, checkpoint: str | None = None,
                 start: str = "tail", scope_hosts: Iterable[str] = (), batch_size: int = 2000,
                 body_cap: int = 65536, hydrate_limit: int = 256,
                 overlap: int = 128, warmup: int = 50000,
                 injection_socket: str | None = None, injection_active: bool = False,
                 injection_threshold: float = 0.5, hydrate_all: bool = False,
                 interest_socket: str | None = None, interest_active: bool = False):
        self.source = source
        self.mailbox = Path(mailbox)
        self.checkpoint = Path(checkpoint) if checkpoint else None
        self.batch_size = max(1, batch_size)
        self.body_cap = max(1024, body_cap)
        self.hydrate_limit = max(1, hydrate_limit)
        self.overlap = max(0, min(overlap, self.batch_size // 2))
        self.conn = open_capture(source)
        # Optional enrichment columns — present in some capture backends, absent in others.
        # Detected once so the hydration SELECT degrades gracefully instead of erroring.
        _cols = {r[1] for r in self.conn.execute("PRAGMA table_info(http_traffic)")}
        self._opt_cols = [c for c in ("ip_address", "fingerprint") if c in _cols]
        lane = make_lane(injection_socket, active=injection_active, threshold=injection_threshold)
        self.engine = SignalEngine(scope_hosts, lane=lane, full_coverage=hydrate_all)
        # Perception spine (ADR-0003): out-of-process unsupervised interest scorer.
        # None => dormant; the pipeline behaves exactly as before it was wired.
        self.interest_lane = make_interest_lane(interest_socket, active=interest_active)
        # Operator-side investigation graph (sidecar, never the capture DB). Accumulates
        # infra nodes (host, backend, framework, endpoint_family) and edges across runs so a
        # finding can be pivoted: host -> served_by -> backend -> framework, and neighbours.
        self.graph_path = Path(str(self.mailbox) + ".graph.json")
        self.graph: dict = {"nodes": {}, "edges": []}
        self._edge_keys: set[str] = set()
        if self.graph_path.exists():
            try:
                loaded = json.loads(self.graph_path.read_text())
                self.graph = {"nodes": loaded.get("nodes", {}), "edges": loaded.get("edges", [])}
                self._edge_keys = {f'{e["from"]}|{e["rel"]}|{e["to"]}' for e in self.graph["edges"]}
            except (ValueError, OSError, KeyError):
                self.graph = {"nodes": {}, "edges": []}
        self.recent = collections.deque(maxlen=max(256, self.overlap * 4))
        self.recent_set: set[int] = set()
        self.cursor = self._initial_cursor(start)
        if warmup and self.cursor:
            rows = self.conn.execute(
                _META_SELECT + " WHERE t.request_id <= ? ORDER BY t.request_id DESC LIMIT ?",
                (self.cursor, warmup),
            ).fetchall()
            for row in reversed(rows):
                self.engine.observe_metadata(dict(row), warmup=True)
        if self.cursor and self.overlap:
            recent = self.conn.execute(
                "SELECT m.request_id FROM http_messages m WHERE m.request_id <= ? "
                "ORDER BY m.request_id DESC LIMIT ?", (self.cursor, self.overlap),
            ).fetchall()
            for row in reversed(recent):
                self._remember(int(row[0]))

    def _score_interest(self, envelopes: list[dict]) -> None:
        """Batch-score interest for this step's envelopes and fuse into a priority.

        One socket round-trip per step (the columnar batch); fail-open — a dormant or
        erroring lane leaves every envelope byte-identical to the symbolic pipeline. The
        top-K by fused priority are flagged so a driver can spend the scarce LLM there
        first without dropping the rest.
        """
        if self.interest_lane is None or not envelopes:
            return
        vectors = [feature_list(env) for env in envelopes]
        scores = self.interest_lane.score_batch(vectors, FEATURE_NAMES)
        if scores is None or len(scores) != len(envelopes):
            return  # fail-open: no perception block added
        for env, s in zip(envelopes, scores):
            priority = fuse_interest(env.get("attention", {}).get("score", 0.0), s)
            env["perception"] = {"interest": round(float(s), 4), "priority": round(priority, 4),
                                 "model": "interest-heuristic-v1"}
        keep = select_top_k([(env["request_id"], env["perception"]["priority"]) for env in envelopes])
        for env in envelopes:
            env["perception"]["top_k"] = env["request_id"] in keep

    def _initial_cursor(self, start: str) -> int:
        if self.checkpoint and self.checkpoint.exists():
            try:
                saved = json.loads(self.checkpoint.read_text())
                if saved.get("source") == str(Path(self.source).resolve()):
                    return int(saved.get("request_id") or 0)
            except (OSError, ValueError, TypeError):
                pass
        if start == "tail":
            return int(self.conn.execute("SELECT COALESCE(MAX(request_id),0) FROM http_traffic").fetchone()[0])
        return max(0, int(start))

    def _remember(self, request_id: int) -> None:
        if len(self.recent) == self.recent.maxlen:
            self.recent_set.discard(self.recent[0])
        self.recent.append(request_id)
        self.recent_set.add(request_id)

    def _load_alpn(self) -> None:
        """Refresh host->ALPN. Primary source is http_traffic.alpn, which some capture backends persist
        from the upstream MITM handshake on every proxied request (fully passive, no probe);
        raw_socket_traffic is a secondary source populated only by an active raw-socket tool.
        Both are optional — absent columns/tables leave the HTTP-version lane dormant."""
        m: dict[str, set] = {}
        for sql in (
            "SELECT host, alpn FROM http_traffic WHERE TRIM(COALESCE(alpn,'')) != ''",
            "SELECT target_host, alpn_negotiated FROM raw_socket_traffic "
            "WHERE TRIM(COALESCE(alpn_negotiated,'')) != ''",
        ):
            try:
                rows = self.conn.execute(sql).fetchall()
            except sqlite3.OperationalError:
                continue
            for host, alpn in rows:
                h = (host or "").lower().split(":")[0]
                if h:
                    m.setdefault(h, set()).add((alpn or "").lower())
        self.engine.host_alpn = m

    def step(self) -> StepResult:
        self._load_alpn()
        after = max(0, self.cursor - self.overlap)
        rows = self.conn.execute(
            _META_SELECT + " WHERE t.request_id > ? ORDER BY t.request_id ASC LIMIT ?",
            (after, self.batch_size + self.overlap),
        ).fetchall()
        fresh = [dict(r) for r in rows if int(r["request_id"]) not in self.recent_set and int(r["request_id"]) > after]
        prepared: dict[int, tuple[dict, list[str]]] = {}
        for row in fresh:
            rid = int(row["request_id"])
            reasons = self.engine.observe_metadata(row)
            prepared[rid] = (row, reasons)
            self.cursor = max(self.cursor, rid)
            self._remember(rid)

        # Header lane is cheap enough for every dynamic/interesting pair and catches
        # policy contradictions that status/type/length baselines cannot see.
        header_ids = [rid for rid, (row, reasons) in prepared.items()
                      if reasons or not _base_type(row.get("content_type")).startswith(_STATIC_TYPES)]
        for offset in range(0, len(header_ids), 400):
            ids = header_ids[offset:offset + 400]
            marks = ",".join("?" for _ in ids)
            query = f"""
                SELECT request_id,substr(request_headers,1,65536) request_headers,
                       substr(response_headers,1,65536) response_headers,
                       LENGTH(request_body) AS req_body_len
                FROM http_messages WHERE request_id IN ({marks})
            """
            for raw in self.conn.execute(query, ids):
                row, reasons = prepared[int(raw["request_id"])]
                row.update(dict(raw))
                reasons.extend(self.engine.header_reasons(row))

        candidates: list[tuple[int, list[str]]] = []
        for rid, (row, reasons) in prepared.items():
            reasons = list(dict.fromkeys(reasons))
            if reasons or self.engine.should_sample_body(row):
                candidates.append((rid, reasons))
        eligible_count = len(candidates)

        strong = {
            "authenticated_cache_policy_contradiction", "server_error_response",
            "new_status_for_endpoint", "new_content_type_for_endpoint",
            "wildcard_credentialed_cors", "version_disclosure_header",
        }
        # host-cap bypass requires higher bar: ambient CDN version headers / CORS alone don't qualify
        critical = {"authenticated_cache_policy_contradiction", "server_error_response"}
        def rank(candidate):
            rid, reasons = candidate
            score = sum(_REASON_WEIGHT.get(r, 0) for r in reasons)
            # JS bundles carry no metadata reasons but are the richest intel surface
            # (secrets, endpoint/auth disclosure, source maps). Give them a modest hydration
            # bonus so a few scan per batch; build_signal emits only if intel is found.
            if _base_type(prepared[rid][0].get("content_type")) in _JS_TYPES:
                score += 12
            for r in reasons:
                if r.startswith("response_length_outlier_z=") or r.startswith("outbound_request_size_spike_z="):
                    try:
                        score += min(50, int(float(r.split("=")[1])) * 5)
                    except (ValueError, IndexError):
                        pass
                elif r.startswith("batch_payload_detected_n="):
                    try:
                        score += _REASON_WEIGHT["batch_payload_detected"] + min(25, int(r.split("=")[1]) // 2)
                    except (ValueError, IndexError):
                        pass
            return (-score, rid)

        selected: list[tuple[int, list[str]]] = []
        endpoint_counts: collections.Counter = collections.Counter()
        host_counts: collections.Counter = collections.Counter()
        js_host_counts: collections.Counter = collections.Counter()
        for candidate in sorted(candidates, key=rank):
            rid, reasons = candidate
            row = prepared[rid][0]
            key = self.engine.endpoint_key(row)
            host = (row.get("host") or "").lower()
            is_js = _base_type(row.get("content_type")) in _JS_TYPES
            is_strong = bool(strong.intersection(reasons)) or any(r.startswith("response_length_outlier") for r in reasons)
            is_critical = bool(critical.intersection(reasons))
            # full-coverage bypasses the per-endpoint/per-host diversity caps (single-host eval
            # corpora and bounded assessments want every eligible pair, not a diverse subset).
            if not self.engine.full_coverage:
                if endpoint_counts[key] >= 2 and not is_strong:
                    continue
                # JS bundles each carry unique intel (distinct source files), so a CDN host that
                # serves hundreds gets a wider per-host allowance than the tight metadata-reason
                # diversity cap — otherwise the host-cap re-collapses what the sampling budget let in.
                if is_js:
                    if js_host_counts[host] >= _JS_PER_HOST_CAP:
                        continue
                elif host_counts[host] >= 5 and not is_critical:
                    continue
            selected.append(candidate)
            endpoint_counts[key] += 1
            (js_host_counts if is_js else host_counts)[host] += 1
            if len(selected) >= self.hydrate_limit:
                break
        candidates = selected

        envelopes: list[dict] = []
        before_dupes = sum(self.engine.seen_pairs.values()) - len(self.engine.seen_pairs)
        reason_by_id = dict(candidates)
        for offset in range(0, len(candidates), 200):
            ids = [rid for rid, _ in candidates[offset:offset + 200]]
            marks = ",".join("?" for _ in ids)
            opt = "".join(f"t.{c}," for c in self._opt_cols)
            query = f"""
                SELECT t.request_id,t.method,t.host,t.path,t.url,t.param_names,t.status_code,
                       t.response_length,t.content_type,t.protocol,{opt}
                       substr(m.request_headers,1,65536) request_headers,
                       substr(m.request_body,1,?) request_body,
                       substr(m.response_headers,1,65536) response_headers,
                       substr(m.response_body,1,?) response_body
                FROM http_traffic t JOIN http_messages m USING(request_id)
                WHERE t.request_id IN ({marks}) ORDER BY t.request_id
            """
            params = [self.body_cap, self.body_cap, *ids]
            for raw in self.conn.execute(query, params):
                envelope = self.engine.build_signal(dict(raw), reason_by_id[int(raw["request_id"])])
                if envelope:
                    envelopes.append(envelope)
        self._score_interest(envelopes)
        _append_jsonl(self.mailbox, envelopes)
        if envelopes:
            _register_mailbox(self.mailbox)
        self._update_graph(envelopes)
        _save_checkpoint(self.checkpoint, self.source, self.cursor)
        after_dupes = sum(self.engine.seen_pairs.values()) - len(self.engine.seen_pairs)
        return StepResult(
            scanned=len(fresh), eligible=eligible_count, hydrated=len(candidates), emitted=len(envelopes),
            duplicates=after_dupes - before_dupes, cursor=self.cursor,
            sampled_out=max(0, eligible_count - len(candidates)),
            caught_up=len(rows) < self.batch_size + self.overlap,
        )

    def _update_graph(self, envelopes: list[dict]) -> None:
        """Fold this batch's signals + drained infra facts into the investigation graph."""
        nodes = self.graph["nodes"]
        edges = self.graph["edges"]

        def node(nid: str, ntype: str) -> dict:
            n = nodes.get(nid)
            if n is None:
                n = nodes[nid] = {"type": ntype, "signals": 0, "max_score": 0, "reasons": {}}
            return n

        def edge(a: str, b: str, rel: str) -> None:
            k = f"{a}|{rel}|{b}"
            if k not in self._edge_keys:
                self._edge_keys.add(k)
                edges.append({"from": a, "to": b, "rel": rel})

        for env in envelopes:
            ep = env.get("endpoint", {})
            host = (ep.get("host") or "").lower()
            if not host:
                continue
            hid = "host:" + host
            hn = node(hid, "host")
            hn["signals"] += 1
            hn["max_score"] = max(hn["max_score"], env.get("attention", {}).get("score", 0))
            for r in env.get("observation", {}).get("reasons", []):
                hn["reasons"][r] = hn["reasons"].get(r, 0) + 1
            # host -> resolved IP: distinct hostnames sharing one IP reveal shared infra/origin
            # (shadow hosts, origin behind a CDN, one backend serving several brands).
            ip = (ep.get("ip_address") or "").strip()
            if ip:
                iid = "ip:" + ip
                node(iid, "ip")
                edge(hid, iid, "resolves_to")
            segs = [s for s in (ep.get("path_shape") or "").split("/") if s][:2]
            fid = None
            if segs:
                fid = "endpoint_family:" + host + "/" + "/".join(segs)
                node(fid, "endpoint_family")
                edge(hid, fid, "serves")
            # response fingerprint: the same shape reached from different endpoints marks a
            # templated/catch-all response — an enumeration oracle worth a second look.
            resp = env.get("observation", {}).get("response", {})
            fp = (resp.get("fingerprint") or "").strip()
            if fp:
                fpid = "fingerprint:" + fp
                node(fpid, "response_shape")
                edge(fid or hid, fpid, "responds_as")
            # Via proxy chain: host -> transits -> each intermediary hop (Google edge, Varnish
            # layers, CloudFront). Long chains are elevated request-smuggling surface.
            via = (resp.get("headers", {}) or {}).get("via", "")
            for hop in via.split(","):
                name = hop.strip().split(" ")[-1].strip()
                if name and not name[0].isdigit() and 1 < len(name) < 40:
                    pid = "proxy:" + name.lower()
                    node(pid, "proxy")
                    edge(hid, pid, "transits")

        # Raw backend/framework facts recovered from schema docs — sidecar only.
        for fact in self.engine.infra_edges:
            host = (fact.get("host") or "").lower()
            if not host:
                continue
            hid = "host:" + host
            node(hid, "host")
            if fact["kind"] == "served_by" and fact.get("backend"):
                bid = "backend:" + fact["backend"].lower()
                node(bid, "backend")
                edge(hid, bid, "served_by")
            elif fact["kind"] == "framework" and fact.get("framework"):
                fwid = "framework:" + fact["framework"]
                node(fwid, "framework")
                edge(hid, fwid, "framework")
            elif fact["kind"] == "technology" and fact.get("tech"):
                tid = "technology:" + fact["tech"]
                node(tid, "technology")
                edge(hid, tid, "runs")
        self.engine.infra_edges.clear()

        # Object-identifier edges (ADR-0004): endpoints that share an object id, plus
        # data-flow when an id first appeared in another endpoint's response. Hashes only.
        for fact in self.engine.dataflow_edges:
            oid = "object:" + fact["id_hash"]
            node(oid, "object")
            th, tm, tps = fact["this"]
            tid = f"endpoint:{th} {tm} {tps}"
            node(tid, "endpoint")
            edge(tid, oid, "references")
            for oh, om, ops in fact["others"]:
                eid = f"endpoint:{oh} {om} {ops}"
                node(eid, "endpoint")
                edge(eid, oid, "references")
                if fact["provenance"]:
                    edge(eid, tid, "data_flow")
        self.engine.dataflow_edges.clear()

        # Cross-domain Referer edges: who embeds/pulls in whom. This is the relational signal
        # point-detection cannot see - a first-party page loading a third-party collector. The
        # engine keeps this graph across the whole session; fold it in (edge() dedups) so the
        # sidecar can pivot on embedding structure, not just per-host signal counts.
        for src, dst in self.engine.referer_graph:
            if not src or not dst or _base_domain(src) == _base_domain(dst):
                continue
            sid, did = "host:" + src, "host:" + dst
            node(sid, "host"); node(did, "host")
            edge(sid, did, "embeds")

        if nodes:
            tmp = Path(str(self.graph_path) + ".tmp")
            tmp.write_text(json.dumps(self.graph, sort_keys=True))
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.graph_path)

    def close(self) -> None:
        self.conn.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only HTTP-pair tailer that emits LLM hypotheses")
    ap.add_argument("--source", required=True, help="http_traffic capture SQLite database")
    ap.add_argument("--mailbox", default=".swarmie/signals.jsonl")
    ap.add_argument("--checkpoint", default=".swarmie/checkpoint.json")
    ap.add_argument("--start", default="tail", help="tail, 0, or a request_id")
    ap.add_argument("--scope", action="append", default=[], help="in-scope host (repeatable; ranking only)")
    ap.add_argument("--batch", type=int, default=2000)
    ap.add_argument("--body-cap", type=int, default=65536)
    ap.add_argument("--hydrate-limit", type=int, default=256, help="maximum body pairs per metadata batch")
    ap.add_argument("--warmup", type=int, default=50000)
    ap.add_argument("--poll", type=float, default=0.25)
    ap.add_argument("--once", action="store_true", help="drain current backlog and exit")
    ap.add_argument("--max-rows", type=int, default=0, help="stop after N new rows (0 = caught up)")
    ap.add_argument("--injection-socket", default=os.environ.get("SWARMIE_INJECTION_SOCKET"),
                    help="AF_UNIX path to a prompt-injection classifier sidecar (default: dormant)")
    ap.add_argument("--injection-active", action="store_true",
                    help="promote injection verdicts to first-class signals (default: shadow/annotate-only)")
    ap.add_argument("--injection-threshold", type=float, default=0.5,
                    help="minimum classifier score to treat as a hit")
    ap.add_argument("--hydrate-all", action="store_true",
                    help="disable body-sampling cap; hydrate every non-static pair (bounded assessments/eval)")
    ap.add_argument("--interest-socket", default=os.environ.get("SWARMIE_INTEREST_SOCKET"),
                    help="AF_UNIX path to the perception interest-scorer sidecar (default: dormant)")
    ap.add_argument("--interest-active", action="store_true",
                    help="let interest raise/rank signals (default: shadow/annotate-only)")
    args = ap.parse_args(argv)
    tailer = PassiveTailer(
        args.source, args.mailbox, checkpoint=args.checkpoint, start=args.start,
        scope_hosts=args.scope, batch_size=args.batch, body_cap=args.body_cap,
        hydrate_limit=args.hydrate_limit, warmup=args.warmup,
        injection_socket=args.injection_socket, injection_active=args.injection_active,
        injection_threshold=args.injection_threshold, hydrate_all=args.hydrate_all,
        interest_socket=args.interest_socket, interest_active=args.interest_active,
    )
    totals = StepResult(cursor=tailer.cursor)
    started = time.monotonic()
    try:
        while True:
            step = tailer.step()
            for field in ("scanned", "eligible", "hydrated", "emitted", "duplicates", "sampled_out"):
                setattr(totals, field, getattr(totals, field) + getattr(step, field))
            totals.cursor = step.cursor
            if args.max_rows and totals.scanned >= args.max_rows:
                break
            if args.once and step.caught_up:
                break
            if not args.once and step.caught_up:
                time.sleep(max(0.01, args.poll))
    except KeyboardInterrupt:
        pass
    finally:
        tailer.close()
    elapsed = max(1e-9, time.monotonic() - started)
    print(json.dumps({
        **dataclasses.asdict(totals), "elapsed_seconds": round(elapsed, 3),
        "metadata_rows_per_second": round(totals.scanned / elapsed, 1),
        "source_mode": "read-only", "mailbox": str(Path(args.mailbox).resolve()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
