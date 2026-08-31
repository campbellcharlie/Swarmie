"""Shared feature layer for the tier-1 heuristic scorer.

One vocabulary of injection "tells" (imperative override, role-switch, system-prompt
leak, exfil directive, agent redirect, hidden markers, urgency) plus a few scalar
features. Tier 1 hand-weights these into a logistic score; the same features double as
interpretable spans for the operator.

Stdlib only. Agnostic: nothing here references any target, product, or environment.
"""
from __future__ import annotations

import re

# Each family: a compiled pattern whose match-count is one feature. Ordered; the order is
# the feature order for the linear model.
_FAMILY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("override", re.compile(
        r"(?i)\b(?:ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|preceding|all|any|the)\b[^.\n]{0,30}?"
        r"\b(?:instruction|prompt|direction|rule|guideline|context|message)s?\b")),
    ("role_switch", re.compile(
        r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on|"
        r"new\s+(?:persona|role|character)|developer\s+mode|jailbreak|\bDAN\b|"
        r"roleplay\s+as|simulate\s+a)\b")),
    ("system_leak", re.compile(
        r"(?i)\b(?:system\s+prompt|your\s+(?:instruction|directive|system|initial)|"
        r"reveal\s+your|print\s+your|repeat\s+the\s+(?:words|text|prompt)\s+above|"
        r"what\s+(?:are|were)\s+your\s+instructions|initial\s+prompt)\b")),
    ("exfil", re.compile(
        r"(?i)\b(?:send|exfiltrate|forward|email|post|upload|transmit|leak|paste|report)\b"
        r"[^.\n]{0,40}?\b(?:context|history|conversation|api[\s_-]?key|secret|token|"
        r"credential|password|cookie|session|memory)s?\b")),
    ("redirect", re.compile(
        r"(?i)\b(?:navigate\s+to|go\s+to|browse\s+to|make\s+a\s+request\s+to|fetch|curl|"
        r"open\s+the\s+(?:url|link)|visit)\b[^.\n]{0,40}?https?://")),
    ("hidden_marker", re.compile(
        r"(?:\[\[|\]\]|###|<!--|-->|<\|[^>]*\|>|\b(?:SYSTEM|ASSISTANT|USER)\s*:|"
        r"​|‎|‮)")),
    ("urgency", re.compile(
        r"(?i)\b(?:you\s+must|it\s+is\s+(?:critical|important|imperative|essential)|"
        r"immediately|do\s+not\s+(?:tell|mention|inform|reveal)|without\s+(?:asking|"
        r"telling|informing)|as\s+an\s+ai)\b")),
]

FAMILY_NAMES = [name for name, _ in _FAMILY_PATTERNS]
_URL = re.compile(r"https?://")
_CODE = re.compile(r"```|<script\b", re.I)

# The linear model's feature order: family counts, then scalars.
SCALAR_NAMES = ["url_count", "code_fence", "caps_ratio", "length_norm"]
FEATURE_NAMES = FAMILY_NAMES + SCALAR_NAMES


def family_hits(text: str) -> dict[str, int]:
    return {name: len(pat.findall(text)) for name, pat in _FAMILY_PATTERNS}


def iter_family_matches(text: str):
    """Yield (family, start, end) for every family match — used for operator-side spans."""
    for name, pat in _FAMILY_PATTERNS:
        for m in pat.finditer(text):
            yield name, m.start(), m.end()


def _caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def feature_vector(text: str) -> dict[str, float]:
    """Named features for the linear model. Family counts are clipped at 3 so one repeated
    phrase can't dominate; scalars are normalized to roughly 0..1."""
    hits = family_hits(text)
    vec: dict[str, float] = {name: float(min(hits[name], 3)) for name in FAMILY_NAMES}
    vec["url_count"] = float(min(len(_URL.findall(text)), 5)) / 5.0
    vec["code_fence"] = 1.0 if _CODE.search(text) else 0.0
    vec["caps_ratio"] = _caps_ratio(text)
    vec["length_norm"] = min(len(text) / 2000.0, 1.0)
    return vec


def feature_list(text: str) -> list[float]:
    vec = feature_vector(text)
    return [vec[name] for name in FEATURE_NAMES]
