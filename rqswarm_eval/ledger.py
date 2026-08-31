"""Append-only hash-chained JSONL event ledger (the source of truth).

hash = sha256 over the canonical JSON of the event EXCLUDING the 'hash' key and
any timing key (anything starting with 'wall', plus 'timing'/'elapsed_ms'). Timing
is stored but never enters identity, so runs are byte-reproducible across machines.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Iterable

GENESIS = "0" * 64

# Event kinds permitted in the ledger.
KINDS = {"proposal", "execution", "judge", "discovery", "resource", "meta", "anti"}

# Keys excluded from the hash pre-image: the hash itself and any timing field.
_TIMING_PREFIXES = ("wall",)
_TIMING_EXACT = {"timing", "elapsed_ms", "elapsed", "timestamp", "clock"}


def _is_excluded_key(key: str) -> bool:
    if key == "hash":
        return True
    if key in _TIMING_EXACT:
        return True
    return any(key.startswith(p) for p in _TIMING_PREFIXES)


def _hashable(event: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in event.items() if not _is_excluded_key(k)}


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, ASCII-safe."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def event_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_hashable(event)).encode("utf-8")).hexdigest()


def _tail_state(path: str) -> tuple[int, str]:
    """Return (next_seq, prev_hash) for appending to an existing ledger."""
    if not os.path.exists(path):
        return 0, GENESIS
    last = None
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                last = json.loads(line)
    if last is None:
        return 0, GENESIS
    return int(last["seq"]) + 1, last["hash"]


class Ledger:
    """Append-only writer. Fills seq/prev_hash/hash on each append."""

    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self._seq, self._prev = _tail_state(path)

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        e = dict(event)
        e.pop("hash", None)
        e["seq"] = self._seq
        e["prev_hash"] = self._prev
        e["hash"] = event_hash(e)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(e, sort_keys=True) + "\n")
        self._seq += 1
        self._prev = e["hash"]
        return e


def write_events(path: str, events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convenience: chain a fresh sequence of events into a new/extended ledger."""
    ledger = Ledger(path)
    return [ledger.append(ev) for ev in events]


def read_ledger(path: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def verify_chain(path: str) -> bool:
    """True iff seq is contiguous from 0, every prev_hash links, and every stored
    hash matches a recomputation over the event's non-timing fields."""
    prev = GENESIS
    expected_seq = 0
    for ev in read_ledger(path):
        if int(ev.get("seq", -1)) != expected_seq:
            return False
        if ev.get("prev_hash") != prev:
            return False
        if event_hash(ev) != ev.get("hash"):
            return False
        prev = ev["hash"]
        expected_seq += 1
    return True
