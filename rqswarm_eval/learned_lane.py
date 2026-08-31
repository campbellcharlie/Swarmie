"""Client for an out-of-process learned classifier ("learned lane").

Swarmie stays symbolic: everything with a stable syntax (tokens, headers, structure)
is matched by rules in `passive.py`.  A *learned* lane is added only for families
defined by meaning rather than shape — the first is agent-prompt-injection detection in
response bodies, which no regex can carry.  The model lives in a separate process (e.g. a
Core ML classifier on the Apple Neural Engine); this module is the stdlib-only shim that
Swarmie core uses to consult it.

Boundary rationale (see CLAUDE.md "Non-negotiable boundaries"):
  * The classifier READS the untrusted response body, but only a `label`+`score` verdict
    ever returns.  The raw body never leaves this process for the mailbox or hook context
    (boundary #6): the mailbox envelope carries the verdict, not the text.
  * Transport is an AF_UNIX stream socket — local IPC in the same trust domain that already
    holds the hydrated body — not an HTTP request over the network (boundary #3).
  * Captured content stays untrusted data (boundary #8); the classifier is built to consume
    exactly such hostile text.

Wire contract (one request/response per connection, both length-prefixed):
    request  = uint32-BE length + UTF-8 JSON
               {"v":1,"lane":<str>,"text":<str>,"meta":{"response_type":<str>}}
    response = uint32-BE length + UTF-8 JSON
               {"v":1,"label":<str>,"score":<float 0..1>,"model":<str>,"spans":[[i,j],...]}
`spans` (integer offsets into the submitted text) are optional and operator-side only —
they are never placed in the mailbox envelope.

Fail-open: any connect/timeout/framing/parse error yields `None`, leaving the lane dormant
for that pair.  The lane never raises into the passive hot path and never persists the text
it sends.
"""
from __future__ import annotations

import dataclasses
import json
import socket
import struct

_LEN = struct.Struct(">I")
_MAX_RESPONSE = 1 << 20  # refuse absurd length prefixes from a misbehaving/hostile sidecar


@dataclasses.dataclass(frozen=True)
class Verdict:
    lane: str
    label: str
    score: float
    model: str
    hit: bool  # score >= threshold AND label is a positive class

    def as_signal(self, *, shadow: bool) -> dict:
        """The redacted verdict placed in the mailbox envelope. No text, no offsets."""
        return {
            "lane": self.lane, "label": self.label, "score": round(self.score, 4),
            "model": self.model, "shadow": bool(shadow),
        }


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("sidecar closed mid-message")
        buf += chunk
    return bytes(buf)


class LearnedLane:
    """A single learned detector backed by a socket sidecar.

    `active` is the shadow-mode switch, interpreted by the engine:
      * shadow (default): the verdict annotates signals that emit for other reasons but
        never changes which signals emit or how they rank — score, don't act.
      * active: the verdict is promoted to a first-class reason that can raise a signal on
        its own and contributes to attention weighting.
    """

    def __init__(self, socket_path: str, *, active: bool = False, threshold: float = 0.5,
                 lane_name: str = "agent_injection", positive_labels: tuple[str, ...] = ("injection",),
                 text_cap: int = 65536, timeout: float = 0.25):
        self.socket_path = str(socket_path)
        self.active = bool(active)
        self.threshold = float(threshold)
        self.lane_name = lane_name
        self.positive_labels = tuple(positive_labels)
        self.text_cap = max(1, int(text_cap))
        self.timeout = max(0.001, float(timeout))

    def classify(self, text: str, *, response_type: str = "") -> Verdict | None:
        if not text:
            return None
        payload = json.dumps({
            "v": 1, "lane": self.lane_name, "text": text[:self.text_cap],
            "meta": {"response_type": response_type},
        }, ensure_ascii=True).encode()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(_LEN.pack(len(payload)) + payload)
                (n,) = _LEN.unpack(_recv_exact(sock, 4))
                if n > _MAX_RESPONSE:
                    return None
                resp = json.loads(_recv_exact(sock, n).decode("utf-8", "replace"))
        except (OSError, ValueError, struct.error, ConnectionError):
            return None  # fail-open: dormant for this pair
        if not isinstance(resp, dict) or "score" not in resp:
            return None  # a response without a score is malformed -> fail open
        label = str(resp.get("label", ""))
        try:
            score = float(resp["score"])
        except (TypeError, ValueError):
            return None
        hit = score >= self.threshold and label in self.positive_labels
        return Verdict(lane=self.lane_name, label=label, score=score,
                       model=str(resp.get("model", "")), hit=hit)


def make_lane(socket_path: str | None, *, active: bool = False,
              threshold: float = 0.5) -> LearnedLane | None:
    """Construct a lane, or None when no sidecar is configured (dormant)."""
    if not socket_path:
        return None
    return LearnedLane(socket_path, active=active, threshold=threshold)
