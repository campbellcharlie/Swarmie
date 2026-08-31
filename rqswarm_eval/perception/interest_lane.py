"""Client for an out-of-process interest scorer ("interest lane").

Swarmie stays symbolic and cheap in its hot path: every completed pair is reduced to a
fixed feature vector by `obs_features.py`.  The *interest* lane consults an out-of-process,
unsupervised scorer that turns a batch of those vectors into per-vector interest values in
`[0, 1]` — how anomalous/novel each observation looks against a running baseline.  The
scorer lives in a separate process (see `sidecar/scorers/interest.py`); this module is the
stdlib-only shim Swarmie core uses to reach it.

Boundary rationale (see CLAUDE.md "Non-negotiable boundaries"):
  * Only derived numeric features cross this boundary — never raw bodies, headers, tokens,
    or query values (boundary #6).  The vectors are the redacted, structural view.
  * Transport is an AF_UNIX stream socket — local IPC in the same trust domain — not an
    HTTP request over the network (boundary #3).
  * A signal remains a hypothesis: the interest score annotates/ranks, it does not decide
    that a vulnerability exists (boundary #4).

Wire contract (one request/response per connection, both length-prefixed):
    request  = uint32-BE length + UTF-8 JSON
               {"v":1,"kind":"interest","feature_names":[<str>,...],"batch":[[<float>,...],...]}
    response = uint32-BE length + UTF-8 JSON
               {"v":1,"scores":[<float>,...],"model":<str>}

Fail-open: any connect/timeout/framing/parse error, a `scores` that is not a list, or a
`scores` whose length does not match the batch, yields `None` — leaving the lane dormant
for that batch.  The lane never raises into the caller and never persists what it sends.
"""
from __future__ import annotations

import json
import socket
import struct

_LEN = struct.Struct(">I")
_MAX_RESPONSE = 1 << 20  # refuse absurd length prefixes from a misbehaving/hostile sidecar


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("sidecar closed mid-message")
        buf += chunk
    return bytes(buf)


class InterestLane:
    """An unsupervised interest scorer backed by a socket sidecar.

    `active` is the shadow-mode switch, interpreted by the engine:
      * shadow (default): the interest score annotates signals and can influence ranking
        among signals that emit for other reasons — score, don't act.
      * active: the score is promoted so that high interest can raise a signal on its own
        and contributes to attention weighting.
    """

    def __init__(self, socket_path: str, *, active: bool = False, timeout: float = 0.5):
        self.socket_path = str(socket_path)
        self.active = bool(active)
        self.timeout = max(0.001, float(timeout))

    def score_batch(self, batch: list[list[float]],
                    feature_names: list[str]) -> list[float] | None:
        if not batch:
            return []  # nothing to score -> no socket call
        try:
            # Build the payload inside the try so a non-coercible batch value (float()
            # on a bad element) fails OPEN like any other error, never into the hot path.
            payload = json.dumps({
                "v": 1, "kind": "interest",
                "feature_names": list(feature_names),
                "batch": [[float(x) for x in vec] for vec in batch],
            }, ensure_ascii=True).encode()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(_LEN.pack(len(payload)) + payload)
                (n,) = _LEN.unpack(_recv_exact(sock, 4))
                if n > _MAX_RESPONSE:
                    return None
                resp = json.loads(_recv_exact(sock, n).decode("utf-8", "replace"))
        except (OSError, ValueError, TypeError, struct.error, ConnectionError):
            return None  # fail-open: dormant for this batch
        if not isinstance(resp, dict):
            return None
        scores = resp.get("scores")
        if not isinstance(scores, list) or len(scores) != len(batch):
            return None  # non-list or length mismatch -> fail open
        try:
            return [float(s) for s in scores]
        except (TypeError, ValueError):
            return None


def make_interest_lane(socket_path: str | None, *, active: bool = False) -> InterestLane | None:
    """Construct an interest lane, or None when no sidecar is configured (dormant)."""
    if not socket_path:
        return None
    return InterestLane(socket_path, active=active)
