"""AF_UNIX server harness for the learned-lane sidecar.

Speaks the wire contract in `rqswarm_eval/learned_lane.py`:
    request  = uint32-BE length + UTF-8 JSON {"v":1,"lane":...,"text":...,"meta":{...}}
    response = uint32-BE length + UTF-8 JSON {"v":1,"label":...,"score":...,"model":...,"spans":...}

One request/response per connection. The server delegates scoring to any object with a
`.score(text, response_type=...) -> ScoreResult` method and a `.model_id`. Framing, socket
lifecycle, and error handling live here so each scorer stays a pure function of text.

Run:  python -m sidecar.server --scorer heuristic --socket /tmp/swm.sock
      python -m sidecar.server --scorer coreml --model-dir sidecar/models/injection.mlpackage --socket /tmp/swm.sock
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import struct
import threading

from .scorers import Scorer, load_scorer

_LEN = struct.Struct(">I")
_MAX_REQUEST = 1 << 20  # refuse absurd length prefixes


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("client closed mid-message")
        buf += chunk
    return bytes(buf)


def handle_connection(conn: socket.socket, scorer: Scorer) -> None:
    with conn:
        try:
            (n,) = _LEN.unpack(_recv_exact(conn, 4))
            if n > _MAX_REQUEST:
                return
            req = json.loads(_recv_exact(conn, n).decode("utf-8", "replace"))
            if isinstance(req.get("batch"), list):
                # Batch interest protocol (perception spine). Coerce inside the try so any
                # malformed vector drops the connection and the client fails open.
                feature_names = [str(x) for x in (req.get("feature_names") or [])]
                batch = [[float(x) for x in vec] for vec in req["batch"]]
                scores = scorer.score_batch(batch, feature_names)
                reply = json.dumps({
                    "v": 1, "scores": [round(float(s), 6) for s in scores],
                    "model": scorer.model_id,
                }).encode()
            else:
                text = str(req.get("text", ""))
                response_type = str((req.get("meta") or {}).get("response_type", ""))
                result = scorer.score(text, response_type=response_type)
                reply = json.dumps({
                    "v": 1, "label": result.label, "score": round(float(result.score), 6),
                    "model": scorer.model_id, "spans": result.spans,
                }).encode()
            conn.sendall(_LEN.pack(len(reply)) + reply)
        except (OSError, ValueError, TypeError, AttributeError, struct.error, ConnectionError):
            return  # drop the connection; the client fails open


class SidecarServer:
    def __init__(self, socket_path: str, scorer: Scorer):
        self.socket_path = socket_path
        self.scorer = scorer
        self._stop = threading.Event()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(socket_path)
        os.chmod(socket_path, 0o600)
        self._srv.listen(64)
        self._srv.settimeout(0.5)

    def serve_forever(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    conn, _ = self._srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=handle_connection, args=(conn, self.scorer),
                                 daemon=True).start()
        finally:
            self.close()

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        self._srv.close()
        with contextlib.suppress(OSError):
            os.unlink(self.socket_path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Swarmie learned-lane classifier sidecar")
    ap.add_argument("--socket", required=True, help="AF_UNIX path to bind")
    ap.add_argument("--scorer", default="heuristic", choices=["heuristic", "coreml", "interest"])
    ap.add_argument("--model-dir", help="path to the .mlpackage (coreml scorer)")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="advisory; Swarmie applies its own --injection-threshold")
    args = ap.parse_args(argv)
    kw = {}
    if args.scorer == "coreml":
        if not args.model_dir:
            ap.error("--model-dir is required for the coreml scorer")
        kw["model_dir"] = args.model_dir
    scorer = load_scorer(args.scorer, **kw)
    server = SidecarServer(args.socket, scorer)
    print(json.dumps({"ready": True, "scorer": args.scorer, "model": scorer.model_id,
                      "socket": args.socket}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
