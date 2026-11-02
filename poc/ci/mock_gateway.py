#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Mock gateway front door for endpoint end-to-end tests (TEST ONLY, never in production).

mTLS server that requires a client certificate signed by the test CA, answers /_gw/health with 200 and any model
call with a streamed "pong", and logs one JSON line per request (client certificate subject, path, X-AGY headers).

  mock_gateway.py --cert server.crt --key server.key --ca ca.pem [--host 127.0.0.1] [--port 443] [--log FILE]
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOG: Any = sys.stdout


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _log(self, status: int) -> None:
        cert = self.connection.getpeercert() if hasattr(self.connection, "getpeercert") else None  # type: ignore[attr-defined]
        subject = dict(x[0] for x in cert.get("subject", ())) if cert else {}
        LOG.write(json.dumps({"path": self.path, "method": self.command, "status": status,
                              "client_cn": subject.get("commonName", ""),
                              "agy_headers": {k: v for k, v in self.headers.items() if k.lower().startswith("x-agy")}}) + "\n")
        LOG.flush()

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._log(status)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/_gw/health"):
            self._send(200, b"ok", "text/plain")
        elif self.path.startswith("/v1beta/models"):
            self._send(200, json.dumps({"models": [{"name": "models/agy-auto"}]}).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        turn = {"candidates": [{"content": {"role": "model", "parts": [{"text": "pong"}]}, "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2}}
        if "streamGenerateContent" in self.path:
            self._send(200, f"data: {json.dumps(turn)}\r\n\r\n".encode(), "text/event-stream")
        else:
            self._send(200, json.dumps(turn).encode(), "application/json")

    def log_message(self, *_: Any) -> None:
        return


def main() -> int:
    global LOG
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--log", default="")
    a = ap.parse_args()
    if a.log:
        LOG = open(a.log, "a", encoding="utf-8")  # noqa: SIM115
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=a.ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(a.cert, a.key)
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
