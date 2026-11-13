"""Test-owned RFC3161 responder; constructs a new response for each request.

Source preparation only. No replay file or production time override is used.
The fixture clock matches pinned test_cli_signing.py's FREEZE_DT.
"""
import hashlib
import importlib
import importlib.metadata
import os
import json
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tzlocal
from asn1crypto import tsp
from certomancer.registry import ServiceLabel
from pyhanko_testing_commons.test_data.samples import (
    TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519,
)

architectures = {"rsa": TESTING_CA, "ecdsa": TESTING_CA_ECDSA,
                 "ed25519": TESTING_CA_ED25519}
moment = datetime(2020, 8, 1, tzinfo=tzlocal.get_localzone())
tsa = architectures[sys.argv[1]].service_registry.summon_timestamper(
    ServiceLabel("tsa"), at_time=moment,
)
capture = Path(sys.argv[2])
capture.mkdir()
capture_lock = threading.Lock()
next_request = 0


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global next_request
        length = int(self.headers["Content-Length"])
        if length > 65536:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        request = tsp.TimeStampReq.load(body)
        response = tsa.request_tsa_response(request).dump()
        with capture_lock:
            sequence = next_request
            next_request += 1
            request_path = capture / f"request-{sequence:04}.der"
            response_path = capture / f"response-{sequence:04}.der"
            with request_path.open("xb") as target:
                target.write(body)
            with response_path.open("xb") as target:
                target.write(response)
            record = {
                "request_path": str(request_path), "response_path": str(response_path),
                "request_sha256": hashlib.sha256(body).hexdigest(),
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "digest_algorithm": request["message_imprint"]["hash_algorithm"]["algorithm"].native,
                "imprint": request["message_imprint"]["hashed_message"].native.hex(),
                "nonce": request["nonce"].native, "moment": moment.isoformat(),
            }
            with (capture / "requests.jsonl").open("a", encoding="utf8") as records:
                records.write(json.dumps(record) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
if sys.flags.optimize != 0:
    raise RuntimeError("Test TSA assertions must remain enabled")
def snapshot(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
ready = {"port": server.server_port, "moment": moment.isoformat(),
         "python": snapshot(sys.executable), "driver": snapshot(__file__),
         "optimize": sys.flags.optimize, "PYTHONOPTIMIZE": os.environ.get("PYTHONOPTIMIZE"),
         "certomancer_version": importlib.metadata.version("certomancer"),
         "modules": {name: snapshot(importlib.import_module(name).__file__) for name in
                     ["certomancer.services", "certomancer.registry.pki_arch", "pyhanko_testing_commons.test_data.samples"]}}
(capture / "server-ready.json").write_text(json.dumps(ready, indent=2) + "\n")
print(json.dumps(ready), flush=True)
server.serve_forever()
