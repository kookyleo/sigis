"""Current-clock, correctly signed RFC3161 tokens from a non-TSA leaf anchor.

The negative deliberately uses the existing signer1-long certificate and key.
No certificate validity, EKU, key or chain byte is modified. Only this fixture's
new ephemeral HTTP listener is used.
"""
import argparse
import hashlib
import importlib.metadata
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from asn1crypto import tsp
from certomancer.registry import ArchLabel, CertLabel, CertomancerConfig, ServiceLabel
from certomancer.services import TimeStamper

parser = argparse.ArgumentParser()
parser.add_argument('--crypto', required=True)
parser.add_argument('--architecture', required=True)
parser.add_argument('--artifacts', required=True)
args = parser.parse_args()
assert args.architecture == 'rsa'
requests = []
server = ThreadingHTTPServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
base = f'http://127.0.0.1:{server.server_port}'
crypto = Path(args.crypto).resolve()
arch = CertomancerConfig.from_file(str(crypto / 'certomancer.yml'),
    key_search_dir=str(crypto), external_url_prefix=base).get_pki_arch(ArchLabel('testing-ca'))
label = CertLabel('signer1-long')
cert = arch.get_cert(label)
spec = arch.get_cert_spec(label)
key = arch.key_set.get_private_key(spec.subject_key)
tsa = TimeStamper(cert, key, certs_to_embed=[arch.get_cert(CertLabel('interm'))])
assert 'time_stamping' not in (cert.extended_key_usage_value.native if cert.extended_key_usage_value else [])
artifacts = Path(args.artifacts).resolve()
artifacts.mkdir(parents=True, exist_ok=True)
root = artifacts / 'not-a-tsa.der'
root.write_bytes(cert.dump())
good_cert = arch.get_cert(CertLabel('tsa'))
good_path = artifacts / 'tsa.der'
good_path.write_bytes(good_cert.dump())
good_tsa = arch.service_registry.summon_timestamper(ServiceLabel('tsa'), at_time=None)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'requests': requests}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        request = tsp.TimeStampReq.load(body)
        is_dummy = request['message_imprint']['hashed_message'].native == hashlib.sha256(b'dummy').digest()
        selected = good_tsa if self.path == '/switch' and is_dummy else tsa
        response = selected.request_tsa_response(request).dump()
        requests.append({'method': 'POST', 'path': self.path, 'status': 200, 'count': 1})
        self.send_response(200)
        self.send_header('Content-Type', 'application/timestamp-reply')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)
    def log_message(self, *args):
        pass

server.RequestHandlerClass = Handler
print(json.dumps({'architecture': 'rsa', 'clock': 'current UTC',
    'pyhanko': importlib.metadata.version('pyhanko'),
    'certvalidator': importlib.metadata.version('pyhanko-certvalidator'),
    'exported_root': {'path': str(root), 'length': root.stat().st_size,
                      'sha256': hashlib.sha256(root.read_bytes()).hexdigest()},
    'tsa_url': base + '/tsa', 'switch_url': base + '/switch', 'good_tsa_cert': str(good_path), 'metrics_url': base + '/metrics'}), flush=True)
server.serve_forever()
