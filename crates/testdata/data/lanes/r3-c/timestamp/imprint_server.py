"""Test-only signed algorithm substitution on the accepted live TSA service.

Run as a normal current-clock ephemeral live_server.py process. Only the parsed
request fed to Certomancer's real TSA signer is changed, before CMS signing.
Original request nonce/imprint bytes, TSA identity/key/path/revocation routes,
CMS digest/signature algorithms and accepted live server are preserved.
"""
import argparse
import hashlib
import importlib.metadata
import itertools
import json
import runpy
import sys
from pathlib import Path
from asn1crypto import algos, tsp
from certomancer.services import TimeStamper

p = argparse.ArgumentParser(add_help=False)
p.add_argument('--imprint-mode', choices=['valid', 'wrong-all', 'wrong-final'], required=True)
args, rest = p.parse_known_args()
assert importlib.metadata.version('pyhanko') == '0.38.1'
assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
artifacts = Path(rest[rest.index('--artifacts') + 1]).resolve()
artifacts.mkdir(parents=True, exist_ok=True)
original = TimeStamper.request_tsa_response
sequence = itertools.count()

def record(path):
    raw = path.read_bytes()
    return {'path': str(path.resolve()), 'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def signed_response(self, request):
    index = next(sequence)
    before = request.dump()
    actual = tsp.TimeStampReq.load(before, strict=True)
    imprint = actual['message_imprint']['hashed_message'].native
    requested = actual['message_imprint']['hash_algorithm']['algorithm'].native
    assert requested == 'sha256'
    # Native PdfTimeStamper uses SHA256(b'dummy'); pinned Python uses SHA256(b'').
    dummy = imprint in [hashlib.sha256(b'dummy').digest(), hashlib.sha256(b'').digest()]
    mismatched = args.imprint_mode == 'wrong-all' or (args.imprint_mode == 'wrong-final' and not dummy)
    if mismatched:
        # Strong SHA384 avoids introducing a weak-algorithm or CMS-signature denial.
        # Echo the actual32-byte SHA256 imprint while claiming SHA384 in TSTInfo.
        actual['message_imprint']['hash_algorithm'] = algos.DigestAlgorithm({'algorithm': 'sha384'})
    response = original(self, actual)
    info = response['time_stamp_token']['content']['encap_content_info']['content'].parsed
    assert info['message_imprint']['hashed_message'].native == imprint
    assert info['nonce'].native == request['nonce'].native
    assert info['message_imprint']['hash_algorithm']['algorithm'].native == ('sha384' if mismatched else 'sha256')
    paths = {}
    for label, raw in [('actual-request', before), ('signer-input', actual.dump()),
                       ('actual-response', response.dump()), ('actual-token', response['time_stamp_token'].dump())]:
        path = artifacts / f'imprint-{index:03d}-{label}.der'
        path.write_bytes(raw)
        paths[label] = record(path)
    row = {'sequence': index, 'mode': args.imprint_mode, 'dummy': dummy,
           'requested_algorithm': requested, 'response_algorithm': info['message_imprint']['hash_algorithm']['algorithm'].native,
           'imprint_hex': imprint.hex(), 'nonce': request['nonce'].native,
           'CMS_digest_algorithm': response['time_stamp_token']['content']['signer_infos'][0]['digest_algorithm']['algorithm'].native,
           'TSA_certificate_sha256': hashlib.sha256(self.tsa_cert.dump()).hexdigest(),
           'signed_before_response': True, 'generation_time': info['gen_time'].native.isoformat(),
           'driver': record(Path(__file__).resolve()), 'accepted_base_driver': record(base),
           'signer_module': record(Path(original.__code__.co_filename)), 'files': paths, 'new_unique_credit': 0}
    with (artifacts / 'imprint-events.jsonl').open('a') as out:
        out.write(json.dumps(row) + '\n')
    return response

TimeStamper.request_tsa_response = signed_response
# At the intended fixture path, timestamp/ and pkcs12-lta/ are sibling folders.
base = Path(__file__).resolve().parents[1] / 'pkcs12-lta' / 'live_server.py'
sys.argv = [str(base), *rest]
runpy.run_path(str(base), run_name='__main__')
