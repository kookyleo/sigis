"""Fresh public token validation over the real probe preimage and declared hash.

No signing, recorded verdict replay, clock override or root/revocation waiver.
A signed SHA384 declaration over echoed SHA256 bytes must be intact=False while
CMS signature validity and the actual TSA certificate path remain trusted.
"""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path
from asn1crypto import cms, pem, x509
from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
from pyhanko.sign.validation.status import TimestampSignatureStatus
from pyhanko_certvalidator import ValidationContext

p = argparse.ArgumentParser()
p.add_argument('--token', required=True)
p.add_argument('--root', required=True)
p.add_argument('--preimage-hex', required=True)
p.add_argument('--expect-intact', choices=['true', 'false'], required=True)
p.add_argument('--record', required=True)
a = p.parse_args()
assert importlib.metadata.version('pyhanko') == '0.38.1'
assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'

def record(path):
    path = Path(path).resolve(); raw = path.read_bytes()
    return {'path': str(path), 'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

async def main():
    raw_root = Path(a.root).read_bytes()
    if pem.detect(raw_root):
        raw_root = pem.unarmor(raw_root)[2]
    root = x509.Certificate.load(raw_root, strict=True)
    sd = cms.ContentInfo.load(Path(a.token).read_bytes(), strict=True)['content']
    context = ValidationContext(trust_roots=[root], allow_fetching=True, revocation_mode='hard-fail')
    try:
        result = await validate_tst_signed_data(sd, context,
            expected_tst_imprint=lambda algorithm: hashlib.new(algorithm, bytes.fromhex(a.preimage_hex)).digest())
        status = TimestampSignatureStatus(**result)
        assert status.valid and status.trusted, status.pretty_print_details()
        assert status.intact is (a.expect_intact == 'true'), status.pretty_print_details()
        info = sd['encap_content_info']['content'].parsed
        row = {'kind': 'fresh pinned real token/preimage algorithm binding',
               'clock_override': False, 'python': record(sys.executable), 'driver': record(__file__),
               'CMS_validation_module': record(validate_tst_signed_data.__code__.co_filename),
               'validation_context_module': record(ValidationContext.__init__.__code__.co_filename),
               'token': record(a.token), 'root': record(a.root), 'preimage_hex': a.preimage_hex,
               'declared_algorithm': info['message_imprint']['hash_algorithm']['algorithm'].native,
               'imprint_hex': info['message_imprint']['hashed_message'].native.hex(),
               'pyhanko': importlib.metadata.version('pyhanko'),
               'certvalidator': importlib.metadata.version('pyhanko-certvalidator'),
               'intact': status.intact, 'valid': status.valid, 'trusted': status.trusted,
               'new_unique_credit': 0}
        Path(a.record).write_text(json.dumps(row, indent=2) + '\n')
        print(json.dumps(row))
    finally:
        await context.aclose()
asyncio.run(main())
