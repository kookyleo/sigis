"""Two explicitly distinct public validations of one actual signed TSA token.

raw_preimage binds the TST-declared algorithm to the real preimage. The separate
signature_component deliberately compares echoed imprint bytes and proves only
CMS signature/path/TSA-purpose validity; it is not a preimage-integrity verdict.
Both calls use the same unchanged ValidationContext/token/current hard-fail PKI.
"""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import sys
import traceback
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

def record(path):
    path = Path(path).resolve(); raw = path.read_bytes()
    return {'path': str(path), 'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def status_record(status):
    return {'intact': status.intact, 'valid': status.valid, 'trusted': status.trusted,
            'bottom_line': bool(status.intact and status.valid and status.trusted),
            'bottom_line_basis': 'derived intact && valid && trusted; not a nonexistent TimestampSignatureStatus method',
            'trust_problem_indic': str(status.trust_problem_indic),
            'validation_path_present': status.validation_path is not None,
            'signer_certificate_sha256': hashlib.sha256(status.signing_cert.dump()).hexdigest(),
            'timestamp': status.timestamp.isoformat()}

async def main():
    raw_root = Path(a.root).read_bytes()
    if pem.detect(raw_root):
        raw_root = pem.unarmor(raw_root)[2]
    root = x509.Certificate.load(raw_root, strict=True)
    sd = cms.ContentInfo.load(Path(a.token).read_bytes(), strict=True)['content']
    info = sd['encap_content_info']['content'].parsed
    echo = info['message_imprint']['hashed_message'].native
    expected = a.expect_intact == 'true'
    row = {'kind': 'fresh pinned raw preimage binding plus separate algorithm-agnostic CMS component',
           'clock_override': False, 'python': record(sys.executable), 'driver': record(__file__),
           'CMS_validation_module': record(validate_tst_signed_data.__code__.co_filename),
           'validation_context_module': record(ValidationContext.__init__.__code__.co_filename),
           'token': record(a.token), 'root': record(a.root), 'preimage_hex': a.preimage_hex,
           'declared_algorithm': info['message_imprint']['hash_algorithm']['algorithm'].native,
           'imprint_hex': echo.hex(), 'pyhanko': importlib.metadata.version('pyhanko'),
           'certvalidator': importlib.metadata.version('pyhanko-certvalidator'),
           'raw_preimage': None, 'signature_component': None, 'new_unique_credit': 0}
    def save():
        Path(a.record).write_text(json.dumps(row, indent=2) + '\n')
    save()
    context = None
    try:
        assert row['pyhanko'] == '0.38.1' and row['certvalidator'] == '0.33.0', row
        context = ValidationContext(trust_roots=[root], allow_fetching=True, revocation_mode='hard-fail')
        raw_kwargs = await validate_tst_signed_data(sd, context,
            expected_tst_imprint=lambda algorithm: hashlib.new(algorithm, bytes.fromhex(a.preimage_hex)).digest())
        raw = TimestampSignatureStatus(**raw_kwargs)
        row['raw_preimage'] = status_record(raw)
        save()  # Retain actual raw fields even if the component/control fails.
        component_kwargs = await validate_tst_signed_data(sd, context,
            expected_tst_imprint=lambda _algorithm: echo)
        component = TimestampSignatureStatus(**component_kwargs)
        row['signature_component'] = {**status_record(component),
            'algorithm_binding_checked': False,
            'basis': 'same token/context; expected callback returns actual echoed bytes only'}
        save()  # Retain both outcomes before any expected-result assertion.
        assert raw.intact is expected, row
        assert row['raw_preimage']['bottom_line'] is expected, row
        if expected:
            assert raw.valid and raw.trusted, row
        # Do not assert negative raw.valid/trusted values: retain what public API returned.
        assert component.intact and component.valid and component.trusted, row
        assert 'time_stamping' in component.signing_cert.extended_key_usage_value.native, row
        assert row['raw_preimage']['signer_certificate_sha256'] == row['signature_component']['signer_certificate_sha256'], row
        print(json.dumps(row))
    except Exception as error:
        row['error'] = {'class': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
        save()
        raise
    finally:
        if context is not None:
            await context.aclose()
asyncio.run(main())
