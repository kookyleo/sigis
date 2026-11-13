"""Mandatory same-output oracle draft; final path tests/support/raw_dsa_oracle.py.

Validates native.pdf only. Original Python token-signing execution is a separate
required receipt. No PKCS#11 signing or software-signing fallback occurs here.
The validator was exercised on a freshly generated ORIGINAL PYTHON output;
validation of a native Rust output remains UNRUN. See input-origin receipts.
"""
import asyncio
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path

from freezegun import freeze_time
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import DisallowWeakAlgorithmsPolicy


def status_json(status):
    return {
        'intact': status.intact,
        'valid': status.valid,
        'trusted': status.trusted,
        'bottom_line': status.bottom_line,
        'coverage': status.coverage.name,
        'modification_level': status.modification_level.name,
        'summary': status.summary(),
        'md_algorithm': status.md_algorithm,
    }


async def run(directory):
    versions = {
        'pyhanko': importlib.metadata.version('pyHanko'),
        'certvalidator': importlib.metadata.version('pyhanko-certvalidator'),
        'python_pkcs11': importlib.metadata.version('python-pkcs11'),
    }
    assert versions == {'pyhanko': '0.38.1', 'certvalidator': '0.33.0',
                        'python_pkcs11': '0.9.5'}, versions
    assert sys.flags.optimize == 0, 'Oracle assertions must remain enabled'
    data = (directory / 'native.pdf').read_bytes()
    root = load_cert_from_pemder(str(directory / 'root.der'))
    intermediate = load_cert_from_pemder(str(directory / 'interm.der'))
    signer = load_cert_from_pemder(str(directory / 'signer.der'))
    with (directory / 'native.pdf').open('rb') as stream:
        signatures = PdfFileReader(stream).embedded_signatures
        assert len(signatures) == 1
        signature = signatures[0]
        assert signature.field_name == 'Sig1'
        # Exact original fixture policy only; no revocation_mode='none'.
        context = ValidationContext(
            trust_roots=[root], other_certs=[intermediate],
            algorithm_usage_policy=DisallowWeakAlgorithmsPolicy(
                dsa_key_size_threshold=1024
            ),
        )
        status = await async_validate_pdf_signature(signature, context, skip_diff=True)
        # Preserve every original val_trusted assertion and reporting call.
        assert status.intact
        assert status.valid
        assert status.trusted
        status.pretty_print_details()
        summary = status.summary()
        assert 'INTACT' in summary
        assert 'TRUSTED' in summary
        from pyhanko.sign.validation.status import SignatureCoverageLevel, ModificationLevel
        assert status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert status.modification_level == ModificationLevel.NONE
        assert status.bottom_line
        assert status.md_algorithm == 'sha256'
        assert status.signing_cert.dump() == signer.dump()
        assert len(status.validation_path) == 3
        default_policy = DisallowWeakAlgorithmsPolicy()
        assert default_policy.dsa_key_size_threshold == 3192
        default_context = ValidationContext(
            trust_roots=[root], other_certs=[intermediate],
            algorithm_usage_policy=default_policy,
        )
        negative = await async_validate_pdf_signature(
            signature, default_context, skip_diff=True
        )
        assert negative.intact and negative.valid
        assert negative.trust_problem_indic.name == "CRYPTO_CONSTRAINTS_FAILURE"
        default_rejected = not negative.trusted and not negative.bottom_line
        default_result = status_json(negative)
        assert default_rejected, default_result
        return {
            **versions, **status_json(status),
            'policy_dsa_threshold': 1024,
            'count': len(signatures), 'field': signature.field_name,
            'pdf_sha256': hashlib.sha256(data).hexdigest(),
            'signer_sha256': signer.sha256.hex(),
            'opened_inputs': [
                {'path': str((directory / name).resolve()),
                 'bytes': (directory / name).stat().st_size,
                 'sha256': hashlib.sha256((directory / name).read_bytes()).hexdigest()}
                for name in ['native.pdf', 'root.der', 'interm.der', 'signer.der']
            ],
            'default_policy_rejected': default_rejected,
            'default_policy': default_result,
        }


with freeze_time('2020-11-01T00:00:00Z'):
    print(json.dumps(asyncio.run(run(Path(sys.argv[1])))))
