"""Fresh CSC live upstream assertions and bidirectional PDF differential checks.

Exact pyHanko 0.38.1 test_live_csc_dummy.py functions: test_simple_sign_with_dummy
and test_implicit_batch_sign_with_dummy, with every original batch parameter.
Validation uses the generated service root and fixed time instead of the global
sample root and wall clock; fetching is disabled, preventing external traffic.
"""

import argparse
import asyncio
import importlib.metadata
import json
from io import BytesIO
from pathlib import Path

from asn1crypto import x509
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.signers import PdfSignatureMetadata, async_sign_pdf
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.status import ModificationLevel, SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext
from pyhanko_testing_commons.test_data.samples import MINIMAL_ONE_FIELD
from pyhanko_testing_commons.test_utils.csc_utils.csc_dummy_client import CSCDummy


async def check(data, root, expected_reason=None):
    reader = PdfFileReader(BytesIO(data))
    assert len(reader.embedded_signatures) == 1
    emb = reader.embedded_signatures[0]
    if expected_reason is not None:
        assert emb.sig_object['/Reason'].endswith(expected_reason)
    status = await async_validate_pdf_signature(
        emb, ValidationContext(trust_roots=[root], allow_fetching=False),
        skip_diff=True,
    )
    # Exact async_val_trusted assertions (including details and summary).
    assert status.intact
    assert status.valid
    assert status.trusted
    status.pretty_print_details()
    summary = status.summary()
    assert 'INTACT' in summary
    assert 'TRUSTED' in summary
    assert status.coverage == SignatureCoverageLevel.ENTIRE_FILE
    assert status.modification_level == ModificationLevel.NONE
    assert status.bottom_line
    untrusted = await async_validate_pdf_signature(
        emb, ValidationContext(trust_roots=[], allow_fetching=False), skip_diff=True
    )
    assert untrusted.intact and untrusted.valid
    assert not untrusted.trusted and not untrusted.bottom_line
    return {
        'intact': status.intact, 'valid': status.valid,
        'trusted': status.trusted, 'bottom_line': status.bottom_line,
        'coverage': status.coverage.name, 'modification_level': status.modification_level.name,
        'empty_roots_trusted': untrusted.trusted,
    }


async def run(args):
    assert importlib.metadata.version('pyHanko') == '0.38.1'
    assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
    root = x509.Certificate.load(bytes.fromhex(args.root))
    directory = Path(args.directory)
    expected_auth = args.number // args.batch
    async with CSCDummy(
        endpoint_url=args.url, credential_id='testing-ca/signer1-long', timeout=10,
        batch_size=args.batch, waste_time=args.waste,
    ) as signer:
        async def sign(number):
            writer = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
            metadata = PdfSignatureMetadata(
                reason=f"I'm number #{number}!" if args.reason else None
            )
            out = await async_sign_pdf(
                writer, signature_meta=metadata, existing_fields_only=True,
                signer=signer, in_place=True,
            )
            return out.getvalue()
        results = await asyncio.gather(*(sign(i) for i in range(1, args.number + 1)))
        auth_count = signer.auth_manager.authorizations_requested
        assert auth_count == expected_auth
    python = []
    rust = []
    for index, data in enumerate(results, 1):
        reason = f'#{index}!' if args.reason else None
        (directory / f'python-{index}.pdf').write_bytes(data)
        python.append(await check(data, root, reason))
        rust.append(await check((directory / f'rust-{index}.pdf').read_bytes(), root, reason))
    return {'authorizations_requested': auth_count, 'python': python, 'rust': rust}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--root', required=True)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--time', required=True)
    parser.add_argument('--number', type=int, required=True)
    parser.add_argument('--batch', type=int, required=True)
    parser.add_argument('--waste', type=int, required=True)
    parser.add_argument('--reason', action='store_true')
    args = parser.parse_args()
    with freeze_time(args.time, real_asyncio=True):
        print(json.dumps(asyncio.run(run(args))))
