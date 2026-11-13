"""Fresh current-clock document timestamp integrity/trust controls (no signing)."""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
from io import BytesIO
from pathlib import Path

from asn1crypto import pem, x509
from pyhanko.pdf_utils.decode_limits import DecodeLimits
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_timestamp
from pyhanko_certvalidator import ValidationContext


def record(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


async def check(data, roots):
    reader = PdfFileReader(BytesIO(data), decode_limits=DecodeLimits.for_trusted_input())
    assert not reader.embedded_regular_signatures
    assert len(reader.embedded_timestamp_signatures) == 1
    context = ValidationContext(trust_roots=roots, allow_fetching=True,
                                revocation_mode='hard-fail')
    try:
        status = await async_validate_pdf_timestamp(reader.embedded_timestamp_signatures[0], context)
        return {"intact": status.intact, "valid": status.valid, "trusted": status.trusted,
                "accepted": status.intact and status.valid and status.trusted,
                "coverage": status.coverage.name}
    finally:
        await context.aclose()


async def main(args):
    data = Path(args.output).read_bytes()
    root_data = Path(args.root).read_bytes()
    if pem.detect(root_data):
        root_data = pem.unarmor(root_data)[2]
    root = x509.Certificate.load(root_data, strict=True)
    positive = await check(data, [root])
    assert all(positive[k] for k in ['intact', 'valid', 'trusted', 'accepted']), positive
    changed = bytearray(data)
    assert changed[:5] == b'%PDF-'
    changed[7] = ord('6') if changed[7] != ord('6') else ord('7')
    wrong_imprint = await check(bytes(changed), [root])
    assert not wrong_imprint['intact'] and wrong_imprint['valid'], wrong_imprint
    empty = await check(data, [])
    assert not empty['trusted'] and not empty['accepted'], empty
    return {"positive": positive, "wrong_imprint": wrong_imprint, "empty_roots": empty}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--root', required=True)
    parser.add_argument('--record', required=True)
    args = parser.parse_args()
    assert importlib.metadata.version('pyhanko') == '0.38.1'
    assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
    before = {name: record(path) for name, path in [('output', args.output), ('root', args.root)]}
    result = asyncio.run(main(args))
    assert before == {name: record(path) for name, path in [('output', args.output), ('root', args.root)]}
    receipt = {'kind': 'fresh pinned current-clock actual native document timestamp check',
               'clock_override': False, 'inputs_before_parse': before, 'driver': record(__file__),
               'result': result, 'new_unique_credit': 0}
    Path(args.record).write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
