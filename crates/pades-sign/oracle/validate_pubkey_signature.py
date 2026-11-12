"""Validate a Rust-produced public-key encrypted signature or decrypted copy.

This is a live pyHanko 0.38.1 comparison of the exact assertions in
test_sign_encrypted.py. Copy validation deliberately uses skip_diff=True.
"""

import argparse
import importlib.metadata
import json

from freezegun import freeze_time
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.crypt import AuthStatus, SimpleEnvelopeKeyDecrypter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


def main():
    assert importlib.metadata.version('pyhanko') == '0.38.1'
    assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
    parser = argparse.ArgumentParser()
    parser.add_argument('--pdf', required=True)
    parser.add_argument('--trust', required=True)
    parser.add_argument('--time', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--copied', action='store_true')
    args = parser.parse_args()
    with freeze_time(args.time), open(args.pdf, 'rb') as source:
        reader = PdfFileReader(source)
        if args.copied:
            assert not reader.encrypted
        else:
            assert reader.encrypted
            credential = SimpleEnvelopeKeyDecrypter.load(
                args.key, args.cert, key_passphrase=b'secret'
            )
            assert reader.decrypt_pubkey(credential).status != AuthStatus.FAILED
        signatures = reader.embedded_signatures
        assert len(signatures) == 1
        signature = signatures[0]
        if args.copied:
            signature.compute_integrity_info()
        context = ValidationContext(
            trust_roots=[load_cert_from_pemder(args.trust)],
            allow_fetching=False,
        )
        status = validate_pdf_signature(signature, context, skip_diff=True)
        result = {
            'intact': status.intact,
            'valid': status.valid,
            'trusted': status.trusted,
            'bottom_line': status.bottom_line,
            'coverage': status.coverage.name,
            'modification_level': (
                status.modification_level.name if status.modification_level is not None else None
            ),
            'skip_diff': True,
        }
        if args.copied:
            assert not status.intact
        else:
            for key in ('intact', 'valid', 'trusted', 'bottom_line'):
                assert result[key], result
            assert result['coverage'] == 'ENTIRE_FILE', result
            assert result['modification_level'] == 'NONE', result
            status.pretty_print_details()
            assert 'INTACT' in status.summary()
            assert 'TRUSTED' in status.summary()
        print(json.dumps(result))


if __name__ == '__main__':
    main()
