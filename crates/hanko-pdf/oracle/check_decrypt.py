"""Differential check: open an encrypted PDF written by hanko-pdf with
pyHanko 0.38.1 and report pyHanko's verdict as JSON.

Uses pyHanko's public API (MIT, see crates/hanko-pdf/LICENSE-pyHanko).

Usage: check_decrypt.py <pdf> <password:PW | pubkey:LABEL>

`pubkey:rsa` uses PUBKEY_TEST_DECRYPTER (testing-ca decrypter1 with
keys-rsa/signer.key.pem); `pubkey:<label>` uses an ECC decrypter of
`ecc-testing-ca-with-decrypters` (certificate from
crates/hanko-testdata/data/lanes/b/crypt-pki, key from keys-ecdsa).

Output: {"status": "OWNER"|"USER"|"FAILED", "mac_status": ...,
"hello": <first page content contains b"Hello">}.
"""

import json
import pathlib
import sys

from pyhanko.pdf_utils.crypt import SimpleEnvelopeKeyDecrypter
from pyhanko.pdf_utils.reader import PdfFileReader

ROOT = pathlib.Path(__file__).resolve().parents[3]
CRYPTO = ROOT / 'crates/hanko-testdata/data/pyhanko/crypto'
PKI = ROOT / 'crates/hanko-testdata/data/lanes/b/crypt-pki'


def main():
    path, cred = sys.argv[1], sys.argv[2]
    kind, _, arg = cred.partition(':')
    with open(path, 'rb') as inf:
        r = PdfFileReader(inf)
        if kind == 'password':
            result = r.decrypt(arg)
        elif arg == 'rsa':
            result = r.decrypt_pubkey(
                SimpleEnvelopeKeyDecrypter.load(
                    str(CRYPTO / 'keys-rsa/signer.key.pem'),
                    str(CRYPTO / 'testing-ca/interm/decrypter1.cert.pem'),
                    b'secret',
                )
            )
        else:
            result = r.decrypt_pubkey(
                SimpleEnvelopeKeyDecrypter.load(
                    str(CRYPTO / f'keys-ecdsa/{arg}.key.pem'),
                    str(PKI / f'{arg}.cert.pem'),
                    None,
                )
            )
        hello = False
        if result.status.name != 'FAILED':
            page = r.root['/Pages']['/Kids'][0].get_object()
            hello = b'Hello' in page['/Contents'].data
        json.dump(
            {
                'status': result.status.name,
                'mac_status': result.mac_status.name,
                'hello': hello,
            },
            sys.stdout,
        )


if __name__ == '__main__':
    main()
