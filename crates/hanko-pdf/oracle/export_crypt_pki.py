"""Export the Certomancer test certificates used by hanko-pdf's crypt tests.

Port support for pyHanko 0.38.1 `pkgs/pyhanko/tests/test_crypt.py`
(MIT, see crates/hanko-pdf/LICENSE-pyHanko): the ECDH tests use the
`ecc-testing-ca-with-decrypters` architecture of pyHanko's Certomancer
configuration (`crypto/certomancer.yml`).

Only certificates are exported. The matching private keys are pyHanko's
public test keys, which the Rust tests read from
`crates/hanko-testdata/data/pyhanko/crypto/keys-ecdsa/` by path.

Usage (from the repository root, with Certomancer installed):

    python crates/hanko-pdf/oracle/export_crypt_pki.py

Output: `crates/hanko-testdata/data/lanes/b/crypt-pki/<label>.cert.pem`.

The certificates have fixed validity periods in the configuration, so the
generation time does not matter. Serial numbers and names are deterministic;
ECDSA signature values are not, so regenerated files differ byte-wise but
identify the same certificates (issuer and serial number), which is what the
committed `pubkey-ecc-test.pdf` fixture requires.
"""

import base64
import pathlib
import sys

import yaml
from certomancer.registry import ArchLabel, CertLabel, CertomancerConfig

ROOT = pathlib.Path(__file__).resolve().parents[3]
CRYPTO_DIR = ROOT / 'crates/hanko-testdata/data/pyhanko/crypto'
OUT_DIR = ROOT / 'crates/hanko-testdata/data/lanes/b/crypt-pki'

ARCH = 'ecc-testing-ca-with-decrypters'
LABELS = [
    'decrypter1',
    'decrypter2',
    'decrypter3',
    'decrypter-x25519',
    'decrypter-x448',
]


def main():
    with open(CRYPTO_DIR / 'certomancer.yml') as inf:
        cfg = yaml.safe_load(inf)
    config = CertomancerConfig(
        cfg, key_search_dir=str(CRYPTO_DIR), lazy_load_keys=True
    )
    arch = config.get_pki_arch(ArchLabel(ARCH))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for label in LABELS:
        cert = arch.get_cert(CertLabel(label))
        der = cert.dump()
        body = base64.encodebytes(der).decode('ascii').replace('\n', '')
        lines = [body[i : i + 64] for i in range(0, len(body), 64)]
        text = (
            '-----BEGIN CERTIFICATE-----\n'
            + '\n'.join(lines)
            + '\n-----END CERTIFICATE-----\n'
        )
        (OUT_DIR / f'{label}.cert.pem').write_text(text)
        print(f'{label}: serial {cert.serial_number}', file=sys.stderr)


if __name__ == '__main__':
    main()
