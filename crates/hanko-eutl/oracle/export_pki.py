"""Export the Certomancer test PKIs used by lane E tests.

Writes one PEM file per certificate label to
``crates/hanko-testdata/data/lanes/e/pki/<arch>/<label>.cert.pem``.
Only certificates are exported (no private keys).

Usage (from the repository root, with pyHanko 0.38.1 and certomancer
installed)::

    python -I crates/hanko-eutl/oracle/export_pki.py

The configuration is pyHanko's ``crypto/certomancer.yml``, loaded exactly as
``pyhanko_testing_commons.test_data.samples`` does. Certificate validity
periods are fixed in that file, so the export does not depend on the
current time; ECDSA signatures are randomised, so re-running the export
produces different (equally valid) certificate bytes.
"""

import os
import sys

import yaml
from asn1crypto import pem
from certomancer.registry import ArchLabel, CertomancerConfig

ARCHS = ['testing-ca', 'testing-ca-ecdsa', 'testing-ca-qualified', 'unrelated-tsa']


def main():
    root = os.getcwd()
    data = os.path.join(root, 'crates', 'hanko-testdata', 'data')
    crypto = os.path.join(data, 'pyhanko', 'crypto')
    with open(os.path.join(crypto, 'certomancer.yml'), 'r') as inf:
        cfg = yaml.safe_load(inf.read())
    certomancer = CertomancerConfig(cfg, key_search_dir=crypto, lazy_load_keys=True)
    out_root = os.path.join(data, 'lanes', 'e', 'pki')
    count = 0
    for arch in ARCHS:
        pki = certomancer.get_pki_arch(ArchLabel(arch))
        out_dir = os.path.join(out_root, arch)
        os.makedirs(out_dir, exist_ok=True)
        for _iss, specs in pki.enumerate_certs_by_issuer():
            for spec in specs:
                cert = pki.get_cert(spec.label)
                with open(os.path.join(out_dir, f'{spec.label}.cert.pem'), 'wb') as f:
                    f.write(pem.armor('CERTIFICATE', cert.dump()))
                count += 1
    print(f'exported {count} certificates', file=sys.stderr)


if __name__ == '__main__':
    main()
