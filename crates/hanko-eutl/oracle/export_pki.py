"""Export the Certomancer test PKIs and signed trusted lists for lane E.

Writes, from one Certomancer instance (``pyhanko_testing_commons``'s
``CERTOMANCER``, configured from pyHanko's ``crypto/certomancer.yml``):

* ``crates/hanko-testdata/data/lanes/e/pki/<arch>/<label>.cert.pem``: one PEM
  file per certificate (no private keys);
* ``crates/hanko-testdata/data/lanes/e/tl/certomancer-lotl.xml``:
  ``certomancer_lotl(TESTING_CA_QUALIFIED, 'root', [('interm-qualified', 'be',
  'https://example.com/')])`` as in ``test_parse_generated_lotl``;
* ``crates/hanko-testdata/data/lanes/e/tl/certomancer-qualified-tl.xml``:
  ``certomancer_pki_as_trusted_list(TESTING_CA_QUALIFIED, 'root')`` as in
  ``_testing_ca_registry`` of ``test_ades_validation.py``.

Certomancer issues certificates when first asked for them; ECDSA signatures
are randomised, so certificates of the ECDSA architectures differ between
runs. Everything that must fit together is therefore exported in one run.

Usage (repository root)::

    PYTHONPATH=<pyHanko v0.38.1>/internal/common-test-utils/src \\
        python crates/hanko-eutl/oracle/export_pki.py
"""

import os
import sys

from asn1crypto import pem
from certomancer.registry import ArchLabel, CertLabel, EntityLabel
from pyhanko_testing_commons.test_data.certomancer_trust_lists import (
    certomancer_lotl,
    certomancer_pki_as_trusted_list,
)
from pyhanko_testing_commons.test_data.samples import CERTOMANCER, TESTING_CA_QUALIFIED

ARCHS = ['testing-ca', 'testing-ca-ecdsa', 'testing-ca-qualified', 'unrelated-tsa']


def export_certs(out_root):
    count = 0
    for arch in ARCHS:
        pki = CERTOMANCER.get_pki_arch(ArchLabel(arch))
        out_dir = os.path.join(out_root, arch)
        os.makedirs(out_dir, exist_ok=True)
        for _iss, specs in pki.enumerate_certs_by_issuer():
            for spec in specs:
                cert = pki.get_cert(spec.label)
                with open(os.path.join(out_dir, f'{spec.label}.cert.pem'), 'wb') as f:
                    f.write(pem.armor('CERTIFICATE', cert.dump()))
                count += 1
    return count


def main():
    lanes_e = os.path.join(os.getcwd(), 'crates', 'hanko-testdata', 'data', 'lanes', 'e')
    count = export_certs(os.path.join(lanes_e, 'pki'))
    tl_dir = os.path.join(lanes_e, 'tl')
    os.makedirs(tl_dir, exist_ok=True)
    lotl = certomancer_lotl(
        TESTING_CA_QUALIFIED,
        EntityLabel('root'),
        entries=[(CertLabel('interm-qualified'), 'be', 'https://example.com/')],
    )
    with open(os.path.join(tl_dir, 'certomancer-lotl.xml'), 'w', encoding='utf-8') as f:
        f.write(lotl)
    tl = certomancer_pki_as_trusted_list(TESTING_CA_QUALIFIED, EntityLabel('root'))
    with open(os.path.join(tl_dir, 'certomancer-qualified-tl.xml'), 'w', encoding='utf-8') as f:
        f.write(tl)
    print(f'exported {count} certificates and 2 lists', file=sys.stderr)


if __name__ == '__main__':
    main()
