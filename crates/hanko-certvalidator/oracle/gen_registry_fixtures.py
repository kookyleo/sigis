"""Write the synthetic certificates of test_registry.py as DER files.

The upstream tests build unsigned certificates in memory with
`_gen_issuer_candidate_cert` / `_gen_subject_candidate_cert`. This script
imports those helpers from the pyhanko-certvalidator 0.33.0 test suite and
writes their output, so the Rust port uses identical inputs:

    $HANKO_ORACLE crates/hanko-certvalidator/oracle/gen_registry_fixtures.py \
        $HANKO_CV_SRC/pkgs/pyhanko-certvalidator OUT_DIR
"""

import os
import sys

pkg_dir, out = sys.argv[1], sys.argv[2]
sys.path.insert(0, pkg_dir)
os.makedirs(out, exist_ok=True)

from tests.test_registry import (  # noqa: E402
    _gen_issuer_candidate_cert as issuer,
    _gen_subject_candidate_cert as subject,
)

certs = {
    'issuer-foo-root-0': issuer(b'foo', 'issuer', ('root', 0)),
    'issuer-bar-root-1': issuer(b'bar', 'issuer', ('root', 1)),
    'issuer-bar-root-0': issuer(b'bar', 'issuer', ('root', 0)),
    'issuer-foo-root-1': issuer(b'foo', 'issuer', ('root', 1)),
    'subject-aki-foo': subject(b'foo', 'issuer', None),
    'subject-coords-root-0': subject(None, 'issuer', ('root', 0)),
    'subject-aki-foo-coords-root-0': subject(b'foo', 'issuer', ('root', 0)),
    'subject-aki-foo-coords-root-0-ski-bar': subject(
        b'foo', 'issuer', ('root', 0), b'bar'
    ),
    'subject-aki-quux-coords-root-0': subject(b'quux', 'issuer', ('root', 0)),
}
for name, cert in certs.items():
    with open(os.path.join(out, name + '.der'), 'wb') as f:
        f.write(cert.dump())
