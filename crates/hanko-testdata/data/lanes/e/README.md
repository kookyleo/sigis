# Lane E fixtures

## `pki/`

Certificates of pyHanko's Certomancer test PKIs (`testing-ca`,
`testing-ca-ecdsa`, `testing-ca-qualified`, `unrelated-tsa`), one PEM file
per certificate label. Produced from
`crates/hanko-testdata/data/pyhanko/crypto/certomancer.yml` (pyHanko 0.38.1,
certomancer 0.16.0) with:

    python -I crates/hanko-eutl/oracle/export_pki.py

Validity periods are fixed in the configuration. No private keys are
exported; the corresponding keys are pyHanko's public test keys under
`data/pyhanko/crypto/keys-*`.

License: MIT (derived from pyHanko test data, see `../../pyhanko/LICENSE-pyHanko`).
