# CLI signing fixtures

Test-only PKI material exported from pyHanko 0.38.1's TESTING_CA by export.py.
The upstream test fixtures and derived materials are MIT-licensed; see
LICENSE-pyHanko at the repository root. Private keys are public test keys.
The encrypted key and PKCS#12 fixture password is `secret`.

Regenerate with the pinned interpreter:

```sh
/tmp/pyhanko-oracle/venv/bin/python crates/testdata/data/lanes/r3-c/signing/export.py
```
