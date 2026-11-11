# crypt-pki

Certificates of the `ecc-testing-ca-with-decrypters` architecture of
pyHanko's Certomancer configuration
(`../../pyhanko/crypto/certomancer.yml`), used by the ECDH tests of
`crates/pdf/tests/crypt.rs` (port of pyHanko 0.38.1
`test_crypt.py`).

- Generator: `crates/pdf/oracle/export_crypt_pki.py` (Certomancer
  0.16.0). Run from the repository root.
- Time: not relevant. The configuration fixes the validity periods
  (2020-01-01 to 2025-01-01), serial numbers and names; only the ECDSA
  signature values change on regeneration.
- Private keys are not exported: the tests read pyHanko's public test keys
  from `../../pyhanko/crypto/keys-ecdsa/<label>.key.pem`.

| File | Subject key |
| --- | --- |
| `decrypter1.cert.pem` | P-256 |
| `decrypter2.cert.pem` | P-384 |
| `decrypter3.cert.pem` | P-521 (recipient of `pyhanko/pdf/pubkey-ecc-test.pdf`) |
| `decrypter-x25519.cert.pem` | X25519 |
| `decrypter-x448.cert.pem` | X448 |

License: derived from pyHanko's test configuration (MIT, see
`../../pyhanko/LICENSE-pyHanko`).
