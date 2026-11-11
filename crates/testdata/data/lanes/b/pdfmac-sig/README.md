# pdfmac-sig

Encrypted PDFs whose PDF MAC (ISO 32004) is attached to a signature
(`MacLocation.IN_SIG` cases of pyHanko 0.38.1 `test_pdfmac.py`), signed by
pyHanko 0.38.1 until lane D's signer can produce them. Used by
`crates/pdf/tests/pdfmac.rs`, which checks the MAC verdicts.

- Generator: `crates/pdf/oracle/gen_pdfmac_sig_fixtures.py`
  (pyHanko 0.38.1, pyhanko-certvalidator 0.33.0, Certomancer 0.16.0). Run
  from the repository root.
- File names: `<upstream test>-<standard|pubkey>.pdf` (encryption with the
  standard password handler, password `secret`, or with the public-key
  handler for `testing-ca/interm/decrypter1.cert.pem`).
- Each document is checked with pyHanko before it is written: good cases
  must have a valid MAC, bad cases must fail MAC validation with the
  message the upstream test expects.
- Time: the signing time is the generation time; no validation time is
  involved (only the MAC is checked). Keys, salts, nonces and signatures
  are random, so regenerated files differ byte-wise but not in verdict.

License: test documents derived from pyHanko's test suite (MIT, see
`../../pyhanko/LICENSE-pyHanko`).
