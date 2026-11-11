# Test fixtures from pyhanko-certvalidator

Copied from `pkgs/pyhanko-certvalidator/tests/fixtures/` in
<https://github.com/MatthiasValvekens/pyHanko> at commit
`0b27455d49ecde3d2853f598558f76d1af38cbf1` (2026-11-11). Private key
directories (`*/keys`) were not copied; no test reads them.

| Directory | Origin | License |
| --- | --- | --- |
| `nist_pkits/` | NIST Public Key Interoperability Test Suite (PKITS), with test case definitions (`pkits*.json`) written for pyhanko-certvalidator | PKITS data: work of the U.S. Government, not subject to copyright in the U.S.; JSON definitions: MIT (`LICENSE-pyhanko-certvalidator`) |
| `openssl-ocsp/` | OpenSSL OCSP test vectors, with `openssl-ocsp.json` written for pyhanko-certvalidator | Apache-2.0 (`openssl-ocsp/LICENSE`); JSON: MIT |
| `freshness/`, `multitasking-ocsp/`, `testing-ca-*/`, `self-signed-with-policy.crt`, `ades/`, `attribute-certs/`, `multilayer/`, `testing-aia/`, `certs_to_unpack/` | pyhanko-certvalidator test PKI (generated with Certomancer) | MIT (`LICENSE-pyhanko-certvalidator`) |
