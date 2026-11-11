# pyHanko test data

Copied from `internal/common-test-utils/src/pyhanko_testing_commons/test_data/data/`
in <https://github.com/MatthiasValvekens/pyHanko> at commit
`0b27455d49ecde3d2853f598558f76d1af38cbf1` (2026-11-11). This is the data
directory that pyHanko's own test suites (`pkgs/pyhanko/tests`,
`pkgs/pyhanko-cli/tests`) load.

| Directory | Content | License |
| --- | --- | --- |
| `crypto/` | Test PKI: Certomancer configuration (`certomancer.yml`), keys, PKCS#12 files, certificates | MIT (`LICENSE-pyHanko`) |
| `pdf/` | Input and reference PDFs | MIT |
| `xml/` | XML test inputs | MIT |
| `img/` | Images for stamp tests | MIT |
| `fonts/` | Noto and Source Serif fonts | SIL Open Font License 1.1 (`fonts/LICENSE.*`) |
| `tl/` | EU trusted lists and LOTL snapshots | CC BY 4.0, European Commission (`tl/COPYRIGHT`) |

**The private keys under `crypto/` are public test keys from the pyHanko
repository. They must never be used for anything but tests.**

Certificates for most pyHanko tests are generated at test time by
Certomancer from `crypto/certomancer.yml`; exported PKI material for the Rust
tests is produced by the lead with `tools/pyhanko-oracle/` and stored under
`data/pyhanko-pki/` (see `docs/hanko-lanes.md`).
