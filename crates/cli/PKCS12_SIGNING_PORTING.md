# Accepted bounded PKCS12 and LTA CLI ports

Accepted source: `f1cd5948cf0a487610b6b362f2b1340c113bc46f`. Exactly11unique originals/35source parameters;
eight P12 functions/28cases, strict/nonstrict LTA two functions/6cases,
and one provider-independent missing-TSA function. Basic P12 and PEM
remain in SOFTWARE_SIGNING_PORTING.md and are counted only once.

| Exact immutable upstream ID | Original cases | Native test |
| --- | ---: | --- |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_unencrypted_p12` | 4 | `pkcs12_signing::test_cli_addsig_unencrypted_p12` |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_unencrypted_p12_without_nopass` | 4 | `pkcs12_signing::test_cli_addsig_unencrypted_p12_without_nopass` |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_with_setup` | 12 | `pkcs12_signing::test_cli_addsig_p12_with_setup` |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_setup_requires_config` | 1 | `pkcs12_signing::test_cli_addsig_p12_setup_requires_config` |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_setup_unreadable` | 1 | `pkcs12_signing::test_cli_addsig_p12_setup_unreadable` |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_setup_corrupted_keystore` | 1 | `pkcs12_signing::test_cli_addsig_p12_setup_corrupted_keystore` |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_setup_or_pfx_argument_required` | 1 | `pkcs12_signing::test_cli_addsig_p12_setup_or_pfx_argument_required` |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_passfile` | 4 | `pkcs12_signing::test_cli_addsig_p12_passfile` |
| `pyhanko-cli/test_cli_signing.py::test_cli_pades_lta` | 3 | `pkcs12_lta::test_cli_pades_lta` |
| `pyhanko-cli/test_cli_signing.py::test_cli_pades_lta_nonstrict` | 3 | `pkcs12_lta::test_cli_pades_lta_nonstrict` |
| `pyhanko-cli/test_cli_signing.py::test_cli_pades_lta_no_timestamp_url` | 1 | `pkcs12_lta::test_cli_pades_lta_no_timestamp_url` |

P12 positive algorithms: RSA/ECDSA/Ed25519/Ed448. Setup password locations
are config/prompt/file for each algorithm; four source error functions are
nonparametrized. LTA uses the upstream three-algorithm LTV matrix.

All213 actual subprocess receipts include48 retained basic+165 C11 records.
They preserve35original native/reference decision pairs,30fresh same-native-
output validations, exact error strings, configs/PFX/root/passfiles and
actual immutable final CLI/test ELF identities. Supplemental password,
schema, sentinel, unknown-requirement and runtime controls earn zero IDs.
Five direct top-level records and45new/61retained serial policy rows are
in-process proof, not product subprocess clock/fetcher injection.

Current-clock LTA uses the existing signer1-long credential rather than
expired signer1 from frozen2020 unit fixtures. This adaptation is explicit;
there is no product clock/validity override. Real native HTTP TSA/OCSP/CRL
metrics precede reference traffic. Native/Python full trust, same-output
empty-root distrust and wrong-digest controls are mandatory. Historical
NoRev native simple-P12 controls are distinct from revocation-capable Python.

The bounded P12 adapter consumes the whole caller configuration/context/
runtime and preserves mandatory refusal without legacy fallback. The
ordinary PEM SomeCFG refusal stays unchanged. No new dependency, lockfile,
vendor or existing reader API change is introduced. Other CLI flows and
help/provider/qualification gaps remain separate; no complete-port or
universal fail-closed claim follows. See docs/lanes/round3/l-cli-lta.md.
