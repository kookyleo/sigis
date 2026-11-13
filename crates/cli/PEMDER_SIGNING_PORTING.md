# Accepted bounded PEM/DER signing originals

Source `a48fb320b8a665eaee39a4eb346c5b7eaa7d4965` accepts exactly ten new unique upstream functions/30 original parameters after current CLI/source/runtime, actual serial policy evidence and all six workspace gates. C252/173/0/79 includes the previously accepted basic PEM/P12 functions once. This table counts functions, not process receipts, parameter wrappers, supplements or oracle calls.

All IDs have prefix `pyhanko-cli/test_cli_signing.py::`, implemented in `tests/pemder_signing.rs` with the same function name.

| Exact function suffix | Original parameters | Coverage |
| --- | ---: | --- |
| test_cli_addsig_pemder_without_nopass | 4 | RSA/ECDSA/Ed25519/Ed448; actual empty prompt, real output and fresh validation |
| test_cli_addsig_pemder_with_setup | 4 | Selected complete setup, raw DER leaf and PEM chain |
| test_cli_addsig_pemder_with_wrong_key_usage | 1 | Ed25519 purpose denial, output preserved |
| test_cli_addsig_pemder_with_wrong_extd_key_usage | 1 | Ed25519 mandatory EKU denial; bounded stricter upstream-xfail difference |
| test_cli_addsig_pemder_with_setup_in_custom_config_file | 4 | Explicit custom configuration and actual indirect material selection |
| test_cli_addsig_pemder_with_setup_encrypted_key | 12 | Four architectures × configured/passfile/prompt password |
| test_cli_addsig_pemder_setup_requires_config | 1 | Missing configuration refusal |
| test_cli_addsig_pemder_some_args_required | 1 | Incomplete credential selection refusal |
| test_cli_addsig_pemder_setup_does_not_exist | 1 | Missing selected setup refusal |
| test_cli_addsig_pemder_with_unreadable_additional_certs | 1 | Actual malformed chain material refusal |
| Total unique functions / parameters | 10 / 30 | No runtime provider exclusions |

Current native/reference pairs show29 original status agreements and1 stricter native EKU refusal. All24 original native positive PDFs receive fresh same-output public Python verification;4 successful password supplements and1 empty-configured-password refusal add zero IDs. The xfail Python output's separate verification is not counted as native output.

Configured passphrase, including empty bytes, remains authoritative over passfile/no-pass; supplied passfiles are opened before dispatch and the first trimmed line is used when selected. Full effective policy/configuration is preserved; unsupported mandatory requirements explicitly reject with no basic-engine fallback. Shared alias tests cover direct construction, ordinary validation and existing P12 as well as PEM, including actual equal-alias signing positives. These supplements do not earn additional upstream IDs.

The attached-context lower signer still applies all KU entries even when the adapter requests match-any; complete parity for that combination remains an explicit stricter compatibility gap. Native trust controls use historical NoRev, whereas fresh public Python verification uses fixture fetching/revocation. Known-xfail EKU denial is an observed bounded fail-closed difference, not a universal trust claim. The complete CLI/port remains unfinished.

See `docs/lanes/round3/l-pemder.md` for source/ELF/runtime and final-gate evidence; immutable function ownership and central `acceptance.json` control accepted counts.
