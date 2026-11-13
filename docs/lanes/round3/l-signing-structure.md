# Accepted raw DSA, trailer provenance and basic software commands

Source724d078dadea3bffb1f4ba7203a31a19ff855c63 completes exactly four immutable upstream functions. The complete workspace gate and independent current-source/runtime review precede acceptance. Counts become1431total/1307passed/23skipped/101pending. Native1901discovered/1898passed/3ignored/0failed across182reports is a separate measurement.

| Owner / original ID | Complete native port |
| --- | --- |
| P: pyhanko/test_pkcs11.py::test_simple_sign_with_raw_dsa | Root round3_raw_dsa::test_simple_sign_with_raw_dsa, one SoftHSM case |
| S: pyhanko/test_xref.py::test_trailer_refs | trailer_provenance::test_trailer_refs, no source parameters |
| C: pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder | software_signing::test_cli_addsig_pemder, four original algorithms |
| C: pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12 | software_signing::test_cli_addsig_p12, four original algorithms |

## Raw DSA signing

The dedicated root suite requires the reviewed private SoftHSM module/utility and an explicit fixture opt-in before initialization. It requires both actual advertised DSA_SHA256 and raw CKM_DSA, pulls leaf/intermediate/root certificates from the token, exercises native raw C_Sign and DER conversion, then produces a real SHA256/Sig1 PDF. Full native and fresh same-output pinned Python both require intact/valid/trusted/bottom_line, ENTIRE_FILE and NONE. The current full-gate PDF is13600bytes, SHA2562cd55b789a70c069cf183b57c2b35e4bc69beb414c914f20763bb7face2633d9. Default3192-bit DSA policy still rejects; the original fixture's explicit1024-bit policy trusts. No default algorithm policy is weakened.

A separate unchanged original Python SoftHSM function previously passed once with the compatible isolated python-pkcs110.9.5 wheel. That reference is distinct from current native execution and same-output validation, not rerun or replayed as a native result. The base0.38.1/CV0.33 oracle venv is unchanged. The25-file overlay and module/utility hashes are verified on both workers. Only existing root rsa/pkcs8 dev edges are added; all462package versions,22workspace members and resolved features remain unchanged. The old partial ignored package wrapper is relocated to the complete root suite and counted once. General DSA matrix parameters remain excluded until separately proved; SafeNet and default-context-warning exclusions remain.

## Trailer/container provenance

The additive writer API retains actual source reader/state and complete numbered-container snapshots with private key/index paths. Incremental raw Root tokens carry genuine trailer provenance; update_container leaves numbered updates/no-op bytes unchanged. Numbered and nested edits write their complete outer object, not a raw reference's referent. Strict missing-reference and authentication errors propagate without default-reader reopen or decode-budget reset. Seven native tests include one original and six controls. Six freshly parsed actual native input/output buffers agree with public Python operations; two no-ops are byte-identical, four serializations differ.

This is a documented Rust value/COW snapshot adaptation. Independently retrieved handles do not propagate Python live-alias mutations, and readonly trailer views are not Python object-identity parity. No shared object field/trait/export/dependency/layer shape is changed. Other model gaps remain skipped.

## Two basic software commands

Only directly selected canonical PEM/DER and PKCS12 built-ins enter the bounded public adapter. Extended/unknown/duplicate flags, supplied or effective unsupported configuration, other providers and public encrypted-document signing reject before loading credentials or prompting. The old full-owner fallback and allow_encrypted=true callers are excluded. Reader/authentication/strictness/decode state and actual runtime time pass through existing native signing APIs. All existing configuration, plugin, crypt, fields, stamps, runtime-read and ordinary validation modules/fixtures remain unchanged; the dispatcher alone gains the reviewed basic-command route.

The two exact originals cover RSA/ECDSA/Ed25519/Ed448, real DER leaf plus original PEM intermediate, and encrypted PFX password input. Three focused native command tests and seven capability/mandatory-policy guards pass. Current full-gate48durable process records contain12native signing attempts,12fresh Python CLI comparisons, eight fresh same-native-output public validations and16native trust/no-root controls. Eight original successes and four wrong-password rejections have individually preserved input/output/argv/ELF/helper hashes and184archived records.

Fresh Python verification uses its original live PKI and checks bottom_line, integrity, empty-root distrust and changed-digest refusal. Native extra trust/no-root controls select the explicit historical2020-08-01 moment with revocation disabled. These are different contexts; no equivalent-context, whole-original-pytest rerun, current-time trust or full LTV/qualified/provider claim is made. CLI help still contains an inherited registry-only summary; remaining runtime/help parity remains open. C252/152/0/100 is scoped command acceptance, not full CLI completion.

## Gate, input identity and retained evidence

Build, workspace tests, strict all-target clippy, strict docs, dependency layers and fmt pass on one frozen source. The current private CLI is08fc1fa6878bb53cdcce0b484428784283332a59457bf435484d4cb6382c4b94,123336872bytes/version0.0.1; both workers match. Nine actual full-gate selections and all28native command processes select those bytes. Producer13units/229emitted inputs and current code/fixtures are independently checked. The thin main entry is unchanged and represented by actual producer JSON; it is not falsely included in the selected229checksum records. Actual full-gate raw-DSA and software-command test ELFs have durable hash-matching copies, distinct from earlier focused binaries.

The initial clippy process succeeded but its collector failed to parse two fingerprint JSON reads. Initial bad bytes were not retained; stable post-gate copies do not prove the cause. All errors/raw available evidence remain preserved. The corrected artifact-only sampler saves every raw/stat attempt before parsing, uses bounded two-consecutive stable reads and still rejects invalid/noncontent/input mismatches. Actual clippy was rerun before docs/layer/fmt; unchanged valid build/test observations remain their original phases. No target/cache cleanup, flags/features/profile/sccache/local-placement bypass or service restart occurs.

Final selected compiler/input checks cover434phase observations/2788records/453actual paths. AA/SDK manifest provenance references were prepared strictly; actual recovery uses zero such aliases. Literal foreign inputs require matching actual and candidate Git bytes. The sampler and binary format decoder are bounded diagnostic tools, not an OS-level tracing or universal build-script/cache guarantee.

All retained V213/S69/L18/P/Adobe/HTTP/time-tolerance and ordinary validation controls pass current-source verification. Current CV22records are intact. Five full-gate capability telemetry payloads and one auxiliary ordinary-config read were interrupted by harness output; original rows are untouched. Actual same-source serial seven-guard/61row and one-original/32parameter library-API config reruns supply complete evidence; the latter makes zero additional CLI selections. The retained runtime verifier's old new_ids4 label refers to previously accepted L functions and is not additional credit.

Artifacts: /home/l/.codex/artifacts/sigis/round3-launch/next-batch/. Earlier focused results keep their real commits and hashes. Complete porting and universal fail-closed parity remain unproved: remaining CLI/LTA/qualification/provider behavior, final actual CLI-LTA and23honest exclusions still require work. Encoding/model differences are not themselves trust verdicts. No service switch or restart is authorized by these counts.
