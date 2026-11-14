# C: three named signature appearance functions

Accepted baseline ab08d1c6, compiled14d6c6a3: CLI252/193/0/59, overall
1431/1360/12/59. Decode3 and default-appearance2 are already counted once.

## Exact owned increment

All are in pyhanko-cli/test_cli_signing.py:

- test_cli_sign_visible_with_style: RSA/ECDSA/Ed25519/Ed448, four cases.
- test_cli_sign_visible_with_qr_style: the same four; execute nosmoke.
- test_cli_sign_visible_with_qr_style_omit_stamp_url: Ed25519 only, one case.

Three unique functions, nine cases; no provider exclusion or broader signing
engine is approved. Preserve complete inherited post_validate teardown.

## Files and interfaces

C may edit pemder_signing.rs and, only if a measured need requires it, existing
signature_appearance.rs/lib.rs, plus new appearance_styles/styled helper tests
and C fixtures. appearance_default.rs is a test target, not a production file.
Do not edit fields.rs, lower crates, manifests, lockfile or central counters.
Existing named stamp styles, PdfSigner and URL text parameters suffice; route
an exact missing interface to L rather than adding a second engine.

Preserve all effective/raw configuration, five-field MAIN usage, caller context,
authenticated reader strictness/remaining decode budget/MAC, default appearance
and refusal contracts. Retain original named text/QR configuration and precise
missing-URL diagnostic. Require actual signed-output trust/coverage/seed/DocMDP,
same-output empty-root denial and real AP/URL assertions. A nonempty AP alone
is not rendering or QR equivalence. Native sentinel checks are supplemental;
do not prefill the unchanged original fixture output.

Artifacts: round3/c/styled-three/. Qualified8 remains separate; public detailed
APIs exist but mandatory time/trust semantics cannot be replaced by Basic or a
relaxed retrospective clock guard. No current credit for this increment.

## Execution and reporting

Use tools/cargo-locked.sh for every Cargo call, one at a time per lane. It
injects canonical rust-target-env and delegates placement/concurrency to system
rust-slots; automatic VM dispatch is allowed. Preserve sccache, targets, flags,
profiles and features. Do not introduce a repository lock, local pin or job cap.
Keep proof snapshots lean; compressed ELF archives require distinct raw/archive
SHA256 and length checks. Do not clean shared targets or old evidence.

Port complete exact upstream assertions before implementation. Use the pinned
pyHanko0.38.1/CV0.33.0 oracle at /tmp/pyhanko-oracle/venv, assertions enabled.
Fresh original bodies, same-output comparisons, replay and native executions
remain distinct. Trust decisions fail closed; mandatory unsupported conditions
refuse. Report exact IDs and parameters, source/ELF/runtime/input receipts,
per-crate total/passed/skipped/pending and divergences. Root owns acceptance
counts and full build/test/clippy -D warnings/strict doc/layer/fmt gates.

English local commits only; no push, pkill, service restarts, target cleanup or
interference with other sessions. Preserve frozen branches, proof artifacts and
dirty lockfiles. Save progress and handoffs under the assigned artifact path.
