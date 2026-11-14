# L source473 acceptance and bounded next assignments

Accepted compiled source: `473b7cbddef5df4aaaefef5a0f7075953927d0b3`.

The source473 cohort completes exactly eleven unique upstream functions: ten C-owned CLI originals and one S-owned fetch original. No P-owned or V original is added. Accepted inventory is **1431 total /1374 passed /10 skipped /47 pending**; library scope is **1168/1157/10/1**. Immutable ownership remains unchanged. The Root ledger postimage preserves all346old raw overrides in order and appends eleven passed rows, yielding357; prior dispositions remain intact.

**57 functions remain unfinished:47 Pending (46 CLI plus1 V) and10 skipped (9 S plus1 P SafeNet).** Function IDs, parameters, Rust wrappers, callbacks, API calls and executable captures are separate counts.

## Current per-crate inventory

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| sigis-pki-certvalidator |133|131|2|0|
| sigis-pki-fetch |56|53|3|0|
| sigis-cms |78|78|0|0|
| sigis-pki-core |4|4|0|0|
| sigis-pdf |406|402|4|0|
| sigis-pdf-diff |94|94|0|0|
| sigis-pades-sign |297|296|1|0|
| sigis-pades |47|46|0|1|
| sigis-eutl |53|53|0|0|
| sigis-cli |252|206|0|46|
| sigis |11|11|0|0|

## Exact accepted originals

| Upstream function | Owner | Native mapping |
| --- | --- | --- |
| `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_custom_default_style` |C| `appearance_default_styles::test_cli_sign_visible_with_custom_default_style` |
| `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_default_style_and_others_in_config` |C| `appearance_default_styles::test_cli_sign_visible_with_default_style_and_others_in_config` |
| `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_undefined_default_style` |C| `appearance_default_styles::test_cli_sign_visible_with_undefined_default_style` |
| `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_style_but_no_config` |C| `appearance_visible_negatives::test_cli_sign_visible_with_style_but_no_config` |
| `pyhanko-cli/test_cli_signing.py::test_cli_underspecified_visible_new_field` |C| `appearance_visible_negatives::test_cli_underspecified_visible_new_field` |
| `pyhanko-cli/test_cli_signing.py::test_cli_underspecified_visible_new_field_no_name` |C| `appearance_visible_negatives::test_cli_underspecified_visible_new_field_no_name` |
| `pyhanko-cli/test_cli_signing.py::test_cli_explicit_style_but_field_invisible` |C| `appearance_visible_negatives::test_cli_explicit_style_but_field_invisible` |
| `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_setup_config_unreadable` |C| `pkcs11_requirements::test_cli_pkcs11_setup_config_unreadable` |
| `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_args_required` |C| `pkcs11_preflight_two::test_cli_pkcs11_args_required` |
| `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_setup_requires_config` |C| `pkcs11_preflight_two::test_cli_pkcs11_setup_requires_config` |
| `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_policy_hands_ownership_to_the_context` |S| `round3_policy_context_ownership::test_policy_hands_ownership_to_the_context` |

S1uses the explicitly disclosed complete-suite inference; the other ten candidates have direct full-log pass lines.

## Actual source473 gate

All six returned0/audit0: build7.44s, test1517.83s, clippy24.91s, strict doc220.61s, layer3.98s and fmt3.82s. Full compiler audit covers518selected units/3117input records. Actual top-level Rust totals are **2191 discovered /2187 passed /4 ignored /0 failed /224 reports**; P2 child summaries are excluded. All63package-qualified raw/gzip captures bind actual Running paths, complete five-field summaries and separate compressed/decompressed hashes/lengths.

Independent final review returned0 in70.459s:71423checks,16399proof paths,552current source locators and724historical source versions. [Final review](/home/l/.codex/artifacts/sigis/round3-launch/cli-policy-integration/final-review/review.json) SHA256 **68c4a379af0b4f130250fb653cdb67599c42893d8a8fefd01cd1d7ebcee12a1d**; [actual receipt](/home/l/.codex/artifacts/sigis/round3-launch/cli-policy-integration/final-review/actual-receipt.json) SHA256 **92e2d0157d8f57331ad42d31fab3d47fad2a2d068b678644cc911cb93de1a535**. The top-level failed.json is preserved attempt history, not the current result.

The coherent CLI is SHA256 `15ce7c48c0047dd35787088303f6dc089111bcc98b5cdf2415293b90835622a1`/124233528bytes, actual producer8.02s/13units/237inputs/audit0; both VM copies returned0 with the same path/hash. It is the compiler-event executable captured after Cargo returned, not a run-instant or lock-held attestation. Current CLI focus returned0 in286.02s (19units/256inputs/audit0): default8pass/84.65s, visible13pass/173.90s, PEM/DER9pass/0.22s, P2two/3.99s and config5pass/18.34s. Five package-qualified raw/gzip captures include two exact immutable byte reuses for storage only. See [current focus receipt](/home/l/.codex/artifacts/sigis/round3-launch/cli-policy-integration/current-cli-receipt.json) and [five captures](/home/l/.codex/artifacts/sigis/round3-launch/cli-policy-integration/current-cli-executables/capture.json).

Tests-first history is retained honestly: default0/8 and config0/5 against the old accepted CLI; visible originals1pass/3fail, not all RED; P2first-GREEN2/2/b431with genuine full fixtures; S API RED E0432x1/CVE0599x5at e280is absent API, not behavior failure. The zero-ID unsupported-style control measured0/1before precise missing-config migration; all20guards remain, current PEM/DER9pass. Cowner59/1and invalid old0f26producer evidence are retained as failed/historical, not silently credited. The old5ebscalar18collector crash had no terminal Rust rc and proves no full pass; external collector guard/drain repairs are evidence infrastructure, not product code.

## Source, runtime and trust proof boundaries

Compiler proof is content/origin-specific, not universal literal locator identity. Two standalone S9527phases retain text.d Root+OWNER versus binary Root+Root locators: exact text SHA256 `6bcc791b8e1bc90e2e94eb10c9c4f641f4a53ed2f66625ca2618010fec786f5b` and binary SHA256 `cd5f51d8528355264c45f6002aa75c4b16c82df52e846b5ce3265e0e78f9f5e0`. Full additionally has exactly38enumerated units/46raw alias occurrences (36Clippy manifest+5test fixture+5Clippy fixture),6relative files/7concrete path pairs/2alternate origins. Exact phase/text/binary hashes delimit actual-origin own HEAD/common-Git and Root473same-relative SHA256/BLAKE3/length proof; unknown aliases fail. This is neither generic normalization nor full external environment attestation. Failed strict audit attempts remain historical evidence, not native failures.

Full S05fuses literal Root+Root source locators and raw ELF `238b86f231380f9d17d77a090e32cd9c2c5cfc8c60e86e62fbfdededa4801544`/88799152bytes, distinct from focused `7aeeb4a08631af8fb607598bfde80a75dadacb1ca2889df1df4642271049708b`/88788024bytes. Full225INPUTmarkers comprise223complete records and2unparseable raw lines1821/1865, retained without joining/repair/reconstruction; focused225complete inputs are separate. Sealed S review08a24bd9binds full11exports/29HTTP/0new reference API calls and focus20actual API/2constructor refusals with six literal subfield differences. It does not claim all-field parity.

Full S has11registered tests/11PASS/0FAIL/0IGNORE/0FILTER, with9complete single-line results and2transport-missing native functions: test_policy_hands_ownership_to_the_context and independent_handler_contexts_have_independent_pools_and_issued_caches. Exactly those two use complete-suite/source/capture inference plus independent focused serial-harness start/terminal success for all11functions (10interleaved starts with separate ok terminals,1single-line result). Only S1 is a newly credited inferred original; the supplement adds0IDs. All ten C candidate IDs have direct full result lines. No missing line is fabricated and no generic inference is granted.

All five MAIN usage predicates, caller context/options/time, mandatory policy, authenticated PDF reader/strict remaining decode budget/MAC and WithTime containment are retained. The bounded controls are not an exhaustive policy, encrypted-document, finite-serialization, rendering/scanner or universal fail-closed/parity/full-port proof. V remains47/46/0/1; genuine complete historical MAIN rescue is still a separate Pending original. The source9d trust matrix is historical, not fresh source473V parity.

## Remaining completion scope and immediate assignments

| CLI upstream module | Pending |
| --- | ---: |
| validation/test_cli_qualified_validation.py |22|
| test_cli_signing_pkcs11.py |10|
| test_cli_signing.py |7|
| test_cli_decode_limits.py |4|
| test_cli_ltv.py |3|
| Total |46|

Full work ownership is P's temporary10C-owned provider originals plus its own1SafeNet skip; C's other36CLI originals; V's1Pending original; S's9skips (3fetch+2deprecated CV+4PDF type/language); L's integration/gates/acceptance. That partition is broader than immediate implementation authority:

- S: [three remaining lifecycle originals](s-remaining-fetch-three-source.md), TESTS ONLY with the explicit limited empty-capability fixture mapping; no production/API or general source-graph parity.
- P: [one Env PIN token-signing original](p-cli-signing-env-pin.md), bounded tests-first implementation/allfiveeffectiveEd25519rows/new private store. Other nine signing originals remain source-only. Whole CLIlib is P-exclusive until freeze/L handoff.
- C: [one qualified-required original](c-qualified-one-tests-first.md), TESTS/FIXTURE PREPARATION ONLY, with qualified+required VALID and nonqualified+not-required VALID controls before same-byte mandatory negative credit. The [eight-original source inventory](c-qualified-current-source.md) is retained, within22remaining qualified-module functions. No production/lib/lower/manifest edits.
- V: [one later-revoked leaf original](v-leaf-revoked-completion.md), bounded tests-first implementation with status5314/owned-facts5444guards. Its current Pending annotation/count remains until a later accepted proof.
- L: all shared coordination, exact source integration, metadata/ledger, final gates and local main transactions. No lane merges or expands shared APIs independently.

Future packets receive no credit from this cohort. All Cargo uses tools/cargo-locked.sh/canonical rust-target-env/system slots/preserved sccache. Keep exclusive ownership, local English commits, old proofs and dirty independent work; no target cleaning, speed flags/features/profiles, manual remote Cargo, pushes, kills, service restarts or interference.

Storage recovery preserved source, targets, caches, services and old proof bytes. Online discard reduced sparse physical allocation122765152256→84733988864bytes (about38.0GB); the logical500GiB trim report is not500GiB newly freed. All70old raw paths are restored locally with exact bytes/mode/mtime and the temporary read-only view is unmounted; no ongoing FUSE dependency remains. Receipts: [local restoration](/home/l/.codex/artifacts/sigis/round3-launch/cli-policy-integration/storage-local-restoration.json), [view release](/home/l/.codex/artifacts/sigis/round3-launch/cli-policy-integration/storage-view-release.json) and [physical allocation](/home/l/.codex/artifacts/sigis/round3-launch/cli-policy-integration/sparse-target-free-extent-reclaim.json).

