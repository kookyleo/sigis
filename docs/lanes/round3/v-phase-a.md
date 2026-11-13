# Approved V phase A: opt-in exact main predicate

Lead assignment2026-11-14, accepted parent d1c2d325b8c47ce4e3953a47c396ec0bc83a9a4c/compiled21323. Existing V47 are accepted regressions; this compatibility increment earns ZERO new original IDs. Current immutable overall1431/1347/17/67 remains unchanged.

Approve the documented phase-A public surface in crates/pades/oracle/proposals/ades-exact-options/README.md and accepted-parent-addendum.md: non-exhaustive defaultable AdesValidationOptions with one complete exact_key_usage_settings object; basic_validation_with_options, with_time_validation_with_options, lta_validation_with_ades_options, simulate_future_lta_validation_with_ades_options, validate_pdf_ades_with_options. Existing functions delegate with Default/None, retaining their individual default/order/status behavior and all current signatures. LtaOptions/QualificationSpec stay unchanged. No automatic CLI opt-in.

Exclusive production scope: crates/pades/src/ades/{mod.rs,basic.rs,with_time.rs,lta.rs} and an optional new options.rs; pades validation.rs/lib.rs only if the existing PDF forwarding/export genuinely requires it, with a minimal documented hunk. No core/CMS/CV/fetch/P/CLI/ades-model/manifest/lock/layer edit. Tests: new crates/pades/tests/ades_exact_options.rs and temporary exclusive root tests/round3_ades_exact_main_options.rs for acyclic real signer callers; new fixture/oracle directory crates/testdata/data/lanes/r3-v/ades-exact-options/. Existing CMS fixture inputs are read-only. No new crate edge. L owns integration and all final gates/lockfile/acceptance.

Use an isolated worktree/current-parent projection preserving the old V history and dirty work. Port all substantive pinned assertions and new public API tests FIRST; record actual missing-API diagnostics as API unavailability, never behavioral RED. Then implement. Original regression ownership is the exact47 IDs below, unchanged. Every Cargo invocation through tools/cargo-locked.sh; one lane process, automatic system rust-slots placement only, canonical target/sccache preserved. No raw/manual remote Cargo, repository flock/local pin/job cap/speed flags/features/profile or target cleanup.

Some retains ALL5 Core fields verbatim, including None versus empty KU/EKU and any/all/explicitness; set only CMS exact selector, leave legacy selector None. Propagate through initial CMS/PDF, discovery retry, final historical MAIN recheck and future simulation. Preserve dispatcher TimestampsFirst versus detailed SignerFirst. Never send MAIN predicate to fixed-purpose TSA operations. Preserve every caller/clone field, backend close ownership, trust/algorithm/cutoff/revocation/freshness/assertion/AC/qualification/POE constraint. No new POE from DSS/TST presence, unverified imprint or cutoff; no default-profile retry or report revalidation after rejection. If a stage cannot carry a mandatory predicate, reject and leave pending. Trust decisions fail closed.

Separate TSA policy/context/handler-sharing and S lifecycle/default bootstrap are NOT assigned here. No getters, fake managers, fallback factories or empty test wrappers. Explicit same/equal contexts retain their existing private registry/role behavior. Reports consume the SAME result.

Required native controls: old-versus-new Default/None in all five entries with whole status/path/time/POE/qualification and caller identity/settings; genuine CMS and PDF DS-only/empty/NR/forbidden/any-all/EKU cases; valid/wrong-purpose TSA; actual historical LTA plus future, mandatory revinfo/crypto/AC/NO_POE/corrupt-imprint/context/coverage negatives; demonstrate full predicate forwarding at each final decision, not only an initial error. Root can receive precise API requests; do not weaken assertions.

Use fresh pinned pyHanko0.38.1/CV0.33.0 /tmp/pyhanko-oracle/venv with assertions enabled. Compare actual SAME native bytes against the correct exact low-level/AdES surface; ordinary normalized reference stays separate. State context temporal/profile differences, recording replay versus fresh execution, provider exclusions and divergences. Do not label old owner recordings fresh. Save command/source/exit/current ELF and actual input/output receipts with SHA256/length; Root will independently rebuild/test.

Report English total/passed/skipped/pending per crate (V pades47/47/0/0,ades-model0/0/0/0 unchanged until L accepts feature evidence), source/tests-first/production-only English local commit hashes, exact parameters, fresh/native differential results, divergences/limits, dirty-lock preservation. No push, pkill, service restart or other-session interference; old lane sessions stay unchanged. Artifacts under round3/v/ades-exact-phase-a/.

## Existing accepted regression IDs (zero new credit)

- `pyhanko/test_ades_validation.py::test_pades_basic_happy_path`
- `pyhanko/test_ades_validation.py::test_pades_basic_happy_path_with_tl`
- `pyhanko/test_ades_validation.py::test_pades_fail_qualification_requirements`
- `pyhanko/test_ades_validation.py::test_embedded_cades_happy_path`
- `pyhanko/test_ades_validation.py::test_embedded_cades_basic_tampered`
- `pyhanko/test_ades_validation.py::test_embedded_cades_sig_tampered`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_happy_path`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_tampered_timestamp`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_sig_tampered_timestamp`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_happy_path_with_tl`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_fail_qualification_requirements`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_non_qtst_tsa_fail`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_non_qtst_tsa_pass`
- `pyhanko/test_ades_validation.py::test_embedded_cades_provably_revoked`
- `pyhanko/test_ades_validation.py::test_embedded_cades_revoked_no_poe`
- `pyhanko/test_ades_validation.py::test_embedded_cades_pre_revoke_with_poe`
- `pyhanko/test_ades_validation.py::test_pades_lta_happy_path_current_time`
- `pyhanko/test_ades_validation.py::test_pades_lta_happy_path_past_time`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_happy_path`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_happy_path_eseal`
- `pyhanko/test_ades_validation.py::test_pades_lta_fail_qualification_requirements`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_happy_path_with_ts_chain`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_no_revinfo_fail`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_with_broken_ts_chain`
- `pyhanko/test_ades_validation.py::test_pades_lta_expired_timestamp`
- `pyhanko/test_ades_validation.py::test_pades_missing_dts`
- `pyhanko/test_ades_validation.py::test_pades_lta_happy_path_past_time_with_chain`
- `pyhanko/test_ades_validation.py::test_pades_hash_algorithm_banned_but_poe_ok`
- `pyhanko/test_ades_validation.py::test_pades_lta_hash_algorithm_banned_and_no_poe`
- `pyhanko/test_ades_validation.py::test_pades_lta_algo_permaban`
- `pyhanko/test_ades_validation.py::test_pades_lta_live_ac_validation`
- `pyhanko/test_ades_validation.py::test_nontraditional_hybrid_lta`
- `pyhanko/test_ades_validation.py::test_nontraditional_hybrid_lta_with_failed_timestamp`
- `pyhanko/test_ades_validation.py::test_pades_multi_sig_timestamp_algo_hedge_ok`
- `pyhanko/test_ades_validation.py::test_pades_multi_doc_timestamp_algo_hedge_ok`
- `pyhanko/test_ades_validation.py::test_pades_multi_sig_timestamp_with_unknown_digest`
- `pyhanko/test_ades_validation.py::test_content_ts_with_different_digest_not_supported`
- `pyhanko/test_ades_validation.py::test_bootstrap_handlers_default_backend`
- `pyhanko/test_ades_validation.py::test_certificate_fetching_rule_matrix`
- `pyhanko/test_ades_validation.py::test_never_fetch_certs_keeps_revinfo_fetching`
- `pyhanko/test_ades_validation_report.py::test_pades_basic_report_smoke_test`
- `pyhanko/test_ades_validation_report.py::test_pades_basic_failing_report_smoke_test`
- `pyhanko/test_ades_validation_report.py::test_pades_basic_indeteriminate_report_smoke_test`
- `pyhanko/test_ades_validation_report.py::test_pades_lta_report_smoke_test`
- `pyhanko/test_ades_validation_report.py::test_pades_with_attributes_report_smoke_test`
- `pyhanko/test_ades_validation_requests.py::test_pades_basic_happy_path_requests`
- `pyhanko/test_ades_validation_requests.py::test_pades_lta_happy_path_current_time_requests`

## Subsequent accepted parent

Main0c500be8 accepts configured identities/getpass on source4d47 after all six
workspace gates; authoritative counts are1431/1350/17/64, C188/64. These new
changes affect CLI files and acceptance metadata; the V production preimages
remain byte-identical to the assignment parent. This assignment adds zero IDs
and accepts no V implementation. V retains its tests-first/isolated-history and
Root integration/full-gate obligations.
