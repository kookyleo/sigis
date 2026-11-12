# Typed algorithm horizons and exact time sliding

This S increment consumes L's accepted shared cutoff/error API on main17f74b8.
It changes no shared schema, context API, root file or dependency. V retains
ownership of authenticated-POE recovery and complete AdES/LTA acceptance.
Accepted unique-function counts remain S824/753/63/8 and CMS78/73/2/3; every
new test below is a supplemental native regression, with zero upstream credit.

## Resulting behavior

CMS enforcement returns `ValidationError::DisallowedAlgorithm` directly for
signature, digest and signature/digest-combination policy denials. It retains
exact typed `banned_since` metadata and checks in the pinned order. The CMS
status and path-error mapper preserve that same error and original failing path;
Some(cutoff) maps to CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the exact existing
error_time_horizon, while None remains CRYPTO_CONSTRAINTS_FAILURE. Dates in
reason strings do not create horizons. No denied policy becomes trusted.

Certificate algorithm checks use best_signature_time, as pinned
certvalidator validate.py:1072 specifies, independently of certificate validity
at validation_time. Typed errors, contextual PathFailure.time_horizon, original
failing paths and actual leaf/intermediate positions survive both detailed and
stripped APIs. The AC producer already preserves typed cutoffs and checks at
best_signature_time; its existing implementation is protected without changing
AC production code.

OCSP_NOCHECK responders retain the existing signature, issuer, EKU and validity
gates. The missing algorithm-policy query is restored at validation_time with
the actual responder signature algorithm and issuer key. A denied responder
cannot provide required OCSP; the caller receives InsufficientRevinfoError and
the original subscriber path, matching the pinned provenance-error wrapper.
NOCHECK does not bypass a timed or permanent policy denial.

Time sliding returns unchanged control time for allowed constraints, even with
incidental cutoff metadata. A timed denial returns exactly
min(control_time, cutoff), including equality. A permanent denial remains a
typed error. Rewinding does not provide POE, revocation evidence or trust, and
cannot override earlier revocation/freshness cutoffs.

## Tests-first evidence and discovered corrections

All 27 prepared native test definitions were applied before consumer edits.
CMS failed compilation because enforcement still returned String; certificate
horizon tests had 2 passes/1 failure (missing contextual cutoff), AC4 passed,
private time-slide tests had 3 passes/1 failure, and public time-slide tests had
2 passes/7 failures. These recorded failures preceded their semantic repairs.

Fresh public-path oracle work subsequently disproved the preparation's claim
that certificate policy should use validation_time. Its initial Rust assertions
mirrored that existing implementation. S corrected the assertions first: all
three new path tests then failed at the wrong policy time. Only then was the
production hook changed to best_signature_time; the three older certificate
failure-context helpers were corrected to assert the pinned time too. The old
preparation reports and initial green logs are historical evidence, superseded
by final runs; they are not complete compatibility proof.

Fresh same-fixture oracle testing also identified an existing mandatory-policy
omission: Rust returned true immediately for OCSP_NOCHECK responders. Pinned
validate_ocsp.py:97-126 skips responder revocation while still checking its
signature algorithm in a simplified context at validation_time. Real policies
with best_signature_time < cutoff < validation_time demonstrate the required
rejection. An additional native regression covers both issuer positions, real
required OCSP, exact main/side policy moments and original failure paths. It
first failed because the side-policy call was missing, then explicitly failed
because the forbidden timed policy returned success. Only after those two red
runs was the NOCHECK production branch repaired. All **28 new native
regressions** now pass, separately from unique upstream-function accounting.

## Native coverage inventory

The seven CMS functions are in `validate::algorithm_horizon_tests`:

- `cms_constraint_constructor_defaults_do_not_infer_cutoffs`
- `cms_enforcement_preserves_typed_exact_cutoffs_and_short_circuits`
- `cms_status_preserves_timed_and_permanent_denials_at_every_stage`
- `cms_allowed_constraints_ignore_incidental_cutoffs`
- `cms_date_like_reasons_do_not_create_cutoffs`
- `cms_path_mapping_preserves_original_path_typed_error_and_cutoff`
- `cms_cutoff_never_overrides_failed_integrity`

They exercise all three policy stages, exact messages/cutoffs, six timed versus
permanent status cases, actual CMS cryptography/path validation, absent trust,
tampered digest, stage order/moments and typed metadata overriding unrelated
legacy contextual horizon. Their committed harvest fixture supplies SignedData,
PDF digest and certificates only, never a recorded verdict. Revocation is disabled
only in this narrow CMS fixture context; separate path/AC tests require it.

Certificate tests in `tests/validate.rs::algorithm_horizon` cover:

- `certificate_algorithm_cutoff_survives_detailed_and_stripped_path_apis`
- `permanent_certificate_denial_does_not_infer_cutoff_from_reason`
- `allowed_certificate_constraint_with_cutoff_still_requires_revocation`

They use both leaf and intermediate positions in the real multitasking-ocsp
chain, distinct best/validation times, exact typed/context horizons and both APIs.
The additional
`nocheck_ocsp_responder_retains_mandatory_algorithm_policy_at_validation_time`
regression uses the same signed certificates and OCSP bytes and a genuine
time-dependent policy, not a call-index denial. Root and intermediate issuers
both exercise cutoff equality/later success controls and the strict
best-time < cutoff < validation-time rejection. The exact selected-policy trace
must be [best_signature_time, validation_time].

Four AC functions in `tests/ac_validate.rs::algorithm_horizon` cover:

- `attribute_algorithm_denial_preserves_exact_cutoff_at_best_signature_time`
- `attribute_policy_uses_best_signature_time_before_and_at_cutoff`
- `permanent_attribute_denial_does_not_infer_cutoff_from_reason`
- `allowed_attribute_constraint_with_cutoff_still_requires_ac_revocation`

These validate the actual revocable role AC, AA path/controls and required CRLs;
best time before/equal/after cutoff, permanent refusal and missing AC issuer CRL
remain distinct assertions. No fiat assertions substitute for revocation.

Private helper tests in `ltv::time_slide::algorithm_horizon_tests` are:

- `denied_timed_signature_uses_exact_minimum_including_equality`
- `permanent_denial_with_date_like_reason_is_a_typed_error`
- `permanent_denial_without_reason_is_still_a_typed_error`
- `allowed_signature_ignores_incidental_cutoff_metadata`

Nine public-entry tests in `tests/ades_time_slide_algorithm_horizon.rs` are:

- `timed_certificate_and_crl_constraints_reach_the_actual_call_sites`
- `timed_ocsp_signature_constraint_preserves_the_real_responder_path`
- `permanent_denials_from_certificate_crl_and_ocsp_remain_typed`
- `allowed_cutoff_metadata_does_not_rewind_any_call_site`
- `rewinding_an_intermediate_algorithm_does_not_supply_leaf_certificate_poe`
- `rewinding_an_intermediate_algorithm_does_not_supply_revinfo_poe`
- `rewinding_does_not_bypass_delegated_ocsp_responder_poe`
- `revocation_precedes_algorithm_recovery_for_crl_and_ocsp`
- `algorithm_recovery_does_not_bypass_revinfo_freshness`

The CRL, certificate and OCSP signature sites use real upstream time-slide
fixtures. Since some share the same algorithm/key, a recording policy selects
one actual traversal occurrence for fault injection and verifies full issuer-key,
algorithm and time traces. Separate public OCSP_NOCHECK regression uses a pure
time-dependent policy and does not rely on occurrence selection. Missing
certificate/responder/revinfo POE, revocation ordering and freshness are enforced.
Existing upstream time-slide wrappers that disable policy remain unchanged.

## Evidence and compatibility boundaries

All native logs and fresh oracle scripts/results are under
`/home/l/.codex/artifacts/sigis/round3/s/algorithm-horizon/native-run/`.
There are no new dependencies, provider/runtime exclusions or availability skips.
Detailed final commands, counts, source hashes and commit heads are recorded in
that directory's ready receipt. Selected tests do not establish whole-lane or
whole-workspace readiness; L owns integration and its full gate.

The fresh CMS/helper oracle matrix has 19 probe records: two constructor records,
six direct enforcement calls plus six actual CMS validations, four further CMS
controls aggregated in one record, eight time-slide helper calls and two path
error-mapping calls. It signs one fresh CMS input. The 15 full time-slide records
are 15 actual public time_slide calls using the same fixture inputs as Rust.
Fresh public certificate/AC and OCSP_NOCHECK matrices perform 22 completed
validation calls (12 path, 10 AC), plus two public path-building operations.
Nineteen verdict/error comparisons agree; three AC denial cases reject with
TypeError instead of the approved structured error. The matrix script saves all
18 original records and deliberately exits nonzero to expose those differences;
the separate four-case OCSP policy probe exits zero with all assertions met.
Earlier probe-development attempts (45 validation attempts, four path-building
calls) are preserved separately and not added to the final 22-case comparison.
Thus the development ledger contains 67 validation attempts and six path builds,
not 67 passing comparisons. These measurements are distinct from native tests and unique
upstream-function counts.

Pinned Python's AC algorithm-denial branch passes unsupported constructor
keywords to DisallowedAlgorithmError and raises TypeError. Rust still rejects
with the approved structured error, preserving cutoff. This is an explicit
exception-shape compatibility difference, not a passing equivalent oracle
assertion. No trust decision is more permissive in these denial cases.

The full historical S branch remains preserved. Cross-layer validator/DSS
callers are delivered as root-integration patches, retaining rejection assertions
and avoiding the dev-dependency cycles removed by main f88ba17. The uncommitted
generated Cargo.lock is excluded from S commits. Context/core-schema/reader/MAC
and the main scheduler wrapper are unchanged.

## Reproducible verification

Run each command serially from the S worktree, using the normal updated wrapper.
No manual remote invocation, empty RUSTC_WRAPPER, local-mode switch, job flags,
compiler flag/profile/feature change or alternate target was used. Captured
scheduler receipts prove s7 slot0 for earlier native checks and s7 slot1 for the
final strict Clippy invocation; final CMS tests and strict docs ran on s7 slot0.
The scheduler selects placement automatically.
Some later jobs waited for the existing main gate's build-directory lock, and
no build or service was stopped.

```sh
tools/cargo-locked.sh check -p sigis-cms -p sigis-pki-certvalidator
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python \
  tools/cargo-locked.sh test -p sigis-pki-certvalidator
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python \
  tools/cargo-locked.sh test -p sigis-cms --lib --test test_cms \
  --test test_key_usage_constraints
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python \
  tools/cargo-locked.sh test -p sigis-pki-core --lib key_usage::tests
tools/cargo-locked.sh clippy -p sigis-cms -p sigis-pki-certvalidator \
  --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' tools/cargo-locked.sh doc -p sigis-cms \
  -p sigis-pki-certvalidator --no-deps
tools/cargo-locked.sh fmt -p sigis-cms -p sigis-pki-certvalidator -- --check
tools/cargo-locked.sh test --test layering
```

The final certificate package run passes 156 native tests, zero failures/ignored,
including all 21 new certificate/AC/time-slide regressions. Final selected CMS
runs pass 90 native tests (9 unit, 77 test_cms wrappers, 4 KU/EKU wrappers),
including seven new horizon tests; inherited partial wrappers remain downgraded
in the accepted ledger. Strict Clippy, strict docs, formatting and the
acyclic dependency-layer check all pass. The
rebase's seven KU unit tests pass independently. The layer check enforces
acyclic dev-dependencies; neither new cross-validator root patch was installed
into PDF-diff/PDF. Final strict-check results are in the ready receipt.

For central integration, the ready receipt supplies a code-only patch against
main17f74b8. It includes the earlier accurate leaf-flag regression increment so
L need not cherry-pick the historical report/known-red commits. Do not merge the
whole S branch solely on the strength of this verified consumer increment.


Lead integration note: this is source7b842d6 selected over current
main045decd, without its ancestor known-red caller suites. Counts remain
S824/754/63/7, overall1431/1052/66/313 (zero new upstream functions). The
three Python AC TypeError exception-shape mismatches remain explicit; this
is not complete AC error parity or complete LTA/timestamp-POE acceptance.


Lead acceptance: sourcec4158bd passed build/test/clippy-Dwarnings/strictdocs/
layer-cycle/fmt on main;1321native tests,1313passed/8ignored/0failed. The28
new helpers add0upstreampasses; all documented oracle-scope and error-shape
limitations remain.
