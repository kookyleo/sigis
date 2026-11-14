# Ordinary OCSP issuer identity hardening

Accepted compiled source: `d5e93ec9348f19d3bdf0c1e1b7920f16d8a157d6`.

CVinventory remains **133total/131passed/2skipped/0pending**. The extra identity regressions add0upstream IDs; the remaining2deprecated originals are source-audit-only.

## Zero-ID ordinary trust repairs and known reference divergence

Tests-first source a095 has actual OCSP4pass/1fail/5.245s and EUTL3pass/5fail/4.83s, both exit101. Exactlytwo narrow production paths change: direct OCSP issuer authorization requires complete responder/issuer DER identity instead of copied certificate-signature bytes; the returned EUTL inner TrustAnchor retains the already-selected service's valid_from/valid_until with other defaults intact. Actual d5eGREEN is OCSP5pass/0fail/2.716s and EUTL8pass/0fail/4.629s, both exit0. CV remains133/131/2/0 and EUTL53/53/0/0; these controls add0IDs.

Fresh pinned Python OCSP at a095made10public calls:6accept/4raw-signature refusals. It accepts the copied-signature fake issuer in both ordinary APIs, while hardened d5eRust rejects it. Genuine direct/delegated positives and raw-signature negatives remain. This is an intended stricter security divergence, not upstream parity or universal fail-closed proof. Original2020observed clock/PIT=false representation and independent fresh contexts are explicit; Python a095 is not relabelled as a d5e native run.

Fresh EUTL Python at a095records34model scenarios/36public CV calls:28VALID and8expected service-window refusals (5NotYetValidError/3ExpiredError). Direct selected-anchor bounds survive separate contexts; issued-chain positives remain distinct from direct-anchor date controls. Upstream has no trust_anchors_at API: numeric filtering is a labelled local projection. Equal-key history tie order is excluded, no older-service fallback is granted, and native inner Unspecified service-role versus upstream CA/TSA qualifiers remains. The model dataclasses were not authenticated TL/LOTL input; these controls do not establish qualification/CMS/TST/PDF/LTA or general historical/authority-equality parity.

Patch review SHA256 `9588b2de2617b26d33bea60397c3d027e299ec6487490710256b98f9912d8e04` covers2235checks/298files/226source bindings. Bounded current focus review SHA256 is `fc6582567434e536b6e6cdedb3c5363d80612f5b4fbebeb662baec18208c5e53`; its earlier scope is separate from the final complete gate.

## Actual d5e gate and independent final review

Allsix actual stages returned0/audit0: build7.55s, workspace test1494.91s, clippy28.6s, strict docs277.93s, layering5.26s and fmt3.52s. Compiler proof covers524phaseunits/3130input records/519immutable current Root files; the test phase selected255units. Actual top-level Rust totals are **2222discovered /2218passed /4ignored /0failed /227reports**; measured/filtered counts remain separate, with0filtered. These actual reports are not an upstream-function count or a prediction from added wrappers.

Independent final review: `/home/l/.codex/artifacts/sigis/round3-launch/shared-trust-integration/final-review/first-v3.json`, SHA256 **6e183e0ea0da1e618f8953615be66996280e6a13378e11a537c04a60f1d0fd4c**; actual receipt `/home/l/.codex/artifacts/sigis/round3-launch/shared-trust-integration/final-review/first-v3-execution.json`, SHA256 **be69bd09ce2d1919d660063d4a667fdb90b28f4a76be330c381c2ad71da35cd8**. Actual returned result **0**, elapsed **43.444365s**. Verified scope: 524 compiler phaseunits /3130 input records /519immutable current Git paths;43finite aliases /35affected units /6pairs /1origin3f1d /8duplicates preserved;2222discovered /2218passed /4ignored /0failed /227intact reports /0measured /0filtered;66raw+gzip native captures;fullS3all13named and all331INPUT/19CASE/32HTTP/1EXECUTABLE/1LIFECYCLE markers intact with0malformed.

All66package-qualified full native gzip captures retain actual Running paths, five-field summaries and separate compressed/raw hashes and lengths. Captures are post-completed-test-phase, not run-instant identity. FullS3raw ELF is `22d9d61d493a834bda3f8138ab6ec3536853f97b738f1be95ef59139e3b801b4`/88888528bytes; its gzip is `f148ac073f9560fd750bd5ca6d5ace2ef56a263e6733d47bdf8d0b053f75fe82`/23037783bytes. Focused S3raw `e342fbca9d2effa3a3e6d6eeab540fea387c71ac7f227e88a1fc8ea9e7b438f5`/88877288bytes remains a distinct actual executable.

The full S3target has13intact named success results, including allthree exact newly credited originals. Its raw markers are331/331INPUT,19/19CASE (18unique exports),32/32HTTP,1EXECUTABLE and1LIFECYCLE, with0malformed records. Focused13execution is independently retained. Of five private zero-ID controls,4have intact named lines; only remaining_fetch_policy_none_has_no_added_private_owner uses explicit source-registration/unchanged-mapping plus completed unfiltered CV82suite inference, with no invented named line. That one inference earns0IDs and does not affect the three directly named originals. OCSP5and EUTL8all have intact named successes. V's47original mappings retain46complete and1Pending, with48mapped native named lines; this cohort neither credits that Pending original nor changes its ignore/annotation.

## Exact compiler locator boundaries

The sealed source-locator review is `source-locator-review/review.json`, SHA256 `6493ae803462e868a15c1b651091296ba425d9c2f26a7ba6d7103c56041afa2f`; finite bindings are `finite-literal-bindings.final.json`, SHA256 `4d3aa00185d2318e30c2247b9704b9cc68c11c442757ea0a28fa6baeefbbdd56`. Exactly43binary alias occurrences across35affected phaseunits and6literal source pairs are allowed:5test and38clippy occurrences, with8duplicate occurrences preserved. The one actual origin is r3-s-primitives at immutable3f1d in the same Git repository; origin/current Root immutable bytes, SHA256/BLAKE3 and lengths agree. Unknown literals fail; no generic rebasing or normalization is granted.

Alias metadata units and two test units absent from the66native captures are bound through their actual emitted unit, fingerprint, text/binary dep-info, source and Git evidence. No native ELF association is invented for them and alias binding does not add captures or function IDs. This content/origin proof is not full external environment attestation.

## Retained limits

General independently supplied mutable CertificateRegistry/RevinfoManager graphs, nonempty/custom source reachability, shared-registry aliasing, mutation visibility, source ownership and POE graph parity remain unrepresented. Immutable DER/Arc payload sharing and copied collections do not establish mutable-container identity. No implicit Drop cleanup, context reconstruction, weaker retry, OS roots or new API/framework follows. Allfive MAIN predicates, independent TSA requirements, timing/PKIX/freshness/AC/algorithm, authenticated reader/strict decode/MAC and WithTime containment remain. Broader trust/clock, rendering/scanner, finite serialization, provider and compatibility limits remain explicit. Complete porting and universal parity/all-divergences-fail-closed are not established.

## Historical pre-d5e document retained verbatim

The complete preceding document is retained below as raw historical bytes. Its source/counts and earlier scope statements describe that accepted checkpoint. Current scope and authority are defined above.

# Porting status: sigis-pki-certvalidator (crates/pki-certvalidator)

Upstream: <https://github.com/MatthiasValvekens/pyHanko>, release tag
`pyhanko-certvalidator/v0.33.0` (fixtures identical to the ones imported).

Ported so far: signature algorithm dispatch, path building (with AIA
fetching) and validation at a time of interest, revocation checking (CRLs
including indirect and reason-partitioned ones, delta CRLs, OCSP including
delegated responders) with supplied or fetched information, freshness
policies, qualified policies, and asn1crypto-compatible name handling.
Nothing is wired into the Sigis service yet.

## Module mapping

| pyhanko-certvalidator | sigis-hanko | Status |
| --- | --- | --- |
| `errors.py` | `hanko-core/src/errors.rs` | Ported (class names and `isinstance` hierarchy via `ValidationError::is_instance_of`) |
| `sig_validate.py`, `util.py` (PSS) | `hanko-core/src/algorithms.rs` | Ported: RSA PKCS#1 v1.5 (MD5, SHA-1, SHA-2, SHA-3), RSASSA-PSS, ECDSA P-256/384/521 (the ECDSA-with-SHA3 OIDs take the digest from context, as asn1crypto has no digest for them), DSA (FIPS 186 sizes only; parameter inheritance in paths as in `validate.py`), Ed25519, Ed448; `DisallowWeakAlgorithmsPolicy` with the RSA and DSA key size thresholds. ML-DSA returns `AlgorithmNotSupported`. certval verifies certificate signatures through this code for the algorithms it does not support itself |
| `policy_decl.py` | `src/policy.rs`, `hanko-core/src/algorithms.rs` | Ported: revocation checking rules and policies, freshness types, `CertRevTrustPolicy`, `PKIXValidationParams` (initial name subtrees, `max_policy_graph_nodes`, `merge`), `DisallowWeakAlgorithmsPolicy`, `NonRevokedStatusAssertion` |
| `authority.py` | `hanko-core/src/cert.rs` (`Cert`), `src/authority.rs` | Ported: `TrustAnchor` with `TrustQualifiers` (standard parameters, path lengths, validity period, `TrustedServiceType`), the `TrustManager` interface (`as_trust_anchor`, `find_potential_issuers`), `derive_quals_from_cert`, name-and-key anchors (`from_name_and_key`, carried by an unsigned synthetic certificate), `Authority` equality |
| `registry.py` (`SimpleCertificateStore`, `CertificateRegistry`, `LayeredCertificateStore`, trust manager service-type filter) | `src/registry.rs`, `src/validate.rs` | Ported (lookups by name, key hash, key identifier, issuer and serial; AKI-based issuer disambiguation also used in path building) |
| `context.py` | `src/context.rs` | Partly: trust roots and a trust manager, other certificates, CRLs and OCSP responses (readable through `crls()` / `ocsps()`, extensible with `with_revinfo`), fetchers, moment (with `point_in_time_validation`), best signature time, time tolerance, policies, assertions, `retrieve_crls` |
| `path.py` | `src/path.rs` | Ported: `ValidationPath` (`find_issuing_authority`, `truncate_to_issuer_and_append`, `copy_and_drop_leaf`, `copy_and_append`, `pkix_len`), `QualifiedPolicy` |
| `policy_graph.py` | `src/validate/rfc9618.rs` | Native graph operations and authority/user projection, used by path validation; certval remains mandatory |
| `_state.py` (`check_path_verif_recursion`) | `src/revinfo/mod.rs` (`Subject::stack`) | Ported |
| `validate.py` (`validate_path`, `_check_revocation` incl. soft-fail on fetch errors), `__init__.py` (`CertificateValidator`, `find_valid_path`) | `src/validate.rs`, `src/revinfo/mod.rs` | Ported; RFC 5280 processing delegated to `certval`. `PathFailure` carries what pyHanko's exceptions carry (`is_ee_cert`, time horizon, original path) |
| `revinfo/archival.py` (`_judge_revinfo`) | `src/revinfo/freshness.rs` | Ported; replaceable through the `FreshnessJudge` trait |
| `revinfo/validate_crl.py` (`verify_crl`) | `src/revinfo/crl.rs` | Ported: candidate CRL issuer search (direct, indirect, `cRLIssuer`), issuer path validation with the recursion guard, IDP scoping, reason coverage across CRLs (`onlySomeReasons`), delta CRLs, `certificateIssuer` entries, fetching more CRLs when the supplied ones do not suffice. CRL issuer AIA fetching is not supported (the fetch trait only fetches certificate issuers) |
| `revinfo/validate_ocsp.py` | `src/revinfo/ocsp.rs` | Ported: CertID matching, responder lookup (name, key hash, SKI), issuer and delegated responders with full path validation (revocation included unless `ocsp-nocheck`), fetched responses replace supplied ones for certificates with an OCSP URL |
| `path` building (`registry.py`, `CertificationPathBuilder`) | `src/validate.rs::build_paths` | Ported (name chaining with key identifiers, AIA issuer fetching when no issuer is known) |
| `name_trees.py` | `src/validate/name_constraints.rs`, certval | Exact native excluded-name predicates, with mandatory certval name checks and intersected permitted subtrees |
| `fetchers/` | `sigis-pki-fetch` | Ported there; used through `sigis_pki_core::fetch` traits |
| asn1crypto name handling (`Name.human_friendly`, string preparation) | `src/names.rs`, `src/stringprep_tables.rs` | Ported: names failing RFC 4518 preparation make validation fail as in pyHanko |
| `validate.py` (`async_validate_ac`, `check_ac_holder_match`, `_candidate_ac_issuers`, `validate_aa_usage`, `_check_ac_signature`, `_validate_ac_targeting`, `_check_aa_controls`), `path.py` (`aa_attr_in_scope`), `asn1_types.py` (`AAControls`) | `src/ac.rs` | Ported: RFC 5755 AC parsing (both tagging styles of `baseCertificateID`), holder matching, AA search by name / issuer-serial / AKI, AA usage, AA path with aaControls and AA path length, signature, validity, targeting, revocation of the AC through the CRL/OCSP code (`revinfo::Target`) |
| `validate.py` (`SUPPORTED_EXTENSIONS`) | `src/validate.rs` | Ported: critical extensions outside pyHanko's list fail; inside it, certval treats them as processed |
| `ltv/poe.py` | `src/ltv/poe.rs` | Ported (`POEManager` with the "now" default of `__getitem__`, by-digest registration, merge) |
| `ltv/time_slide.py` (+ `collect_relevant_crls_with_paths`, `collect_relevant_responses_with_paths`) | `src/ltv/time_slide.rs` | Ported; the algorithm policy can be switched off (`algo_usage_policy=None`) with `TimeSlideOptions` |
| `ltv/ades_past.py` | `src/ltv/mod.rs` (`past_validate`) | Ported, including the validity-intersection pre-check |
| `ltv/errors.py` | `src/ltv/mod.rs` (`LtvError`) | Ported (`InsufficientPOEError`, `TimeSlideFailure`, `PastValidatePrecheckFailure`) |
| ASN.1 from `asn1crypto` and `pyhanko/sign/ades/*_asn1.py` | `hanko-core/src/asn1/` | ESS `SigningCertificate(V2)`, `SignaturePolicyIdentifier`, `CommitmentTypeIndication` defined here; CMS/X.509/OCSP/TSP from RustCrypto |

## Current assigned acceptance

Round3 source d1e38df is accepted at133 total /131passed /2skipped /0pending.
The two registry deprecations remain skipped. Exact mappings and proof:
[native graph report](../../docs/lanes/round3/s-policy-graph.md).
Already-materialized merge empty-set provenance remains a separate shared API
gap; native node limits do not pre-bound certval. Universal parity is not claimed.

## Test mapping

The initial first-lane inventory paragraph below is historical. The current
assigned denominator is133; common-utils/fetch/lifecycle belong to pki-fetch.
Consolidated ownership.json plus acceptance.json is authoritative.

Baseline: tag `pyhanko-certvalidator/v0.33.0` (commit `b48999514cb4`). It has
**175** test functions (counted with `ast`, including methods of test
classes): **25 ported and passing, 111 pending (lane A), 39 proposed for
skipping** (two modules, see below; lane A confirms). The ported
functions include two data-driven suites (29 OpenSSL OCSP cases and 246 NIST
PKITS cases).

| Upstream test module (functions) | Rust test file | Status |
| --- | --- | --- |
| `test_sig_validate.py` (3) | `tests/sig_validate.rs` | Ported 3/3. `test_algorithm_not_supported` uses an unknown private-arc OID because `const-oid` rejects `2.999`. Plus 6 extra tests on generated fixtures |
| `test_certificate_validator.py` (2) | `tests/certificate_validator.rs` | Ported 2/2 (including the qualified policy assertions) |
| `test_freshness.py` (6) | `tests/freshness.rs` | Ported 6/6 |
| `test_validate.py` (21) | `tests/validate.rs`, `tests/pkits.rs`, `tests/openssl_ocsp.rs` | Ported 21/21 |
| `test_ades_time_slide.py` (13) | `tests/ades_time_slide.rs` | Ported 13/13 |
| `test_policy_proc.py` (13) | `tests/policy_proc.rs` | Ported 13/13 |
| `test_registry.py` (9) | `tests/registry.rs` | Ported 7; skipped 2: `test_system_trust_fallback_deprecated` and `test_extra_trust_roots_deprecated` test deprecated Python entry points (operating-system trust store fallback, `extra_trust_roots`) that this port does not have |
| `test_ac_validate.py` (27) | `tests/ac_validate.rs` | Ported 27/27 |
| `test_common_utils.py` (15), `test_fetch_limits.py` (11), `test_fetcher_lifecycle.py` (16) | `hanko-fetch/tests/` | See `hanko-fetch/PORTING.md` |
| — | `tests/context_api.rs` | Lane A tests for the trust manager, trust anchor validity qualifiers and context revocation information access and extension |
| `test_name_trees.py` (6) | `src/validate/name_constraints_tests.rs` | Round 3: all six functions pass with all 54 exact upstream cases. The predicates are used by production excluded-name validation; `tests/policy_proc.rs` also checks case normalization and non-overmatching |
| `test_policy_graph.py` (33) | `src/validate/rfc9618_tests.rs` | All33 accepted after the full workspace gate on d1e38df; actual graph operations replace the eight partial adapters |

`test_crl_fetch_races.py` exists only after the release (on pyHanko `main`) and
is not part of the baseline.

### `test_validate.py` in detail

| Upstream test | Status |
| --- | --- |
| `test_rsassa_pss`, `test_rsassa_pss_exclusive`, `test_ed25519` | Ported |
| `test_ed448` | Ported |
| `test_assert_no_revinfo_needed_by_fiat` | Ported (extended: also shows that the intermediate needs its own assertion) |
| `test_multitasking_ocsp` | Ported |
| `test_openssl_ocsp` (29 cases) | Ported: **29/29 agree**, including messages |
| `test_nist_pkits` (246 cases) | Ported: **245/246 agree**; 1 known divergence (below) |
| `test_fail_validation_if_required_delta_crl_not_available` | Ported |
| `test_root_time_bound`, `test_root_expired`, `test_root_not_yet_valid`, `test_basic_certificate_validator_root_expiration_unquestioned` (3 cases), `test_extreme_not_after` | Ported |
| `test_nist_pkits_user_notice`, `test_408020_cps_pointer_qualifier_test20` | Ported |
| `test_nist_pkits_with_simulated_crl_downloads` | Ported (in `tests/pkits.rs`); same known divergences |
| `test_building_trust_path_fetched_in_different_orders`, `test_do_not_fetch_crl_if_cache_sufficient`, `test_41503_invalid_deltacrl_test3_combine_cache_with_fetched`, `test_context_retrieve_all_crls` | Ported with in-memory fake fetchers |

### NIST PKITS known divergence (1)

It fails closed: the port rejects where pyhanko-certvalidator accepts.
The test asserts that no divergence is fail-open and that the list is
exact.

| Cases | Reason |
| --- | --- |
| 4.2.3 | `UTCTime` year 1950 cannot be decoded by the `der` crate |

Error classes agree for all other cases. Messages match pyHanko's for the
revocation errors; 91 path validation messages differ, mostly because certval
reports a status without naming the failing certificate, and because dates are
formatted differently.

## pyHanko (signing / PDF validation) tests

Not started in this phase: `pkgs/pyhanko/tests` (`test_cms.py`,
`test_signing.py`, `test_pades.py`, `test_ades_validation*.py`,
`test_diff_analysis.py`, ...) depend on CMS signature validation, PDF parsing
and DSS handling, which are later phases.

## Behavioural notes

- Path building follows pyHanko (name chaining, key identifiers), so broken
  paths are reported as validation errors, not as missing paths.
- `soft-fail` only tolerates *fetch* failures in pyHanko. With no fetching,
  supplied revocation information that applies but fails validation is an
  error in every mode.
- OCSP and CRL times with fractional seconds (allowed by DER) are accepted by
  decoding a copy without the fraction; signatures are verified over the
  original bytes.
- PEM input is parsed leniently, as asn1crypto does (first `CERTIFICATE`
  block, any line length).

## Round 3 S skip audit (targeted verification passed)

The immutable assigned baseline remains **133 / 92 / 41 / 0**
(total / passed / skipped / pending). The verified lane result is
**133 / 98 / 35 / 0**, pending lead integration acceptance.
See [ROUND3-S-AUDIT.md](ROUND3-S-AUDIT.md)
for every inherited skip, exact assertions, parameters and remaining gaps.

Six new production name-predicate tests preserve all 54 upstream cases.
All six pass in Rust, and a fresh pinned-AST inventory confirms every case.
Eight synthetic policy-result adapter tests preserve output assertions and
expose the zero-length graph guard bug, but bypass upstream graph mutation
setup. All 33 graph functions therefore remain skipped, eight with partial
coverage. The two deprecated registry entrypoints remain explicit gaps.
No new provider-dependent early return was added.

Fresh pinned Python oracle evidence: 54 name test parameter invocations
and eight user-constrained policy test invocations passed. Oracle calls
are separate from Rust tests and upstream function counts. Build logs and
reproducible commands are in the lane artifact handoff. Wrapper formatting
completed; check passed on vm2064 slot0, and the full library unit suite
(25 tests) plus `policy_proc` integration suite (13 tests) passed on vm2065
slot0. All tests ran with zero failures and zero ignored tests. The two
context-preservation unit tests are regression coverage, not new upstream
function passes. The lead still owns the complete workspace gate.


## Independent algorithm-failure certificate-position regression

`tests/algorithm_failure_context.rs` adds three supplemental native tests
using the actual multitasking-ocsp certificate chain and both real OCSP
responses under required revocation checks. The detailed failure preserves
the full built path, the exact typed core error survives validate_path,
and the algorithm hook receives validation time and actual issuer key.
Leaf rejection must set is_ee_cert=true; intermediate rejection stays false.
The original implementation failed that leaf assertion (2 passed / 1 failed).
The producer now sets the flag from the actual issued-certificate index.
No algorithm refusal, path material, revocation requirement or error class
was weakened. A date-like permanent reason still has no contextual horizon.

After the fix, all three regressions and the existing validate suite's
20 tests passed with zero ignored tests. Check and targeted strict Clippy
also passed on vm2065 slot0; repository-wrapper formatting passed. Four
fresh pinned oracle records independently confirm valid control, both
rejection contexts/original paths and missing-required-OCSP rejection.
Full error wording differs as previously documented; class, certificate
position, original path and permanent horizon are the compared fields.
No provider/runtime exclusion or new dependency is present.

This changes no upstream-function count. It is not typed-cutoff/CMS/LTA
or time-slide recovery acceptance. The full future-API regression matrix
remains separate, pending safe S synchronization with the L shared API.
Logs, exact commands and live reference outputs are in the S artifact
algorithm-failure-context-* files. The L-owned wrapper/context/core files
and the existing lockfile change remain untouched by this increment.

## Round 3 typed algorithm horizon consumers

S's tests-first consumer implementation and complete native/oracle accounting
are documented in [s-algorithm-horizons.md](../../docs/lanes/round3/s-algorithm-horizons.md).
Typed cutoff propagation, best-signature-time policy checks and exact time-slide
minimum semantics preserve permanent rejection and mandatory POE/revocation.
The OCSP_NOCHECK responder policy omission is covered by a substantive new
regression. These native helpers add zero unique upstream-function credit; the
accepted main62a72a2 ledger remains authoritative until L integration.


## Subsequent shared policy-composition acceptance

Source f91dccd closes the preceding materialized-empty/zero-issued policy gap
after12 tests-first supplemental regressions and all six workspace gates.
Current assigned counts stay133/131/2/0. The additional conjunctive field and
explicit replacement API are documented in
[L policy composition](../../docs/lanes/round3/l-policy-composition.md).
Legacy empty Vec remains wildcard; an explicit empty effective constraint
remains empty through merge, clone, anchor composition and high-level validation.
External exhaustive struct literals must supply the new public field or use
Default/struct update. Certval-before-native-limit resource scope is unchanged.
The bounded asymmetric Python empty+Any behavior is intentionally stricter;
no universal policy/trust parity is claimed.


## CRL recursion trust repair

Source03a156c restricts the recursive issuer exemption to certificate path
validation. Every current CRL still requires its own signature verification.
Two named direct/full AC negative tests first accepted a signature-only forged
CRL while a genuine control passed; the fixed three-test suite covers require
and soft-fail without network, with six actual input hashes and eight fresh
same-input pinned Python decisions. All197 CV tests and the complete workspace
gate pass. These adversarial helpers add no immutable upstream credit; assigned
counts remain133/131/2/0. The older Python shortcut has a narrower active-path
identity boundary; universal lexical or trust parity is not inferred.


## Lead AC retrieval acceptance

Source 7500fc7 passes all six workspace gates: 1578 discovered,
1570 passed, 8 ignored, zero failed, 142 reports.
The two earlier gate failures remain recorded: stale V AC replay/cache controls
and a real CSC batching race. Neither was hidden by a skip or weaker assertion.
Current counts: V47/47/0/0, L11/6/0/5; overall1431/1131/30/270.

AC retrieval now shares production transport limits, caches and actual-AA
request identity with PKC retrieval, and routes actual AC DER to its methods.
Strict metadata envelope checks reject nonminimal headers before I/O. Serial
INTEGER contents remain capped at20 encoded bytes; arbitrary-length serials
are not supported. The response matcher uses the signed AC issuer Name DER
and actual AA key hash. Eight genuinely signed Name variants agree with the
pinned public validator, including three positive controls. A proposed matcher
first accepted an oracle rejection; that candidate was corrected before merge.
Fetched/cached CRLs still require the accepted03 signature guard. Required and
hard-fail policies reject forged signatures; explicit soft-fail can tolerate a
separate unavailable provider as the pinned policy does. It is not evidence
that a forged CRL is authenticated or that all modes reject every bad response.

V's complete remaining two original functions pass after its recorded AC
adapter gains actual AC request binding. The adapter uses production fetchers
over frozen responses with full CertID selection; it is not new live HTTP.
The signature-mutation control creates a new fetcher from changed records,
so an earlier cached genuine response cannot mask the intended negative input.
S's real loopback HTTP composition and its repeated-cache rejection controls
are separate evidence. No helper, recording, parameter or oracle call earns
an extra immutable function.

The context non_revoked_status_assertions getter returns an immutable borrowed
view of existing caller state. Six tests and two compile-fail doctests retain
order/hash/time/clone/security requirements and actual strict revocation
matching. Successful optional validation does not invent an assertion. The
accessor changes no default, policy, field or trust verdict and earns no ID.

L completes strict live issuer fetching and both full-chain/leaf-only base
cases. Their three new PDFs receive real native LTA, exact LtaUpdates and fresh
same-output Python LTA; empty roots reject. Leaf-only signing requests the
exact downloaded leaf through a forwarding real certificate fetcher before
validation, rather than relying only on a shared TSA issuer-URL count. The
two exact upstream functions independently pass all three original executions.
CSC automatic batches now stop admitting jobs when full and bind commit to
their original batch; retained-result/public-commit semantics remain tested.
The existing three batch/authorization-count parameters remain unchanged.

All divergences cannot be labelled fail-closed. Bounded serial/metadata refusals
are stricter, but explicit optional-revocation policy, report/time metadata and
other declared semantic/encoding gaps are not universal trust proofs. A separate
combined ECC/RSA test context has a retained native/Python validation discrepancy
under colliding synthetic issuer/serial identities. Using role-specific contexts
for the exact upstream test does not repair that registry/path-selection gap.
It remains under independent diagnosis, rather than being relabelled fail-closed.
Unmerged CLI code remains outside acceptance; three configuration loader functions still
need their exact CMS intact/valid assertions despite a raw-signature control.
Detailed red/green logs, oracle outputs, public byte hashes and independent
reviews are retained under round3-launch/s-ac-combined and round3/l-certomancer-next.
