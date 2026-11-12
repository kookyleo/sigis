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
| `policy_graph.py` (`user_constrained_policies`) | `src/validate.rs` (`qualified_policies`) | Ported over certval's final policy graph (edges reconstructed from expected policy sets) |
| `_state.py` (`check_path_verif_recursion`) | `src/revinfo/mod.rs` (`Subject::stack`) | Ported |
| `validate.py` (`validate_path`, `_check_revocation` incl. soft-fail on fetch errors), `__init__.py` (`CertificateValidator`, `find_valid_path`) | `src/validate.rs`, `src/revinfo/mod.rs` | Ported; RFC 5280 processing delegated to `certval`. `PathFailure` carries what pyHanko's exceptions carry (`is_ee_cert`, time horizon, original path) |
| `revinfo/archival.py` (`_judge_revinfo`) | `src/revinfo/freshness.rs` | Ported; replaceable through the `FreshnessJudge` trait |
| `revinfo/validate_crl.py` (`verify_crl`) | `src/revinfo/crl.rs` | Ported: candidate CRL issuer search (direct, indirect, `cRLIssuer`), issuer path validation with the recursion guard, IDP scoping, reason coverage across CRLs (`onlySomeReasons`), delta CRLs, `certificateIssuer` entries, fetching more CRLs when the supplied ones do not suffice. CRL issuer AIA fetching is not supported (the fetch trait only fetches certificate issuers) |
| `revinfo/validate_ocsp.py` | `src/revinfo/ocsp.rs` | Ported: CertID matching, responder lookup (name, key hash, SKI), issuer and delegated responders with full path validation (revocation included unless `ocsp-nocheck`), fetched responses replace supplied ones for certificates with an OCSP URL |
| `path` building (`registry.py`, `CertificationPathBuilder`) | `src/validate.rs::build_paths` | Ported (name chaining with key identifiers, AIA issuer fetching when no issuer is known) |
| `policy_graph.py`, `name_trees.py` | — (`certval`) | Replaced by certval (RFC 5280 name constraints, RFC 9618 policy graph), plus the pyHanko-specific parts in `src/validate.rs`: permitted subtrees of anchor and caller intersected, excluded subtrees matched case-insensitively and without trailing dots, the policy graph size limit, and pyHanko's permitted/excluded failure messages |
| `fetchers/` | `sigis-pki-fetch` | Ported there; used through `sigis_pki_core::fetch` traits |
| asn1crypto name handling (`Name.human_friendly`, string preparation) | `src/names.rs`, `src/stringprep_tables.rs` | Ported: names failing RFC 4518 preparation make validation fail as in pyHanko |
| `validate.py` (`async_validate_ac`, `check_ac_holder_match`, `_candidate_ac_issuers`, `validate_aa_usage`, `_check_ac_signature`, `_validate_ac_targeting`, `_check_aa_controls`), `path.py` (`aa_attr_in_scope`), `asn1_types.py` (`AAControls`) | `src/ac.rs` | Ported: RFC 5755 AC parsing (both tagging styles of `baseCertificateID`), holder matching, AA search by name / issuer-serial / AKI, AA usage, AA path with aaControls and AA path length, signature, validity, targeting, revocation of the AC through the CRL/OCSP code (`revinfo::Target`) |
| `validate.py` (`SUPPORTED_EXTENSIONS`) | `src/validate.rs` | Ported: critical extensions outside pyHanko's list fail; inside it, certval treats them as processed |
| `ltv/poe.py` | `src/ltv/poe.rs` | Ported (`POEManager` with the "now" default of `__getitem__`, by-digest registration, merge) |
| `ltv/time_slide.py` (+ `collect_relevant_crls_with_paths`, `collect_relevant_responses_with_paths`) | `src/ltv/time_slide.rs` | Ported; the algorithm policy can be switched off (`algo_usage_policy=None`) with `TimeSlideOptions` |
| `ltv/ades_past.py` | `src/ltv/mod.rs` (`past_validate`) | Ported, including the validity-intersection pre-check |
| `ltv/errors.py` | `src/ltv/mod.rs` (`LtvError`) | Ported (`InsufficientPOEError`, `TimeSlideFailure`, `PastValidatePrecheckFailure`) |
| ASN.1 from `asn1crypto` and `pyhanko/sign/ades/*_asn1.py` | `hanko-core/src/asn1/` | ESS `SigningCertificate(V2)`, `SignaturePolicyIdentifier`, `CommitmentTypeIndication` defined here; CMS/X.509/OCSP/TSP from RustCrypto |

## Test mapping

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
| `test_policy_graph.py` (33) | `src/validate/policy_graph_tests.rs` (partial) | All 33 remain skipped. Eight synthetic final-graph adapter tests exercise output assertions but bypass upstream process/mapping setup. The other 25 retain exact graph-operation gaps; PKITS and policy size-limit regressions do not complete these functions |

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
