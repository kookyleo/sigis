# Porting status: pyhanko-certvalidator → hanko-certvalidator

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
| `sig_validate.py`, `util.py` (PSS) | `hanko-core/src/algorithms.rs` | Ported: RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA P-256/384/521, Ed25519. DSA, Ed448 and ML-DSA return `AlgorithmNotSupported` |
| `policy_decl.py` | `src/policy.rs`, `hanko-core/src/algorithms.rs` | Ported: revocation checking rules and policies, freshness types, `CertRevTrustPolicy`, `PKIXValidationParams`, `DisallowWeakAlgorithmsPolicy`, `NonRevokedStatusAssertion` |
| `authority.py` | `hanko-core/src/cert.rs` (`Cert`), `src/authority.rs` (`TrustAnchor`) | Partly: certificate trust anchors (with or without enforced validity). Name+key anchors and derived qualifiers pending |
| `context.py` | `src/context.rs` | Partly: trust roots, other certificates, CRLs, OCSP responses, fetchers, moment (with `point_in_time_validation`), best signature time, time tolerance, policies, assertions, `retrieve_crls` |
| `path.py` | `src/path.rs` | Ported: `ValidationPath` (`find_issuing_authority`, `truncate_to_issuer_and_append`, `copy_and_drop_leaf`, `copy_and_append`, `pkix_len`), `QualifiedPolicy` |
| `policy_graph.py` (`user_constrained_policies`) | `src/validate.rs` (`qualified_policies`) | Ported over certval's final policy graph (edges reconstructed from expected policy sets) |
| `_state.py` (`check_path_verif_recursion`) | `src/revinfo/mod.rs` (`Subject::stack`) | Ported |
| `validate.py` (`validate_path`, `_check_revocation` incl. soft-fail on fetch errors), `__init__.py` (`CertificateValidator`, `find_valid_path`) | `src/validate.rs`, `src/revinfo/mod.rs` | Ported; RFC 5280 processing delegated to `certval`. `PathFailure` carries what pyHanko's exceptions carry (`is_ee_cert`, time horizon, original path) |
| `revinfo/archival.py` (`_judge_revinfo`) | `src/revinfo/freshness.rs` | Ported; replaceable through the `FreshnessJudge` trait |
| `revinfo/validate_crl.py` (`verify_crl`) | `src/revinfo/crl.rs` | Ported: candidate CRL issuer search (direct, indirect, `cRLIssuer`), issuer path validation with the recursion guard, IDP scoping, reason coverage across CRLs (`onlySomeReasons`), delta CRLs, `certificateIssuer` entries, fetching more CRLs when the supplied ones do not suffice. CRL issuer AIA fetching is not supported (the fetch trait only fetches certificate issuers) |
| `revinfo/validate_ocsp.py` | `src/revinfo/ocsp.rs` | Ported: CertID matching, responder lookup (name, key hash, SKI), issuer and delegated responders with full path validation (revocation included unless `ocsp-nocheck`), fetched responses replace supplied ones for certificates with an OCSP URL |
| `path` building (`registry.py`, `CertificationPathBuilder`) | `src/validate.rs::build_paths` | Ported (name chaining with key identifiers, AIA issuer fetching when no issuer is known) |
| `policy_graph.py`, `name_trees.py` | — (`certval`) | Replaced by certval (RFC 5280, RFC 9618 policy graph) |
| `fetchers/` | `hanko-fetch` | Ported there; used through `hanko_core::fetch` traits |
| asn1crypto name handling (`Name.human_friendly`, string preparation) | `src/names.rs`, `src/stringprep_tables.rs` | Ported: names failing RFC 4518 preparation make validation fail as in pyHanko |
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
| `test_policy_proc.py` (13) | — | Pending (lane A: trust anchor qualifiers) |
| `test_registry.py` (9) | — | Pending (lane A: registry, AIA disambiguation) |
| `test_ac_validate.py` (27) | — | Pending (lane A: attribute certificate validation) |
| `test_common_utils.py` (15), `test_fetch_limits.py` (11), `test_fetcher_lifecycle.py` (16) | — | Pending (lane A: `hanko-fetch`, tested against a local fake server) |
| `test_name_trees.py` (6) | — | Proposed skip: pyHanko-internal name constraint trees; certval implements name constraints (PKITS 4.13 passes). Lane A to confirm or port as behaviour tests |
| `test_policy_graph.py` (33) | — | Proposed skip: pyHanko-internal policy graph; certval implements RFC 9618 (PKITS 4.8–4.12 pass). Lane A to confirm or port as behaviour tests |

`test_crl_fetch_races.py` exists only after the release (on pyHanko `main`) and
is not part of the baseline.

### `test_validate.py` in detail

| Upstream test | Status |
| --- | --- |
| `test_rsassa_pss`, `test_rsassa_pss_exclusive`, `test_ed25519` | Ported |
| `test_ed448` | Ported as a **known divergence**: Ed448 is not supported, the port asserts a clean `PathValidationError` |
| `test_assert_no_revinfo_needed_by_fiat` | Ported (extended: also shows that the intermediate needs its own assertion) |
| `test_multitasking_ocsp` | Ported |
| `test_openssl_ocsp` (29 cases) | Ported: **29/29 agree**, including messages |
| `test_nist_pkits` (246 cases) | Ported: **243/246 agree**; 3 known divergences (below) |
| `test_fail_validation_if_required_delta_crl_not_available` | Ported |
| `test_root_time_bound`, `test_root_expired`, `test_root_not_yet_valid`, `test_basic_certificate_validator_root_expiration_unquestioned` (3 cases), `test_extreme_not_after` | Ported |
| `test_nist_pkits_user_notice`, `test_408020_cps_pointer_qualifier_test20` | Ported |
| `test_nist_pkits_with_simulated_crl_downloads` | Ported (in `tests/pkits.rs`); same known divergences |
| `test_building_trust_path_fetched_in_different_orders`, `test_do_not_fetch_crl_if_cache_sufficient`, `test_41503_invalid_deltacrl_test3_combine_cache_with_fetched`, `test_context_retrieve_all_crls` | Ported with in-memory fake fetchers |

### NIST PKITS known divergences (3)

All of them fail closed: the port rejects where pyhanko-certvalidator
accepts. The test asserts that no divergence is fail-open and that the list
is exact.

| Cases | Reason |
| --- | --- |
| 4.1.4, 4.1.5 | DSA signatures not supported (request R1) |
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
