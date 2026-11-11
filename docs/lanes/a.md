# Lane A — Certificates & CMS

Owner: lane A (branch `hanko/a-cms-cert`). See `docs/hanko-lanes.md`.

## Status

Phase 0 done before the lane split: certvalidator foundation (25 test functions ported, see `crates/hanko-certvalidator/PORTING.md`).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_ac_validate.py` | 27 | 0 | 0 | 27 |
| `test_ades_time_slide.py` | 13 | 0 | 0 | 13 |
| `test_certificate_validator.py` | 2 | 2 | 0 | 0 |
| `test_common_utils.py` | 15 | 0 | 0 | 15 |
| `test_fetch_limits.py` | 11 | 0 | 0 | 11 |
| `test_fetcher_lifecycle.py` | 16 | 0 | 0 | 16 |
| `test_freshness.py` | 6 | 6 | 0 | 0 |
| `test_name_trees.py` | 6 | 0 | 0 | 6 |
| `test_policy_graph.py` | 33 | 0 | 0 | 33 |
| `test_policy_proc.py` | 13 | 0 | 0 | 13 |
| `test_registry.py` | 9 | 0 | 0 | 9 |
| `test_sig_validate.py` | 3 | 3 | 0 | 0 |
| `test_validate.py` | 21 | 14 | 0 | 7 |
| `test_cms.py` | 78 | 0 | 0 | 78 |
| `test_key_usage_constraints.py` | 4 | 0 | 0 | 4 |
| `test_tsa_fetcher.py` | 10 | 0 | 0 | 10 |
| `test_tsa_fetcher_requests.py` | 4 | 0 | 0 | 4 |

## Known divergences

None yet.

## Requests to the lead

None yet.

## Requests from other lanes (relayed by the lead, 2026-11-12)

When rebasing onto `main`, keep this section in your version of this file.

- **A-1 (from lane E, R-E2).** `ValidationPath::qualified_policies()`: the
  pyhanko-certvalidator `QualifiedPolicy` set (issuer-domain and user-domain
  policy OIDs after RFC 5280 policy processing). Needed for pre-eIDAS
  qualification in `hanko-eutl` (lane E divergence D-E1).
- **A-2 (from lane E, R-E3).** Trust anchor qualifiers on `TrustAnchor`
  (`TrustQualifiers`: `valid_from`, `valid_until`, `trusted_service_type`,
  `standard_parameters`), enforced during validation, and a trust manager hook
  in `ValidationContextBuilder` (pyhanko-certvalidator `TrustManager` with
  `as_trust_anchor` / `find_potential_issuers`), so that a `TSPRegistry` can
  act as the trust source (lane E divergence D-E2).
- **A-3 (from lane E, R-E7).** `hanko_cms::validate_cms_signature` needs the
  key usage settings (pyHanko applies `non_repudiation` / `digital_signature`
  defaults for PDF signatures) and the CMS algorithm policy as parameters (or
  an options struct). AdES mapping needs `is_ee_cert` / `is_side_validation`
  on `ValidationError::{Expired, Revoked}` (`handle_certvalidator_errors`).
  LTA validation needs a way to extend a `ValidationContext` with DSS
  material (certificates, CRLs, OCSP responses) and POEs.
- **A-4 (from the lead, R-E1).** There is now one `KeyUsageConstraints`:
  `hanko_core::key_usage` (lane E's version, moved from `hanko-validate`;
  **owned by lane A from now on**). Replace `hanko_cms::key_usage` with a
  re-export of `hanko_core::key_usage`, and reconcile the APIs there: lane A
  has `with_key_usage(&[&str])` and `validate(..)` with extra arguments,
  lane E has `with_key_usage(impl IntoIterator)`, `validate(cert)` plus
  `validate_with_extra(..)`, and a derived `Default`. Check that `Default`
  matches pyHanko (`explicit_extd_key_usage_required=True`). Keep the lane E
  call sites in `hanko-validate` / `hanko-eutl` compiling; ask the lead if a
  call site in a lane E crate must change.
- **A-5 (from lane D).** `DigestAlgorithm` needs SHA3-256/384/512 and
  SHAKE256 (`test_ecdsa_with_sha3`, `test_rsa_with_sha3`, Ed448 with
  `shake256_len`). Signing support for Ed448, DSA and ML-DSA would need
  RustCrypto `ed448-goldilocks`, `dsa`, `ml-dsa` (covered by your R1).
- **A-6 (from lane D).** A getter for the CRLs and OCSP responses supplied to
  a `ValidationContext` (pyHanko embeds `vc.ocsps` / `vc.crls`, e.g.
  `dummy_ocsp_vc` in `test_ocsp_embed`, `test_pades_revinfo_dummydata`).
- **Lead answers to your requests:** R1 approved; add the four crates to
  `crates/hanko-core/Cargo.toml` in the same commit as the code using them.
  R2 done: `HankoError::SignatureValidation { message, ades_subindication:
  Option<hanko_core::ades::AdesSubIndic> }`. R3 done (`hazmat`). R4 done:
  `hanko_testdata::data_dir()` resolves at run time, and
  `hanko_testdata::manifest_dir()` replaces `env!("CARGO_MANIFEST_DIR")`;
  you can drop the local `lane_data` workaround. R5 approved. Also:
  `const-oid` is patched on `main`, so certificates with `2.999.*` policy
  OIDs (Certomancer `testing-ca-qualified`) now decode.
