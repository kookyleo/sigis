# Lane A — Certificates & CMS

Owner: lane A (branch `hanko/a-cms-cert`, worktree `../sigis-wt/a-cms-cert`).
See `docs/hanko-lanes.md`.

## Status

- Phase 0 (before the lane split): certvalidator foundation.
- Phase 1 (this branch): `hanko-cms` ported (`generic_cms.py`, CMS part of
  `status.py`, `KeyUsageConstraints`, CMS algorithm policy, `sign/general.py`
  helpers). `validate_cms_signature`, `validate_timestamp_token` and
  `validate_detached_cms` are filled; `validate_cms_signature_with` and the
  `validate` module expose the full pyHanko API (separate timestamp and AC
  contexts, key usage settings, CMS algorithm policy, a precomputed or
  computed content digest). certvalidator additions: `find_valid_path`,
  `validate_path_detailed` / `PathFailure` (AdES mapping data),
  `ValidationContext::with_other_certs`, `ValidationPath::pkix_len`,
  asn1crypto-compatible name display and string-preparation checks
  (`names`), generic RSASSA-PSS (MGF1 digest different from the message
  digest), the `ecdsa` signature OID.
- Oracle: `/tmp/pyhanko-oracle/venv` is not installed yet; lane A uses a
  local copy at `/tmp/lane-a/venv` (pyHanko 0.38.1, pyhanko-certvalidator
  0.33.0, Certomancer 0.16.0) and the tag sources at `/tmp/lane-a/v0.38.1`.
  Fixtures: `crates/hanko-testdata/data/lanes/a/harvest/` (see its README).

- Phase 2: `hanko-fetch` ported (HTTP fetchers with caches, budget,
  multi-URL fallback; RFC 3161 client). Tests use a local server on
  127.0.0.1 and pyHanko-produced TSA responses (`data/lanes/a/tsa/`).

- Phase 3a: revocation checking ported closely from `validate_crl.py` /
  `validate_ocsp.py` (indirect CRLs, `cRLIssuer`, reason coverage, CRL
  issuer recursion guard, delegated OCSP responder revocation, fetching with
  soft-fail), AIA issuer fetching in path building, qualified policies
  (RFC 9618 §5.5), `point_in_time_validation`. NIST PKITS: 243/246 agree.

- Phase 3b: `ltv` filled: `PoeManager`, `time_slide`, `past_validate`
  (lane E can use them now).

Next: attribute certificate
validation, registry and trust anchor qualifiers (`test_registry.py`,
`test_policy_proc.py`), decision on `test_name_trees.py` /
`test_policy_graph.py`.

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_ac_validate.py` | 27 | 27 | 0 | 0 |
| `test_ades_time_slide.py` | 13 | 13 | 0 | 0 |
| `test_certificate_validator.py` | 2 | 2 | 0 | 0 |
| `test_common_utils.py` | 15 | 15 | 0 | 0 |
| `test_fetch_limits.py` | 11 | 11 | 0 | 0 |
| `test_fetcher_lifecycle.py` | 16 | 0 | 16 | 0 |
| `test_freshness.py` | 6 | 6 | 0 | 0 |
| `test_name_trees.py` | 6 | 0 | 0 | 6 |
| `test_policy_graph.py` | 33 | 0 | 0 | 33 |
| `test_policy_proc.py` | 13 | 0 | 0 | 13 |
| `test_registry.py` | 9 | 0 | 0 | 9 |
| `test_sig_validate.py` | 3 | 3 | 0 | 0 |
| `test_validate.py` | 21 | 21 | 0 | 0 |
| `test_cms.py` | 78 | 60 | 2 | 16 |
| `test_key_usage_constraints.py` | 4 | 4 | 0 | 0 |
| `test_tsa_fetcher.py` | 10 | 8 | 2 | 0 |
| `test_tsa_fetcher_requests.py` | 4 | 4 | 0 | 0 |
| **Total** | **271** | **174** | **20** | **77** |

`test_cms.py` details (skips, pending items, recorded-call agreement) are in
`crates/hanko-cms/PORTING.md`.

## Known divergences

All fail closed (the port rejects or reports less trust where pyHanko
accepts); the tests assert this.

- NIST PKITS: 3 cases (DSA, UTCTime 1950), see
  `crates/hanko-certvalidator/PORTING.md`.
- `test_cms.py` recorded calls: 17 of 161 differ, all listed in
  `crates/hanko-cms/tests/test_cms.rs` (`KNOWN`): MD5, SHA-3, DSA, Ed448
  (request R1).
- Without a validation context, nothing is trusted (pyHanko uses the OS
  trust store).

## Requests to the lead

- **R1 — hanko-core algorithm dependencies.** `algorithms.rs` (lane A) needs
  MD5, SHA-3 / SHAKE256, DSA and Ed448 to match pyHanko (15 `test_cms.py`
  functions, NIST PKITS 4.1.4/4.1.5, the Ed448 certvalidator test). Please
  add to `crates/hanko-core/Cargo.toml` (versions match the digest 0.11 /
  signature 3 family already in use):
  `md-5 = { version = "0.11", default-features = false, features = ["oid"] }`,
  `sha3 = { version = "0.11", default-features = false, features = ["oid"] }`,
  `dsa = { version = "0.7", default-features = false }`,
  `ed448-goldilocks = { version = "0.14.0-pre.15", default-features = false }`.
  Lane A will then add the variants `Md5`, `Sha3_224`, `Sha3_256`,
  `Sha3_384`, `Sha3_512` and `Shake256` to `DigestAlgorithm` (§4 interface:
  additive, but exhaustive `match`es in other crates would need a new arm;
  none exist today) and `Dsa(..)` / `Ed448` to `SignatureMechanism`.
- **R2 — `HankoError` variant for CMS validation failures.** The §4
  functions return `hanko_core::Result`; pyHanko raises
  `SignatureValidationError` with an AdES sub-indication. Please add
  `HankoError::SignatureValidation { message: String, ades_subindication: Option<&'static str> }`.
  Until then `From<CmsError> for HankoError` maps to `Malformed` (full
  message kept, fails closed); callers that need the class use
  `hanko_cms::validate_cms_signature_with` (returns `CmsError`).
- **R3 — `x509-cert` feature in hanko-core.** `cert.rs` uses
  `x509_cert::certificate::Raw` (feature `hazmat`), which hanko-core only
  gets through feature unification with `certval`; `cargo check -p
  hanko-core` alone fails. Please enable `features = ["pem", "hazmat"]` for
  x509-cert in `crates/hanko-core/Cargo.toml`.
- **R4 — hanko-testdata data path with a shared target directory.**
  `hanko_testdata::path` uses the compile-time `CARGO_MANIFEST_DIR`. All
  worktrees share `/build/sigis/target` and the same relative package path,
  so cargo reuses a hanko-testdata build from another worktree, and fixtures
  added on a lane branch are looked up in `main`'s checkout (observed here).
  Suggest resolving the data directory at run time, e.g. from the test
  binary's `CARGO_MANIFEST_DIR` (`<crate>/../hanko-testdata/data`), falling
  back to the compile-time path. Lane A's tests do this locally
  (`tests/common/mod.rs::lane_data`).
- **R6 — `ValidationError` variants for LTV.** pyhanko-certvalidator has
  `InsufficientPOEError` and `TimeSlideFailure`. `hanko_certvalidator::ltv`
  reports them through its own `LtvError`; the §4 functions
  (`time_slide`, `past_validate`) map them to
  `ValidationError::PathValidation` with the message. If lane E needs to
  tell them apart through `HankoError`, please add
  `ValidationError::InsufficientPoe(String)` (a `PathValidationError`
  subclass in pyHanko).
- **R5 — additive interface changes in `hanko-cms` and `hanko-fetch` (for approval).** Kept
  every §4 item; added fields to `SignatureStatus` (`trust_problem_indic`,
  `pkcs7_signature_mechanism`, `md_algorithm_name`, `revocation_details`,
  `error_time_horizon`, `validation_time`) and to
  `StandardCmsSignatureStatus` (`cades_signer_attrs`, `ac_attrs`,
  `ac_validation_errs`). In `hanko-certvalidator::ltv`, `PoeType` gained
  `Policy`, `PoeManager` gained `with_current_time`, `poe_time`,
  `register_by_digest`, `iter`, `merge`. `TrustProblem::KeyUsage` also carries the
  self-signed `InvalidCertificateError`. In `hanko-fetch`, `FetchLimits`
  gained `max_requests`, `max_cert_requests`, `max_aia_urls_per_object`
  (pyhanko-certvalidator 0.33 `FetchLimits`), `HttpFetchers` is now built
  with `HttpFetchers::new(FetcherSettings)` (fields private, shared caches
  and budget), and `HttpTimeStamper` with `HttpTimeStamper::new(url)` plus
  builder methods (`url` and `limits` stay public). Consumers that construct
  these structs with literals would need the new constructors; readers are
  unaffected.
