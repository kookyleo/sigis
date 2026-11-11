# Lane A — Certificates & CMS

Owner: lane A (branch `hanko/a-cms-cert`, worktree `../sigis-wt/a-cms-cert`).
See `docs/hanko-lanes.md`.

## Status

- Phase 0 (before the lane split): certvalidator foundation.
- Phase 1 (this branch): `sigis-cms` ported (`generic_cms.py`, CMS part of
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
- Oracle: the standard venv `/tmp/pyhanko-oracle/venv` and the sources in
  `/tmp/pyhanko-oracle/src` (§5.4). Fixtures:
  `crates/testdata/data/lanes/a/harvest/` (see its README).

- Phase 2: `sigis-pki-fetch` ported (HTTP fetchers with caches, budget,
  multi-URL fallback; RFC 3161 client). Tests use a local server on
  127.0.0.1 and pyHanko-produced TSA responses (`data/lanes/a/tsa/`).

- Phase 3a: revocation checking ported closely from `validate_crl.py` /
  `validate_ocsp.py` (indirect CRLs, `cRLIssuer`, reason coverage, CRL
  issuer recursion guard, delegated OCSP responder revocation, fetching with
  soft-fail), AIA issuer fetching in path building, qualified policies
  (RFC 9618 §5.5), `point_in_time_validation`. NIST PKITS: 243/246 agree.

- Phase 3b: `ltv` filled: `PoeManager`, `time_slide`, `past_validate`
  (lane E can use them now).

- Phase 3c: attribute certificate validation (`sigis_pki_certvalidator::ac`),
  used by `sigis-cms` for certified signer attributes; pyHanko's list of
  supported critical extensions enforced.

- Phase 3d: certificate registry and trust anchor qualifiers
  (`test_registry.py`, `test_policy_proc.py`); `test_name_trees.py` and
  `test_policy_graph.py` skipped with equivalent coverage (see
  `crates/pki-certvalidator/PORTING.md`).

- Round 1 integration (rebased on `main` b9176be): `sigis_pki_core::key_usage`
  is the single `KeyUsageConstraints` (A-4), `sigis-cms` uses
  `sigis_pki_core::ades`, `CmsError` maps to `HankoError::SignatureValidation`,
  fixtures resolve at run time. `ValidationContext` gained a trust manager
  hook (A-2), `crls()` / `ocsps()` (A-6) and `with_revinfo` (A-3).

- R1 (last commit of the branch): MD5, SHA-3 and SHAKE256 digests, DSA
  (with parameter inheritance in paths) and Ed448 verification, the DSA key
  size threshold of `DisallowWeakAlgorithmsPolicy`, and CMS policies passed
  through the validation context (`AlgorithmUsagePolicy::digest_combination`).
  certval verifies certificate signatures through `sigis-pki-core` for the
  algorithms it lacks. All 161 recorded `test_cms.py` calls and 245/246
  PKITS cases agree. This commit needs R8 in lane E code.

Remaining: `test_embed_ac_revinfo_adobe_style` waits on lane E
(`ades_lta_validation`).

Gate (2026-11-12): lane A crates green at every commit (fmt, build, test,
clippy `--all-targets`, doc with `-D warnings`). Workspace: at 62757c1,
`cargo nextest run --workspace --exclude hanko-ades` passes (439 tests) and
only the `sigis-pades` unit tests fail to compile (R7); at 7fb18a5,
`sigis-eutl` and its dependents also need R8. A fresh harvest of
`test_cms.py` with `/tmp/pyhanko-oracle/venv` (new ECDSA signatures)
replays 77/77.

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
| `test_name_trees.py` | 6 | 0 | 6 | 0 |
| `test_policy_graph.py` | 33 | 0 | 33 | 0 |
| `test_policy_proc.py` | 13 | 13 | 0 | 0 |
| `test_registry.py` | 9 | 7 | 2 | 0 |
| `test_sig_validate.py` | 3 | 3 | 0 | 0 |
| `test_validate.py` | 21 | 21 | 0 | 0 |
| `test_cms.py` | 78 | 75 | 2 | 1 |
| `test_key_usage_constraints.py` | 4 | 4 | 0 | 0 |
| `test_tsa_fetcher.py` | 10 | 8 | 2 | 0 |
| `test_tsa_fetcher_requests.py` | 4 | 4 | 0 | 0 |
| **Total** | **271** | **209** | **61** | **1** |

`test_cms.py` details (skips, pending items, recorded-call agreement) are in
`crates/cms/PORTING.md`.

## Known divergences

All fail closed (the port rejects or reports less trust where pyHanko
accepts); the tests assert this.

- NIST PKITS: 1 case (4.2.3, UTCTime 1950 not decodable), see
  `crates/pki-certvalidator/PORTING.md`.
- `test_cms.py` recorded calls: all 161 agree.
- DSA: only the FIPS 186 key sizes (1024/160, 2048/224, 2048/256,
  3072/256) verify (RustCrypto `dsa`); pyca accepts other sizes.
- ML-DSA verification is not supported (`AlgorithmNotSupported`).
- Without a validation context, nothing is trusted (pyHanko uses the OS
  trust store).

## Requests to the lead

Resolved in lead round 1: R1 approved (implementation: see R8), R2, R3, R4
and R5 done or approved.

- **R6 — `ValidationError` variants for LTV (open).** pyhanko-certvalidator
  has `InsufficientPOEError` and `TimeSlideFailure`.
  `sigis_pki_certvalidator::ltv` reports them through its own `LtvError`; the §4
  functions (`time_slide`, `past_validate`) map them to
  `ValidationError::PathValidation` with the message. If lane E needs to
  tell them apart through `HankoError`, please add
  `ValidationError::InsufficientPoe(String)` (a `PathValidationError`
  subclass in pyHanko).
- **R7 — lane E unit tests construct `sigis_cms` status structs with
  literals (needs a lane E change).** R5 added fields to `SignatureStatus`
  and `StandardCmsSignatureStatus`, so three struct literals in lane E's
  `#[cfg(test)]` code no longer compile:
  `crates/pades/src/basic.rs:303` and
  `crates/pades/src/with_time.rs:290` (`SignatureStatus { .. }`),
  `crates/pades/src/with_time.rs:313`
  (`StandardCmsSignatureStatus { .. }`). Both types now derive `Default`
  (the fail-closed status); the fix is `..Default::default()` as the last
  line of each literal. Everything else in the workspace builds; clippy is
  clean with `--exclude hanko-ades` plus `-p hanko-ades --lib`.
- **R8 — R1 changes exhaustive matches in lane E crates.** The new
  `DigestAlgorithm` variants (`Md5`, `Sha3_224`, `Sha3_256`, `Sha3_384`,
  `Sha3_512`, `Shake256`) break three exhaustive `match`es in lane E code
  that did not exist when R1 was written:
  `crates/eutl/src/xml/dsig.rs:304` and `:346` (digest to
  RSA / ECDSA signature OID) and
  `crates/pades/src/etsi_report.rs:179` (digest to XML URI). Lane A
  keeps the R1 work in a separate commit at the end of this branch
  ("Verify MD5, SHA-3, SHAKE256, DSA and Ed448 signatures"); every lane A
  crate is green with it, `sigis-eutl` and `sigis-pades` need the arms. Each
  match needs an arm for the new variants: in `dsig.rs`, an "unsupported
  algorithm" error (XML-DSig there only uses SHA-1/SHA-2), and in
  `etsi_report.rs`, the XML Signature URIs
  (`http://www.w3.org/2007/05/xmldsig-more#sha3-256` etc.; MD5:
  `http://www.w3.org/2001/04/xmldsig-more#md5`). Please apply those arms
  when merging, or tell lane A to mark `DigestAlgorithm` `#[non_exhaustive]`
  instead.

## Requests from other lanes (relayed by the lead, 2026-11-12)

Status of the relayed items:

- **A-1 (lane E): done.** `ValidationPath::qualified_policies()` returns
  `Option<&[QualifiedPolicy]>` (issuer- and user-domain policy OIDs, plus
  CPS URI and user notice text), set on paths returned by
  `validate_path_qualified` / `find_valid_path`. The pre-eIDAS check of
  `sigis-eutl` can use it.
- **A-2 (lane E): done.** `TrustAnchor::with_qualifiers(cert,
  TrustQualifiers { valid_from, valid_until, trusted_service_type,
  standard_parameters, max_path_length, .. })` and
  `TrustAnchor::from_name_and_key`; qualifiers are enforced during
  validation. Trust manager hook: trait
  `sigis_pki_certvalidator::TrustManager` (`as_trust_anchor(&Cert)`,
  `find_potential_issuers(&Cert)`) and
  `ValidationContextBuilder::trust_manager(Arc<dyn TrustManager>)`. Path
  building consults the manager after the supplied anchors; CRL and OCSP
  issuer lookup sees the supplied anchors, other certificates and the path.
- **A-3 (lane E): done.** `sigis_cms::validate_cms_signature_with(..,
  &CmsValidationOptions)` takes `key_usage_settings`, the CMS algorithm
  policy and separate timestamp / AC contexts; pyHanko's PDF defaults
  (`non_repudiation` or `digital_signature`) are passed by the caller, as in
  pyHanko. `is_ee_cert` / `is_side_validation`: `ValidationError` is
  lead-owned, so they are on `sigis_pki_certvalidator::PathFailure` (returned by
  `find_valid_path` / `validate_path_detailed`), and
  `sigis_cms::validate::handle_path_failure` already ports
  `handle_certvalidator_errors` (`CertUsageResult::error_subindic`). If lane
  E prefers the fields on `ValidationError::{Expired, Revoked}`, that is a
  lead change. DSS material: `ValidationContext::with_revinfo(certs, crls,
  ocsps)` returns an extended copy; POEs go into
  `sigis_pki_certvalidator::ltv::poe::PoeManager` (`register`,
  `register_by_digest`, `merge`).
- **A-4 (lead): done.** See commit "Use the shared key usage and AdES types
  from hanko-core". The lane E call sites compile unchanged. `Default` now
  equals `new()` (pyHanko: `explicit_extd_key_usage_required=True`); the
  derived `Default` had `false`. Key purpose names now follow asn1crypto
  exactly: `1.2.840.113583.1.1.5` is `adobe_authentic_documents_trust` (was
  `pdf_signing`), and `0.4.0.2231.3.0` has no name in asn1crypto (was
  `tsl_signing`; now its dotted OID). No lane E code uses either name.
- **A-5 (lane D): done in the R1 commit (merge needs R8).**
  `DigestAlgorithm::{Md5, Sha3_224, Sha3_256, Sha3_384, Sha3_512,
  Shake256}` (SHAKE256 with 64-byte output; `id-shake256-len` maps to it),
  `DigestAlgorithm::ALL` / `from_name`, `SignatureMechanism::{Dsa, Ed448}`;
  DSA and Ed448 verification. Signing (Ed448, DSA, ML-DSA) is lane D's; the crates are
  then available in `sigis-pki-core`.
- **A-6 (lane D): done.** `ValidationContext::crls()` and `ocsps()` return
  the supplied DER encodings.
