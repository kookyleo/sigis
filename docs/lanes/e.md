# Lane E — Validation, AdES, trusted lists

Owner: lane E (branch `hanko/e-validate`). See `docs/hanko-lanes.md`.

## Status

- Phase 1 (in progress): `hanko-eutl` — trusted list parsing, XMLDSig/XAdES
  verification with an own C14N implementation, TSP registry, qualification
  assessment, LOTL bootstrapping and fetching, caches. `hanko-validate`:
  `settings` (`KeyUsageConstraints`), `errors`, AdES indications (`report`).
- Phase 2 (in progress): `hanko-validate` PDF validation coded against the
  lane A/B/C stubs (coverage, DocMDP/FieldMDP, modification review, CMS and
  document timestamp validation calls). Next: `hanko-ades` (`ades.py`,
  reports) and Rust replays of the AdES oracle recordings.

PKI: lead item L1 is open, so lane E exported the Certomancer test PKIs
(`testing-ca`, `testing-ca-ecdsa`, `testing-ca-qualified`, `unrelated-tsa`;
certificates only) locally with `crates/hanko-eutl/oracle/export_pki.py`
into `crates/hanko-testdata/data/lanes/e/pki/`, plus two XAdES-signed
lists. The oracle ran outside the repository with pyHanko 0.38.1,
pyhanko-certvalidator 0.33.0, certomancer 0.16.0, signxml 5.2.0 and
xsdata 26.10 (Python 3.14). Once L1 lands, the tests can switch to
`data/pyhanko-pki/`.

AdES oracle fixtures: `crates/hanko-ades/oracle/record_plugin.py` runs
pyHanko's own `test_ades_validation*.py` (tag v0.38.1) and records, per
test case and per `ades.*_validation` call, the validated object (CMS or
whole PDF), the frozen time, all HTTP exchanges with the Certomancer
services, and pyHanko's verdict, plus the PKI certificates of that run and
the generated trusted lists. Output:
`crates/hanko-testdata/data/lanes/e/ades/*.json` (76/76 upstream cases
passed under the recorder; 144 validation calls, 98 HTTP exchanges). The
Rust ports will replay these once lanes A, B and C fill
`validate_cms_signature`, `PdfFile` and `DiffPolicy`.

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_ades_validation.py` | 40 | 0 | 0 | 40 (oracle recorded) |
| `test_ades_validation_report.py` | 5 | 0 | 0 | 5 (oracle recorded) |
| `test_ades_validation_requests.py` | 2 | 0 | 0 | 2 (oracle recorded) |
| `test_trusted_list.py` | 53 | 53 | 0 | 0 |

## Known divergences

See `crates/hanko-eutl/PORTING.md` (D-E1 … D-E4). All of them fail closed.

## Requests to the lead

- **R-E1 (dependency graph, informational).** `hanko-eutl` now depends on
  `hanko-certvalidator` and `hanko-validate` (for `KeyUsageConstraints`,
  `SignatureValidationError` and the AdES indications), and will be a
  dependency of `hanko-ades`. §2 shows `hanko-eutl` depending on
  `hanko-core` only; please update the graph. `KeyUsageConstraints`
  (`settings.py`) is in `hanko_validate::settings`; lane A's
  `test_key_usage_constraints.py` and `generic_cms` need it too but
  `hanko-cms` cannot depend on `hanko-validate`. Proposal: move
  `settings.rs` (and `report.rs`, the AdES indications that
  `SignatureValidationError` carries) to `hanko-core` (e.g.
  `hanko_core::key_usage`, `hanko_core::ades`), owned by lane E or the lead;
  `hanko-validate` would re-export them. Until then lane E keeps them in
  `hanko-validate`.
- **R-E2 (lane A interface).** `ValidationPath::qualified_policies()`
  (pyhanko-certvalidator `QualifiedPolicy` set: issuer- and user-domain
  policy OIDs after RFC 5280 policy processing). Needed for pre-eIDAS
  qualification (divergence D-E1).
- **R-E3 (lane A interface).** Trust anchor qualifiers
  (`TrustQualifiers`: `valid_from`, `valid_until`, `trusted_service_type`,
  `standard_parameters`) on `TrustAnchor`, enforced during validation, and a
  trust manager hook in `ValidationContextBuilder` (pyhanko-certvalidator
  `TrustManager` with `as_trust_anchor` / `find_potential_issuers`), so a
  `TSPRegistry` can act as the trust source (divergence D-E2).
- **R-E5 (crate gap, blocks lane A and E tests).** `const-oid` 0.10.x
  (also 0.10.3) rejects OIDs whose first arc is 2 and second arc exceeds 39
  (`ARC_MAX_SECOND = 39` in `arcs.rs`), e.g. `2.999.31337.0`, which pyHanko's
  Certomancer PKI `testing-ca-qualified` uses as certificate policies.
  Decoding any certificate with such an OID fails (`malformed OID`), and
  `hanko-certvalidator` path validation fails with `EncodingError`.
  Proposal: an upstream fix in RustCrypto/formats (const-oid stores the
  first two arcs in one byte), and until it is released a patched
  `const-oid` under `vendor/` via `[patch.crates-io]` (lead-owned root
  `Cargo.toml`). Lane E works around it for policy matching
  (`hanko_eutl::util::certificate_policy_oids`).
- **R-E6 (lane B interface).** For the coverage check and DocMDP `/Lock`
  lookup: `RevisionInfo` with `startxref: u64` and `xref_end: u64` (end of
  the revision's xref table or stream, pyHanko
  `get_xref_container_info(rev).end_location`), and
  `EmbeddedSignature::field_object: ObjectId` (the signature field
  dictionary). Until then `hanko-validate` scans for `startxref`, uses the
  revision end as xref end (can only lower coverage) and searches the
  AcroForm for the field.
- **R-E7 (lane A interface).** `hanko_cms::validate_cms_signature` needs the
  `key_usage_settings` (pyHanko applies `non_repudiation` /
  `digital_signature` defaults for PDF signatures) and the CMS algorithm
  policy as parameters; AdES mapping needs `is_ee_cert` /
  `is_side_validation` on `ValidationError::{Expired, Revoked}`
  (`handle_certvalidator_errors`); LTA validation needs a way to extend a
  `ValidationContext` with DSS material (certs, CRLs, OCSP responses) and
  POEs.
- **R-E8 (hanko-core).** A `HankoError` variant for signature validation
  failures carrying the AdES sub-indication (e.g.
  `HankoError::SignatureValidation { message, subindication: &'static str }`).
  `hanko-validate` currently maps `SignatureValidationError` to
  `HankoError::Malformed`.
- **R-E9 (hanko-testdata, affects all lanes).** `hanko_testdata::path`
  and friends use the compile-time `env!("CARGO_MANIFEST_DIR")`. With the
  shared target directory and sccache, the compiled `hanko-testdata` can
  come from another worktree: in `e-validate`, `hanko_testdata::path`
  resolved to `/home/l/D/kooky/sigis-wt/c-diff/crates/hanko-testdata/data`.
  Tests then read fixtures from another branch (or fail on lane-specific
  fixtures). Proposal: resolve at run time from
  `std::env::var("CARGO_MANIFEST_DIR")` of the test crate
  (`<crate>/../hanko-testdata/data`), or from a `HANKO_TESTDATA` variable.
  Lane E tests do this locally (`tests/common/mod.rs::data`).
- **R-E4 (hanko-core, minor).** `Moment::parse_rfc3339` ignores numeric
  offsets other than `+00:00`. `hanko-eutl` has its own `xsd:dateTime`
  parser (`util::parse_xsd_datetime`); a shared one in `hanko-core` would
  avoid the duplicate.
