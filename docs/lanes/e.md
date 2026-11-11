# Lane E — Validation, AdES, trusted lists

Owner: lane E (branch `hanko/e-validate`). See `docs/hanko-lanes.md`.

## Status

Phase gate (2026-11-11, branch `hanko/e-validate`, rebased on `main`
c2f1b08): `cargo clippy --workspace --all-targets` clean,
`cargo doc --no-deps --workspace` with `-D warnings` clean,
`cargo nextest run --workspace` 134 passed, 15 skipped (ignored tests
blocked on other lanes).

- `sigis-eutl`: done. TS 119 612 parsing with service history, XMLDSig /
  XAdES verification (own C14N 1.0/1.1 and Exclusive C14N on `roxmltree`),
  TSP registry, qualification assessment and requirements, LOTL parsing and
  signer bootstrapping, fetching with in-memory / file system caches.
  `test_trusted_list.py` 53/53; differential test against pyHanko 18/18.
- `sigis-pades`: `settings` (`KeyUsageConstraints`), `errors`, AdES
  indications; PDF signature and document timestamp validation against the
  lane A/B/C interfaces (SubFilter, coverage levels, DocMDP / FieldMDP /
  `/Lock`, modification review, `docmdp_ok`). Pending: seed values (lane D
  `SigSeedValueSpec`), signer attributes, validation side of `dss.py`.
- `sigis-pades`: basic validation (§5.3) and validation with time (§5.5)
  on top of `sigis_cms`, qualification analysis, TS 119 102-2 XML reports,
  JSON / status-only reports. Pending: LTA (§5.6), past signature
  validation, POE extraction (needs lane A `ltv`, lane B DSS).
- Oracle: AdES recordings for all 76 upstream cases; 13 replayed test ports
  written and ignored until `sigis_cms::validate_cms_signature` lands.

Interface additions in lane E crates: `PdfSignatureStatus::docmdp_ok`,
`PdfSignatureStatus::bottom_line`; `sigis_pades::ades::AdesStatus` is now a
re-export of the identical `sigis_pades::report::AdesStatus`.

PKI: lead item L1 is open, so lane E exported the Certomancer test PKIs
(`testing-ca`, `testing-ca-ecdsa`, `testing-ca-qualified`, `unrelated-tsa`;
certificates only) locally with `crates/eutl/oracle/export_pki.py`
into `crates/testdata/data/lanes/e/pki/`, plus two XAdES-signed
lists. The oracle ran outside the repository with pyHanko 0.38.1,
pyhanko-certvalidator 0.33.0, certomancer 0.16.0, signxml 5.2.0 and
xsdata 26.10 (Python 3.14). Once L1 lands, the tests can switch to
`data/pyhanko-pki/`.

Differential test (TL): `crates/eutl/tests/differential.rs`, 18
inputs incl. tampered lists, 18/18 agree with pyHanko.

AdES oracle fixtures: `crates/pades/oracle/record_plugin.py` runs
pyHanko's own `test_ades_validation*.py` (tag v0.38.1) and records, per
test case and per `ades.*_validation` call, the validated object (CMS or
whole PDF), the frozen time, all HTTP exchanges with the Certomancer
services, and pyHanko's verdict, plus the PKI certificates of that run and
the generated trusted lists. Output:
`crates/testdata/data/lanes/e/ades/*.json` (76/76 upstream cases
passed under the recorder; 144 validation calls, 98 HTTP exchanges). The
Rust ports will replay these once lanes A, B and C fill
`validate_cms_signature`, `PdfFile` and `DiffPolicy`.

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_ades_validation.py` | 40 | 13 | 0 | 27 (oracle recorded) |
| `test_ades_validation_report.py` | 5 | 0 | 0 | 5 (oracle recorded) |
| `test_ades_validation_requests.py` | 2 | 0 | 0 | 2 (oracle recorded) |
| `test_trusted_list.py` | 53 | 53 | 0 | 0 |

## Known divergences

See `crates/eutl/PORTING.md` (D-E1 … D-E4). All of them fail closed.

## Requests to the lead

- **R-E1 (dependency graph, informational).** `sigis-eutl` now depends on
  `sigis-pki-certvalidator` and `sigis-pades` (for `KeyUsageConstraints`,
  `SignatureValidationError` and the AdES indications), and will be a
  dependency of `sigis-pades`. §2 shows `sigis-eutl` depending on
  `sigis-pki-core` only; please update the graph. `KeyUsageConstraints`
  (`settings.py`) is in `sigis_pades::settings`; lane A's
  `test_key_usage_constraints.py` and `generic_cms` need it too but
  `sigis-cms` cannot depend on `sigis-pades`. Proposal: move
  `settings.rs` (and `report.rs`, the AdES indications that
  `SignatureValidationError` carries) to `sigis-pki-core` (e.g.
  `sigis_pki_core::key_usage`, `sigis_pki_core::ades`), owned by lane E or the lead;
  `sigis-pades` would re-export them. Until then lane E keeps them in
  `sigis-pades`.
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
  `sigis-pki-certvalidator` path validation fails with `EncodingError`.
  Proposal: an upstream fix in RustCrypto/formats (const-oid stores the
  first two arcs in one byte), and until it is released a patched
  `const-oid` under `vendor/` via `[patch.crates-io]` (lead-owned root
  `Cargo.toml`). Lane E works around it for policy matching
  (`sigis_eutl::util::certificate_policy_oids`).
- **R-E6 (lane B interface).** For the coverage check and DocMDP `/Lock`
  lookup: `RevisionInfo` with `startxref: u64` and `xref_end: u64` (end of
  the revision's xref table or stream, pyHanko
  `get_xref_container_info(rev).end_location`), and
  `EmbeddedSignature::field_object: ObjectId` (the signature field
  dictionary). Until then `sigis-pades` scans for `startxref`, uses the
  revision end as xref end (can only lower coverage) and searches the
  AcroForm for the field.
- **R-E7 (lane A interface).** `sigis_cms::validate_cms_signature` needs the
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
  `sigis-pades` currently maps `SignatureValidationError` to
  `HankoError::Malformed`.
- **R-E9 (hanko-testdata, affects all lanes).** `sigis_testdata::path`
  and friends use the compile-time `env!("CARGO_MANIFEST_DIR")`. With the
  shared target directory and sccache, the compiled `sigis-testdata` can
  come from another worktree: in `e-validate`, `sigis_testdata::path`
  resolved to `/home/l/D/kooky/sigis-wt/c-diff/crates/testdata/data`.
  Tests then read fixtures from another branch (or fail on lane-specific
  fixtures). Proposal: resolve at run time from
  `std::env::var("CARGO_MANIFEST_DIR")` of the test crate
  (`<crate>/../testdata/data`), or from a `HANKO_TESTDATA` variable.
  Lane E tests do this locally (`tests/common/mod.rs::data`).
- **R-E4 (hanko-core, minor).** `Moment::parse_rfc3339` ignores numeric
  offsets other than `+00:00`. `sigis-eutl` has its own `xsd:dateTime`
  parser (`util::parse_xsd_datetime`); a shared one in `sigis-pki-core` would
  avoid the duplicate.

## Lead responses (2026-11-12)

Merged into `main` with the lead round recorded in `docs/hanko-lanes.md` §8.
- R-E1 done: `KeyUsageConstraints` is `sigis_pki_core::key_usage` (owned by lane
  A, which reconciles it with its own copy), the AdES indications are
  `sigis_pki_core::ades` (owned by lane E); `sigis_pades::{settings, report}`
  re-export them. The `hanko-eutl → hanko-validate` dependency stays (for
  `SignatureValidationError`); the graph in §2 is updated.
- R-E4 done: `sigis_eutl::util::parse_xsd_datetime` delegates to
  `Moment::parse_xsd_datetime` (same strict `hh:mm:ss` semantics).
- R-E5: `const-oid` patched on `main` (`vendor/const-oid`); certificates
  with `2.999.*` OIDs decode. You can drop workarounds such as
  `util::certificate_policy_oids` if they only existed for this.
- R-E8 done: `HankoError::SignatureValidation { message, ades_subindication }`;
  `sigis_pades::sv_error` maps to it.
- R-E9 done: run-time fixture paths; `tests/differential.rs` uses
  `sigis_testdata::manifest_dir()`.
- R-E2, R-E3, R-E7 relayed to lane A (A-1, A-2, A-3); R-E6 relayed to lane B
  (B-2). Seed values relayed to lane D (D-1).

## Lead round 2 (2026-11-12)

- The 13 AdES replay tests run against lane A's CMS validation and pass
  (the recorded SignedData already carried the `[0]` tag; the test helper
  no longer wraps it twice). `path_validation_of_qualified_pki` runs with
  the patched `const-oid`.
- R7 / R8 applied by the lead: test struct literals use
  `..Default::default()`; `digest_algo_uri` returns `None` outside pyHanko's
  table and the ETSI report fails with pyHanko's message; XML-DSig rejects
  MD5 / SHA-3 / SHAKE256.
- `ValidationError::InsufficientPoe` is mapped like other path validation
  errors (pyHanko `handle_certvalidator_errors`).
- Layout: `hanko-validate` and `hanko-ades` are merged into `crates/pades`
  (`sigis_pades`, AdES in `sigis_pades::ades`); `SignatureValidationError`
  moved to `crates/ades-model`; `eutl` depends on `ades-model` instead of the
  PDF validator. See `docs/crates.md`.
- `is_ee_cert` / `is_side_validation`: decided to stay on lane A's
  `PathFailure` (returned by `find_valid_path` / `validate_path_detailed`);
  use `sigis_cms::validate::handle_path_failure` for the AdES mapping.
