# Lane E — Validation, AdES, trusted lists

Owner: lane E (branch `hanko/e-validate`). See `docs/hanko-lanes.md`.

## Status

- Phase 1 (in progress): `hanko-eutl` — trusted list parsing, XMLDSig/XAdES
  verification with an own C14N implementation, TSP registry, qualification
  assessment, LOTL bootstrapping and fetching, caches. `hanko-validate`:
  `settings` (`KeyUsageConstraints`), `errors`, AdES indications (`report`).
- Next: `hanko-validate` PDF validation (`pdf_embedded`, `status`, `dss`) and
  `hanko-ades` (`ades.py`, reports), coded against the lane A/B/C stubs.

PKI: the Certomancer test PKIs are not exported yet (lead item L1). Tests
that need them are pending; lane E will run the export locally into
`crates/hanko-testdata/data/lanes/e/` once a local pyHanko venv installs
(`/tmp/lane-e/venv`, outside the repository).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_ades_validation.py` | 40 | 0 | 0 | 40 |
| `test_ades_validation_report.py` | 5 | 0 | 0 | 5 |
| `test_ades_validation_requests.py` | 2 | 0 | 0 | 2 |
| `test_trusted_list.py` | 53 | 39 | 0 | 14 |

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
- **R-E4 (hanko-core, minor).** `Moment::parse_rfc3339` ignores numeric
  offsets other than `+00:00`. `hanko-eutl` has its own `xsd:dateTime`
  parser (`util::parse_xsd_datetime`); a shared one in `hanko-core` would
  avoid the duplicate.
