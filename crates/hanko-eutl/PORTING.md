# Porting status: hanko-eutl

Owner: E. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `sign/validation/qualified/tsp.py` | `src/tsp.rs` | ported |
| `sign/validation/qualified/q_status.py` | `src/q_status.rs` | ported |
| `sign/validation/qualified/assess.py` | `src/assess.rs` | ported (see divergence D-E1) |
| `sign/validation/qualified/eutl_parse.py` | `src/parse.rs` | ported; xsdata bindings replaced by a `roxmltree` DOM walk |
| `sign/validation/qualified/eutl_fetch.py` | `src/fetch.rs` | ported; `aiohttp` replaced by the synchronous `TlFetcher` trait |
| `sign/validation/qualified/lotl-certs/` | `lotl-certs/` | copied |
| `sign/validation/policy_decl.py` (`QualificationRequirements`) | `src/assess.rs` | ported |
| `sign/ades/qualified_asn1.py` | `src/qc_statements.rs` | ported (QC statements needed for assessment) |
| `generated/etsi/` (xsdata bindings) | — | skipped: replaced by direct DOM access in `src/parse.rs` |
| signxml `XAdESVerifier` (dependency) | `src/xml/dsig.rs` | reimplemented (no Rust XMLDSig crate verifies XAdES) |
| lxml C14N (dependency) | `src/xml/c14n.rs` | reimplemented: Canonical XML 1.0/1.1 and Exclusive C14N 1.0 |

### XML decisions

- DOM: `roxmltree` 0.20 (read-only, namespace aware, DTDs rejected). It keeps
  source ranges, so the canonicalizer recovers the prefixes as written.
- Canonicalization: no maintained pure-Rust crate implements exclusive and
  inclusive C14N over a DOM subset (the crates found bind libxml2/xmlsec).
  `src/xml/c14n.rs` implements both for "subtree minus excluded subtree"
  document subsets, which is all XMLDSig enveloped/same-document references
  need. Tested against the W3C C14N 1.0 examples 3.3 and 3.4 and against
  real EU trusted lists.
- Signature checks follow signxml 4.x as pyHanko calls it: SHA-1 signature
  and reference digests rejected, certificate validity checked at the
  verification time, `KeyValue` must match the certificate, any number of
  references, `SignedProperties` reference required with matching
  `SigningCertificate(V2)` digests. Like signxml, "C14N 1.1" is rendered with
  the C14N 1.0 rules (lxml has no 1.1 serializer), and unknown transforms are
  ignored.

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_trusted_list.py` | `tests/trusted_list.rs` | 53 | 39 | 0 | 14 |

Pending: the 14 functions that need the Certomancer `testing-ca`,
`testing-ca-ecdsa` and `testing-ca-qualified` PKIs (`test_parse_generated_lotl`,
`test_criteria_accept`, `test_criteria_reject`, `test_tsp_registry*` (4),
`test_qcstatements_processing`, `test_conclude_*` (7)).

Time pinning: upstream tests that validate signatures at the current time
(`test_validate_tl_wrong_signature`, `test_validate_and_parse_lotl_default_certs`,
`test_parse_services_from_real_tl_via_*lotl`) pass an explicit validation
time here (the LOTL issuance date, or 2026-06-16 for the LOTL + BE list), so
they do not break when the list signer certificates expire.
`test_validate_tl_wrong_signature` additionally runs at the current time.

## Known divergences

- **D-E1** (`assess.py`, pre-eIDAS qualification): pyHanko reads the
  user-domain policies of the validated path (RFC 5280 valid policy tree).
  `hanko-certvalidator` does not expose that tree yet, so
  `path_qualified_policies` computes a subset (explicit policy on the leaf,
  each intermediate asserting it or `anyPolicy`; no result with policy
  mappings). It can only make fewer certificates qualified. Requested from
  the lead (`docs/lanes/e.md`, R-E2).
- **D-E2** (`TSPTrustManager`): pyhanko-certvalidator enforces trust anchor
  qualifiers (service validity window) during path validation.
  `hanko-certvalidator` has no trust qualifiers yet, so
  `TspTrustManager::trust_anchors_at` leaves out anchors whose window does not
  contain the validation time; the outcome is the same for validation at
  that time. Requested (R-E3).
- **D-E3** (malformed certificates in a list): pyHanko loads
  `X509Certificate` values lazily with asn1crypto; an undecodable
  certificate makes the service definition fail with a
  `TspServiceParsingError` here (the service is not registered).
- **D-E4** (XML schema validation): signxml validates the `ds:Signature`
  element against the XMLDSig schema. The port checks the element order of
  `Signature`, `SignedInfo` and `Reference` only.
