# Porting status: hanko-cms

Owner: lane A. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `sign/validation/generic_cms.py` | `src/validate.rs`, `src/lib.rs` | Ported: `validate_sig_integrity`, `validate_algorithm_protection` (RFC 6211), signing-certificate attribute check (v1 and v2), `extract_certs_for_validation`, `cms_basic_validation`, `validate_cert_usage` + `handle_certvalidator_errors` (AdES sub-indications), `async_validate_cms_signature`, `extract_self_reported_ts`, timestamp token validation (`validate_tst_signed_data`, signature and content timestamps, `collect_timing_info`), `async_validate_detached_cms` (generalized over the content digest source, see `ContentDigester`) |
| `sign/validation/generic_cms.py` (`collect_signer_attr_status`, `process_certified_attrs`) | `src/attributes.rs` | Ported, on `hanko-certvalidator::ac` |
| `sign/validation/status.py` (CMS part) | `src/status.rs` | Ported: `SignatureStatus`, `TimestampSignatureStatus`, `StandardCMSSignatureStatus`, `RevocationDetails`, claimed/certified attribute maps, `CAdESSignerAttributeAssertions`, `summary()`, `pretty_print_details()` (without qualification sections, lane E) |
| `sign/validation/settings.py` (`KeyUsageConstraints`) | `src/key_usage.rs` | Ported (configuration parsing is CLI-side, lane L) |
| `sign/validation/utils.py` | `src/policy.rs` | Ported: `CMSAlgorithmUsagePolicy`, `lift_policy`, default policy, `_ensure_digest_match` (including asn1crypto's NULL-parameter comparison quirk) |
| `sign/validation/errors.py` (CMS errors) | `src/errors.rs` | Ported (`SignatureValidationError`, `DisallowedAlgorithmError`, `CMSExtractionError`, `CMSStructuralError`) |
| `sign/general.py` (attributes, certificate extraction, ESS matching) | `src/signed_data.rs` | Ported. Parsing keeps original encodings (lenient TLV walk), so signed attributes are verified as encoded, like asn1crypto |
| `sign/ades/report.py` (indications) | `src/ades.rs` | Ported |
| ASN.1 (`cms`, `tsp` from asn1crypto) | `cms`/`x509-tsp` crates + `hanko-core::asn1::{tlv, raw_oid}` | Replaced by crates where strict DER is fine (`TSTInfo`, algorithm identifiers, ESS); lenient walk elsewhere |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_cms.py` | `tests/test_cms.rs` | 78 | 60 | 2 | 16 |
| `test_key_usage_constraints.py` | `tests/test_key_usage_constraints.rs` | 4 | 4 | 0 | 0 |

How `test_cms.py` is ported: the upstream tests sign with pyHanko, then
validate. The harvest (`oracle/harvest.sh`, fixtures in
`crates/hanko-testdata/data/lanes/a/harvest/`) runs the upstream tests and
records every validation call with its inputs and pyHanko's outcome. Each
Rust test replays the calls of its upstream function, asserts the upstream
assertions on the hanko-cms result, and compares the outcome with pyHanko's
field by field (`tests/common/mod.rs`). Unlisted differences fail the test,
listed ones (`KNOWN`) must still differ, and every difference must fail
closed. All 161 recorded calls agree (`KNOWN` is empty).

Skipped (signing side, lane D):

- `test_sign_weak_digest_prevention`: the signer refuses MD5.
- `test_key_based_digest_selection`: `select_suitable_signing_md` (signer).

Partly ported: `test_overspecify_cms_digest_algo` (its signer-refusal half
is lane D), `test_direct_pdfcmsembedder_usage` (DSS half is lanes B/E).

Pending:

- `test_embed_ac_revinfo_adobe_style`: its assertions are on
  `ades_lta_validation` (lane E); the integrity checks it makes are
  replayed and agree.

## Divergences

- No context given: pyHanko falls back to the OS trust store; hanko-cms
  trusts nothing (stricter).
- Name comparison follows asn1crypto: names whose values fail RFC 4518
  string preparation never match and make path validation fail
  (`hanko-certvalidator::names`).
- Error messages for malformed claimed attributes differ in the parser
  detail after "Failed to parse ... of type '...': " (asn1crypto internals).
