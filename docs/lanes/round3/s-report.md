# Round 3 lane S report

Session: `sigis-r3-s`; branch: `hanko/r3-s`; baseline: `34482bf`.
Status: in progress. No new passes are claimed yet.

## Baseline unique-function accounting

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| sigis-cms | 78 | 75 | 2 | 1 |
| sigis-eutl | 53 | 53 | 0 | 0 |
| sigis-pdf | 406 | 384 | 17 | 5 |
| sigis-pdf-diff | 94 | 92 | 2 | 0 |
| sigis-pki-certvalidator | 133 | 92 | 41 | 0 |
| sigis-pki-core | 4 | 4 | 0 | 0 |
| sigis-pki-fetch | 56 | 38 | 18 | 0 |
| **Total** | **824** | **738** | **80** | **6** |

## Active work

- Independent bounded tasks: certvalidator skip assertions and policy/name-tree parity; fetcher lifecycle skip assertions; CMS pending/skip/partial-pass review.
- Main lane: PDF decode-limit integration assertions, PDF object-model skip audit, PDF MAC callers and centralized P/V requests.
- All Cargo commands use `tools/cargo-locked.sh`; detailed logs and handoffs are stored under `/home/l/.codex/artifacts/sigis/round3/s/`.

## Interface and assertion requests to L

1. Route decode-limit propagation to P: `SignOptions` currently has no `DecodeLimits`; timestamp, archival-chain and DSS byte-slice APIs reopen with defaults. The exact three upstream functions use a trusted reader to process an oversized object stream; preserve caller-selected limits at every internal reopen. Proposed API: `SignOptions.decode_limits`, `TimestampOptions.decode_limits`, explicit reader/limit-aware archival-chain and DSS variants, without changing default callers. S will own Rust caller tests under `crates/pdf/tests/` and add acyclic dev dependencies on P/V crates.
2. Route `test_pdf_mac_pades` and `test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel` implementation to P: signer must supply PDF MAC attributes bound to the individual signing session and reject concurrent reuse as upstream. S owns the acceptance tests; V supplies full LTA validation for the first case.
3. Route two PDF-diff coverage skips to V: exact `test_tamper_sig_obj` and `test_anomalous_coverage` must exercise validator integrity/coverage outcomes. No empty PDF-diff re-enable wrappers will be counted.
4. Route four PDF layout/resource skips to P: `test_box_constraint_over_underspecify`, `test_box_constraint_recalc`, `test_resource_add_test`, `test_duplicate_resource`; return exact Rust assertions/parameter coverage so S can audit without double counting.
5. P owns implementation and proof for the 13 inherited P signing skips listed in `s.md`. Please provide exact function-ID mappings, parameter/provider exclusions and remaining feature gaps. S will centrally audit them without editing signing files.

## Evidence and limitations

Initial read confirms the three decode-limit tests require real signing/archival/DSS updates, rather than reader-only or recorded Python outcomes. The two PDF MAC tests remain empty ignored wrappers at baseline. No fixture replay is labelled a fresh live oracle comparison. No trust-verdict parity claims have been added.

## Verification checkpoint

This is an implementation checkpoint, not a ready milestone. Tool host
failures and package/build-lock waits prevented Rust acceptance. Do not
merge this increment as a passing lane without the checks below.

### Conservative reviewed accounting

The immutable starting table above is retained for comparison. The two
historically partial CMS functions are downgraded to pending until their
complete assertions pass. No unverified candidate earns a new pass.

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| sigis-cms | 78 | 73 | 2 | 3 |
| sigis-eutl | 53 | 53 | 0 | 0 |
| sigis-pdf | 406 | 384 | 17 | 5 |
| sigis-pdf-diff | 94 | 92 | 2 | 0 |
| sigis-pki-certvalidator | 133 | 92 | 41 | 0 |
| sigis-pki-core | 4 | 4 | 0 | 0 |
| sigis-pki-fetch | 56 | 38 | 18 | 0 |
| **Total** | **824** | **736** | **80** | **8** |

### Implemented candidates and exact obligations

- Fetcher increment `f3d0f9b`: lazy transport closes/recreates a session;
  four lifecycle assertions and an invalid-auth compile-failure assertion.
  Accepted counts remain 56/38/18/0; five candidate functions require Rust
  checks. The 13 remaining gaps are explicit in the crate PORTING file.
- Certvalidator: six name predicates, all 54 upstream parameters, wired
  into excluded-name checks. Eight additional policy-result tests cover
  only the production final-graph adapter and remain partial/skipped;
  25 other graph operations and two deprecated APIs remain gaps. The
  zero-length final graph now reports anyPolicy. Only the six predicates
  can become new passes after successful Rust verification.
- CMS: real signer tests cover four key/digest-selection cases, weak MD5
  rejection, and fixed-mechanism SHA256 success versus SHA512 conflict.
  No new pass is claimed. `test_direct_pdfcmsembedder_usage` still lacks
  exact low-level, in-place, DocMDP and DSS count assertions. The historical
  overspecified-digest pass lacked the signer refusal; its new test is
  pending verification. Full Adobe AC revinfo acceptance still needs V's
  complete AdES-LTA caller.
- PDF: two compile-failure guards plus valid-input controls in
  `generic::pdf_string` express integer rejection for string input and
  dictionary keys. They remain skipped until rustdoc checks pass.
- [Exact PDF skip dispositions](s-pdf-skip-audit.md) cover all 17 inherited
  PDF skips and both PDF-diff validator requests. No empty wrapper earns
  coverage. The five PDF integration functions still require P/V APIs.

The complete 93-ID exact upstream source inventory is saved as
`inherited-skips-exact-source.json` and `.md` in the artifact directory.
It includes all 13 P-owned IDs; recording source obligations does not
prove passing Rust ports. `runtime-skip-candidates.json` records 54 source
locations for separate runtime audit, including lexical false positives.
Detailed per-function mappings and commands are in `cms-handoff.md`,
`pki-fetch-handoff.md`, `pki-certvalidator-handoff.md`, and the owning crate
audit files. Existing EUTL/core passes were not reverified in this increment.

### Oracle evidence, separate from Rust function counts

- Fetcher fresh direct upstream run: 16 lifecycle functions plus two TSA
  assertions, 18 unique functions, exit 0. The earlier pytest collection
  error is not a passing result.
- Certvalidator fresh direct upstream run: six functions across 54 name
  parameters and eight user-policy functions, zero failures. These are
  62 invocations of 14 unique upstream functions. The eight policy
  functions remain skipped in Rust because graph setup is incomplete.
- No new CMS/PDF live comparison is claimed without a returned result.
- No trust-verdict or universal fail-closed claim follows from the new
  encoding/type/model audit. Keep all adversarial rejection controls.

### Tool and verification limitations

Tiny commands repeatedly waited hundreds to thousands of seconds outside
the shell, and multiple tool hosts timed out/reset, losing session handles.
Cargo commands used `tools/cargo-locked.sh` throughout, but returned only
package-cache/build-directory lock waits. No build flag, target, shared
tool, service or other session was modified. Exact owned commands still
waiting without compilation are cancelled after cwd/argv/log verification,
so this checkpoint does not intentionally leave background builds.

Required follow-up checks, serialized through the existing wrapper:

```sh
tools/cargo-locked.sh check -p sigis-pki-certvalidator
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p sigis-pki-certvalidator --lib
tools/cargo-locked.sh check -p sigis-pki-fetch
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p sigis-pki-fetch --test test_fetcher_lifecycle
tools/cargo-locked.sh test -p sigis-pki-fetch --doc
tools/cargo-locked.sh check -p sigis-cms
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p sigis-cms --test signing_parity
tools/cargo-locked.sh test -p sigis-pdf --doc
```

L must also inspect whether wrapper/slot-lock lifetime accounts for the
observed multiple long-lived Cargo processes. This is a diagnostic request,
not a proven concurrency bug. All integration, merged lockfile generation,
workspace gate and final acceptance remain L-owned.
