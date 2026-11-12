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

- Fetcher increment `a32a69a` (previously `f3d0f9b`): lazy transport closes/recreates a session;
  four lifecycle assertions and an invalid-auth compile-failure assertion.
  Accepted counts remain 56/38/18/0; five candidate functions require Rust
  checks. The 13 remaining gaps are explicit in the crate PORTING file.
- Certvalidator: six name predicates, all 54 upstream parameters, wired
  into excluded-name checks. Eight additional policy-result tests cover
  only the production final-graph adapter and remain partial/skipped;
  25 other graph operations and two deprecated APIs remain gaps. The
  zero-length final graph now reports anyPolicy. Only the six predicates
  can become new passes after successful Rust verification.
- CMS: the checked-in signer test covers four key/digest-selection cases.
  The earlier tool-timeout attempts to add weak MD5 rejection and the
  fixed-mechanism SHA256/SHA512 conflict assertions did not write those
  tests. They are implementation obligations, not implemented candidates.
  No new pass is claimed. `test_direct_pdfcmsembedder_usage` still lacks
  exact low-level, in-place, DocMDP and DSS count assertions. The historical
  overspecified-digest pass lacked the signer refusal; its complete test
  must still be added. Full Adobe AC revinfo acceptance still needs V's
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

### Historical tool and verification limitations

Tiny commands repeatedly waited hundreds to thousands of seconds outside
the shell, and multiple tool hosts timed out/reset, losing session handles.
Cargo commands used `tools/cargo-locked.sh` throughout, but returned only
package-cache/build-directory lock waits. No build flag, target, shared
tool, service or other session was modified. Exact owned commands still
waiting without compilation are cancelled after cwd/argv/log verification,
so this checkpoint does not intentionally leave background builds.

Required follow-up checks through the existing wrapper:

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

### Scheduling recovery after db8a75c

Main `db8a75c` is included. Existing owned commits were preserved as
`a32a69a` (fetchers), `ab6c02f` (CMS), `272c54e` (PKI) and `4eef17d`
(PDF guards/report). The resumed worktree was clean.

All new Cargo commands use the updated `tools/cargo-locked.sh` and retain
the configured compiler cache. System rust-slots owns placement, per-host
serialization and job caps. No forced local mode, repository flock,
manual job flags or empty `RUSTC_WRAPPER` is added. Existing builds remain
unchanged; the historical cancellation procedures above do not apply to
this resumed run. Scheduling repair itself changes no function count.

The next necessary targeted check is `tools/cargo-locked.sh check -p
sigis-pdf`; its complete output is captured in `resume-pdf-check.log`.
Host/slot evidence and actual check results will be added after completion.
The six PDF/CMS pending integration APIs and P/V assertion requests above
remain active. All integration, merged lockfile generation, workspace gate
and final acceptance remain L-owned.

### Resumed host/slot evidence and V interface increment

The necessary PDF check launched from the default login shell reports:

```text
/usr/local/lib/rust-slots/bin/cargo
rust-remote: vm2065 slot0  /home/l/D/kooky/sigis-wt/r3-s
```

Command: `tools/cargo-locked.sh check -p sigis-pdf`; output:
`slots-pdf-check.log`; result is pending. The previously submitted
`resume-pdf-check.log` came from a non-login shell whose PATH resolved the
Rustup Cargo shim, rather than rust-slots. It yielded a build-directory
lock wait and is not host/slot evidence. That existing invocation remains
unchanged. All resumed invocations now retain the default login environment;
no empty compiler-wrapper or scheduling-variable export is introduced.

V requested context-preserving historical validation. S implemented the
minimal additive `ValidationContext::with_timing(ValidationTimingParams)`
and `with_fetchers(Fetchers)` methods in the owned context module. They
clone the existing context and replace only the named field. New unit
assertions were written before the methods and verify nondefault timing,
revocation and AC target restrictions, trust material, policy/freshness
handle identity, all three fetcher identities and source immutability.
This is an API increment for L review and routing to V; no module export
or shared core type changed. Rust verification remains pending. These
regressions earn no additional assigned upstream function pass.

## Verified scheduling recovery increment

Actual completed checks supersede the earlier pending statements above:

| Check | Scheduler evidence | Result |
| --- | --- | --- |
| `tools/cargo-locked.sh check -p sigis-pdf` | automatic `vm2065 slot0` | passed, 24.79s |
| `tools/cargo-locked.sh test -p sigis-pdf --doc` | default login environment, wrapper retained | three doctests passed, zero ignored |
| `tools/cargo-locked.sh check -p sigis-pki-fetch` | automatic `vm2064 slot2` | passed, 19.74s |

Logs: `slots-pdf-check.log`, `slots-pdf-doc.log`,
`pki-fetch-resume-check.log` under the S artifact directory. The scheduling
fix itself earns no functions; the two newly executed PDF rejection guards
satisfy two formerly skipped functions:

| Upstream ID | Rust assertion | Parameters |
| --- | --- | --- |
| `pyhanko/test_internal_utils.py::test_pdfstring_typing` | `generic::pdf_string` compile-failure doctest | integer -1 rejected; legal byte-string positive control |
| `pyhanko/test_internal_utils.py::test_assign_non_name_to_dict` | `generic::pdf_string` dictionary-key compile-failure doctest | integer 10 rejected; legal name-key positive control |

The three Rust doctests represent **two** unique upstream functions. No
oracle/provider early return exists in these assertions. The Rust rejection
occurs at compilation; this is an explicit runtime-model compatibility
adaptation, not a universal trust-verdict claim.

### Current reviewed unique-function accounting

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| sigis-cms | 78 | 73 | 2 | 3 |
| sigis-eutl | 53 | 53 | 0 | 0 |
| sigis-pdf | 406 | 386 | 15 | 5 |
| sigis-pdf-diff | 94 | 92 | 2 | 0 |
| sigis-pki-certvalidator | 133 | 92 | 41 | 0 |
| sigis-pki-core | 4 | 4 | 0 | 0 |
| sigis-pki-fetch | 56 | 38 | 18 | 0 |
| **Total** | **824** | **738** | **78** | **8** |

These remain lane-report counts pending L acceptance. Fetcher check alone
does not prove the lifecycle or credential tests; those counts stay at the
baseline. PKI's first resumed check exposed an error conversion mismatch;
the caller now maps the normalized-name failure through the existing
validation error constructor. A separate policy-test qualifier needed
`Some(Any)`. Both source fixes are present, but their follow-up check,
unit and policy suites have not yet run. Existing formatting processes
are preserved unchanged, and no duplicate recovery build is started.

CMS `signing_parity.rs` is now confirmed at 109 lines, with both new
candidate tests present exactly once. The strict MD5 assertion requires
`HankoError::Signing` and `md5 is not allowed`; any other refusal does not
satisfy the upstream assertion. The overspecified-mechanism positive case
still needs full cryptographic verification, so it remains pending.
A targeted CMS suite is submitted through the updated wrapper; no result
has yet been accepted. The P-owned MD5 policy-order concern will be routed
as an observed failure only after this suite returns.

### Runtime and P-owned skip audit artifacts

`runtime-skip-audit.md` is confirmed written: the 54 occurrences split
into 38 lexical false positives, nine conditional oracle locations across
three tests, six static inherited-gap locations across five IDs, and one
ignored diagnostic. These are source-location counts, not extra functions.
No new runtime oracle execution is inferred from tool availability.

`p-owned-skip-audit.md` is confirmed written as a requirements audit;
all 13 functions retain P ownership and no new pass credit. Fresh pinned
source review corrects three provisional descriptions: multivalued signer
attributes require rejection of duplicate SignerAttributesV2 values with
`Expected single` (both AC-context parameters); delayed signing without
prevalidation and with validation information requires an explicit
missing-certificate refusal; detached eContent is a validator rejection
of `pdf-sig-with-econtent.pdf`, not merely a signer-input guard. Exact
current-P test equivalence and provider exclusions remain to be verified.

Current source increments, formatting/test processes and uncommitted
Cargo.lock are preserved. This is not a ready milestone; L still owns the
merged lockfile, integration gates and acceptance.


## Lead curated follow-up (gate pending)

Accepted main6ec3816 remains S824/754/63/7 and overall1431/1052/66/313.
The historical tables above are not the current acceptance ledger. Only the
independent certificate-position correction below is selected; it adds no
upstream function. Typed CMS/time-slide and archived cross-lane work remain
unaccepted. Main structured algorithm cutoff metadata is preserved.

## Verified independent path-context correction

`algorithm_failure_context` first ran 2 passed / 1 failed on vm2065 slot0:
leaf algorithm denial reported is_ee_cert=false. The producer now derives
that flag from the actual certificate's index and retains its existing
full original path and typed core error. This bounded change needs neither
new shared fields nor a context/core edit and remains compatible with L's
structured-error migration after the producer is reconciled at rebase.
It does not implement timed cutoff propagation and grants no new pass.

Final commands (absolute main wrapper, caller cwd r3-s):

```sh
/home/l/D/kooky/sigis/tools/cargo-locked.sh check -p sigis-pki-certvalidator
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python /home/l/D/kooky/sigis/tools/cargo-locked.sh test -p sigis-pki-certvalidator --test algorithm_failure_context --test validate
/home/l/D/kooky/sigis/tools/cargo-locked.sh clippy -p sigis-pki-certvalidator --lib --test algorithm_failure_context -- -D warnings
/home/l/D/kooky/sigis/tools/cargo-locked.sh fmt -p sigis-pki-certvalidator -- --check
```

Check passed in 0.87s; native tests passed 3/3 plus 20/20 existing path
regressions (compile 1.91s); strict Clippy passed in 5.07s. All compiling
commands selected **vm2065 slot0**. Formatting passed after correcting only
a new-test line wrap. No native tests were ignored or filtered. Logs:
algorithm-failure-context-{red,check,green,clippy,fmt-final}.log.

The four fresh oracle records use the exact same input certificates and
OCSP responses, invoking the actual pinned async_validate_path: successful
control, leaf/intermediate mandatory algorithm rejection, retained original
path and no invented cutoff from the date-like reason, then missing
required OCSP rejection. Native tests build their real path and compare
detailed versus stripped core errors. Full diagnostic wording is not
claimed identical; the meaningful class/context/horizon fields agree.
Reproduce the oracle via the fixed interpreter on
~/.codex/artifacts/sigis/round3/s/algorithm-failure-context-oracle.py.
No recorded verdict was consumed.



## Independent forbidden-only KU repair

L's C-requested `KeyUsageConstraints` repair is verified independently:
forbidden usages are checked before the None/empty positive KU early return.
Five meaningful native regressions were added first (two failed before repair),
then all 27 core tests, four original CMS KU/EKU functions, strict core Clippy
and formatting passed. All compiling invocations used vm2065 slot0. Fresh live
oracle: 26 calls, 20 agreeing controls and six intentional stricter Rust
rejections; pinned Python has the same early-return bug. Default None versus
explicit empty semantics remain intact. This adds zero upstream function credit.
See [the independent ready report](s-key-usage-forbidden.md) for exact mappings,
parameters, commands, exclusions and evidence. No known-red CMS source changes,
L reader/MAC/context/core-schema files, wrapper or lockfile are included.

