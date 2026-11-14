# Lead acceptance update: owned context default

Accepted source: `9d921382ea837819b2ad5dda2b9546adc83dba03`.
Exactly one S original changes from skipped to passed:
`pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_provisions_and_owns_a_backend`,
mapped to `round3_context_default_backend::test_context_provisions_and_owns_a_backend`.
The previously accepted bootstrap4 and Disabled original remain counted once;
private matrices, native companion tests, probes and comparison calls add no IDs.

Counts after the completed cohort acceptance transaction:
S **824 total /814 passed /10 skipped /0 pending**;
fetch **56 total /52 passed /4 skipped /0 pending**;
library **1168 total /1156 passed /11 skipped /1 pending**;
overall **1431 total /1363 passed /11 skipped /57 pending**.
The single library pending item belongs to V's separately reviewed disposition;
this S packet does not claim zero library pending or own other cohort deltas.

All six actual Root source9d gates returned0 with audit0:
build7.14s, test1354.13s, clippy25.5s, strict doc212.45s, layer4.74s and fmt3.38s.
Measured full Rust: **2147 discovered /2143 passed /4 ignored /0 failed /219 reports**.
The independent [final source/runtime/gate review](/home/l/.codex/artifacts/sigis/round3-launch/styled-context-integration/final-review/review.json)
has SHA256 `0fe33202d9be8c59a0b1b77b6e5c429190b4516cbdf7e22d47ee45612705230e`.
These are completed source-specific measurements preceding the acceptance
transaction, not execution by this documentation draft or old-owner replay.

The accepted two-production-path increment is generic
`ValidationContextBuilder::build_with_backend_fallback<F>` in CV context.rs,
with only `F: FnOnce() -> Arc<dyn FetcherBackend>`, plus L2
`policy::bootstrap_validation_context` in pades policy.rs using concrete real
`HttpFetchers::default()`. Root imported exact minimal owner postimages.
Both entries share the existing builder validation and field-moving body;
policy/DER errors precede any default allocation, and the chosen backend issues
components once. Ordinary build remains disabled when no selection is supplied.
Explicit components, including empty components, suppress fallback; explicit
borrowed/adopted backend and retrieval/close authority retain existing precedence
and exact identity. No new thread/static bound, public owner getter, Drop close,
dependency/manifest/layer edge or manager/source/POE ownership framework appears.

The actual returned context reaches existing Basic/CMS/path/revocation consumers.
Caller timing/best-time/tolerance, trust anchors/qualifiers/manager, PKIX,
algorithms, freshness judge, assertions, targeted AC restrictions and all five
MAIN usage fields remain effective with real positive and typed negative
controls. Actual HTTP missing404/malformed200/forged CRL/OCSP, corrupted CMS and
rootless-anchor controls refuse trust. Repeated close retains owner, caches and
budget: initial requests3, cached after close3, new URL4, connections2,
timeouts0 and close calls4. A genuine outer Malformed error leaves the caller's
context available. Native leaf/CRL/nonce-matched OCSP evidence is freshly signed;
intermediate root CRL/local evidence remains signed fixture replay. This does
not establish a new AC/TSA HTTP profile or source/POE handoff.

Tests preceded implementation. Root's actual c338 API checks report four missing
builder-method E0599 diagnostics and one missing L2-import E0432; this is API
absence, not behavioral RED. First f561 CV72/root8 and the fresh unchanged
pinned original1 plus separate real-default/two-close probe are historical
f561 executions. Current9d Root focus8 and full-run Root8 are separate actual
executions with distinct retained ELFs. The current full CV lib summary is
72PASS/0FAIL/0IGNORE, derived from its own `sigis_pki_certvalidator_lib` capture
and full-test block, not inferred from the earlier focused72 or a global Root
scope. No separate CV counter changes for this fetch-owned original.

Current9d focus and full each select all8 native profiles. Each peer run makes
16 context-construction attempts, **14 actual validation API calls** and14
matching comparable flag/bottom-line results over exact low-level MAIN and
ordinary normalizing CMS. The other two attempts encounter Malformed OCSP
ValueErrors during Python context construction before API entry; native refuses
those HTTP bytes during validation. These are refusal phase gaps, not16API
calls or16matching flag results. There are no case/policy exclusions or peer
network attempts. Python consumes local candidate evidence and does not repeat
native real HTTP. No universal parity, fail-closed or complete-port claim follows.

The [current focus review](/home/l/.codex/artifacts/sigis/round3-launch/styled-context-integration/s-focus-review/review.json)
SHA256 is `70508a78ca3e94ba8ca3684730f26fd7b5a819603c97d01a090008b5e0b6d6d5`.
It verifies17/17 actual wire records. The separate optional
[full S sidecar](/home/l/.codex/artifacts/sigis/round3-launch/styled-context-integration/s-full-review/review.json)
SHA256 is `913a4fb01ba6d4deee3247bf1160b0bd97ae4915e7e802f883251a4a2907c9ac`.
It verifies **16 complete HTTP records among17 actual markers**. One full-log
issuer/first transport JSON line is split by a concurrent test-result line;
its exact raw line1151 and next raw continuation remain preserved. The explicit
projection is only complete original lines, byte-for-byte and in order:1 ELF,
all8 cases and16 HTTP records. No broken record is joined/reconstructed and no
case/material/policy is filtered. Focus17/17 never fills the missing full wire
record. The first full peer parse failure before API entry remains separate
from the successful unchanged-oracle retry with proper stream/process receipts.
This optional limitation does not turn completed core gates into failures.

Every retained gzip has separate archive/raw length and SHA256;58 full native
captures were independently checked. Current focus ELF SHA256 is
`0b27f3845121fe715474558c96c6ade435aaa225f6ae6ba53ae46f8d9f8e51f0`
(88754584 bytes), archive SHA256
`b654fccc8216f83281a057a079c60692f822c3ac12f85df50aca0238c0e1931c`.
Full S ELF SHA256 is
`2d9145bf712abb260eb47f797d6d6a717edf9c6c19c5971ac608e5070da02e70`
(88764976 bytes), archive SHA256
`996bd9ea307dd6d31b093bcb432fcdcb7c6791bca5da3619cb0b341bce7abdd2`.
Post-run snapshots remain labelled post-run; different native ports/certificates
and diagnostic strings retain their original bytes rather than normalization
or relabelling. The original full test-log SHA256 is
`6b5244cb09107bfddc73afe0bec02c468516a1b5e796c916db35c5368a99a06d`.

Four fetch lifecycle originals remain skipped:

- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_no_backend_when_fetchers_are_unreachable`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_unreachable_fetchers_still_adopt_an_owned_backend`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_policy_hands_ownership_to_the_context`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_policy_without_handlers_hands_over_nothing`

The registry-reachability pair remains deferred. The policy-ownership pair has
a separate [approved two-source request](/home/l/.codex/artifacts/sigis/round3-launch/s-policy-owner-two-source-request.md)
for future source work, with no production implementation or accepted pass here.
This accepted packet does not add policy-owner/source/POE machinery or erase
those four remaining gaps. Supplied(empty) remains distinct from Disabled.

Cohort integration and the separate C/V dispositions are recorded in
[the styled-context containment acceptance](../../docs/lanes/round3/l-styled-context-containment.md).

## Historical preceding acceptance snapshots

The complete previous document follows with its original bytes. Its earlier
counts, skip lists, in-progress notices and acceptance boundaries are historical.

# Lead acceptance update

Accepted source: `14d6c6a3340714e14fe1d1798e047227b0442dc5`.
The complete current-source Root gate and independent final review precede
this one-original acceptance; prior accepted functions remain counted once.

Accepted counts following the completed new cohort gate:
S **824 total /813 passed /11 skipped /0 pending**;
fetch **56 total /51 passed /5 skipped /0 pending**;
library **1168 total /1156 passed /12 skipped /0 pending**;
overall **1431 total /1360 passed /12 skipped /59 pending**.
The overall cohort includes the separately reviewed C packet; this S delta
accounts for exactly one skipped-to-passed original, not all cohort additions.

Full source-specific gate: **All six returned0 with audit0 (build 3.2s; test 1113.47s; clippy 9.75s; doc 64.23s; layer 3.7s; fmt 3.57s)**.
Measured full Rust discovered/passed/ignored/failed/report counts:
**2118 discovered /2115 passed /3 ignored /0 failed /215 reports**.
Final independent source/runtime review path and SHA256:
**/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/final-review/review.json SHA256 25fa11d1ab703d58c5c0ca450b9afbd35a35cb6a8fac55f15ea67178e9d0ea58**.
These actual source14d measurements and final proof precede acceptance.
Previous134 gate totals and focused counts remain separate historical evidence.

Only `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_without_fetching_owns_nothing`
gains one new accepted function in this S packet. It maps to
`round3_handler_bootstrap::test_bootstrap_without_fetching_owns_nothing`.
The preceding four bootstrap originals are already accepted. The old13 root
wrappers and three inline public-policy controls remain regressions and add
zero new IDs; a separate Python probe and reference calls add none.

The existing accepted S implementation already provides Disabled behavior.
Root's first focused execution on f6447f5e was GREEN; current14d focus is
1PASS/0FAIL/13filtered. No production behavioral RED, implementation repair or
new S production is claimed. policy.rs remains cfcd2f45. Current source14d,
not an older run relabelled by identical ELF bytes, binds the focused evidence.

The approved mapping is Disabled only: actual absent CRL/OCSP components and
fetching_allowedFalse correspond to Python fetchers=None and its actual
manager predicate; ownerNone and harmless explicit close remain. No fake
manager/accessor is added. Supplied(empty) Python presenceTrue versus native
availabilityFalse is a separate boundary and is not mapped or credited.

Actual native controls show cold Disabled0HTTP/0connections, a same-CMS/context
reachable legacy positive with1request, and Disabled still refusing the warm
cache with requests staying1. Require-mode controls retain typed missing-
revinfo refusal with old component calls0 and trusted sufficient signed local
evidence without retrieval. Caller root, clock, digest, component identity and
policy requirements remain. This is not outer cleanup, context-owner adoption,
registry/revinfo/POE state sharing or a new trust-domain handoff.

Current Root freshly runs one unchanged pinned original and a separate None
identity/no-factory/no-close probe. Three actual native require-mode profiles
receive six fresh offline peer calls, all matching, with zero exceptions,
exclusions or network. Exact low-level MAIN and ordinary CMS remain separate
surfaces. The loopback/cache leaf is native HTTP proof, not one of these three
Python profiles. CRL/OCSP bodies remain signed fixture replay. These scoped
agreements establish no universal fail-closed/parity or complete-port claim.

Current focus verifies compressed-archive and decompressed-ELF identities
separately. Root reports same-byte exit0/about0.80s; complete JSON/stdout are
retained, but expected negative InsufficientRevinfo stderr and a separate
same-byte process receipt were not retained. No missing stderr or receipt is
fabricated. Focus evidence and later full-gate evidence retain their distinct
source/process/capture identities.

Five lifecycle originals remain skipped after this one-ID acceptance:

- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_provisions_and_owns_a_backend`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_no_backend_when_fetchers_are_unreachable`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_unreachable_fetchers_still_adopt_an_owned_backend`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_policy_hands_ownership_to_the_context`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_policy_without_handlers_hands_over_nothing`

This current acceptance adds no implementation for the five remaining gaps.
A separate L-approved implicit-default-context packet is in progress under `/home/l/.codex/artifacts/sigis/round3-launch/s-implicit-context-default-approval.md`, with no pass or production acceptance yet. Its sole original is test_context_provisions_and_owns_a_backend. Exclusive production scope is CV context.rs plus pades policy.rs: add generic ValidationContextBuilder::build_with_backend_fallback<F> where F:FnOnce()->Arc<dyn FetcherBackend>, and L2 policy::bootstrap_validation_context using actual HttpFetchers and a real Basic consumer. Ordinary build remains disabled; explicit fetchers including empty suppress fallback, and validated construction/owner precedence remain. No new dependency/manifest/layer edge or source/POE framework is approved. The other four lifecycle gaps remain unapproved; this future packet earns no current credit.
Earlier accepted counts, skip lists and boundaries below retain their
historical meaning and original bytes.

Evidence: `s-focus-review/review.json`, `checker.py`, `actual-receipt.json`
and `review.md` under
`/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/`.
Current focus result SHA256:
`fd86ea047c4dd56aed75609ab7a21fa7f514fcdca5acba7ab1d35cff74bf4c11`.
Separately completed source14d full-run S evidence has14native tests,29actual exported profiles and58new same-byte reference calls; exact MAIN agrees28/29, ordinary CMS agrees26/29. Actual reference subprocess exit0 in1.439418s retains stdout/stderr and before/after log/driver hashes. Its one exact stricter refusal and bidirectional ordinary normalization differences remain bounded. This separate complete-run proof does not reconstruct missing focus stderr/process receipts. Review `/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/s-full-review/review.json`, SHA256 `e1bd64ca24def3ab67140bb9e1e2fba5cd18b65bedd71e9ed5d3fa68245de83f`.


## Historical preceding lead acceptance

# Lead acceptance update

Accepted source134be605: **56 total /50 passed /6 skipped /0 pending**.
Exactly four direct-bootstrap lifecycle originals complete; prior46 functions
retain their status once. All six source-specific workspace gates returned zero with audit0; final independent current-source review is complete. Measured full Rust: **2111 discovered /2108 passed /3 ignored /0 failed /214 reports**. Final review: `/home/l/.codex/artifacts/sigis/round3-launch/appearance-bootstrap-integration/final-gate-review.json`, SHA256 `0738956ffae1c16e2d89ea6f195d174fb16da7324c29860dcdde17e3182b2faa`.

- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_owns_the_default_backend` -> `round3_handler_bootstrap::test_bootstrap_owns_the_default_backend`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_owns_the_default_backend_explicitly` -> `round3_handler_bootstrap::test_bootstrap_owns_the_default_backend_explicitly`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_leaves_a_supplied_backend_alone` -> `round3_handler_bootstrap::test_bootstrap_leaves_a_supplied_backend_alone`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_leaves_supplied_fetchers_alone` -> `round3_handler_bootstrap::test_bootstrap_leaves_supplied_fetchers_alone`

Actual source134 focus13+33, four genuine unchanged originals, four separate
probes,26nativeprofiles/52same-byte calls and real HTTP/cache/close controls
precede acceptance. Exact25agree1stricter and ordinary23agree3differences remain
separate; ordinary differences are bidirectional, no universal fail-closed claim.
Existing public owner fields/helper shared views remain; supplied empty has no
fallback, borrowed close0, default backend is real. This is direct handler
ownership and main retrieval, not context/source/POE ownership or outer cleanup.

Six lifecycle gaps remain skipped in this cohort:
- `test_context_provisions_and_owns_a_backend`
- `test_no_backend_when_fetchers_are_unreachable`
- `test_unreachable_fetchers_still_adopt_an_owned_backend`
- `test_bootstrap_without_fetching_owns_nothing`
- `test_policy_hands_ownership_to_the_context`
- `test_policy_without_handlers_hands_over_nothing`

Disabled fifth remains supplemental zero-ID proof pending its own separately
approved semantic mapping. Reachability2/policy2/implicit-context1 remain gaps.
See docs/lanes/round3/l-appearance-bootstrap.md. Earlier count tables below
are historical and retain their original bytes.

## Historical preceding lead acceptance

# Lead acceptance update

Accepted source21323f9c: **56 total /46 passed /10 skipped /0 pending**.
Exactly two backend-context lifecycle originals complete: supplied backend
close0/private owner-None and adopted backend close1/exact private Arc identity.
Actual explicit close remains distinct from Drop; repeated typed errors,
clones/security fields, explicit-fetchers precedence, factory-after-validation,
managed versus caller transport and cache/budget boundaries are tested. Fresh
unchanged pinned originals and current source-specific gate precede acceptance.
No implicit HTTP default, weaker context or universal lifecycle/timeout/profile
claim is introduced. The prior44 functions retain their counts. The ten other
lifecycle originals remain skipped; tables and exclusions below describe their
original historical snapshots. See docs/lanes/round3/l-detached-backend-context.md.

## Historical preceding lead acceptance

# Lead acceptance update

Accepted source7232e9c: **56 total /44 passed /12 skipped /0 pending**.
One deprecated supplied-session forwarding original is accepted, with standard
Rust compile-time deprecation as an explicit phase adaptation. Actual constructor
deny guard, modern positive controls, caller identity/request errors and fresh
same-endpoint/original Python controls pass the complete source-specific gate.
Transport deadline/body configuration, optional async compatibility and backend
lifecycle exclusions remain. Earlier counts/skip lists below are historical.
See docs/lanes/round3/l-alias-coverage.md and acceptance.json.

# Porting status: sigis-pki-fetch (crates/pki-fetch)

Owner: lane A. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `fetchers/api.py` (`FetchLimits`, interfaces) | `src/budget.rs`, `hanko-core::fetch` | Ported; `FetchLimits` also carries the transport limits (timeout, response size) |
| `fetchers/common_utils.py` | `src/common.rs`, `src/budget.rs` | Ported: content-type sets, `unpack_cert_content` (DER, PKCS#7, PEM), `enumerate_delivery_point_urls`, `gather_aia_issuer_urls` (certificates and ACs), `format_ocsp_request` (SHA-1/SHA-256 CertID, nonce), `process_ocsp_response_data`, `FetchBudget`, `cap_aia_urls`. The asyncio job helpers become sequential loops with the same semantics (first OCSP success wins, CRL fetch fails only if every URL failed, failing issuer URLs are skipped) |
| `util.py` (`get_ocsp_urls`, `get_relevant_crl_dps`) | `src/common.rs` | Ported |
| `fetchers/requests_fetchers/`, `fetchers/aiohttp_fetchers/` | `src/fetchers.rs` | Ported as one backend (`HttpFetchers`): per-URL / per-certificate caches including failures, shared budget, `Accept` / `User-Agent` headers, status 200 required |
| HTTP sessions (`requests`, `aiohttp`) | `src/transport.rs` | Replaced by `reqwest` (blocking, rustls) behind `HttpTransport`; per-request timeout and response size limit |
| `sign/timestamps/api.py`, `common_utils.py` | `src/tsa.rs` | Ported: `request_cms`, `get_nonce`, `handle_tsp_response`. The dummy-response cache and `validation_paths` (signing-side size estimation) are lane D |
| `sign/timestamps/requests_client.py`, `aiohttp_client.py` | `src/tsa.rs` (`HttpTimeStamper`) | Ported: headers, basic auth, HTTPS check, content-type check, nonce check |
| `sign/timestamps/dummy_client.py` | — | Lane D (test TSA) |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_common_utils.py` | `tests/test_common_utils.rs` | 15 | 15 | 0 | 0 |
| `test_fetch_limits.py` | `tests/test_fetch_limits.rs` | 11 | 11 | 0 | 0 |
| `test_fetcher_lifecycle.py` | `tests/test_fetcher_lifecycle.rs` | 16 | 4 | 12 | 0 |
| `test_tsa_fetcher.py` | `tests/test_tsa_fetcher.rs`, `src/tsa.rs` compile-fail doctest | 10 | 9 | 1 | 0 |
| `test_tsa_fetcher_requests.py` | `tests/test_tsa_fetcher_requests.rs` | 4 | 4 | 0 | 0 |
| **Total** | | **56** | **43** | **13** | **0** |

Notes:

- Upstream runs the network tests once per backend (aiohttp, requests);
  here there is one backend, so each runs once against a transport that
  fails and counts requests. Logging assertions (warning once, then debug)
  are ported as state checks (`FetchBudget::exhaustion_reported`); the port
  does not log.
- The round-3 lifecycle audit is below. Rust `Drop` covers some resource
  ownership assertions, but it does not supply the missing context/bootstrap
  ownership-transfer protocol. These are feature gaps, not harmless language
  differences.
- `test_tsa_fetcher.py` retains one skip:
  `test_deprecated_aiohttp_timestamper_forwards` (a deprecated Python alias).
  `test_auth_coercion_rejects_nonsense` now passes through the compile-fail
  doctest: a non-credential object fails Rust's string parameter type check.
- Tests avoid external network access: a local server on 127.0.0.1 plays the TSA,
  serving a response of pyHanko's test TSA for a fixed request
  (`oracle/gen_tsa_fixtures.py`); "unreachable host" is a closed local
  port. The PDF-signing halves of the TSA tests are lane D; their
  validation halves are replayed from recorded pyHanko calls.
- `tests/fetchers.rs` adds success-path tests (certificate, CRL, caching,
  content type, HTTP status, size limit) that upstream lacks.

## Round 3 lifecycle and inherited-skip audit

`tests/test_fetcher_lifecycle.rs` ports four upstream function assertions
before the corresponding lazy-session implementation. `LazyTransport` now
defers HTTP session creation, releases its idle session through `close`, and
creates another session for a later request. Requests in flight retain their
session until completion; this native resource lifetime differs from closing
an aiohttp session while a request is running. The upstream tests exercise
idle sessions only.

The verified round-3 count is **56 total / 43 passed / 13 skipped / 0 pending**.
The five newly established passes are the four same-named lifecycle tests
below and the `HttpTimeStamper::with_basic_auth` compile-fail doctest for
`test_auth_coercion_rejects_nonsense`. Each upstream function counts once.
The 13 retained skips remain explicit assertion or API gaps below.

The repository-wrapper check completed on vm2064 slot2 in 19.74 seconds.
The full package test log records vm2065 slot0 and all eight successful
suite summaries: 0 library unit tests, 4 supplemental fetcher tests,
15 common-utils tests, 11 limit tests, 4 lifecycle tests, 8 TSA tests,
4 requests-TSA tests and 1 compile-fail doctest. This is **47 Rust tests**,
with zero failed, ignored or filtered tests. Four supplemental fetcher
tests earn no upstream-function credit, leaving **43 unique functions**.
The full-test command followed a successful package formatting command.
After a tool-host reset the original outer process exit code is unavailable;
all final Cargo suite summaries are complete and successful, and the
original command processes have exited. Tests were not rerun to recover
that outer status.

Reproducible commands and complete logs are recorded in
`~/.codex/artifacts/sigis/round3/s/pki-fetch-handoff.md`,
`pki-fetch-resume-check.log`, `pki-fetch-resume-test.log` and
`pki-fetch-resume-test-summary.json`. No recording, oracle call or Rust
wrapper count earns an additional upstream-function pass.

The first 16 IDs below have prefix
`pyhanko-certvalidator/test_fetcher_lifecycle.py::`. The last two have prefix
`pyhanko/test_tsa_fetcher.py::`.

| Function | Exact Rust assertion or remaining feature gap |
| --- | --- |
| `test_context_provisions_and_owns_a_backend` | Gap: no context option provisions a default HTTP backend or closes it between operations. |
| `test_context_leaves_a_supplied_backend_alone` | Gap: contexts accept `Fetchers`, not a borrowed backend object; no separate backend ownership branch exists. |
| `test_context_leaves_supplied_fetchers_alone` | Same-named Rust test: drop the context, assert external fetcher transport has not dropped, then drop the caller's final handle and assert exactly one drop. |
| `test_context_adopts_an_owned_backend` | Gap: no owned-backend marker or context close protocol. |
| `test_no_backend_without_fetching` | Same-named Rust test: the default context has no OCSP, CRL or certificate fetcher and its fetcher set is empty. |
| `test_no_backend_when_fetchers_are_unreachable` | Gap: no injected revinfo-manager/registry bootstrap branch whose unused backend creation can be tested. |
| `test_unreachable_fetchers_still_adopt_an_owned_backend` | Gap: no explicit adopted backend independent of reachable fetchers. |
| `test_bootstrap_owns_the_default_backend` | Gap: no validation-data-handler bootstrap API provisions an owned default backend. |
| `test_bootstrap_owns_the_default_backend_explicitly` | Gap: no explicit default-backend sentinel or handler bootstrap ownership field. |
| `test_bootstrap_without_fetching_owns_nothing` | Gap: no handler bootstrap API or handler fetching-allowed state. |
| `test_bootstrap_leaves_a_supplied_backend_alone` | Gap: no borrowed-backend handler bootstrap branch. |
| `test_bootstrap_leaves_supplied_fetchers_alone` | Gap: no supplied-fetcher handler bootstrap branch. |
| `test_policy_hands_ownership_to_the_context` | Gap: no policy-to-context handler ownership transfer. |
| `test_policy_without_handlers_hands_over_nothing` | Gap: no policy builder accepting optional validation-data handlers. |
| `test_lazy_session_is_reusable_after_closing` | Same-named Rust test: defer factory, reuse the first session, close/drop it exactly once, create a distinct second session, close it, and allow repeated close. |
| `test_lazy_session_close_without_a_session` | Same-named Rust test: close succeeds without calling the transport factory. |
| `test_deprecated_aiohttp_timestamper_forwards` | Gap: no deprecated constructor alias/session forwarding API; existing request-error coverage does not establish alias/deprecation behaviour. |
| `test_auth_coercion_rejects_nonsense` | `HttpTimeStamper::with_basic_auth` compile-fail doctest rejects a non-string object with a Rust type error. This replaces Python's runtime `TypeError`; the error text is intentionally different. |

The upstream lifecycle functions are not parametrized. The lazy-session
tests explicitly cover repeated close and reuse; ownership tests observe
actual destructor counts. No provider/tool availability branch skips these
new assertions. Existing fetch tests have no runtime provider exclusions;
their CMS validation halves use committed fixture replay, not fresh oracle
generation. The prior live reference audit executed 18 unique upstream
functions (16 lifecycle and two TSA assertions), with no parameter skips.
That historical reference execution is separate from this resumed Rust
test run and earns no additional passes or trust-verdict comparisons.

The central runtime audit also uses a separate denominator: 54 lexical
candidate occurrences, comprising 38 false positives, nine conditional
oracle occurrences in three supplemental tests, six static inherited-gap
occurrences covering five assigned functions, and one ignored diagnostic
survey. None is a runtime provider exclusion in this crate. An exclusion
branch's presence does not establish that a test actually took it.


## Lead AC retrieval acceptance

Source 7500fc7 passes all six workspace gates: 1578 discovered,
1570 passed, 8 ignored, zero failed, 142 reports.
The two earlier gate failures remain recorded: stale V AC replay/cache controls
and a real CSC batching race. Neither was hidden by a skip or weaker assertion.
Current counts: V47/47/0/0, L11/6/0/5; overall1431/1131/30/270.

AC retrieval now shares production transport limits, caches and actual-AA
request identity with PKC retrieval, and routes actual AC DER to its methods.
Strict metadata envelope checks reject nonminimal headers before I/O. Serial
INTEGER contents remain capped at20 encoded bytes; arbitrary-length serials
are not supported. The response matcher uses the signed AC issuer Name DER
and actual AA key hash. Eight genuinely signed Name variants agree with the
pinned public validator, including three positive controls. A proposed matcher
first accepted an oracle rejection; that candidate was corrected before merge.
Fetched/cached CRLs still require the accepted03 signature guard. Required and
hard-fail policies reject forged signatures; explicit soft-fail can tolerate a
separate unavailable provider as the pinned policy does. It is not evidence
that a forged CRL is authenticated or that all modes reject every bad response.

V's complete remaining two original functions pass after its recorded AC
adapter gains actual AC request binding. The adapter uses production fetchers
over frozen responses with full CertID selection; it is not new live HTTP.
The signature-mutation control creates a new fetcher from changed records,
so an earlier cached genuine response cannot mask the intended negative input.
S's real loopback HTTP composition and its repeated-cache rejection controls
are separate evidence. No helper, recording, parameter or oracle call earns
an extra immutable function.

The context non_revoked_status_assertions getter returns an immutable borrowed
view of existing caller state. Six tests and two compile-fail doctests retain
order/hash/time/clone/security requirements and actual strict revocation
matching. Successful optional validation does not invent an assertion. The
accessor changes no default, policy, field or trust verdict and earns no ID.

L completes strict live issuer fetching and both full-chain/leaf-only base
cases. Their three new PDFs receive real native LTA, exact LtaUpdates and fresh
same-output Python LTA; empty roots reject. Leaf-only signing requests the
exact downloaded leaf through a forwarding real certificate fetcher before
validation, rather than relying only on a shared TSA issuer-URL count. The
two exact upstream functions independently pass all three original executions.
CSC automatic batches now stop admitting jobs when full and bind commit to
their original batch; retained-result/public-commit semantics remain tested.
The existing three batch/authorization-count parameters remain unchanged.

All divergences cannot be labelled fail-closed. Bounded serial/metadata refusals
are stricter, but explicit optional-revocation policy, report/time metadata and
other declared semantic/encoding gaps are not universal trust proofs. A separate
combined ECC/RSA test context has a retained native/Python validation discrepancy
under colliding synthetic issuer/serial identities. Using role-specific contexts
for the exact upstream test does not repair that registry/path-selection gap.
It remains under independent diagnosis, rather than being relabelled fail-closed.
Unmerged CLI code remains outside acceptance; three configuration loader functions still
need their exact CMS intact/valid assertions despite a raw-signature control.
Detailed red/green logs, oracle outputs, public byte hashes and independent
reviews are retained under round3-launch/s-ac-combined and round3/l-certomancer-next.
