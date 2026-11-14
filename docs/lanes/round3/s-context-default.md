# S: accepted implicitly provisioned context backend

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

See [the cohort acceptance](l-styled-context-containment.md) for the separate
C/V results and Root-owned ledger transaction. The two public signatures and
original scoped authorization remain in the preserved historical brief below.

## Historical original assignment and pre-acceptance scope

The complete earlier assignment follows with its original bytes. Its proposal,
counts and no-acceptance notices describe the original pre-acceptance state.

# S: implicitly provisioned context backend

Accepted baseline ab08d1c6: S824/813/11/0, fetch56/51/5/0. The Disabled original
is accepted separately and is not counted again. This packet proposes one ID:
pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_provisions_and_owns_a_backend.
The explicit fetching-enabled construction must own a real default HTTP backend,
retain the returned context through real operations and support repeated close.

## Scoped L authorization

S exclusively edits CV context.rs and its context_tests.rs for an additive
backend-agnostic builder primitive, and pades ades/policy.rs for the actual L2
fetching-enabled constructor; new S root integration tests/fixtures are allowed.
V owns with_time.rs separately. Root retains shared API acceptance. No other
production paths, dependency/layer edges, manifests or lockfile may change.

Approved public signatures:

```rust
ValidationContextBuilder::build_with_backend_fallback<F>(self, fallback: F)
    -> Result<ValidationContext, ValidationError>
where F: FnOnce() -> Arc<dyn FetcherBackend>;

policy::bootstrap_validation_context(builder: ValidationContextBuilder)
    -> Result<ValidationContext, ValidationError>;
```

The L2 adapter uses actual HttpFetchers and returns a context consumed by real
Basic/CMS/path/revocation validation. Ordinary build stays disabled. Call the
default only when both private choices are unset, after all existing fallible
policy/DER validation; get_fetchers once. Explicit fetchers, including none,
suppress default/factory while explicit adopted ownership remains authoritative.
Preserve borrowed/adopted handle identity, precedence and every builder capability
without public-context reconstruction or duplicated validation. No new static or
thread bound, global factory, automatic Drop cleanup or source/POE framework.

Test the full selection matrix, invalid-policy/DER pre-allocation refusal, real
HTTP/cache/close/reconnect and all caller policies, plus mandatory missing/forged
evidence and wrong-root denial. Existing type-phase and Disabled-only mappings
do not normalize Supplied(empty) or establish other ownership flows. Four other
lifecycle IDs remain gaps: no_backend_when_fetchers_are_unreachable,
unreachable_fetchers_still_adopt_an_owned_backend,
policy_hands_ownership_to_the_context, policy_without_handlers_hands_over_nothing.

Artifacts: round3/s/context-default/. No new context-default pass is accepted.

## Execution and reporting

Use tools/cargo-locked.sh for every Cargo call, one at a time per lane. It
injects canonical rust-target-env and delegates placement/concurrency to system
rust-slots; automatic VM dispatch is allowed. Preserve sccache, targets, flags,
profiles and features. Do not introduce a repository lock, local pin or job cap.
Keep proof snapshots lean; compressed ELF archives require distinct raw/archive
SHA256 and length checks. Do not clean shared targets or old evidence.

Port complete exact upstream assertions before implementation. Use the pinned
pyHanko0.38.1/CV0.33.0 oracle at /tmp/pyhanko-oracle/venv, assertions enabled.
Fresh original bodies, same-output comparisons, replay and native executions
remain distinct. Trust decisions fail closed; mandatory unsupported conditions
refuse. Report exact IDs and parameters, source/ELF/runtime/input receipts,
per-crate total/passed/skipped/pending and divergences. Root owns acceptance
counts and full build/test/clippy -D warnings/strict doc/layer/fmt gates.

English local commits only; no push, pkill, service restarts, target cleanup or
interference with other sessions. Preserve frozen branches, proof artifacts and
dirty lockfiles. Save progress and handoffs under the assigned artifact path.
