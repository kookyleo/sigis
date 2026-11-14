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
