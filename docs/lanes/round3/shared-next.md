# Next shared interfaces: bounded temporary ownership

Lead decision:2026-11-14. Accepted main25768a56/source73d remains
1431/1342passed/20skipped/69pending. This brief assigns implementation work;
it does not accept new tests, change defaults or promote counts. Immutable
ownership.json remains unchanged. L retains integration, shared lockfile,
all final gates, metadata and main merges. No lane may merge into main.

Use isolated current-main projections rather than replaying unaccepted owner
history. Preserve all existing branches, work and dirty Cargo.lock. Every
Cargo invocation uses tools/cargo-locked.sh with system placement/concurrency,
canonical rust-target-env and preserved sccache. One lane process runs Cargo;
no repository lock, local pin, job cap, manual remote Cargo, target override,
cache cleanup or speed flag/profile/feature change. English code/docs/commits,
local commits only; no push, service restart, pkill or session interference.
Save source snapshots, logs and handoffs to the lane artifacts throughout.

## S: borrowed and adopted fetcher backends

Temporary exclusive implementation paths:

- crates/pki-core/src/fetch.rs: the backend trait only.
- crates/pki-certvalidator/src/context.rs and context_tests.rs: selection,
  explicit close and directly embedded private ownership/clone controls.
- crates/pki-fetch/src/fetchers.rs and tests/backend_context_lifecycle.rs.
- A new crates/pki-fetch/oracle/backend_context_lifecycle.py if needed;
  existing S report/audit paths remain owned.

Approve the proposed core FetcherBackend: Send+Sync+Debug with
get_fetchers(&self)->Fetchers and close(&self)->Result<(),FetchError>. Approve
ValidationContextBuilder::{fetcher_backend,owned_fetcher_backend}(Arc<dyn
FetcherBackend>) and ValidationContext::close(&self)->Result<(),FetchError>.
No public inspection getter, transport API, production dependency, module
restructure or manifest/lock/layer change is authorized.

Only these exact originals are assigned for this increment:

- pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_leaves_a_supplied_backend_alone
- pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_adopts_an_owned_backend

Port their complete0/1 close counts and private None/exact-Arc ownership
assertions first. Tests precede implementation; a missing-API compiler result
is evidence of an unavailable API, never a behavioral RED or passing port.
Do not introduce a no-op product API to manufacture a later failure.
The other ten fetcher originals remain separate and unaccepted.

Required selection and lifecycle contract:

- Distinguish an unset builder fetcher choice from explicit Fetchers::none,
  for example with private Option<Fetchers>. Explicit fetchers always wins
  retrieval regardless of setter order, including explicit none.
- The last backend setter selects one backend and its borrowed/adopted mode.
  An adopted backend is retained for close even when explicit fetchers wins.
  Resolve factory retrieval only after builder validation succeeds, at most
  once per build; no implicit default HTTP backend provisioning.
- Borrowed backend receives no context close call. Adopted owner is the exact
  supplied Arc even while caller references survive. Each explicit close
  delegates and propagates its error; do not take/clear ownership, close once
  behind the caller's back or add implicit Drop-based close.
- Context clone, with_timing and with_fetchers preserve all unstated fields,
  including the exact owner Arc and all trust/freshness/assertion/AC settings.
- HttpFetchers::new/default privately retain their managed LazyTransport;
  with_transport never adopts caller transport, even if it is a LazyTransport.
  Close only the managed pool. Preserve existing settings, issued-set caches
  and request budget across close/reuse.
- Backend get_fetchers is a factory: new component caches and a new shared
  budget for each returned set, sharing the configured transport. Existing
  as_fetchers remains the same shared view. Preserve typed transport failures;
  no failure may become empty fetchers or a weaker validation requirement.

Actual supplementary controls must cover setter order, explicit none, clones,
close errors/repeated calls, caller-managed transport, real lazy-session
close/recreation, factory independence and issued-set budget/cache retention.
No extra unique-function credit for these controls. Fresh pinnedCV0.33.0 oracle
runs must execute both unchanged originals and separately report identity/0/1
outcomes, source hashes and zero network/provider exclusions. Do not confuse
Rust Arc memory lifetime with close authority.

## V: exact main-signer CMS predicate

Temporary exclusive implementation paths:

- crates/cms/src/validate.rs: one options field, one early ambiguity check,
  one shared main-signer predicate selection inside the existing operation.
- tests/round3_cms_exact_main_predicate.rs and
  tests/round3_cms_exact_operation_guards.rs.
- Minimal committed fixture data/manifest under
  crates/testdata/data/lanes/r3-v/cms-exact-main/; existing V proposal/report
  paths remain owned. No active old AdES profile test/default import.

Approve CmsValidationOptions.exact_key_usage_settings:
Option<sigis_pki_core::key_usage::KeyUsageConstraints>. None preserves the
existing ordinary facade contract; Some preserves every native predicate
field and intentional empty value without normalization, for the main signer
only. When both legacy and exact options are Some, even equal or empty, return
CmsError::Malformed with component text:

```text
key_usage_settings and exact_key_usage_settings are mutually exclusive
```

Reject at the direct CMS entry before content digest/operation work. Preserve
fixed TSA purpose, both validation orders, every private registration/role and
context identity rule, algorithm cutoffs, revocation/freshness/assertions/AC
requirements. No rebuilt context, fallback/second weaker validation, public
certificate preload, manufactured POE, status waiver, automatic CLI opt-in or
ordinary/AdES default change. Other source/literal migrations require a concrete
request to L; current reviewed repository literals use outer update syntax.
Disclose the source compatibility impact on external exhaustive struct literals.

Install the12+2 drafted substantive tests before implementation and preserve
the actual missing-field compiler baseline. Before claiming runtime results:

- Supply the actual source-bound manifest/necessary certificate or CMS bytes;
  do not treat a missing fixture panic as behavioral evidence or silently
  substitute the unexecuted f822 projection.
- Extend distinguishing predicate cases to BOTH TimestampsFirst and SignerFirst:
  digital-signature-only with empty/exactNR and forbidden or match-all controls.
  Include Some(empty KU) positive control. NR+empty alone does not test whether
  SignerFirst honors the new predicate.
- Run the existing actual operation_registration_tests and validation_order_tests.
  Retain integrity/ESS/algorithm/root/revocation/TSA/ambiguity/context guards.
- Add fresh pinned oracle comparisons for the actual predicate cases. Separate
  exact Core/pinned AdES semantics from the deliberately normalizing ordinary
  public facade; preserve known stricter forbidden-only differences. Earlier
  six LTA profile calls are not fresh validation of this new seam.

This seam adds ZERO immutable upstream IDs. No broader AdES options are
assigned here; propose those only after this shared boundary is accepted.

## Delivery and acceptance

Each lane commits tests first, implementation separately, then a minimal
current-main packet listing exact files/postimages, API boundaries, actual
source/producer/test ELF/input/oracle receipts and negative controls. Report
total/passed/skipped/pending per assigned crate, fixed unique-function IDs,
parameters, provider exclusions and divergences separately from Rust wrappers
and oracle calls. Preserve all earlier failed probes and actual result identity.
Use pyHanko0.38.1/CV0.33.0 at /tmp/pyhanko-oracle/venv; record real interpreter/
module/version and assertion-enabled profile, never literal labels alone.
Trust decisions must fail closed and unsupported mandatory requirements reject.

Only after L's current-source integration, complete workspace build/test/strict
clippy/strictdoc/layer/fmt gate and independent review may S's two original IDs
move from skipped to passed. V guards and all supplemental controls add0IDs.
No service switch, push or complete-port/universal trust claim follows.
