# Detached CMS, backend ownership and required validation contexts

Accepted source: `21323f9c389cf754af36e6248c58c628c4c05b27`.
Baseline: pyHanko0.38.1 /certvalidator0.33.0. L performed local integration and
all six source-specific workspace gates before accepting exactly five original
functions. No push, process kill, service restart, target/cache/profile change
or ownership transfer was performed.

Measured native results: **2061 discovered /2058 passed
/3 ignored /0 failed**,206 reports. Actual gates:
build0 (11.17s); test0 (1046.52s); clippy0 (27.84s); doc0 (253.43s); layer0 (3.75s); fmt0 (3.15s). These Rust wrapper/doctest counts are separate from the immutable
1,431 unique upstream functions.

## Exact unique-function accounting

| Owner / crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P / sigis-pades-sign |297|296|1|0|
| V / sigis-pades |47|47|0|0|
| S / structural-PKI crates |824|808|16|0|
| C / sigis-cli |252|185|0|67|
| L / lead live integration |11|11|0|0|
| Overall |1431|1347|17|67|
| Library crates |1168|1151|17|0|

Only these five immutable IDs are appended, with all earlier overrides kept:

| Upstream function | Original cases | Native mapping |
| --- | ---: | --- |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_detached` |12|`detached_signing::test_cli_addsig_pemder_detached`|
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_detached_no_field_arg` |1|`detached_signing::test_cli_addsig_pemder_detached_no_field_arg`|
| `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_leaves_a_supplied_backend_alone` |1|public backend test plus private owner-None assertion|
| `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_adopts_an_owned_backend` |1|public backend test plus private exact-Arc assertion|
| `pyhanko/test_signing.py::test_default_validation_context_deprecated` |1|three root doctests and real explicit-context signed-PDF integration, with the explicit language-phase adaptation below|

The CMS exact-main seam and all lifecycle/security controls add zero IDs.
Native wrappers, original parameters and fresh reference API calls never add
extra unique-function credits. No baseline ownership record is changed.

## Detached CLI scope

The original matrix is timestamp absent/present × RSA/ECDSA/Ed25519 × PEM/DER,
12 complete cases. The separate RSA field-incompatibility case requires the
exact `--field is not compatible with --detach` diagnostic and preserves the
preexisting output sentinel. This is detached CMS generation; it does not
claim to implement every PDF signing, provider, reader or CLI command.

Actual new CLI is `91088a347199975ce6bf2d0b21bd8275b2b478c6a2ebe0c0401c80da30ee341e`,
123792072bytes, produced from the coherent source with13 selected local units
and233 input records. Both worker copies match the current absolute artifact,
hash, length and version. Copies are distribution evidence, not inferred VM
native execution. The thin CLI bin compiler event and unchanged main.rs are
separate from selected library checksum coverage. Root focus1a1 CLI8b203 and
combined-source213 CLI9108 remain distinct.

Every actual native detached result is checked as the same bytes: public native
CMS integrity/validity/trust, equal-evidence empty-root refusal, and fresh pinned
Python validation. Native acquisition captures its own TSA requests/responses
before reference execution; the independent reference command has separate
requests. Signature tokens must bind the real outer signature imprint, nonce
and algorithm, have valid issued signatures/timeStamping EKU, and match actual
responses. Claimed signingTime without TSA is distinguished from timestamp
status. Actual final native/reference evidence and policy controls are retained
under `detached-next-integration/`; focused and full-gate runs are not relabelled.

Whole supported detached configuration, effective-field/schema aliases and
mandatory usage/context/runtime requests remain authoritative; unsupported
mandatory settings reject before key loading, network or output. Selected
setup/raw credential conflicts and field incompatibility do not silently fall
back to the attached engine. The accepted ordinary authenticated-reader and
legacy missing-KU repair remain intact. The bounded detached command does not
issue its own trust verdict. Output uses the actual write operation; no atomic
rename guarantee is claimed.

## Backend/context lifecycle

The two originals include real0/1 explicit-close observations and exact private
ownership assertions, not Arc destruction counts. A borrowed backend remains
caller-owned; an adopted context retains exactly the supplied Arc while caller
references survive. Each explicit close delegates again and preserves typed
errors. Clone, with_timing and with_fetchers preserve all unstated security
fields and close authority. There is no implicit Drop-based close, hidden
owner clearing or weaker context reconstruction.

Explicit fetchers, including Fetchers::none, win both setter orders. The last
backend setter selects the backend and borrowed/adopted mode. Factory retrieval
occurs once only after builder validation succeeds, without an implicit HTTP
default. Managed HTTP pools close/reopen; explicitly supplied transports remain
caller-managed. Factory-created component caches/budgets are independent, while
the existing as_fetchers view and issued-set caches/shared budget retain their
semantics. Tests and fresh unchanged Python originals keep ownership, lazy
transport and real network-versus-replay boundaries explicit.

The fetch crate is56/46/10/0; the remaining ten lifecycle originals stay skipped.
This acceptance neither supplies all optional async/request-backend behavior nor
proves every timeout/provider profile.

## Explicit required-context phase adaptation

The Python original validates a real signed PDF with omitted context and checks
an OS-trust deprecation warning, without asserting returned trust. Rust already
requires a borrowed ValidationContext at the public validator. The accepted
adaptation excludes None/omitted context at compile time: a real positive API
call compiles; the two unchanged negative calls first fail under ordinary fences
with E0308/E0061, then their exact diagnostic compile-fail doctests pass. These
three examples represent one original, not three functions or a Rust runtime
warning. No shim, OS-root default, new public API or no-context signing ban is
introduced.

The separate real RSA/SHA256/Sig1 PDF signs with the existing no-context signing
API, then validates with explicit roots and explicit empty roots under matching
caller time, candidates and soft-fail settings. Integrity, exact signer/path,
coverage/modification and no-root denial remain substantive. Both decisions
receive fresh same-PDF pinned reference checks. The separately recorded unchanged
Python original's warning is not labelled a Rust warning or a returned-trust
assertion. SafeNet hardware PIN remains the one P skipped function.

## Exact CMS main predicate: zero IDs

The approved new CmsValidationOptions.exact_key_usage_settings preserves all
five Core fields and intentional empty values only for MAIN; None retains
ordinary facade normalization. Both selectors Some reject with the exact typed
malformed ambiguity diagnostic before direct-entry digest/operation. Both orders
use the same existing signer closure, fixed TSA purpose and private role/registry
logic. Caller context, AC/assertions, algorithm cutoffs, PKIX, revocation and
freshness are not weakened. No fallback validation, public preseed, manufactured
POE, automatic CLI opt-in or default/profile change is introduced.

External exhaustive Rust struct literals must add the new field or struct update;
this is not universal source compatibility. Actual ROOT14 predicate/operation
and16 library controls are separately retained. The new full-gate exported CMS
bytes receive fresh full-gate-source references, distinct from d125 focused
proof. Exact low-level/full-predicate AdES and normalizing ordinary facade
surfaces are not interchangeable: constructor refusals are not API entries,
two custom-algorithm rows are not given invented Python policies, two Core
forbidden-only cases remain native-stricter, and AdES explicit-time construction
has a different temporal context shape. Main results do not prove full-LTA parity.

## Remaining five-lane work and trust limits

P has one SafeNet original skip plus provider/general parameter work. V retains
all47 originals and audits beyond scoped archival/POE/identity profiles. S has16
skips:PDF4,certvalidator2,fetch10. C has67 pending originals, other signing/LTV/
qualification/provider/reader-state flows. L has11/11 originals and owns gates,
parameter/skip/provenance audits and final service-replacement acceptance.

The measured legacy absent-KU signing mismatch was already repaired in73d and
is preserved. Two optional-EKU raw full-PDF facade refusals and two forbidden-only
Core cases remain stricter than pinned Python; provider/empty-PIN directions
and broader unassigned behavior remain bounded/unknown. This cohort does not
claim all divergences fail closed, universal trust parity or a complete port.
All historical failed probes, actual source/ELF scopes and malformed parallel
logs remain preserved; only independently verified clean controls can support
acceptance. No raw evidence field is repaired.
