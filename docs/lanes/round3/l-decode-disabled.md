# Acceptance: decode continuity and Disabled bootstrap

Date2026-11-14. Accepted compiled source `14d6c6a3340714e14fe1d1798e047227b0442dc5`, parent accepted
main6b35096d/source134be605. The preceding accepted inventory was1431/1356/13/62. This current-source
acceptance follows the completed Root gate and independent final review.

## Completed source gate and exact inventory

- Full six-stage returned gate results: **All six returned0 with audit0 (build 3.2s; test 1113.47s; clippy 9.75s; doc 64.23s; layer 3.7s; fmt 3.57s)**.
- Actual full Rust discovered/passed/ignored/failed/report counts:
  **2118 discovered /2115 passed /3 ignored /0 failed /215 reports**.
- Independent final review `/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/final-review/review.json`
  SHA256: **25fa11d1ab703d58c5c0ca450b9afbd35a35cb6a8fac55f15ea67178e9d0ea58**.

Independent final review binds actual completed summaries, selected-source
input audits and all34compressed full-run captures (old32 plus decode target
and CLI library units). Archive SHA/length, decompressed raw ELF SHA/length and
actual Running paths were checked separately. Focus and full gate remain
separate completed proofs; the counts and hashes above are measured.

After the completed Root gate/review, exactly C3+S1 are accepted: overall1431/1360/12/59;
C252/193/0/59; S824/813/11/0; fetch56/51/5/0; library1168/1156/12/0.
P297/296/1/0, V47/47/0/0 and L11/11/0/0 remain unchanged. The final ledger has341overrides (existing337raw objects/order retained plus4).
The original conditional ledger-proposal.json remains immutable in ART. No accepted original ID is downgraded
or otherwise changed by the V diagnostic below.

| New unique original | Mapping | Exact parameters |
| --- | --- | --- |
| pyhanko-cli/test_cli_decode_limits.py::test_simple_commands | decode_limits_simple::test_simple_commands | encrypt/list/addfields/addfields-resave:4 |
| pyhanko-cli/test_cli_decode_limits.py::test_text_stamp | decode_limits_simple::test_text_stamp | text:1 |
| pyhanko-cli/test_cli_decode_limits.py::test_qr_stamp | decode_limits_simple::test_qr_stamp | QR:1 |
| pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_without_fetching_owns_nothing | round3_handler_bootstrap::test_bootstrap_without_fetching_owns_nothing | one unchanged original; Disabled-only native semantic mapping |

## Closed current focus and actual source boundaries

Actual source16ef A2 CLI baseline is3RustPASS/1FAIL. Only the trusted addfields
and addfields-resave command paths fail; text/QR/encrypt/list are already green.
Source14d repairs fields.rs only, transferring the SAME selected parsed reader
through PdfReopenState/open_with_state and make_fresh only for resave. Default
finite/lenient and explicit trusted state, remaining budget and original encrypted
field refusal remain; no new route, shared API or dependency. C state2PASS and
integration4PASS cover3originals/6parameters plus zero-ID controls.

Current immutable CLI34d4a7de/124035704bytes has13producerunits/236inputrecords,
with matching vm2064/vm2065 copy receipts. Actual C37process receipts cover
6prepares+12native original commands+6fresh unchanged original bodies+
6same-native-input helpers+5actual-native-output inspections+2encrypted-field
refusals. All131archive hashes/lengths and26actual Python-read bindings pass.
Unsigned encryption/field/page/revision/stamp checks are actual new outputs,
not sample-only tests, and are not signature trust or QR/rendering proof.
Finite unit1000->200/late300 denial proves transfer, not finite-budget final
serialization; trusted compact replay/write/reopen is a separate control.

S Disabled mapping changes tests only, not production. Actual current source14d
runs1testPASS/13filtered, one fresh unchanged original, and3same-native profiles /
6reference API calls. No legacy fetch escapes before or after cache warmup;
missing required revocation evidence refuses, authenticated signed local evidence
succeeds, and reachable legacy controls perform the actual retrieval. Component/
owner absence and repeated harmless close support only Disabled. Supplied(empty)
presence/availability is not normalized. Missing standalone same-byte process
receipt and expected Python InsufficientRevinfo stderr remain disclosed; complete
stdout JSON/log plus Root-reported exit0 are retained, with no invented trace.

Separately completed source14d full-run S evidence has14native tests,29actual exported profiles and58new same-byte reference calls; exact MAIN agrees28/29, ordinary CMS agrees26/29. Actual reference subprocess exit0 in1.439418s retains stdout/stderr and before/after log/driver hashes. Its one exact stricter refusal and bidirectional ordinary normalization differences remain bounded. This separate complete-run proof does not reconstruct missing focus stderr/process receipts. Review `/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/s-full-review/review.json`, SHA256 `e1bd64ca24def3ab67140bb9e1e2fba5cd18b65bedd71e9ed5d3fa68245de83f`.

Both sealed focus reviews and actual checker receipts are under
`/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/c-focus-review` and
`/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/s-focus-review`. Earlier source/owner proofs remain historical;
post-run gzip snapshots do not claim run-instant copying, worker copies do not
claim worker test execution, and focus completion does not imply full gate.
The prior source13426profile/52call exact25agree1stricter and ordinary23agree/
3bidirectional differences remain historical bounded observations. Source3a's
12matched-profile stricter refusals plus1different-default comparison likewise
do not establish universal conservatism or automatic exact CLI behavior.

## Current validation risk: no accepted production repair

V's source `d56ba126f4b6ceff9ceb5aaf4e6446ae0a3b20ae` has unchanged production relative to14d
for the relevant public APIs. Its [urgent WithTime report](/home/l/.codex/artifacts/sigis/round3/v/qualified-preliminary-completion/urgent-with-time-finding.md) records
4nativePASS/1hardeningRED/0ignore and63fresh pinned API diagnostic calls.
Genuine signed main CMS/proper authenticated TST with an expired leaf yields
public native WithTime OK/trusted for invalid `path_length` and actual
`bad_cert_signature`, while pinned WithTime refuses those two before expiry.
NameConstraints/unknown-critical/required-KU omissions are shared with the
pinned Python surface, and still are not a safety guarantee. Final LTA missing-
history/bad-purpose/corrupt-imprint controls remain denying; they do not repair
the separately public WithTime trust result.

Verified source entrypoints:
[with_time_validation](../../../crates/pades/src/ades/with_time.rs#L334),
[with_time_validation_with_options](../../../crates/pades/src/ades/with_time.rs#L353),
[with_time_result](../../../crates/pades/src/ades/with_time.rs#L164),
[lta_validation](../../../crates/pades/src/ades/lta.rs#L363), and
[past_validate_with](../../../crates/pki-certvalidator/src/ltv/mod.rs#L144).
Relevant source hashes match source14d and diagnostic d56, as recorded in the
proposal manifest. This is a substantive incomplete-path trust risk and confirms
that **not all current trust divergences fail closed**. It adds0original IDs and
is not an accepted production fix. Root separately reviews acceptance impact;
no already accepted ID is mechanically downgraded by this document.

No clock waiver, trusted retained-path promotion or mechanical failed-past API
promotion is permitted. Approved bounded V containment is now in progress, with original-ID audit
required; P independently audits read-only and Root owns shared API/production/
acceptance. A generic safe historical-completion rule has not been established. A green bounded C/S full gate cannot erase that separate
hardening RED or justify full-port/universal trust parity.

## Remaining work and next bounded lane work

L has approved bounded V containment in `/home/l/.codex/artifacts/sigis/round3-launch/v-withtime-containment-approval.md`. It is in progress and not an accepted production repair: only with_time.rs and its unit/adversarial test/fixture paths may change; failed MAIN must never become trusted/OK from a retained path and valid timestamp alone. Typed failure, diagnostic path/API and timing bounds stay available. Existing full LTA production stays unchanged. An audit of all47 original IDs/affected assertions is required, with any proposed downgrade routed to Root; no count is silently changed. P independently audits read-only; Root owns shared API, integration and acceptance. No clock waiver or mechanical failed-past promotion is approved.

A separate L-approved implicit-default-context packet is in progress under `/home/l/.codex/artifacts/sigis/round3-launch/s-implicit-context-default-approval.md`, with no pass or production acceptance yet. Its sole original is test_context_provisions_and_owns_a_backend. Exclusive production scope is CV context.rs plus pades policy.rs: add generic ValidationContextBuilder::build_with_backend_fallback<F> where F:FnOnce()->Arc<dyn FetcherBackend>, and L2 policy::bootstrap_validation_context using actual HttpFetchers and a real Basic consumer. Ordinary build remains disabled; explicit fetchers including empty suppress fallback, and validated construction/owner precedence remain. No new dependency/manifest/layer edge or source/POE framework is approved. The other four lifecycle gaps remain unapproved; this future packet earns no current credit.

C retains59pending functions. Its next styling slice is exactly named text4alg +
QR4alg +missing-URL Ed255191 =3originals/9parameters:
`test_cli_sign_visible_with_style`, `test_cli_sign_visible_with_qr_style`,
`test_cli_sign_visible_with_qr_style_omit_stamp_url`. These are future signed
operations, not accepted through decode3's unsigned output inspections.

S retains11skips (PDF4/CV2/fetch5). Fetch's exact five remaining lifecycle gaps:

- `test_context_provisions_and_owns_a_backend`
- `test_no_backend_when_fetchers_are_unreachable`
- `test_unreachable_fetchers_still_adopt_an_owned_backend`
- `test_policy_hands_ownership_to_the_context`
- `test_policy_without_handlers_hands_over_nothing`

No speculative manager/source/POE-owner handoff is claimed from Disabled's
approved mapping. P retains SafeNet PIN1, V47 and L11 stay accepted under their
current bounded function inventory, and provider, raw-policy, historical proof,
qualification and unassigned feature work remain. Complete port is unfinished.

## Complete S run and fresh same-byte peers

The full source14d handler target passes14 tests. Its29 actual CMS/material
exports receive58 fresh pinned API calls in1.439418seconds, with no reference
network attempts or exceptions. Exact MAIN flags agree28/29; the remaining
forbidden-usage refusal is stricter. Ordinary normalization agrees26/29 with
three bidirectional profile differences. All three new Disabled profiles agree
on both surfaces. These offline candidate-material comparisons do not reproduce
Python HTTP/session ownership; native loopback controls supply that evidence.

The independent full-S review is
`/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/s-full-review/review.json`,
SHA256 `e1bd64ca24def3ab67140bb9e1e2fba5cd18b65bedd71e9ed5d3fa68245de83f`.
It binds full raw ELF2d085061/88834984bytes separately from focus ELF95cdd6b4.
Of258 input markers,257 are complete hashed JSON records over17paths; one
interleaved raw two-line record remains undecoded and is not reconstructed.
All29 case exports and three HTTP records are complete. Earlier source134
default profiles remain explicitly historical counterparts.

The archive collector initially omitted the CLI main-test boundary after its
library units. Its five completed captures and failure were retained; the
corrected collector captured only the remaining29. Existing successful build/
test evidence was retained and the four remaining gate stages ran once. No
product test was repeated or hidden by this recovery. Final reviewer attempts
are retained separately; the completed review uses exact persistent proof
inventories and original path/hash/length archive bindings for temporary outputs.
