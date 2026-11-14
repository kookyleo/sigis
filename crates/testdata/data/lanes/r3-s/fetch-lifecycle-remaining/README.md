# Remaining fetch-lifecycle oracle support

This tests-only packet maps exactly three immutable upstream functions:

- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_policy_without_handlers_hands_over_nothing`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_no_backend_when_fetchers_are_unreachable`
- `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_unreachable_fetchers_still_adopt_an_owned_backend`

Each original is unparameterized and contains one assertion. The runner invokes
the complete unchanged pinned source bodies through pytest. The policy original
asserts absence of the `fetcher_backend` kwargs key; it does not assert a universal
zero factory count or remove caller-provided authority. The unreachable originals
use `_handlers_only()` with empty local C/R stores, no registry certificate fetcher,
no revocation-manager fetchers and the same registry object inside the manager.
The borrowed/adopted close/identity/factory/error observations are separate probes.
`RecordingBackend.close()` counts explicit calls but does not close its HTTP
delegate. No Python transport-close proof is claimed.

The approved native adaptation is deliberately limited to that empty fixture:
explicit issued `Fetchers::none()` passed through the real fetching-enabled L2
`bootstrap_validation_context` suppresses internal default/component retrieval,
while preserving the returned context's local material and separately selected
close owner. Actual Basic/CMS/path/revocation consumers and HTTP controls are
required in the Rust target. This does not implement arbitrary external mutable
CertificateRegistry/RevinfoManager aliases, independent nonempty/custom source
fetchers or a manager/POE graph. Those source-compatibility gaps remain even if
these three exact function ports are accepted. Constructor/component identity
proof is distinct from runtime cache/retrieval proof.

`original_fetch_lifecycle_oracle.py` records real interpreter/distribution/module
hashes, assertion-enabled execution, complete bodies and fixture-closure hashes,
three pytest invocation outcomes and separately labelled supplemental probes.
It denies network for this exact network-free scope and disables the unused
`requests_mock` plugin because its import probes an IPv6 listener; this is not an
original/provider exclusion. Installed pyHanko release version data is recorded
separately from the source-tree development placeholder rather than falsely
claiming those generated metadata bytes match. All actual CV implementation
module sources are checked against pinned CV0.33.0.

`same_bytes_fetch_lifecycle_oracle.py` validates every actual native-exported JSON
profile offline, without generating replacement signatures or filtering malformed
material. It checks actual native log/output receipts, the source-bound producer
receipt and the lossless compressed test ELF's raw SHA/length before comparing
exact MAIN and separately ordinary normalizing public CMS surfaces. It accepts
markers `FETCH_REMAINING_NATIVE_CASE`, `FETCH_REMAINING_EXECUTABLE` and
`FETCH_REMAINING_HTTP_EXCHANGE`. The JSON export schema is retained from the S1
consumer harness. HTTP/factory/cache/close behavior is native evidence; these
fresh Python calls inspect the same available bytes, clock, roots and predicate
and do not replay native fetch transactions or prove full AdES result parity.
Constructor errors remain errors, separate from successful API flag comparisons.
Known ordinary-facade predicate normalization differences must remain visible.

The fixture/runner sources add zero accepted IDs themselves. Only L's current
source integration, complete gate and mapping review may promote the selected
three originals. No production/API/manifest/lock/dependency change is present.
