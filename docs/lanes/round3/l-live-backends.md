# Accepted live requests, lazy-session and concurrent signing

Source `8819a77c424f1d5b0f40a423d8d5191fae3824e0` passes build, workspace tests, clippy with -D warnings,
strict documentation, dependency layering/cycles and formatting. Native gate:
1710 discovered / 1702 passed / 8 ignored /
0 failed, 152 reports. The four new immutable IDs are:

| Exact upstream function | Rust target / test | Original executions | Produced PDFs |
| --- | --- | ---: | ---: |
| test_requests_fetchers_happy_path | live_pades / requests::test_requests_fetchers_happy_path | 2 (strict True/False) | 2 |
| test_requests_fetcher_backend_happy_path | live_pades / requests::test_requests_fetcher_backend_happy_path | 2 (strict True/False) | 2 |
| test_async_lazy_session | live_pades_lazy / test_async_lazy_session | 1 | 1 |
| test_async_sign_many_concurrent | live_pades_concurrent / test_async_sign_many_concurrent | 1 | 10 |

All IDs belong to integration-tests/test_live_certomancer.py. Unique functions
count once. The focused three-target run passes six native tests, including
the previously accepted strict/base functions. Its eighteen real output PDFs
have independently recomputed native/Python PDF/root hashes; fifteen PDFs
belong to the four new functions. Every produced output receives real native
AdES LTA OK, intact/valid/trusted, exact StandardDiffPolicy LtaUpdates, fresh
pinned Python0.38.1/CV0.33.0 same-output LTA and empty-root distrust.
The complete workspace gate separately repeats these checks and retains its
own eighteen PDF outputs and actual hashes. Nothing is counted from replayed
verdicts, a reader-only test or an unavailable provider.

Requests explicit construction retains three independent blocking production
HTTP fetchers with ten-second request limits and literal permit_pem=strict.
Backend construction ignores the original strict parameter exactly as upstream
does. Its close method is a pinned upstream no-op; dropping only the facade
while retained real fetcher handles remain usable preserves that contract.
The unique eager setup client is out of scope before signing. Leaf-only flows
must forward the exact downloaded signer-leaf DER and perform actual AIA HTTP
before native/Python validation; no static issuer or manual prefetch substitutes.

The lazy case drops the unique real setup client before publishing closure.
Independent real production LazyTransport factories for fetchers and TSA each
remain uncreated before closure, then create exactly one actual Reqwest client
during signing. Default async-backend timeout10 and setup/TSA/new validation
timeout5 are retained. A fresh eager validation session is opened after signing.
This establishes resource-owner release, not immediate kernel socket teardown.

Concurrency uses one sidecar/session and the same Arc signer, context/fetchers
and production TSA across ten distinct PdfSigners/readers/writers/outputs.
A start barrier launches the jobs; the completion channel retains the original
index and the actual Sig1 Reason suffix for every completed output. It does
not wait for ten callbacks at one TSA/cache stage or impose a completion order.
Nonblocking telemetry measured ten actual sign calls in flight in the focused
run; the full gate measured 10. Each output independently
passes the full native/Python checker and empty-root controls.

The exact pinned original Python functions independently pass six parameter
executions and their original checker validates all fifteen generated PDFs.
Actual outputs/root DER, source/function hashes and original completion/index
assertions are preserved. The original lazy path emits four unclosed aiohttp
warning headers; run.log retains them. They are not hidden or relabelled as
native failures. No oracle venv package, source function or trust policy changed.

The gate selects a Cargo-produced immutable CLI ELF from this exact source:
SHA256 b7ac8de6226a30d0800510bbc72169b07088fa64da1640b282c015a9e2d7a24c. Its before/after hash and three actual
selection records agree, including identical worker copies. The213 actual V
fixture-open receipts are independently checked against bytes/lengths on their
recorded paths. Canonical target, sccache and system placement are unchanged;
no other job/session, service, target flag, profile or feature was changed.

Accepted root11/10/0/1; overall1431/1233/30/168. Remaining L function is
test_pades_lta_live_with_cli and requires complete real C signing/LTV commands.
Library counts, C98/252 and existing skips are unchanged. Known combined-PKI
registry/path-selection and encoding/model compatibility limitations remain
open; these successful controls do not establish universal fail-closed parity.

Evidence: /home/l/.codex/artifacts/sigis/round3/l-next/ (all-native-v1/, upstream-v1/, independent audits,
executable-v1-receipt.json, gate/gate.json and runtime-verification.json).
