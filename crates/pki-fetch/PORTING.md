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
