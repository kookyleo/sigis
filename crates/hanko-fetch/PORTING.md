# Porting status: hanko-fetch

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
| `test_fetcher_lifecycle.py` | — | 16 | 0 | 16 | 0 |
| `test_tsa_fetcher.py` | `tests/test_tsa_fetcher.rs` | 10 | 8 | 2 | 0 |
| `test_tsa_fetcher_requests.py` | `tests/test_tsa_fetcher_requests.rs` | 4 | 4 | 0 | 0 |

Notes:

- Upstream runs the network tests once per backend (aiohttp, requests);
  here there is one backend, so each runs once against a transport that
  fails and counts requests. Logging assertions (warning once, then debug)
  are ported as state checks (`FetchBudget::exhaustion_reported`); the port
  does not log.
- `test_fetcher_lifecycle.py` (16) is skipped: it tests ownership and
  explicit closing of asyncio HTTP sessions (`aclose`, `OwnedFetcherBackend`,
  `LazySession`). Rust fetchers are plain owned values; resources are
  released by `Drop`, and there is no close protocol to port.
- `test_tsa_fetcher.py` skips `test_deprecated_aiohttp_timestamper_forwards`
  (a deprecated Python alias) and `test_auth_coercion_rejects_nonsense`
  (passing a non-credential object is a type error in Rust).
- No test uses the network: a local server on 127.0.0.1 plays the TSA,
  serving a response of pyHanko's test TSA for a fixed request
  (`oracle/gen_tsa_fixtures.py`); "unreachable host" is a closed local
  port. The PDF-signing halves of the TSA tests are lane D; their
  validation halves are replayed from recorded pyHanko calls.
- `tests/fetchers.rs` adds success-path tests (certificate, CRL, caching,
  content type, HTTP status, size limit) that upstream lacks.
