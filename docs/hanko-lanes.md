# sigis-hanko: parallel port of pyHanko

Status: lane plan, 2026-11-11. Owner of this file: the lead.

Goal: functional parity with **pyHanko 0.38.1** and **pyhanko-certvalidator
0.33.0**, with their test suites as the acceptance baseline. Upstream source
of truth: tags `v0.38.1` (commit `580f49498f76`) and
`pyhanko-certvalidator/v0.33.0` (commit `b48999514cb4`) of
<https://github.com/MatthiasValvekens/pyHanko>. pyHanko's `main` branch is
newer than the release and is **not** the baseline.

## 1. Reuse rule

Port only the logic that the Rust ecosystem lacks. Where a mature crate covers
a building block, depend on it instead of translating pyHanko's equivalent:

| Building block | Crate |
| --- | --- |
| ASN.1 / DER, X.509, CMS, OCSP, TSP | `der`, `x509-cert`, `cms`, `x509-ocsp`, `x509-tsp` (versions pinned in the root `[workspace.dependencies]`) |
| RFC 5280 path validation | `certval` |
| Crypto primitives | RustCrypto (`rsa`, `p256`/`p384`/`p521`, `ed25519-dalek`, `sha1`/`sha2`, `aes`, `rc4`, ...) |
| PDF objects, parsing, serialization | `lopdf` 0.47 |
| Compression filters | `flate2` (and crates for LZW, ASCII85, ... where lopdf lacks them) |
| HTTP | `reqwest` (blocking) |
| PKCS#11 | `cryptoki` |
| XML | `quick-xml` (+ `serde`) |
| Fonts, images, QR | established crates (`ttf-parser`/`owned_ttf_parser`, `subsetter`, `image`/`png`, `qrcode`) |

If a crate has a gap, contribute a fix upstream. Fork or vendor only when
blocked, and record it. Every pyHanko module gets one status in its crate's
`PORTING.md`: **ported**, **replaced by crate X**, or **skipped (reason)**.

## 2. Crates and ownership

Each path has exactly one owner. A lane edits only the paths it owns. Changes
to other paths are requested from the lead (see §6).

| Path | Owner | Content |
| --- | --- | --- |
| `Cargo.toml` (root), `Cargo.lock`*, `crates/hanko/` (facade `sigis-hanko`), `crates/hanko-core/` except `algorithms.rs` and `asn1/`, `crates/hanko-testdata/src/`, `crates/hanko-testdata/data/{pyhanko,pyhanko-certvalidator,sigis-generated,pyhanko-pki}/`, `tools/`, `docs/hanko-lanes.md`, `src/`, `web/`, `vendor/` | Lead | Workspace, shared types and traits, shared fixtures, service |
| `crates/hanko-core/src/algorithms.rs`, `crates/hanko-core/src/asn1/`, `crates/hanko-certvalidator/`, `crates/hanko-cms/`, `crates/hanko-fetch/` | Lane A | Certificate validation, CMS / TSP validation, fetchers |
| `crates/hanko-pdf/` (incl. `fuzz/`) | Lane B | PDF layer, encryption, metadata |
| `crates/hanko-diff/` | Lane C | DocMDP / FieldMDP analysis |
| `crates/hanko-sign/` | Lane D | Signers, fields, appearances, key providers |
| `crates/hanko-validate/`, `crates/hanko-ades/`, `crates/hanko-eutl/` | Lane E | PDF validation, AdES, reports, trusted lists |
| `crates/hanko-testdata/data/lanes/<lane>/`, `docs/lanes/<lane>.md` | That lane | Lane fixtures; lane status and interface requests |

\* Any lane may change `Cargo.lock` as a side effect of adding a dependency
to its own crate. On a rebase conflict, take `main`'s `Cargo.lock` and run
`cargo check --workspace` to re-resolve. Lanes add dependencies to their own
`Cargo.toml` with explicit versions; the lead hoists shared ones into
`[workspace.dependencies]`.

Dependency graph (arrows point to dependencies):

```
hanko-core ◀── hanko-certvalidator ◀── hanko-cms ◀──┬── hanko-validate ◀── hanko-ades
     ▲                ▲                     ▲          │        ▲
     │                └── hanko-fetch       │          │        │
     ├── hanko-pdf ◀── hanko-diff ◀─────────┼──────────┘        │
     │       ▲                              │                   │
     │       └──────── hanko-sign ──────────┘ (+ certvalidator) │
     └── hanko-eutl ────────────────────────────────────────────┘ (later)
sigis-hanko (facade) re-exports all of them.
```

## 3. Lanes

| Lane | Branch | Owned crates | Scope | pyHanko tests | Est. Rust (prod) |
| --- | --- | --- | --- | --- | --- |
| A — Certificates & CMS | `hanko/a-cms-cert` | `hanko-certvalidator`, `hanko-cms`, `hanko-fetch`, `hanko-core::{algorithms,asn1}` | `generic_cms` (SignerInfo, signed-attribute digest, SigningCertificateV2 binding, signature and content timestamps), certvalidator gaps (indirect CRLs, `onlySomeReasons`, delegated OCSP responder revocation, registry/AIA, policy qualifiers, trust-anchor qualifiers, attribute certificates, `ltv`: POE, time slide, past validation), HTTP fetchers and TSA client with cache, limits, timeouts, multi-URL fallback | 271 functions | 5–7k lines |
| B — PDF layer | `hanko/b-pdf` | `hanko-pdf` | Reader with revision history (xref tables and streams, object streams, hybrid files, broken-file recovery), filters and decode limits, incremental writer, signature and DSS discovery, byte-range extraction, embedded files, metadata (Info, XMP), content stream parser, encryption (standard and public-key security handlers, crypt filters), PDF MAC (ISO 32004), cargo-fuzz targets | 406 functions | 8–11k lines |
| C — Modification analysis | `hanko/c-diff` | `hanko-diff` | `diff_analysis`: DocMDP / FieldMDP rules (file structure, metadata, form fields, annotations, DSS / DTS updates), whitelisting policy, `SuspiciousModification` reporting | 94 functions | 3–4k lines |
| D — Signing | `hanko/d-sign` | `hanko-sign` | CMS signing (`cms` builder), PAdES B-B / B-T / B-LT / B-LTA, signature field creation and seed values, certification (DocMDP), DSS updates, document timestamps, LTA renewal, CAdES signed attributes, key providers (software keys, PKCS#11 via `cryptoki` with SoftHSM tests, CSC remote signing), local test TSA, visible appearances (stamps, text layout, fonts, images, QR / barcodes), signing encrypted documents. When at parity: switch the Sigis service from `underskrift` to `hanko-sign` (via the lead) | 297 functions | 8–11k lines |
| E — Validation & AdES | `hanko/e-validate` | `hanko-validate`, `hanko-ades`, `hanko-eutl` | `pdf_embedded` (signatures per revision, coverage, DocMDP / FieldMDP via lane C), `status`, `settings`, validation-side `dss` / LTV, `ades` (EN 319 102-1 building blocks, LTV / LTA, POE extraction, past signature validation), reports (JSON, ETSI TS 119 102-2 XML), EU trusted lists and qualified status (TS 119 612 parsing, XAdES signature check, `quick-xml` bindings instead of `generated/`) | 100 functions | 7–10k lines |
| L — Lead / integration | `main` | see §2 | Skeleton, shared fixtures and oracle, merges, service wiring (`/api/verify` flag, later signing switch), CLI crate and CLI tests after the lanes | 263 functions (CLI, live integration) | — |

Merge order: the skeleton (done) → A and B (first increments that fill their
interfaces) → C → D and E. Lanes work in parallel against the stubs; a stub
returns `HankoError::NotImplemented` until its owner fills it.

## 4. Interface contracts (skeleton on `main`)

All functions and types below exist on `main` and compile. Stubs return
`HankoError::NotImplemented(...)` and never panic. Signatures may only change
through the lead.

- **`hanko-core`** (lead; `algorithms` and `asn1` lane A):
  - `errors::{HankoError, Result, ValidationError, SignatureError, FetchError, FetchErrorKind, not_implemented}`.
  - `cert::Cert` (parsed certificate plus exact DER).
  - `time::Moment`.
  - `algorithms::{DigestAlgorithm, SignatureMechanism, validate_signature, AlgorithmUsagePolicy, DisallowWeakAlgorithmsPolicy}`.
  - `asn1::{ess, sig_policy, commitment, oids}`.
  - `fetch::{OcspFetcher, CrlFetcher, CertificateFetcher, Fetchers}`: synchronous traits; async callers use a blocking task.
  - `sign::{KeySigner, TimeStamper}`: `sign_raw(data, digest)` gets the data, not a digest; `timestamp(message_digest, digest)` returns a `TimeStampToken` `ContentInfo`.
- **`hanko-certvalidator`** (A): `ValidationContext` (+ `ValidationContextBuilder::fetchers`), `ValidationPath`, `TrustAnchor`, `build_paths`, `validate_path`, `CertificateValidator`, `policy::*`, `revinfo::freshness::{FreshnessJudge, judge_revinfo}`, `ltv::{poe::{PoeManager, PoeType, digest_for_poe}, time_slide::time_slide, past_validate}`.
- **`hanko-cms`** (A): `SignedContent`, `SignatureStatus`, `TimestampSignatureStatus`, `StandardCmsSignatureStatus`, `TrustProblem`, `validate_cms_signature`, `validate_timestamp_token`, `validate_detached_cms`.
- **`hanko-fetch`** (A): `HttpFetchers` (implements the three fetch traits), `HttpTimeStamper` (implements `TimeStamper`), `FetchLimits`.
- **`hanko-pdf`** (B): `lopdf` re-export; `PdfFile::{parse, bytes, revisions, object_in_revision, objects_written_in, trailer_in_revision, embedded_signatures, dss}`, `RevisionInfo`, `EmbeddedSignature{..}::signed_data`, `SignatureKind`, `DocumentSecurityStore`, `VriEntry`, `MdpPerm`, `IncrementalWriter::{new, put, allocate, write}`.
- **`hanko-diff`** (C): `DiffPolicy::review_file`, `StandardDiffPolicy`, `DiffOutcome`, `DiffResult`, `ModificationLevel`, `FieldMdpAction`, `MdpPerm` (re-export).
- **`hanko-sign`** (D): `SimpleSigner::{from_pkcs8_der, from_pkcs12}` (implements `KeySigner`), `PdfSignatureMetadata`, `SubFilter`, `PdfSigner::sign_pdf`, `sign_general_data`, `add_document_timestamp`, `add_validation_info`, `pkcs11::{Pkcs11Config, open}`.
- **`hanko-validate`** (E): `validate_pdf_signature`, `validate_pdf_timestamp`, `validate_pdf_ltv_signature`, `PdfSignatureStatus`, `DocumentTimestampStatus`, `SignatureCoverageLevel`, `RevocationInfoValidationType`.
- **`hanko-ades`** (E): `validate_pdf_ades`, `AdesLevel`, `AdesStatus`, `AdesSubIndication`, `AdesValidationResult`, `report::{to_json, to_etsi_xml}`.
- **`hanko-eutl`** (E): `TrustedList`, `TrustService`, `QualificationResult`, `parse_trusted_list`, `qualification`.

Lanes may add public items to their own crates freely. They may not remove or
change the items above without a lead-approved request.

## 5. Tests: the acceptance baseline

### 5.1 Inventory and assignment

Static inventory of the release tags: **1,431 test functions in 55 modules**
(counted with `ast`, including methods of test classes; "param." = functions
with `@pytest.mark.parametrize`). The number of collected cases (after
parametrization) will be added by the lead from `pytest --collect-only` once
the oracle venv installs (§5.4, open item L1).

| Package | Module | Functions | Param. | Lane |
| --- | --- | ---: | ---: | --- |
| pyhanko-certvalidator | `test_ac_validate.py` | 27 | 2 | A |
| pyhanko-certvalidator | `test_ades_time_slide.py` | 13 | 0 | A |
| pyhanko-certvalidator | `test_certificate_validator.py` | 2 | 0 | A |
| pyhanko-certvalidator | `test_common_utils.py` | 15 | 3 | A |
| pyhanko-certvalidator | `test_fetch_limits.py` | 11 | 2 | A |
| pyhanko-certvalidator | `test_fetcher_lifecycle.py` | 16 | 0 | A |
| pyhanko-certvalidator | `test_freshness.py` | 6 | 0 | A |
| pyhanko-certvalidator | `test_name_trees.py` | 6 | 5 | A |
| pyhanko-certvalidator | `test_policy_graph.py` | 33 | 0 | A |
| pyhanko-certvalidator | `test_policy_proc.py` | 13 | 4 | A |
| pyhanko-certvalidator | `test_registry.py` | 9 | 1 | A |
| pyhanko-certvalidator | `test_sig_validate.py` | 3 | 0 | A |
| pyhanko-certvalidator | `test_validate.py` | 21 | 6 | A |
| pyHanko | `test_cms.py` | 78 | 12 | A |
| pyHanko | `test_key_usage_constraints.py` | 4 | 4 | A |
| pyHanko | `test_tsa_fetcher.py` | 10 | 2 | A |
| pyHanko | `test_tsa_fetcher_requests.py` | 4 | 0 | A |
| pyHanko | `test_content_stream_parser.py` | 8 | 4 | B |
| pyHanko | `test_crypt.py` | 84 | 21 | B |
| pyHanko | `test_decode_limits.py` | 29 | 15 | B |
| pyHanko | `test_embed.py` | 9 | 3 | B |
| pyHanko | `test_internal_utils.py` | 127 | 43 | B |
| pyHanko | `test_meta.py` | 39 | 6 | B |
| pyHanko | `test_pdfmac.py` | 50 | 17 | B |
| pyHanko | `test_xref.py` | 60 | 12 | B |
| pyHanko | `test_diff_analysis.py` | 94 | 29 | C |
| pyHanko | `test_barcode.py` | 2 | 0 | D |
| pyHanko | `test_csc.py` | 17 | 3 | D |
| pyHanko | `test_fields.py` | 27 | 6 | D |
| pyHanko | `test_images.py` | 2 | 2 | D |
| pyHanko | `test_pades.py` | 48 | 8 | D |
| pyHanko | `test_pkcs11.py` | 36 | 14 | D |
| pyHanko | `test_seed_values.py` | 36 | 4 | D |
| pyHanko | `test_sign_encrypted.py` | 11 | 5 | D |
| pyHanko | `test_signing.py` | 78 | 9 | D |
| pyHanko | `test_stamp.py` | 25 | 4 | D |
| pyHanko | `test_text.py` | 15 | 1 | D |
| pyHanko | `test_ades_validation.py` | 40 | 11 | E |
| pyHanko | `test_ades_validation_report.py` | 5 | 0 | E |
| pyHanko | `test_ades_validation_requests.py` | 2 | 0 | E |
| pyHanko | `test_trusted_list.py` | 53 | 13 | E |
| pyhanko-cli | `test_cli_crypt.py` | 21 | 1 | L |
| pyhanko-cli | `test_cli_decode_limits.py` | 10 | 4 | L |
| pyhanko-cli | `test_cli_field_mgmt.py` | 7 | 1 | L |
| pyhanko-cli | `test_cli_ltv.py` | 3 | 1 | L |
| pyhanko-cli | `test_cli_plugins.py` | 11 | 0 | L |
| pyhanko-cli | `test_cli_signing.py` | 51 | 10 | L |
| pyhanko-cli | `test_cli_signing_pkcs11.py` | 13 | 0 | L |
| pyhanko-cli | `test_cli_stamp.py` | 12 | 1 | L |
| pyhanko-cli | `test_config.py` | 57 | 17 | L |
| pyhanko-cli | `test_runtime.py` | 6 | 0 | L |
| pyhanko-cli | `validation/test_cli_qualified_validation.py` | 22 | 7 | L |
| pyhanko-cli | `validation/test_cli_validation.py` | 39 | 12 | L |
| integration-tests | `test_live_certomancer.py` | 9 | 0 | L |
| integration-tests | `test_live_csc_dummy.py` | 2 | 0 | L |

Totals: A 271, B 406, C 94, D 297, E 100, L 263 (1,431).

Several modules test across lanes. For example, `test_pades.py` signs (lane D)
and then validates (lane E), and `test_cms.py` validates signatures that a
signer produced. The owning lane ports the test anyway. It uses
oracle-generated fixtures (§5.4) for the other side until that lane's
implementation lands, and switches to the real implementation afterwards.

### 5.2 Fixtures

- Shared pyHanko fixtures are in `crates/hanko-testdata/data/` (lead-owned),
  copied from the release tags with their licenses:
  - `pyhanko/`: test PKI configuration and public test keys, PDFs, XML,
    images, fonts (OFL), EU trusted lists (CC BY 4.0).
  - `pyhanko-certvalidator/`: NIST PKITS, OpenSSL OCSP vectors, test PKIs.
  - `sigis-generated/`: certificates generated for algorithm tests.
- Each subdirectory has a `README.md` with origin and license. Load fixtures
  with `hanko_testdata::{path, read, certvalidator, pyhanko}`.
- Lane-generated fixtures (oracle outputs, exported PKI) go to
  `crates/hanko-testdata/data/lanes/<lane>/`, with the generating script
  under `crates/<crate>/oracle/` and a README stating how they were produced.
- Generated material must be reproducible from a committed script and a
  pinned validation time. Never commit private keys other than pyHanko's
  public test keys.

### 5.3 Test-driven porting rules

- Port a module's tests first or alongside its code. A test function is
  **ported** when it runs in Rust and asserts the same outcome (error class
  and, where pyHanko checks it, message pattern).
- Data-driven suites keep an explicit `KNOWN_DIVERGENCES` list with a reason
  per case. The test fails on an unlisted divergence and on a listed case
  that now agrees (see `crates/hanko-certvalidator/tests/pkits.rs`).
- **Never accept what pyHanko rejects.** Every divergence must fail closed:
  where pyHanko rejects or flags something, the port must not accept it.
  Data-driven tests assert this explicitly ("fail-open divergence" check).
- A lane is accepted when every assigned test function is ported and
  passing, or explicitly skipped with a reason in its crate's `PORTING.md`.
  "Pending" is allowed only before acceptance.
- No `unwrap`/`expect`/`panic` on untrusted input in library code (the crates
  set `clippy::unwrap_used`/`expect_used`/`panic` to warn outside tests).
- Tests never use the network. Fetchers are tested with in-memory fakes or a
  local HTTP server on `127.0.0.1:0`.

### 5.4 Differential harness (pyHanko oracle)

- `tools/pyhanko-oracle/setup.sh` creates a venv in `/tmp/pyhanko-oracle` with
  pyHanko 0.38.1 and pyhanko-certvalidator 0.33.0, plus the source tags.
- Fixture generators run pyHanko (and Certomancer for the test PKI) and write
  inputs plus pyHanko's verdicts as JSON. Their outputs are committed, so
  normal test runs need no Python.
- Differential tests call `hanko_testdata::oracle::run_json(script, args)` and
  compare pyHanko's verdict with the Rust verdict on the same input. They skip
  with a message when the oracle is not installed, and fail if pyHanko's
  verdict is stricter than the port's.
- Lead open item **L1**: install the oracle (PyPI is reachable only
  intermittently from this host), record collected-case counts in §5.1, and
  export the Certomancer test PKI (`crypto/certomancer.yml`, arch
  `testing-ca` and the others the tests use) to
  `crates/hanko-testdata/data/pyhanko-pki/` at a pinned time. Lanes that need
  the PKI before L1 lands may run the export locally into their own lane
  directory, and must say so in their status file.

### 5.5 Reporting

Each lane keeps `docs/lanes/<lane>.md` current, and its phase reports state
per suite (test module): **total / ported-pass / skipped (with reason) /
pending**, plus known divergences. Each crate's `PORTING.md` holds the
module → Rust file → status table.

## 6. Integration rules

1. Each lane works in its own git worktree on branch `hanko/<lane>`, created
   from `main`:
   `git worktree add ../sigis-wt/<lane> -b hanko/<lane> main`.
2. Rebase on `main` often (at least before each phase commit).
3. Never edit files owned by another lane or by the lead. Interface or
   shared-file changes are requested in `docs/lanes/<lane>.md` under
   "Requests to the lead". The lead applies them on `main`, and lanes rebase.
4. A phase ends with a green gate for the whole workspace: `cargo build`,
   `cargo test`, `cargo clippy --all-targets` (no warnings), and
   `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`. Then update the crate's
   `PORTING.md` and `NOTICE`, update `docs/lanes/<lane>.md`, and make an
   English local commit. Commit messages do not mention AI tools. Never push.
5. The lead merges lane branches into `main` with `git merge --ff-only` after
   the lane has rebased, and reruns the gate.
6. Builds: in the worktree, run `eval "$(/usr/local/bin/rust-target-env)"`
   before every `cargo` command (same shell command). All worktrees share one
   target directory, so cargo serialises builds; keep local runs narrow
   (`cargo check -p <crate>`), and run test suites on the workers with
   `rust-remote cargo nextest run -p <crate>`. Do not change `RUSTFLAGS`,
   profiles or `CARGO_TARGET_DIR`.
7. Processes: never use `pkill` / `killall`; kill only by PID. Do not use
   port 38882. Do not restart or modify `sigis.service`. Changes that affect
   the service go through the lead, who coordinates restarts with Leo.
8. Attribution: files derived from pyHanko carry a header naming their
   upstream file. Keep the crate's `NOTICE` (derived-file list) and its
   `LICENSE-pyHanko` copy current.
9. Unsafe code is forbidden in all crates (`#![forbid(unsafe_code)]`).

## 7. Lane briefs

The exact briefs given to each lane session are in §7.1–§7.5. All of them
include §1–§6 by reference.

### 7.1 Lane A — Certificates & CMS

> You are lane A of the sigis-hanko port of pyHanko (repo
> `/home/l/D/kooky/sigis`). Read `docs/hanko-lanes.md` first; its rules (§1
> reuse, §2 ownership, §5 tests, §6 integration) are binding. Work in the
> worktree `../sigis-wt/a-cms-cert` on branch `hanko/a-cms-cert` (create it
> from `main`).
>
> You own `crates/hanko-certvalidator`, `crates/hanko-cms`,
> `crates/hanko-fetch`, `crates/hanko-core/src/algorithms.rs`,
> `crates/hanko-core/src/asn1/`, `crates/hanko-testdata/data/lanes/a/` and
> `docs/lanes/a.md`.
>
> Scope (baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0 tags):
> 1. `hanko-cms`: port `sign/validation/generic_cms.py` (with the CMS-level
>    parts of `status.py` and `sign/general.py`): SignerInfo validation,
>    signed-attribute digest check, `SigningCertificate(V2)` binding,
>    signature-timestamp and content-timestamp validation (`x509-tsp`), key
>    usage constraints, the `StandardCmsSignatureStatus` family. Use the
>    `cms` crate for parsing.
> 2. `hanko-certvalidator` gaps: indirect CRLs / `cRLIssuer`,
>    `onlySomeReasons` accumulation, revocation of delegated OCSP responders,
>    registry and AIA issuer disambiguation, policy qualifiers and trust-anchor
>    qualifiers (`policy_proc`), attribute certificate validation, and `ltv/`
>    (POE manager, time slide, past validation), filling the stubs in
>    `src/ltv/`.
> 3. `hanko-fetch`: HTTP fetchers (OCSP, CRL, certificates) and the RFC 3161
>    TSA client, with cache, size limits, timeouts and multi-URL fallback
>    (`fetchers/`, `sign/timestamps/{api,requests_client,aiohttp_client,common_utils}.py`).
>    Use `reqwest` (blocking). Test against a local server on 127.0.0.1.
>
> Tests to port (§5.1): all 13 pyhanko-certvalidator modules (175
> functions; 25 already ported), `test_cms.py` (78),
> `test_key_usage_constraints.py` (4), `test_tsa_fetcher.py` (10),
> `test_tsa_fetcher_requests.py` (4). `test_name_trees.py` and
> `test_policy_graph.py` may be skipped with a reason if certval covers the
> behaviour (show the equivalent coverage). For signed inputs before lane D
> lands, generate fixtures with the pyHanko oracle (§5.4).
>
> Interfaces you fill: `hanko-cms` and `hanko-fetch` stubs,
> `hanko-certvalidator::ltv`. Lanes D and E depend on them, so land
> `validate_cms_signature` / `validate_timestamp_token` early.
>
> Acceptance: every assigned test ported and passing, or skipped with a
> reason in `PORTING.md`. NIST PKITS divergences reduced to the unsupported
> algorithms (DSA, pre-1970 UTCTime), unless you fix those too. "Never accept
> what pyHanko rejects" asserted. Gate green per phase. Report per-suite
> counts total / ported-pass / skipped / pending.

### 7.2 Lane B — PDF layer

> You are lane B of the sigis-hanko port of pyHanko (repo
> `/home/l/D/kooky/sigis`). Read `docs/hanko-lanes.md` first; its rules are
> binding. Work in `../sigis-wt/b-pdf` on branch `hanko/b-pdf`.
>
> You own `crates/hanko-pdf` (including `crates/hanko-pdf/fuzz`),
> `crates/hanko-testdata/data/lanes/b/` and `docs/lanes/b.md`.
>
> Scope (pyHanko 0.38.1 `pdf_utils/`), on top of `lopdf` 0.47 wherever it
> is sound. Measure lopdf against the tests; where lopdf is wrong or
> missing, contribute upstream or wrap it, and record the decision:
> 1. Reader with full revision history: xref tables and streams, object
>    streams, hybrid-reference files, incremental updates, historical object
>    resolution, strict and lenient modes, broken-file handling (`reader.py`,
>    `xref.py`, `generic.py`, `misc.py`, `rw_common.py`, `filters.py`,
>    `decode_limits.py`).
> 2. Incremental writer and object allocation (`incremental_writer.py`, the
>    needed parts of `writer.py`), byte-exact.
> 3. Signature discovery (`EmbeddedSignature`: field name, `/ByteRange`,
>    `/Contents`, signed revision, document timestamps) and DSS / VRI parsing
>    (`DocumentSecurityStore`), plus `form_tools.py`.
> 4. Embedded files (`embed.py`), extensions (`extensions.py`), metadata
>    (`metadata/`: Info and XMP), content stream parser
>    (`content_stream_parser.py`).
> 5. Encryption: standard and public-key security handlers, crypt filters,
>    permissions, credential serialization (`crypt/`), and PDF MAC
>    (`crypt/pdfmac.py`, ISO 32004). Use RustCrypto for the primitives.
> 6. cargo-fuzz targets for parsing, xref and object-stream decoding, and the
>    incremental writer round trip, in `crates/hanko-pdf/fuzz`. No panics on
>    any input.
>
> Tests to port: `test_xref.py` (60), `test_internal_utils.py` (127),
> `test_decode_limits.py` (29), `test_content_stream_parser.py` (8),
> `test_embed.py` (9), `test_meta.py` (39), `test_crypt.py` (84),
> `test_pdfmac.py` (50). Fixture PDFs are in
> `crates/hanko-testdata/data/pyhanko/pdf/`.
>
> Interfaces you fill: everything in `hanko-pdf` (§4). Lanes C, D and E code
> against it, so land `revisions`, `object_in_revision`,
> `objects_written_in`, `embedded_signatures`, `signed_data`, `dss` and
> `IncrementalWriter` first.
>
> Acceptance: every assigned test ported and passing or skipped with a
> reason; fuzz targets run clean for a documented time budget; gate green
> per phase; per-suite counts reported.

### 7.3 Lane C — Modification analysis

> You are lane C of the sigis-hanko port of pyHanko (repo
> `/home/l/D/kooky/sigis`). Read `docs/hanko-lanes.md` first; its rules are
> binding. Work in `../sigis-wt/c-diff` on branch `hanko/c-diff`.
>
> You own `crates/hanko-diff`, `crates/hanko-testdata/data/lanes/c/` and
> `docs/lanes/c.md`.
>
> Scope: port pyHanko 0.38.1 `sign/diff_analysis/` (`commons.py`,
> `constants.py`, `policy_api.py`, `policies.py`, `rules_api.py`,
> `form_rules_api.py`, `rules/file_structure_rules.py`,
> `rules/metadata_rules.py`, `rules/form_field_rules.py`). That is the
> whitelisting-based review of revisions after a signature: DocMDP levels,
> FieldMDP locks, form filling, annotations, DSS and document-timestamp
> updates, metadata updates, and `SuspiciousModification` reporting.
> Implement `DiffPolicy` / `StandardDiffPolicy` in `hanko-diff`, using only
> `hanko-pdf` for PDF access.
>
> Tests to port: `test_diff_analysis.py` (94 functions at the v0.38.1 tag;
> pyHanko `main` has more, which are not part of the baseline). Most tests
> modify signed PDFs with pyHanko's writer. Generate those inputs (and
> pyHanko's verdicts) with the oracle (§5.4) into
> `crates/hanko-testdata/data/lanes/c/`, and add a differential test that
> runs pyHanko's diff policy on every input.
>
> Dependencies: lane B (`PdfFile::{revisions, object_in_revision,
> objects_written_in, trailer_in_revision}`). Until B lands, write the rules
> and tests against those signatures; ask the lead for interface additions
> you need.
>
> Acceptance: all 94 tests ported and passing or skipped with a reason;
> "never accept what pyHanko rejects" asserted on every suspicious-modification
> case; gate green per phase; per-suite counts reported.

### 7.4 Lane D — Signing

> You are lane D of the sigis-hanko port of pyHanko (repo
> `/home/l/D/kooky/sigis`). Read `docs/hanko-lanes.md` first; its rules are
> binding. Work in `../sigis-wt/d-sign` on branch `hanko/d-sign`.
>
> You own `crates/hanko-sign`, `crates/hanko-testdata/data/lanes/d/` and
> `docs/lanes/d.md`.
>
> Scope (pyHanko 0.38.1):
> 1. CMS signing with the `cms` crate builder (`sign/signers/pdf_cms.py`,
>    `sign/general.py` signing parts, `sign/attributes.py`, `sign/ades/api.py`,
>    `sign/ades/cades_asn1.py`): `SimpleSigner` (PKCS#8, PKCS#12 via a mature
>    crate), signed attributes, CAdES attributes (signature policy,
>    commitment type, signer attributes), signature timestamps.
> 2. PDF signing (`sign/signers/pdf_signer.py`, `pdf_byterange.py`,
>    `cms_embedder.py`, `functions.py`, `constants.py`): PAdES B-B / B-T /
>    B-LT / B-LTA, certification (DocMDP), FieldMDP locks, DSS updates,
>    document timestamps, LTA renewal (`PdfTimeStamper`), signing encrypted
>    documents.
> 3. Fields and seed values (`sign/fields.py`).
> 4. Key providers: PKCS#11 via `cryptoki` (`sign/pkcs11.py`; tests with
>    SoftHSM), CSC remote signing (`sign/signers/csc_signer.py`; tests with a
>    local fake CSC server), key loading (`keys/`).
> 5. Test TSA (`sign/timestamps/dummy_client.py`), so tests need no network.
> 6. Visible appearances: `stamp/`, `pdf_utils/{layout,text,content,images,qr,barcodes}.py`,
>    `pdf_utils/font/` (use `ttf-parser`/`subsetter`, `image`, `qrcode`).
>
> Tests to port: `test_signing.py` (78), `test_pades.py` (48),
> `test_fields.py` (27), `test_seed_values.py` (36), `test_pkcs11.py` (36),
> `test_csc.py` (17), `test_sign_encrypted.py` (11), `test_stamp.py` (25),
> `test_text.py` (15), `test_images.py` (2), `test_barcode.py` (2). These
> tests validate what they sign: until lane E lands, validate outputs with the
> pyHanko oracle (differential), then with `hanko-validate`. Every produced
> PDF in the tests must also pass pyHanko's validator.
>
> Dependencies: lane B (`IncrementalWriter`, `PdfFile`), lane A
> (`ValidationContext` and fetchers for LTV collection, TSA client). Code
> against the stubs and ask the lead for interface additions.
>
> Final step (only at parity, through the lead): replace the vendored
> `underskrift` in the Sigis service with `hanko-sign`. Do not touch `src/`
> yourself.
>
> Acceptance: all assigned tests ported and passing or skipped with a
> reason; pyHanko accepts every PDF the port produces; gate green per
> phase; per-suite counts reported.

### 7.5 Lane E — Validation, AdES, trusted lists

> You are lane E of the sigis-hanko port of pyHanko (repo
> `/home/l/D/kooky/sigis`). Read `docs/hanko-lanes.md` first; its rules are
> binding. Work in `../sigis-wt/e-validate` on branch `hanko/e-validate`.
>
> You own `crates/hanko-validate`, `crates/hanko-ades`, `crates/hanko-eutl`,
> `crates/hanko-testdata/data/lanes/e/` and `docs/lanes/e.md`.
>
> Scope (pyHanko 0.38.1 `sign/validation/`):
> 1. `hanko-validate`: `pdf_embedded.py` (signatures per revision, coverage
>    levels, DocMDP / FieldMDP through `hanko-diff`), `status.py`,
>    `settings.py`, `policy_decl.py`, `utils.py`, `errors.py`, and the
>    validation side of `dss.py` (LTV with embedded revocation information,
>    Adobe-style and PAdES-LT/LTA modes).
> 2. `hanko-ades`: `ades.py` (EN 319 102-1 basic building blocks, validation
>    with timestamps, LTV / LTA, POE extraction, past signature validation,
>    using `hanko-certvalidator::ltv`), `sign/ades/report.py`, and
>    `report/tools.py` (JSON report and ETSI TS 119 102-2 XML via
>    `quick-xml`; do not translate `generated/`, write `serde` bindings for
>    the elements actually used).
> 3. `hanko-eutl`: `qualified/` (TS 119 612 trusted list parsing, LOTL
>    pivots, XAdES signature verification of lists, service history and
>    qualifiers, qualified status assessment), with `quick-xml`. XMLDSig
>    needs canonicalization: evaluate existing crates, contribute upstream if
>    close, otherwise implement the minimal Exclusive C14N needed, with
>    tests.
>
> Tests to port: `test_ades_validation.py` (40),
> `test_ades_validation_report.py` (5), `test_ades_validation_requests.py`
> (2), `test_trusted_list.py` (53). Trusted-list fixtures are in
> `crates/hanko-testdata/data/pyhanko/tl/`. Signed PDFs for the validation
> tests: generate with the oracle (§5.4) until lane D lands. Add a
> differential test comparing your verdicts with pyHanko's on every
> generated input.
>
> Dependencies: lanes A (`hanko-cms`, `ltv`), B (`hanko-pdf`), C
> (`hanko-diff`). Code against the stubs.
>
> Acceptance: all assigned tests ported and passing or skipped with a
> reason; differential verdicts never more lenient than pyHanko; gate green
> per phase; per-suite counts reported. When `validate_pdf_signature` works,
> tell the lead so `/api/verify` can expose it behind a flag.
