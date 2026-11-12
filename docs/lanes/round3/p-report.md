# Round 3 lane P progress report

Status: in progress. Branch: `hanko/r3-p`. Baseline: `34482bf`.

## Accounting

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| sigis-pades-sign | 297 | 271 | 13 | 13 |

These are inherited unique-function counts, not newly verified claims.
No new pass is claimed until the Rust assertions and relevant oracle checks run.
The exact assignment is the lane P entries in `ownership.json`.

## Work in progress

- Port exact upstream HTTP TSA, seed URL and AC presigning/DSS assertions before implementation.
- Independently implement public-key encrypted signing, copy/back-reference handling and signed attachments.
- Review certificate-less signing, duplicate attributes, detached eContent and provider exclusions.
- Audit PDF MAC signing and inherited CMS embedder/DSS assertion completeness.

## Interface requests

The core `KeySigner::signing_cert() -> &Cert` contract cannot represent the
upstream certificate-less `ExternalSigner(None)` flows. P is preparing an
exact minimal request; no cross-lane file has been edited.

## Verification and evidence

Initial command (running): `tools/cargo-locked.sh check -p sigis-pades-sign`.
Logs and staged handoffs: `/home/l/.codex/artifacts/sigis/round3/p/`.
Oracle: `/tmp/pyhanko-oracle/venv/bin/python`; live comparisons have not yet
been claimed in this round. Existing lane D fixtures remain read-only.

## Commits and cleanliness

No round 3 implementation commit yet. Initial worktree was clean.
Only owned paths and this explicitly requested lane report are being edited.

## Approved coordination increment: exact proposed interfaces

Updated against main `db8a75c`. These signatures are proposals, not delivered
or accepted code. No function counts change. The source of the three S-owned
caller tests has been checked in pinned `test_decode_limits.py`.

### Decode limits and state transfer

Exports: `sigis_pades_sign::pdf::writer::{PdfReopenState, PdfOperationResult}`.
All `Result` below means `sigis_pki_core::errors::Result`.

```rust
#[derive(Clone, Debug)]
pub struct PdfReopenState { /* authenticated PdfFile handle, private */ }
impl PdfReopenState {
    pub fn from_reader(reader: sigis_pdf::PdfFile) -> Self;
    pub fn decode_context(&self) -> sigis_pdf::decode_limits::DecodeContext;
    pub fn strict(&self) -> bool;
}
#[derive(Clone, Debug)]
pub struct PdfOperationResult {
    pub pdf: Vec<u8>,
    pub state: PdfReopenState,
}
// Added fields; existing fields and defaults stay compatible.
pub struct SignOptions {
    pub decode_limits: sigis_pdf::decode_limits::DecodeLimits,
    pub reopen_state: Option<PdfReopenState>,
    // existing fields ...
}
pub struct TimestampOptions<'a> {
    pub decode_limits: sigis_pdf::decode_limits::DecodeLimits,
    pub strict: bool,
    pub reopen_state: Option<PdfReopenState>,
    // existing fields ...
}
impl PdfSigner {
    pub fn sign_pdf_with_state(
        &self, pdf: &[u8], opts: &SignOptions,
    ) -> Result<PdfOperationResult>;
}
impl PdfTimeStamper {
    pub fn timestamp_pdf_with_state(
        &self, pdf: &[u8], opts: &TimestampOptions<'_>,
    ) -> Result<PdfOperationResult>;
    pub fn update_archival_timestamp_chain_with_state(
        &self, pdf: &[u8], ctx: &ValidationContext,
        default_md: DigestAlgorithm, state: PdfReopenState,
    ) -> Result<PdfOperationResult>;
}
// sigis_pades_sign::pdf::dss
pub fn add_dss_with_state(
    pdf: &[u8], content: &DssContent<'_>, force_write: bool,
    state: PdfReopenState,
) -> Result<PdfOperationResult>;
```

New defaults: `decode_limits = DecodeLimits::default()`, `strict = true`,
`reopen_state = None`. With `Some(state)`, its selected limits, remaining
budget, strictness and authenticated decryptor are authoritative. Legacy
byte-only wrappers retain their signatures and delegate to the stateful path;
they discard only the final returned state. Internal post-signing, timestamp,
archival and DSS calls always transfer the state and never make a default
reader or call `DecodeContext::fresh()`.

Required L-routed shared primitive (not implemented by P):

```rust
// sigis_pdf::PdfFile
pub fn reopen(&self, bytes: &[u8]) -> sigis_pdf::PdfResult<Self>;
```

It must initialise the parser with `self.decode_context()` before xref decoding,
carry strict/lossless mode and `self.decryptor()`, and charge every newly decoded
xref/object/stream byte against the existing remaining budget. It must not
increase the budget based on the larger output file. Public reader APIs currently
only initialise a fresh context; P cannot implement this primitive without
editing S-owned reader internals. P will use the PDF reader for actual object
resolution and bounded stream reads rather than allowing unbounded lopdf loads.

Concrete caller sequence (all named types imported from the paths above):

```rust
let signed = signer.sign_pdf_with_state(&input, &SignOptions {
    decode_limits: selected_limits,
    ..Default::default()
})?;
let archived = tsa.update_archival_timestamp_chain_with_state(
    &signed.pdf, &validation_context, DigestAlgorithm::Sha256, signed.state,
)?;
let final_pdf = add_dss_with_state(
    &archived.pdf, &dss_content, false, archived.state,
)?;
```

S-owned IDs (no P count credit):
`pyhanko/test_decode_limits.py::test_post_sign_reopen_keeps_limits`
(two DSS placements),
`pyhanko/test_decode_limits.py::test_archival_timestamp_update_keeps_limits`,
and `pyhanko/test_decode_limits.py::test_add_dss_keeps_limits`.
P will supply lower-level regression evidence in addition to S's caller tests.

### Scheduling correction

The earlier report's initial check was launched under the obsolete wrapper;
its log records old repository-lock and package/build-cache waits, not a
successful check. No completion is claimed. All new Cargo commands use the
current wrapper with system rust-slots, without forced local mode, job flags,
or an empty RUSTC_WRAPPER. Host/slot evidence will be recorded from the next
necessary targeted verification.

First necessary check under repaired scheduling: `tools/cargo-locked.sh check
-p sigis-pades-sign` completed successfully. Evidence:
`/home/l/.codex/artifacts/sigis/round3/p/check-slots.log` reports
`rust-remote: vm2064 slot0 /home/l/D/kooky/sigis-wt/r3-p`, and
`Finished dev profile ... in 0.22s`. This is baseline compilation evidence;
no new function passes follow from it.

## Verified layout/resource assertion increment

`crates/pades-sign/tests/test_round3_layout.rs` ports all 28 upstream assertions
and exception contexts across the four S-owned IDs below. No parameters exist
in the pinned source. No provider/runtime exclusions apply.

| S-owned ID (`pyhanko/test_internal_utils.py::`) | Rust test |
| --- | --- |
| `test_box_constraint_over_underspecify` | `test_round3_layout::test_box_constraint_over_underspecify` |
| `test_box_constraint_recalc` | `test_round3_layout::test_box_constraint_recalc` |
| `test_resource_add_test` | `test_round3_layout::test_resource_add_test` |
| `test_duplicate_resource` | `test_round3_layout::test_duplicate_resource` |

`HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test
-p sigis-pades-sign --test test_round3_layout` passed: **4 passed, 0 failed,
0 ignored**. Log: `/home/l/.codex/artifacts/sigis/round3/p/layout-rust.log`.
Fresh pinned Python execution of the original four functions also passed;
this is separate from Rust execution, not fixture replay. Full reproducible
mapping, error kinds and oracle command: `.../p/layout.md`.
These functions remain S-owned and add **zero** to P's 297-function total.
