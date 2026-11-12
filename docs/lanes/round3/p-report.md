# Round 3 lane P progress report

Status: **independent increment ready for L integration**, full lane unfinished.
Branch `hanko/r3-p`, rebased onto accepted main `62a72a2`. No S/V source edits.
The full stateful/MAC/HTTP/AC work is preserved outside the active source under
`/home/l/.codex/artifacts/sigis/round3/p/split-increments/full/`; its missing
shared APIs do not block this independently verified increment.

## Committed increments

| Commit | Change |
| --- | --- |
| `3a0a2ad` | Optional-certificate SigningProvider/DeferredSigner, eight exact certificate-less ports, two exact malformed-CMS rejections, validation-policy preservation, provider skip review |
| `21ac460` | Signed payload and detached CMS attachments, complete related-file/Unicode/byte-equality assertions |
| `8e2107b` | Complete CMS digest-refusal/embedder/DSS assertions and real Rust difference/trust checks for inherited PAdES matrices |

The independent four-layout-function increment is already on main as `33bc368`
(original lane commit `1147918`, previously `3c0b471`). It earns P no count.
No push or other-worktree modification occurred.

## Unique upstream function accounting

| State | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| Last accepted P baseline | 297 | 271 | 13 | 13 |
| Proposed after this verified increment, awaiting L acceptance | 297 | 282 | 2 | 13 |

Eleven newly completed P functions: eight certificate-less functions, duplicate
signer-attribute rejection, detached-eContent rejection, and the attachment.
Raw DSA is honestly moved from inherited skipped to pending because it lacks
actual token invocation/import support. Remaining skipped functions are the
SafeNet hardware case and a Python-specific deprecation warning. The 13 proposed
pending are twelve original pending functions (all except attachment) plus DSA.
The immutable ownership manifest and central accepted counts were not edited.

| Assigned suite | Total | Proposed passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| test_signing.py | 78 | 77 | 1 | 0 |
| test_pades.py | 48 | 40 | 0 | 8 |
| test_seed_values.py | 36 | 35 | 0 | 1 |
| test_sign_encrypted.py | 11 | 8 | 0 | 3 |
| test_pkcs11.py | 36 | 34 | 1 | 1 |
| Remaining assigned suites | 88 | 88 | 0 | 0 |
| Total | 297 | 282 | 2 | 13 |

Rust test counts, parameter instances and oracle calls below are different
units; none creates extra upstream function credit. The three repaired PAdES
functions were already baseline passes; the two CMS functions below remain S-owned.

## Exact ready P function mapping

All Rust test names are identical to the upstream function name.

| Exact upstream ID | Rust suite | Original parameters/assertions |
| --- | --- | --- |
| pyhanko/test_signing.py::test_interrupted_with_delayed_signing_cert_mech | test_round3_certless | No cert, Size256, explicit SHA256-RSA, reservation 8192, copied prepared output, real trusted completion |
| pyhanko/test_signing.py::test_interrupted_with_delayed_signing_cert_directly_specify_md | test_round3_certless | No cert/mechanism, explicit SHA256, reservation 8192, real trusted completion |
| pyhanko/test_signing.py::test_interrupted_could_not_determine_digest_algo | test_round3_certless | No cert/mechanism/digest; Signing refusal with original message fragments |
| pyhanko/test_signing.py::test_interrupted_no_estimation | test_round3_certless | Bytes256/fixed mechanism, no reservation; explicit estimation/bytes_reserved refusal |
| pyhanko/test_signing.py::test_interrupted_with_delayed_signing_no_prevalidation | test_round3_certless | Embed validation info with missing cert; explicit certificate refusal |
| pyhanko/test_signing.py::test_determine_mechanism_no_signing_cert | test_round3_certless | Direct mechanism selection without cert/mechanism refuses |
| pyhanko/test_signing.py::test_signer_info_no_signing_cert | test_round3_certless | Actual CMS SignerInfo construction without cert refuses |
| pyhanko/test_seed_values.py::test_sign_with_sv_missing_cert | test_round3_certless | Required subject-DN seed constraint, missing cert, existing field, explicit mechanism/reservation; exact refusal |
| pyhanko/test_pades.py::test_cades_signer_attrs_multivalued | test_round3_skips | Two identical DER values, no embedded ACs, valid/intact input; Expected single rejection for AC-context true/false in Rust and live oracle |
| pyhanko/test_signing.py::test_sign_reject_econtent_if_detached | test_round3_skips | Unchanged upstream encapsulated-content fixture; full Rust PDF rejection and live error class/message agreement |
| pyhanko/test_signing.py::test_embed_signed_attachment | test_round3_attachment | Fixed original time, detached SHA256 CMS, all ten original assertions plus RF/F, RF/UF and standalone EF/UF same-stream references |

No parameters or runtime providers are skipped in these eleven exact ports.
The eight certificate-less functions have ten Rust wrappers because two extra
refusal-collision regressions were added; they still count as eight functions.
The attachment live comparison is mandatory, checks pyHanko 0.38.1 and rereads
the actual Rust output. Japanese UF names, Names ordering and exact payload/CMS
bytes are preserved.

## Delivered signing interfaces and policy repair

`sigis_pades_sign::signer::SigningProvider` exposes:

```rust
pub trait SigningProvider: Send + Sync + std::fmt::Debug {
    fn signing_cert(&self) -> Option<&Cert>;
    fn cert_chain(&self) -> &[Cert];
    fn signature_algorithm(&self, digest: DigestAlgorithm)
        -> Result<spki::AlgorithmIdentifierOwned>;
    fn sign_raw(&self, data: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>>;
}
```

`DeferredSigner::new(cert: Option<Cert>, chain: Vec<Cert>,
signature_value: DeferredSignatureValue, mechanism: Option<AlgorithmIdentifierOwned>)
-> Self`, with `DeferredSignatureValue::{Size(usize), Bytes(Vec<u8>)}`.
Legacy `PdfSigner::new(metadata, Arc<dyn KeySigner>)` remains available through
an adapter; `PdfSigner::with_signing_provider(metadata, Arc<dyn SigningProvider>)
-> Self` supports delayed certificates. The core KeySigner trait was untouched.
PdfSigner.signer and CmsSigner.signer now use this optional-certificate trait.
No fake cert or panic is used; actual SignerInfo assembly requires a real cert.

Presign context extension now calls caller_context.with_revinfo rather than
rebuilding defaults. A real PdfSigner negative test first demonstrated that
an explicitly forbidden SHA256-RSA certificate algorithm still signed a PDF;
with the fix, that request refuses and the explicit-allow control signs and
validates. The complete caller algorithm/freshness/trust/assertion/AC policy is
preserved by cloning. These two extra behavioral regressions add no upstream
function count. A fresh pinned Python real-signing probe agrees on both outcomes.

Independent review additionally found two diagnostic-priority differences.
New red tests reproduced both; fixed code checks CMS mechanism consistency
before missing SignerInfo cert, and missing presign cert before missing VC.
Both are rejection-diagnostic compatibility repairs, not trust-verdict claims.
Python puts policy detail in the exception cause; Rust includes it in the
outer Signing message. That diagnostic encoding difference is reported separately.

## Complete audit of all 13 inherited signing skips

Ten ready ports are the eight certificate-less and two rejection functions
listed above. The exact remaining IDs are:

| Exact ID | Honest disposition |
| --- | --- |
| pyhanko/test_pkcs11.py::test_simple_sign_from_config_with_signing_pin | SafeNet-only upstream platform/signing PIN; no SafeNet provider configured. Retain explicit provider exclusion, not SoftHSM proof |
| pyhanko/test_pkcs11.py::test_simple_sign_with_raw_dsa | Pending implementation. Core DSA verification works, but pinned cryptoki lacks safe CKM_DSA construction and the token helper lacks native DSA import |
| pyhanko/test_signing.py::test_default_validation_context_deprecated | Python DeprecationWarning about implicit OS trust; no corresponding Rust warning API. Retain language/API exclusion |

`skips.md` retains all thirteen exact IDs, source lines and original parameters;
`certless-implementation.md` records the eight implementations;
`providers-implementation.md` records the SafeNet/DSA proof and the reviewed
external `cryptoki-dsa-mechanism.patch`. No registry/vendor/root dependency
source was modified. CKA_SUBPRIME can already use a safe generic Attribute;
the minimal dependency patch concerns DSA mechanism constants/conversion arms.
L must select an auditable dependency source before real token acceptance.

Extra Rust regressions prove duplicate DER preservation, real DSA certificate
signature verification/tamper rejection, and raw-DSA digest/encoding selection;
they do not stand in for token signing. Runtime exclusions still include DSA,
ML-DSA and three combined ECDSA provider mechanisms; no new HSM run is claimed.
Fresh Python PKCS11 collection lacked python-pkcs11; shared environments and
services were not changed to hide this limitation. Stale core/duplicate-model
ignore reasons have been corrected.

## S-owned assistance and repaired inherited P assertions

The four S-owned layout/resource functions have complete 28-assertion coverage
in test_round3_layout and were integrated on main. New independently verified
S-owned ports are in test_round3_partial_assertions:

- pyhanko/test_cms.py::test_overspecify_cms_digest_algo: matching SHA256 signature
  is intact/valid/untrusted, and conflicting SHA512 request is refused by signer.
- pyhanko/test_cms.py::test_direct_pdfcmsembedder_usage: real low-level certify,
  validation, DSS update, then trusted revalidation with StandardDiffPolicy;
  exact certificate/OCSP counts and original coverage/modification assertions.

These two functions earn zero P credit; L/S must update their acceptance.
P-owned test_pades_two_revisions (three settings), test_pades_lta_two_revisions
(four settings), and test_dss_setting_validation now additionally assert native
integrity/trust/difference/error types; parameter coverage is complete and their
baseline pass counts are not counted again. Details: partial-assertions.md.
V full long-term/AdES status remains separate from ordinary Rust integrity/trust.

## Verification and reproducible commands

All commands use the absolute scheduler launcher in tools/cargo-locked.sh.
No repository lock, forced local mode, job flags, empty RUSTC_WRAPPER, target
cleanup, process kills or service restarts were used. No manual remote Cargo.

```sh
tools/cargo-locked.sh check -p sigis-pades-sign
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p sigis-pades-sign --test test_round3_certless --test test_round3_skips --test test_round3_attachment --test test_round3_partial_assertions --test test_round3_context_policy --test keys_and_cms --test test_signing --test test_seed_values --test test_pades -- --nocapture
tools/cargo-locked.sh clippy -p sigis-pades-sign --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' tools/cargo-locked.sh doc -p sigis-pades-sign --no-deps
tools/cargo-locked.sh fmt -p sigis-pades-sign -- --check
```

Evidence directory: `/home/l/.codex/artifacts/sigis/round3/p/split-increments/`.

| Evidence | Result |
| --- | --- |
| rebased-check.log | Passed on main62a72a2 + ready commits; vm2064 / slot0 |
| rebased-tests.log | 172 passed across nine suites, 0 failed/ignored; vm2064 / slot0 |
| clippy-final.log | all-target -D warnings passed before rebase; vm2064 / slot0 |
| docs.log, fmt.log | strict docs/package formatting passed before rebase |
| rebased-clippy.log, rebased-docs.log, rebased-fmt.log | all-target -D warnings, strict docs and package formatting passed on the rebased source |
| refusal-order-red.log | two new collision failures before the compatibility fixes |
| context-policy-red.log | real forbidden-policy request incorrectly signed before fix; positive control passed |
| context-policy-final.log | both real policy controls pass after fix; vm2064 / slot1 |
| review.md, context-policy.md, corresponding oracle scripts/logs | pinned live priority probes and actual Python policy denial/allow control agree |

The final same-Rust-output live comparisons are mandatory for new exact ports.
The new suites show two trusted delayed-signing PDFs, both duplicate-attribute
AC-context rejections, detached-eContent rejection, the attachment reread, and
the CMS/DSS matrix verdicts. These are fresh interpreter evaluations, not replay
of verdict records. Original Python function runs and fixed D PKI/revinfo input
fixtures remain separate evidence; their counts are not summed as new passes.
The initial skip smoke had 4 pass/1 fail because an incorrect duplicate-model
assumption was tested; the corrected preservation/rejection tests now pass.

## Remaining implementation and precise interface requests

All remaining twelve original pending functions and raw DSA remain pending.
HTTP/seed URL, seven AC functions, public-key signing/copy, decode state and MAC
source/tests are preserved in split-increments/full and implementation-checkpoint
tar.gz. They are not accepted or implicitly exported by this ready increment.

The approved stateful proposal below was published to L before implementation;
its earlier report history is preserved. **These are parked interfaces, not
currently delivered public APIs.** The compilation dependency is the proposed
`sigis_pdf::PdfFile::reopen(&self, bytes: &[u8]) -> PdfResult<Self>`.
A reviewable artifact patch/design is supplied, not applied to S-owned source.
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


Additional implemented signatures:

```rust
// sigis_pades_sign::pdf::signer::PdfTbsDocument
pub fn finish_signing_with_state(
    prepared: PreparedDocument, cms: &[u8], psi: Option<&PostSignInstructions>,
    validation_context: Option<&ValidationContext>,
) -> Result<PdfOperationResult>;
// Additional SignOptions field, default None; state remains authoritative.
pub pubkey_credential: Option<Arc<dyn sigis_pdf::crypt::EnvelopeKeyDecrypter>>;
// PdfSignatureMetadata, default None
pub ac_validation_context: Option<Arc<ValidationContext>>;
```

The writer now obtains objects and decoded DSS streams through the bounded
native PDF reader. It no longer calls lopdf's unbounded eager loader, and
DSS decode failures are propagated instead of falling back to raw bytes.
Native encryption preserves the original file and writes incremental updates;
password/public-key credentials and authenticated handlers survive state transfer.
The effective seed-URL TSA is session-local and used for presign validation,
size estimation, final CMS signing and LTA timestamp instructions. Explicit
TSA configuration takes precedence over a seed URL.


Additional L-routed requests remain:

- Public existing `SecurityHandler::mac_token_handler(&self) ->
  Option<Arc<dyn sigis_pdf::crypt::pdfmac::PdfMacTokenHandlerFactory>>` to retain
  the same custom factory handle during attached MAC generation.
- Default-NotFound `OcspFetcher::fetch_ac_ocsp(&self, ac_der: &[u8], issuer: &Cert)
  -> std::result::Result<Vec<u8>, FetchError>` and
  `CrlFetcher::fetch_ac_crls(&self, ac_der: &[u8]) ->
  std::result::Result<Vec<Vec<u8>>, FetchError>`, with lower HTTP request limits
  preserved. Current parked AC helper requires supplied mandatory evidence;
  this does not close automatic-fetch parity.
- Minimal auditable cryptoki DSA capability increment described above.

The parked per-session MAC API is
`PdfMacSessions::begin(&self, &SecurityHandler, &str) ->
Result<Option<PdfMacSigningSession>>` and
`PdfMacSigningSession::attach_to_cms(&self, &[u8], &[u8], bool) -> Result<Vec<u8>>`.
The shared signer holds only a lease registry, no document key; overlapping
sessions reject with `Other PDF MAC attribute provider found`. Its full tests
for timestamp MACs, standalone DSS MACs, duplicate attributes, invalid digests
and key isolation are still unverified pending shared reader integration.
S owns the two PDF MAC and three decode caller functions; P never adds them
to its count. V owns full LTA acceptance.

## Dependencies, cleanliness and recovery

Only existing workspace acyclic dev-dependencies sigis-pades, sigis-cms and
sigis-pdf-diff are added in this ready increment. No production dependency,
new version or layer relaxation. The approved pki-fetch production use belongs
to the parked/next HTTP increment. L owns merged manifest/lockfile acceptance.

Active implementation/test files are committed. This report, PORTING and handoff
are committed as an owned documentation increment. A generated **Cargo.lock is
uncommitted** and excluded from lane commits; its diff only adds the three
new dev-dependency names to sigis-pades-sign. L regenerates the merged lockfile.
Unused future modules/fixtures/tests were parked outside the repo with complete
copies; no unrelated file or old D fixture was edited.

Recovery artifacts: split-increments/full, split-increments/verified-source,
implementation-checkpoint.patch/tar.gz, report-history.md and pre-rebase backups.
Do not overwrite verified CMS refusal-order fixes or mandatory oracle assertions
when restoring the older full snapshot. No verdict/encoding difference is
universally called fail-closed; attachment date UTC encoding and exception
cause formatting are compatibility differences. Missing mandatory trust policy
or evidence rejects explicitly.


## Lead integration acceptance

L accepted this independent source increment after the full workspace gate
on main8a1568c: P297/282/3/12. Original source commits3a0a2ad/21ac460/8e2107b
were curated as1f30b59/ecea1bf/c5cdae7. No parked reopen/MAC implementation
was imported. Four cross-validator suites now live in root integration tests
round3_signing_{certless,context_policy,skips,partial_assertions}.rs, keeping
the package graph acyclic; all assertions and original function owners remain.
Attachment/layout suites remain in P. Historical command logs above retain
the original P-local paths; the final root gate is separate evidence.

S owns the restored CMS overspecify pass. Direct embedder still needs actual
caller-buffer identity; native low-level/DSS coverage alone does not finish it.
SigningProvider changes public certificate access to Option and changes erased
CmsSigner struct-literal construction; legacy high-level constructors are
adapted. Consumers must use the provider interface or legacy adapters.

Shared reader reopen and MAC factory getter are accepted on main; their
consumer signing/stamp/DSS/archival state propagation remains P work.
