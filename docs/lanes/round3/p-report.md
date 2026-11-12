# Lead acceptance: stateful signing and borrowed CMS

The coherent P runtime source0054aee passed all six gates, then source03a156c
passed the combined gate after closing a newly reproduced shared CRL defect:
1535 discovered / 1527 passed / 8 ignored / zero failed,
across136 reports. Five P functions become passed (seed HTTP URL,
HTTP TSA/revinfo, two public-key signing modes and the signed plaintext copy).
The exact borrowed-buffer CMS function becomes passed once under S/CMS, with
original Vec identity retained through both signing and DSS continuation.
No renderer/state/MAC helper or oracle call adds an upstream-function count.
P297/287/3/7; CMS78/76/1/1; S824/791/27/6; overall1431/1127/30/274.

Caller-selected reader options, decode snapshots and authentication now flow
through signing/DSS/timestamps/stamps and borrowed operations. Session-local
MAC state rejects concurrent shared-signer reuse; caller-buffer failure paths
are staged atomically. The legacy post-parse set_strict method is still a
separate declared compatibility gap. Complete five S PDF callers and seven
P AC functions remain pending; component MAC proof is not whole-function LTA
acceptance. The lockfile adds one existing pki-fetch edge, no version change.

The shared CRL failure was real: a stack shortcut accepted an invalid signature.
L's independent direct verify_ac_crl/full validate_ac tests first failed twice
while the genuine control passed, using a different existing fixture from P's
original ambiguous loop. Actual AC/AA/good/bad/TBS/algorithm SHA receipts match
fresh pinned Python bytes. The fix exempts only issuer certificate path recursion;
every current CRL still requires signed_by. Existing nonrecursive path/signature
order, scope, key usage, freshness, reasons, delta and later policies remain.
Three fixed tests exercise require and soft-fail; eight fresh same-input public
Python decisions and197 existing CV tests pass. Helpers earn zero unique credit.
The prior reference also has a narrower active-path shortcut; this bounded
repair is not a universal claim of lexical equivalence or all-input trust parity.
Evidence: round3-launch/ac-crl-recursion/ and p-integration/.

The following owner checkpoint retains historical source/assertion provenance.
Its provisional tables do not replace the accepted ledger above.

# Round 3 lane P progress report

Status: **consumer, borrowed CMS and AA fetched-candidate increments ready
for L integration; full lane unfinished**.
Coordinator consolidation checkpoint **main62a72a2** records accepted
P297/271/13/13, with layout4 credited only to S/PDF. The repository has since
advanced: the current pinned main **f91dccdc43f8ad852dcafacee3670269c2a872d7**
contains later ledger/API updates, including accepted MD5 sourcec69886c and
the default-NotFound AC retrieval methods from eb0e43a. Its own status table
records P297/282/3/12. These are different named main snapshots, not a lane
count promotion; exact current main ledger/status remain L-owned authority.
No helper/oracle credit is added. The tables below retain their named provenance.
P will checkpoint this report and safely rebase onto pinned f91dccd, retaining
the complete generated lockfile and every owned source/fixture byte. The
already accepted digest patch should be skipped by patch identity; its tests
must remain present. The wrapper has no dirty difference and will not be
staged, reverted or committed by P.
Branch `hanko/r3-p` has pinned main base **cef64d3**, which includes requested
main9ebd87b and the accepted shared reader/MAC/context APIs. P has not rebased
again while L coordinates current integration. Consumer source commits are
**90ac9e5 + 6abf333** (formerly e6c9a39 + e02f345); the owned source/fixtures
were byte-for-byte unchanged by that rebase. The separately verified CMS source
is **6e00181 + e59b307 + bbc6c3d**, documented at c72dcb9. Prior verification
retains its original commit provenance; later checkpoints appear below.
Only P-owned source/fixtures/report are edited; generated Cargo.lock is excluded.
L owns integration, the full workspace gate and any function-count acceptance.
The legacy post-parse set_strict boundary and seven AC function gaps remain
explicit requests, not delivered or silently accepted behavior.

## Authoritative accounting and candidate functions

| State | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| Accepted by L, main8a1568c and later | 297 | 282 | 3 | 12 |
| Candidate after five exact HTTP/encrypted functions, pending review/gate | 297 | 287 | 3 | 7 |

The candidate retains L's accepted raw-DSA skip classification. P's review
identifies it as an implementation gap, not a core-verification limitation;
central reclassification belongs to L/S. Seven AC functions remain pending.
Native helper tests, S-owned callers and fresh Python calls add no P functions.

| Exact new candidate ID | Rust test / parameters / assertions |
| --- | --- |
| pyhanko/test_seed_values.py::test_sv_timestamp_url | test_round3_http_tsa::test_sv_timestamp_url; required seed URL, no explicit client, actual HTTP imprint/nonce, seed status and original details assertion |
| pyhanko/test_pades.py::test_pades_revinfo_http_ts_dummydata | test_round3_http_tsa::test_pades_revinfo_http_ts_dummydata; real HTTP token, Sig1/PAdES subfilter, five DSS certificates/one OCSP, native integrity, fresh oracle timestamp status |
| pyhanko/test_sign_encrypted.py::test_sign_crypt_pubkey_aes256 | test_sign_encrypted::test_sign_crypt_pubkey_aes256; real recipient authentication, native PDF/CMS integrity, fresh oracle intact/valid/trusted/ENTIRE_FILE/NONE and status detail assertions |
| pyhanko/test_sign_encrypted.py::test_sign_crypt_pubkey_rc4 | test_sign_encrypted::test_sign_crypt_pubkey_rc4; same exact assertions with RC4 public-key fixture |
| pyhanko/test_sign_encrypted.py::test_copy_file_with_mdp_signature_and_backref | test_sign_encrypted::test_copy_file_with_mdp_signature_and_backref; native plaintext single-revision copy, catalog back-reference retained, compute_integrity_info and skip_diff=True oracle rejects original signature integrity |

No provider/runtime exclusion in these five candidates. Fixed input fixtures
remain read-only. All new live comparisons require the pinned interpreter;
missing oracle is a test failure. Extra HTTP tests cover optional URL inactivity,
explicit-client precedence, mandatory-empty URL refusal and seed TSA archival
propagation without mutating the reusable signer's configured client.

## Accepted earlier increment and all 13 inherited skips

Original commits3a0a2ad/21ac460/8e2107b were curated by L as
1f30b59/ecea1bf/c5cdae7 and accepted after the workspace gate. Backup history
remains at backup/r3-p-phase1-d9eb861. The four cross-validator suites moved to
root round3_signing_{certless,skips,context_policy,partial_assertions}.rs;
no cyclic dev-dependency was restored. The attachment stays in P.

| Exact inherited upstream ID | Disposition / Rust equivalent / parameter coverage |
| --- | --- |
| pyhanko/test_pades.py::test_cades_signer_attrs_multivalued | Accepted; root round3_signing_skips same-name test, duplicate DER SET values preserved, full Rust rejection with AC-context false/true, fresh oracle agreement |
| pyhanko/test_pkcs11.py::test_simple_sign_from_config_with_signing_pin | Skipped; exact SafeNet provider/signing PIN case, hardware unavailable; SoftHSM does not replace it |
| pyhanko/test_pkcs11.py::test_simple_sign_with_raw_dsa | Central skipped, reviewed implementation gap; core verifies real DSA signatures/tamper, but no safe pinned cryptoki CKM_DSA constructor/native token import; no actual token-signing claim |
| pyhanko/test_seed_values.py::test_sign_with_sv_missing_cert | Accepted; root round3_signing_certless same-name test, mandatory subject DN seed, existing field, explicit mechanism/reservation, missing certificate refusal |
| pyhanko/test_signing.py::test_default_validation_context_deprecated | Skipped; Python DeprecationWarning/implicit OS trust API has no Rust equivalent |
| pyhanko/test_signing.py::test_interrupted_with_delayed_signing_cert_mech | Accepted; root round3_signing_certless same-name test, Size256/SHA256-RSA/reserved8192, real trusted delayed completion |
| pyhanko/test_signing.py::test_interrupted_with_delayed_signing_cert_directly_specify_md | Accepted; same root suite/name, explicit SHA256/no mechanism, reserved8192, real trusted completion |
| pyhanko/test_signing.py::test_interrupted_could_not_determine_digest_algo | Accepted; same root suite/name, absent cert/mechanism/digest, exact signing refusal |
| pyhanko/test_signing.py::test_interrupted_no_estimation | Accepted; same root suite/name, Bytes256/fixed mechanism/no reservation, estimation refusal |
| pyhanko/test_signing.py::test_interrupted_with_delayed_signing_no_prevalidation | Accepted; same root suite/name, validation-info embedding with missing cert, exact precedence/refusal |
| pyhanko/test_signing.py::test_determine_mechanism_no_signing_cert | Accepted; same root suite/name, direct missing mechanism refusal |
| pyhanko/test_signing.py::test_signer_info_no_signing_cert | Accepted; same root suite/name, actual SignerInfo construction refusal |
| pyhanko/test_signing.py::test_sign_reject_econtent_if_detached | Accepted; root round3_signing_skips same-name test, unchanged encapsulated fixture, full Rust rejection and oracle class/message agreement |

The separately accepted attachment function is
pyhanko/test_signing.py::test_embed_signed_attachment, P test_round3_attachment:
all original assertions, Japanese UF names, ordering, payload/CMS exact bytes
and RF/F/RF/UF/EF/UF same-stream identity. No parameters skipped.

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

Ten accepted ports are the eight certificate-less and two rejection functions
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
in test_round3_layout and were integrated on main. The centrally hosted root round3_signing_partial_assertions suite covers:

- pyhanko/test_cms.py::test_overspecify_cms_digest_algo: matching SHA256 signature
  is intact/valid/untrusted, and conflicting SHA512 request is refused by signer.
- pyhanko/test_cms.py::test_direct_pdfcmsembedder_usage: real low-level certify,
  validation, DSS update, then trusted revalidation with StandardDiffPolicy;
  exact certificate/OCSP counts and original coverage/modification assertions.

These functions earn zero P credit. L accepted overspecify; direct embedder
remains pending because actual caller-buffer identity is not yet covered.
P-owned test_pades_two_revisions (three settings), test_pades_lta_two_revisions
(four settings), and test_dss_setting_validation now additionally assert native
integrity/trust/difference/error types; parameter coverage is complete and their
baseline pass counts are not counted again. Details: partial-assertions.md.
V full long-term/AdES status remains separate from ordinary Rust integrity/trust.


## Current state and concurrency interfaces

The signatures below were published and sent to L before implementation. They
are present in the active P source; consumer acceptance remains separate.
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

Accepted L-owned shared primitive (consumed by P):

```rust
// sigis_pdf::PdfFile
pub fn reopen(&self, bytes: &[u8]) -> sigis_pdf::PdfResult<Self>;
```

The accepted reader preserves remaining allowance before eager xref decoding,
strict/lossless policy and authentication subject to encryption-identity guards.
P uses it for actual object resolution and bounded stream reads. Continuation
results now bind the state to actual returned bytes. Sequential snapshots do
not create a shared sibling ledger; reused keys are not a MAC/integrity verdict.

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
P supplies real-operation regressions in test_round3_reopen in addition to
S's caller tests; no S-owned function is counted by P.


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


Additional L-routed requests remain (factory getter is accepted and consumed):
- Default-NotFound `OcspFetcher::fetch_ac_ocsp(&self, ac_der: &[u8], issuer: &Cert)
  -> std::result::Result<Vec<u8>, FetchError>` and
  `CrlFetcher::fetch_ac_crls(&self, ac_der: &[u8]) ->
  std::result::Result<Vec<Vec<u8>>, FetchError>`, with lower HTTP request limits
  preserved. Current AC helper requires supplied mandatory evidence;
  this does not close automatic-fetch parity.
- Minimal auditable cryptoki DSA capability increment described above.

The implemented per-session MAC API is
`PdfMacSessions::begin(&self, &SecurityHandler, &str) ->
Result<Option<PdfMacSigningSession>>` and
`PdfMacSigningSession::attach_to_cms(&self, &[u8], &[u8], bool) -> Result<Vec<u8>>`.
The shared signer holds only a lease registry, no document key; overlapping
sessions reject with `Other PDF MAC attribute provider found`. Seven targeted tests pass for real PAdES signing, timestamp MACs, standalone
DSS MACs, duplicate attributes, invalid digests, key isolation, custom-factory
inheritance, error/clone lease release and deterministic concurrent rejection.
S owns the two PDF MAC and three decode caller functions; P never adds them
to its count. V owns full LTA acceptance.



Additional current signatures (all Result aliases are core errors::Result):

```rust
impl PdfReopenState {
    pub fn reader(&self) -> &sigis_pdf::PdfFile;
    pub fn reopen(&self, bytes: &[u8]) -> Result<Self>;
}
// sigis_pades_sign
pub fn add_validation_info_with_state(
    pdf: &[u8], ctx: &ValidationContext, timestamper: Option<&dyn TimeStamper>,
    state: PdfReopenState,
) -> Result<PdfOperationResult>;
// sigis_pades_sign::pdf::timestamp
pub fn add_validation_info_for_with_state(
    pdf: &[u8], sig: &EmbeddedSig, ctx: &ValidationContext,
    include_timestamps: bool, add_vri_entry: bool, force_write: bool,
    state: PdfReopenState,
) -> Result<PdfOperationResult>;
pub fn update_archival_chain_with_state(
    pdf: &[u8], ts: &dyn TimeStamper, ctx: &ValidationContext,
    default_md: DigestAlgorithm, state: PdfReopenState,
) -> Result<PdfOperationResult>;
// sigis_pades_sign::content::import
pub fn import_page_as_xobject_from_reader(
    target: &mut PdfUpdate, source: &sigis_pdf::PdfFile,
    page_ix: usize, inherit_filters: bool,
) -> Result<lopdf::ObjectId>;
// sigis_pades_sign::stamp
pub fn text_stamp_pdf_with_state(
    pdf: &[u8], style: &TextStampStyle, dest_page: i64, x: f64, y: f64,
    text_params: Option<std::collections::BTreeMap<String, String>>,
    state: PdfReopenState,
) -> Result<PdfOperationResult>;
pub fn qr_stamp_pdf_with_state(
    pdf: &[u8], style: &QrStampStyle, dest_page: i64, x: f64, y: f64,
    url: &str, text_params: Option<std::collections::BTreeMap<String, String>>,
    state: PdfReopenState,
) -> Result<PdfOperationResult>;
```

File stamp compatibility wrappers use default untrusted limits; explicit
with-limits variants select a new independent input budget. Native imports
carry the source reader's remaining budget/auth/strictness. Imported background
files use their own default bounded policy, not the destination's trusted policy.
Legacy borrowed-Document import adapters remain bounded with no source-size
ratio credit. Malformed decoding propagates; raw fallback is removed.

PdfUpdate::{new,fresh} now materialize objects using the native bounded reader,
not lopdf's eager loader. open_with_limits/open_with_state allow explicit policy.
Legacy set_strict changes only compatibility lookups after parsing; new callers
must select policy on initial open or pass authoritative state. Permanent /ID
and raw Encrypt reachable graphs stay unencrypted; public-key metadata is not
mistakenly decrypted. Existing option fields/defaults remain, but public struct
literals for prepared/TBS documents must supply the new state/session fields.

PdfSigner owns only a PdfMacSessions registry. Document keys belong to the
PdfMacSigningSession carried by prepared state; clones share its lease, the
last drop releases it, and errors release it. The inherited custom factory is
used for MAC construction. Plain documents do not acquire the MAC lease.
Timestamp messageImprint and TSA signer digest can differ and are checked
separately. S owns exact structural assertions; V owns native full LTA status.

Issuer collection first uses local candidates, then configured cert fetchers
with depth/node/result bounds and cycle checks. Fetched certificates never
become anchors. Native validation keeps the full caller policy; DSS information
is published only after success. Six real PdfSigner regressions cover fetch,
missing/unrelated/cyclic/untrusted roots, forbidden issuer policy and no partial
evidence publication. The fresh Python positive reads the actual output DSS
and also checks empty-root rejection. Mock fetch evidence is not L's live AIA
transport acceptance and adds no upstream functions.

## Evidence, compatibility boundaries and open work

Artifacts: /home/l/.codex/artifacts/sigis/round3/p/. Earlier report snapshots,
implementation-checkpoint tar/patch, split-increments/full and pre-rebase
backups preserve all history. No source inventory or oracle-only tail earns a
passing native function. Accepted earlier nine suites passed172 Rust tests;
L's later full gate is the acceptance evidence. New targeted results:

| Log | Evidence |
| --- | --- |
| state-current-reader-red.log | vm2064 slot0: three real operations fail returned-reader/output identity before from_output repair; existing budget rejection control passes |
| state-consumers-targeted.log | vm2064 slot0: HTTP6/import7 pass; initial issuer positive oracle fails because basic validation did not consume DSS |
| state-native-targeted.log | vm2064 slot0: issuer6 and reopen4 pass; encrypted12/13, extra indirect-Recipients interoperability probe exposes Python recursion |
| mac-stamp-encrypted.log | vm2064 slot0: MAC7 pass; initial stamp assumes xref decode does not spend remaining allowance, corrected to allow further consumption and forbid replenishment |
| state-stamp-encrypted-final.log | Current final state/stamp/encrypted verification; results updated at the ready checkpoint |

The normal tools/cargo-locked.sh selected vm2064 slot0 for every invocation
above. No empty RUSTC_WRAPPER, forced local mode, jobs/target overrides,
repository flock, kills or service restarts. Every Cargo command, including
formatting/docs/clippy, uses that wrapper. Commands:

```sh
tools/cargo-locked.sh check -p sigis-pades-sign
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p sigis-pades-sign --test test_round3_reopen --test test_round3_http_tsa --test test_sign_encrypted --test test_round3_import_limits --test test_round3_issuer_fetch --test test_round3_mac --test test_round3_stamp_state
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p sigis-pades-sign --all-targets
tools/cargo-locked.sh clippy -p sigis-pades-sign --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' tools/cargo-locked.sh doc -p sigis-pades-sign --no-deps
tools/cargo-locked.sh fmt -p sigis-pades-sign -- --check
```

Fresh same-output oracle verdicts are distinct from committed PKI/OCSP fixture
inputs and original Python reference executions. HTTP probes show optional URL
inactivity and seed/client selection agree. Mandatory empty URL is rejected
by Rust whereas Python permits a missing timestamp: intentional stricter
mandatory handling, not an agreeing oracle refusal. LTA without any client is
not assigned an invented upstream refusal. Public-key indirect /Recipients
makes Python recursively build its security handler on both input and output;
native authentication/integrity passes. This is an encoding/reader
interoperability difference, not an agreed trust verdict. Other diagnostic
cause placement and UTC date encoding differences are not universally described
as fail-closed. Missing mandatory trust/revocation evidence rejects explicitly.

Seven AC exact IDs remain pending: test_pades_live_ac_presign_validation,
test_pades_lta_live_ac_presign_validation, test_cades_signer_attrs_autofill_dss,
test_cades_signer_attrs_validate_acs, test_cades_signer_attrs_validate_acs_no_claimed,
test_cades_signer_attrs_validate_acs_wrong_vc and
 test_cades_signer_attrs_validate_acs_missing_vc (all pyhanko/test_pades.py).
The presign helper validates supplied AC evidence and preserves holder/policy
rejections, but configured automatic AC fetching is not represented by the
current shared traits. Native complete LTA/report assertions require V. Python
exact assertion tails against new Rust PDFs are differential evidence only.

Dependency increment: existing workspace sigis-pki-fetch normal dependency
(L3 -> L0), no new version; all remaining package dependencies unchanged. L
owns merged manifests/lockfile and full workspace gate. No dev cycle, layer
relaxation, S/V source change or old fixture mutation. Final owned commits,
remaining dirt and verification totals will be recorded before ready notice.

Current readiness checkpoint: state-stamp-encrypted-final.log passes5+3+13
Rust tests. MAC7 passes. The continuing package all-target run has passed
AC10, HTTP6, import7, issuer6, reopen5, stamp-state3, encrypted13, existing
PAdES42 and other affected suites with zero failures so far. The later extra
AC tamper regression and strengthened native plaintext-copy rejection will be
rerun after this snapshot; clippy/docs/fmt/root callers remain before commit.

L request: route the published P state APIs to S/C and MAC APIs to S/V now;
they are active and targeted-tested, though not yet integrated. In particular,
S's three exact decode caller functions and two exact MAC functions must call
these real P operations; helper-only tests remain insufficient. The four
layout/resource ports already accepted on main are unchanged and pass again.
Seven AC IDs remain pending until configured AC fetching and native full
status assertions are complete. Their portable Python fixture retains all59
original assertions (two backend executions for each live AC function), with
manifest hashes, a reproducible AST extraction script and MIT license. This
is fresh differential evidence, not59 cases or seven passing Rust ports.

### Native writer regression and narrow follow-up requests

The first complete package run (`consumer-all-targets.log`) passed all suites
through encrypted signing, but test_sign_without_annot failed: eager native
materialization read a malformed page xref that the upstream invisible-field
operation never reads. The repair retains plaintext Read/StrictRead errors per
object: get(id) still returns the original error, and a fresh rewrite refuses
an unreplaced malformed object. Incremental signing may retain unused original
bytes. Budget/stream failures remain eager. Every encrypted-object error remains
eager too, since crypto authentication failures can use the Read error class.
The new native rejection regression and original signing function are included
in the final full rerun. No strictness or object-ID checks were disabled.

One legacy low-level difference remains explicit: PdfUpdate::set_strict changes
compatibility lookup policy after parsing, whereas state() represents the
native reader's initial strictness. Initial open_with_limits, SignOptions,
TimestampOptions and authoritative state all preserve the selected reader
policy. Do not imply the legacy setter changes native parser policy.
L-routed shared request, if post-parse mutation must also be supported:

```rust
impl sigis_pdf::PdfFile {
    pub fn with_strict(&self, strict: bool) -> sigis_pdf::PdfResult<Self>;
}
```

This would reparse the same bytes using remaining allowance, retain lossless
mode/authentication identity and discard incompatible caches. P could then
provide a fallible strictness mutator; no budget-reset parse or ignored error
is proposed. This is not delivered or a new accepted interface.

Review also identified explicit /Crypt streams in fresh plaintext copies:
implicit encrypted copy fixtures pass, but copying explicit ciphertext/filter
without the security handler is invalid. A real bounded fresh-copy regression
is being added before handling that path with the existing native decoder.
No unverified explicit-Crypt support or upstream function credit is claimed.

### Full package result and additional adversarial repairs

consumer-all-targets-final.log: **360 passed / 2 ignored / 0 failed across23
suite reports**, vm2064 slot0, after the unread malformed-page fix. It includes
the original test_sign_without_annot and six real state regressions. The worker
prints35 missing SoftHSM-module messages; inherited PKCS#11 wrappers can return
early, so their nominal Rust passes are not a new HSM execution. Two explicit
ignored provider entries and algorithm exclusions remain. Counts are recorded
in consumer-package-counts.json separately from upstream accounting.

A further review found a real state/MAC boundary, not a mere diagnostic gap.
The shared reopen preserves keys but does not validate changed bytes. A page
numeric mutation preserving length, Encrypt and permanent ID failed native and
fresh Python MAC authentication, yet four P continuation operations accepted
it (open, sign, DSS and timestamp). mac-state-integrity-red.log records the
failure and the valid-state control. PdfUpdate now validates actual input MAC
requirements before any operation, using the existing PDF MAC validator;
reused authentication alone never authorizes a bad input MAC. All encrypted
syntax/authentication errors remain eager. Custom factory handle inheritance
and per-session key isolation remain intact.

explicit-crypt-red.log records two real plaintext-copy failures before native
bounded decoding: copied ciphertext retained /Crypt without a handler, and a
budget below payload size did not reject. Fresh copying now decodes explicit
Crypt data using the original authenticated reader and remaining allowance,
then removes source-specific filters/parameters. The success control compares
original and plaintext-copy payload bytes in Rust and the fresh pinned oracle;
the insufficient-budget control rejects. Import regressions separately showed
this in page contents and nested resources (import-crypt-red.log and
import-resource-crypt-red.log); both now decode through the source reader,
including inherit_filters=true, rather than copying source ciphertext into a
different document.

integrity-boundaries-final.log passes **MAC9 + state6 + stamp-state3 +
encrypted15**, all vm2064 slot0. This is33 Rust tests, not upstream functions.
The final import/copy/stamp run and affected central callers/lints/docs/fmt are
recorded at the ready checkpoint. The package total above is the earlier
snapshot; it is not relabelled as a full gate for subsequent boundary repairs.
The new boundary tests add no assigned function credit.

Implementation is saved in local commit **e6c9a39** (`Preserve bounded signing
state and isolate PDF MAC sessions`). Only owned package/source/fixtures are
included. PORTING/report documentation and the generated Cargo.lock remain
dirty; Cargo.lock will stay outside lane commits. This source save is not a
ready or acceptance assertion while affected central callers and final lint/
doc/format checks continue.

crypt-import-copy-final.log passes **import8 / encrypted15 / stamp25** (48 Rust
tests), vm2064 slot0, including fresh Python equality on explicit-Crypt source
and plaintext-copy payloads. New importing controls cover inherit_filters true
and false and require tiny-source-budget rejection; nested resource streams
also lose source-specific crypt filters. Input-MAC refusal evidence is kept
separate from MAC key/session construction evidence and from V's full LTA work.

Explicit exported MAC hooks for S/V (Result = core errors::Result):

```rust
// sigis_pades_sign::pdf::mac
pub const PDF_MAC_DATA: const_oid::ObjectIdentifier;
impl PdfMacSessions {
    pub fn begin(
        &self, security_handler: &sigis_pdf::crypt::SecurityHandler,
        md_algorithm: &str,
    ) -> Result<Option<PdfMacSigningSession>>;
}
impl PdfMacSigningSession {
    pub fn attach_to_cms(
        &self, document_digest: &[u8], cms_der: &[u8], dry_run: bool,
    ) -> Result<Vec<u8>>;
}
```

Normal consumers call PdfSigner::{sign_pdf_with_state,digest_doc_for_signing};
PreparedDocument carries the opaque session through interrupted completion.
The shared registry is private. S can deterministically overlap two operations
on Arc<PdfSigner> using a blocking TSA and assert the original provider-conflict
Signing error. V consumes produced authenticated PDFs for native LTA; a key or
factory handle is not a validation result.

Fresh oracle call inventory per complete new-suite execution (not accumulated
across reruns and not unique-function counts):

| Scope | Live subprocesses / meaningful decisions |
| --- | --- |
| HTTP6 | Five: required seed PDF status, seed detail status, dummy-data PAdES status, optional-seed no-timestamp status, archival/LTA output status. Additional request counts/nonces/imprints checked natively |
| New three public-key exact functions | Three: AES256/RC4 full trusted results and rewritten plaintext-copy integrity rejection |
| Public-key extra representations | One indirect-ID trusted comparison, two indirect-Recipients reader failures (input/output); these failures are compatibility differences, not trust agreements |
| Explicit Crypt copy | One subprocess reads original and plaintext output, compares both payloads and encryption states; native insufficient-budget control is separate |
| MAC9 | Four: PAdES/LTA positive, custom-factory signed output positive, token right-key success/wrong-key rejection, same-identity tampered-input MAC rejection. The wrong-key error must be PdfMacValidationError |
| Issuer6 | One subprocess reads the actual emitted DSS: trust-root success and empty-root rejection without fetching; mock fetch control/cycle/policy refusals are native |
| Whole-pipeline state regression | One status subprocess checks two intact/valid/trusted signatures plus one document timestamp after stateful DSS/archival updates |
| AC11 partial | Nine fresh subprocesses across seven exact functions, including requests/aiohttp for each of the two live functions. All59 original assertion statements retained; native presign/integrity/tamper controls are separate. No full AC-function credit |

Oversized-object-stream Python generation is input construction, not a verdict
comparison. Committed certificate/AC/OCSP inputs and portable assertion source
are fixtures; all status/MAC/output comparisons above run the pinned interpreter
on this execution's Rust output. Earlier reference-only probes and committed
verdict replay are not relabelled as fresh native passes.


## Pre-rebase ready handoff

Owned implementation commits:

- **e6c9a39** Preserve bounded signing state and isolate PDF MAC sessions.
- **e02f345** Tighten MAC rejection evidence and satisfy signing test lints.

Final verification on the committed source (routine lint rewrites do not change
runtime behavior; the tightened wrong-key assertion was executed afresh):

| Command/result log | Result and host/slot |
| --- | --- |
| state-consumers-check.log | Targeted package check passed, vm2064 slot0 |
| consumer-all-targets-final.log | Complete pre-boundary package snapshot360 passed,2 ignored,0 failed; vm2064 slot0. Later boundary repairs are separately covered below |
| integrity-boundaries-final.log | MAC9/state6/stamp-state3/encrypted15 passed, vm2064 slot0 |
| crypt-import-copy-final.log | import8/encrypted15/stamp25 passed, vm2064 slot0; includes newly added plaintext-copy oracle assertions |
| consumer-root-callers.log | All four affected centrally owned suites passed22 tests (10+2+5+5), vm2064 slot0; no central source changed |
| consumer-clippy-attempt3.log | Package all-target clippy -D warnings passed, vm2064 slot0; preceding attempts exposed test-only slice/initializer/iterator lints, fixed without suppressions |
| consumer-docs.log | Strict package docs passed with RUSTDOCFLAGS=-D warnings; local s7, canonical /build/sigis/target. A normal Cargo target lock was allowed to finish; no repository lock was added. No slot number is invented for the completed local doc job |
| consumer-fmt-check.log | Wrapper package fmt --check passed |
| mac-wrong-key-final.log | Explicit PdfMacValidationError wrong-key rejection and positive control passed, vm2064 slot0 |

All Cargo invocations used tools/cargo-locked.sh; no cache or placement bypass,
manual remote invocation, job flag, alternative target, service change or kill.
The source changes after the complete package run were narrow MAC-input and
explicit-Crypt boundary repairs, validated by real positive/negative operations
and their affected callers. L still runs the complete current workspace gate.

The new candidate total is **297/287/3/7**; authoritative accepted total remains
**297/282/3/12** until L's review/gate. The five exact candidate IDs and all13
inherited-skip dispositions are listed above. The four S-owned layout/resource
ports remain on main and passed again (4 Rust tests,28 original assertions),
earning no P credit. S's three decode and two MAC callers still need its exact
acceptance, and V owns native full LTA validation. Direct CMS embedder retains
its documented caller-buffer identity gap; no pass is inferred from its root
wrapper result.

Only new fixtures in crates/testdata/data/lanes/r3-p were added. Old D fixtures,
S/V/C sources, root manifests/tools/layer rules and services were untouched.
The sole dependency addition is existing workspace sigis-pki-fetch; no version
addition or dev cycle. A generated Cargo.lock remains uncommitted and is not
part of either source commit or this documentation handoff; L regenerates it.
Its current local diff contains stale cross-validator dev names from the earlier
split, not a request to restore those package edges.

The report/PORTING documentation is committed separately after these checks.
The final documentation head and exact remaining git status are also saved in
/home/l/.codex/artifacts/sigis/round3/p/ready-handoff.md. This report is sent only
to lead sigis-cx. Await lead rebase/integration feedback; do not merge into main.

## Synchronization onto current main

At the coordinator's request, P checkpointed all work and rebased onto pinned
current main **cef64d308482d0cd2db917a7476f65184da80bba**. Requested main9ebd87b
was already an ancestor before rebase; main had advanced with typed algorithm,
live fixture and variable ByteRange APIs. No downgrade or cherry-pick omission.
The three commits replayed without conflicts:

| Original | Rebased | Purpose |
| --- | --- | --- |
| e6c9a39 | 90ac9e5 | Native bounded signing/state/MAC/HTTP/public-key implementation and tests |
| e02f345 | 6abf333 | Tightened wrong-key oracle assertion and test lint fixes |
| 54cc643 | 43d5f56 | Original verified interface/report handoff |

Backup branch: backup/r3-p-before-main-cef64d3-54cc643. The complete generated
Cargo.lock and its binary diff were saved outside the repository before the
rebase, then restored without staging. Both its file bytes and git diff match
the checkpoint exactly. Before this report-only synchronization edit, all
owned source/fixtures/report trees matched the old head exactly. No shared
file was staged and no unrelated worktree or active slot was changed.

Rebase evidence is under
/home/l/.codex/artifacts/sigis/round3/p/sync-cef64d3/:
checkpoint.json, rebase-proof.json, Cargo.lock.before/patch and status.before.
The lane wrapper now matches the main absolute scheduler launcher byte-for-byte.
For these necessary post-rebase checks, the coordinator-requested absolute main
wrapper was invoked from the P cwd:

```sh
/home/l/D/kooky/sigis/tools/cargo-locked.sh check -p sigis-pades-sign
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python /home/l/D/kooky/sigis/tools/cargo-locked.sh test -p sigis-pades-sign --test test_round3_issuer_fetch --test test_round3_reopen --test test_round3_mac
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python /home/l/D/kooky/sigis/tools/cargo-locked.sh test -p sigis --test round3_signing_context_policy
```

check.log passed. tests.log passed21 tests (issuer6/state6/MAC9), including
fresh oracle MAC rejection, custom factories, remaining allowance and actual
multi-step signing/DSS/archival operations. root-policy.log passed both real
signer caller-policy denial/allow controls after shared typed-policy updates.
All three receipts identify **vm2064 slot0**. These are targeted synchronization
checks, not a fresh complete workspace gate or additional upstream functions.
Accepted P297/282/3/12 and candidate P297/287/3/7 remain unchanged. interfaces-l
requests remain active; no pending strictness/AC/provider interface is inferred
to have been delivered by this synchronization. Continue only owned work and
route shared implementations through L.

This report-only checkpoint is committed after the rebase. The final
synchronized head is saved in sync-cef64d3/result.json and reported to L. The
only remaining worktree difference is the preserved, uncommitted Cargo.lock.

## Approved S-owned CMS unblock: implemented borrowed sink interfaces

The exact signatures below were published to L before implementation and are
now implemented and tested. S retains exact tests/counting for
pyhanko/test_cms.py::test_sign_weak_digest_prevention and
pyhanko/test_cms.py::test_direct_pdfcmsembedder_usage; P remains297 functions.
Reference: S337789d supplemental regression plus S's committed/report handoff
s-direct-embedder-gap.md, read from the S worktree without modification.

The digest policy query will occur during digest selection, before MAC setup,
mechanism resolution, presign network activity, estimation or raw signing. It
uses the caller ValidationContext algorithm policy at Moment::now(), matching
upstream's actual current/frozen wall-clock query. PdfSigner::at sets reported
signing metadata only; neither that timestamp nor a historical VC moment may
backdate this policy decision.
A denied digest returns Signing with the required 'md5 is not allowed' fragment;
an unrelated mechanism error is not treated as the policy assertion passing.
No new shared type/API or dependency is needed for this policy-stage repair.

All Result aliases below are sigis_pki_core::errors::Result. Exact proposed
exports and signatures:

```rust
// sigis_pades_sign::pdf::signer
#[derive(Debug)]
pub struct PreparedInPlaceDocument<'a> {
    output: &'a mut Vec<u8>, // exclusive borrowed caller-owned Vec, private
    pub document_digest: Vec<u8>,
    pub reserved_region_start: usize,
    pub reserved_region_end: usize,
    pub byte_range: [usize; 4],
    pub md_algorithm: sigis_pki_core::algorithms::DigestAlgorithm,
    pub reopen_state: crate::pdf::writer::PdfReopenState,
    pub mac_session: Option<crate::pdf::mac::PdfMacSigningSession>,
}
pub fn write_and_digest_in_place<'a>(
    output: &'a mut Vec<u8>, update: &mut crate::pdf::writer::PdfUpdate,
    sig_id: lopdf::ObjectId, bytes_reserved: usize,
    md: sigis_pki_core::algorithms::DigestAlgorithm,
) -> Result<PreparedInPlaceDocument<'a>>;
impl<'a> PreparedInPlaceDocument<'a> {
    pub fn output(&self) -> &[u8];
    pub fn fill_with_cms(self, cms: &[u8]) -> Result<&'a mut Vec<u8>>;
    pub fn fill_with_cms_with_state(
        self, cms: &[u8],
    ) -> Result<(&'a mut Vec<u8>, crate::pdf::writer::PdfReopenState)>;
}
// sigis_pades_sign::pdf::dss
pub fn add_dss_in_place<'a>(
    output: &'a mut Vec<u8>, content: &DssContent<'_>, force_write: bool,
) -> Result<&'a mut Vec<u8>>;
pub fn add_dss_in_place_with_state<'a>(
    output: &'a mut Vec<u8>, content: &DssContent<'_>, force_write: bool,
    state: crate::pdf::writer::PdfReopenState,
) -> Result<(&'a mut Vec<u8>, crate::pdf::writer::PdfReopenState)>;
```

write_and_digest_in_place requires output bytes to match update.base(), then
writes/digests transactionally before replacing the bytes of that same borrowed
Vec object. Its exclusive borrow lasts through CMS completion; Vec growth may
move its heap allocation. Identity means the caller's Vec object, proven with
std::ptr::eq after return, not a stable allocation address or ownership transfer.
Field Signature,8192 reservation, SHA256, NO_CHANGES certification and DSS3cert/
1OCSP are retained. Existing byte/copy-return APIs remain compatible.

Fill first prepares MAC/CMS and checks region/size constraints in temporary
bytes. The stateful finish reopens completed bytes with inherited remaining
allowance before committing to the caller buffer, and returns that final state.
Errors preserve the caller's prepared bytes where possible; the native
reader's decode charges and independent snapshot semantics remain authoritative,
with no fresh allowance initialized by a continuation. DSS likewise completes/validates its update before
mutating the caller Vec. The default DSS entry initializes untrusted defaults
once; encrypted or caller-selected policy/budget flows use the stateful entry.
No authorization, MAC or decode error is bypassed. Final metadata/identity and
negative error-preservation assertions will precede implementation and be
reported with runtime evidence. No S/V/root files will be edited by P.

### CMS unblock executable checkpoint

New prerequisite tests were written before implementation. borrowed-api-red.log
records the missing borrowed API compile failure; borrowed-region-red.log
records a real unsigned subtraction panic for invalid reserved offsets.
digest-stage-red.log records three substantive failures: MD5 returned the wrong
mechanism error, an explicitly denied digest consulted the mechanism once, and
the positive digest path never queried the policy. The no-VC explicit MD5
interrupted preparation control already passed. A policy refusal is now checked
by digest selection before MAC setup/extension mechanism probing or presign I/O.
It queries actual Moment::now, not metadata/VC historical time.

The published borrowed APIs are implemented entirely in P. The borrow is a
real &'a mut Vec retained by PreparedInPlaceDocument, not a moved Vec. Its
completion methods return that same object after temporary fill and inherited
bounded reopen succeed. The writer's signature reference is checked before
preparation, and its base must match the caller bytes. add_dss_in_place performs
one default bounded open; the stateful variant retains explicit authentication,
strictness/limits and remaining allowance. Native region bounds/delimiters and
payload size are checked before the only write; no invalid-range panic or
partial buffer mutation is accepted.

cms-unblock-regressions.log passes28 tests on vm2064 slot0:
policy4, borrowed7, MAC9, reopen6 and reserved-region2. The borrowed exact case
retains Signature/SHA256/8192/NO_CHANGES and proves std::ptr::eq for both CMS
completion and DSS on the caller Vec. Fresh pinned val_trusted runs before/after
DSS and checks original helper assertions/details, ENTIRE_FILE/NONE then
ENTIRE_REVISION/LTA_UPDATES, exact3cert/1OCSP, no-root distrust and altered-digest
rejection. This is two subprocesses/six validation decisions, not six functions.
Additional negatives cover mismatched base, absent signature, odd reservation,
oversized CMS, corrupt DSS, spent DSS budget, missing authentication and final
xref reopen with zero remaining budget; all retain caller bytes. An authenticated
AES256 trusted/lenient state survives borrowed fill and DSS.

The policy suite performs one fresh pinned Python subprocess with exact MD5
refusal, custom SHA256 policy denial with zero operation mechanism calls, an
allowed/trusted SHA256 positive and no-VC explicit MD5 preparation. Rust also
verifies native signature integrity. Current-time brackets deliberately differ
from metadata2020 and VC2010 for the denial. No full MD5 software-signing port
is inferred from the external/deferred preparation control.

The two exact IDs remain S-owned: test_sign_weak_digest_prevention maps to
P test_round3_digest_policy::test_sign_weak_digest_prevention; direct embedder
maps to test_round3_in_place::direct_cms_signing_and_dss_return_the_same_caller_vec_object.
S retains its supplemental native validator subset and final exact acceptance.
No S/root source or manifest was changed. P accepted297/282/3/12 and prior
candidate297/287/3/7 do not change for this assistance. No new dependency.

For selected state, the continuing borrowed caller uses:

```rust
let prepared = write_and_digest_in_place(
    &mut caller, &mut update, sig_id, 8192, DigestAlgorithm::Sha256,
)?;
let cms = make_external_cms(&prepared.document_digest)?;
let (same_caller, state) = prepared.fill_with_cms_with_state(&cms)?;
let (same_caller, state) = add_dss_in_place_with_state(
    same_caller, &content, false, state,
)?;
```

Existing copy-return APIs remain. The default borrowed helpers, like legacy
standalone helpers, choose untrusted defaults for a new entry; selected-policy
sequential operations must transfer the returned state. No parser policy reset
or new authentication is introduced by the stateful chain. Earlier full gates
are historical; final affected regressions/lint/doc checks follow before ready.

CMS unblock source is now saved as independent local commits:
**6e00181** Check caller digest policy before signing mechanism resolution;
**e59b307** Add borrowed caller buffers for CMS embedding and DSS updates;
**bbc6c3d** Verify borrowed MAC session completion and DSS continuation.
These add no shared type/dependency edits and no P/S accepted count changes.

cms-unblock-check.log passes package check. cms-unblock-affected.log passes
**182 tests across9 suites**, all vm2064 slot0: PAdES42, policy4, borrowed7,
MAC9, reopen6, reserved-region2, seed34, encrypted15, signing63. This includes
existing interrupted/certificate-less boundaries, malformed signature variants,
large signing, all DSS placements and encrypted post-sign continuation.

cms-borrowed-mac-verified.log passes the final borrowed suite8/8, vm2064 slot0.
The extra MAC case uses the same caller Vec, retains its exclusive session until
completion, verifies the attached input/output MAC natively, then updates DSS
with the returned state and verifies the new standalone MAC. The registry can
be used again after the prepared session drops. This additional MAC container
requires16384 reserved hex digits; an earlier8192 attempt correctly refused a
payload requiring8524. The exact original plaintext direct-embedder case still
uses8192 unchanged. That extra capacity is neither an assertion relaxation nor
new upstream function/parameter credit.

Four affected root suites and final package lint/docs/format are next. S can
consume the concrete exports above now while L completes integration review;
the exact strict error and borrowed identity assertions must remain in S's
own final tests. No prior oracle-only replay is converted to an accepted pass.


### CMS unblock ready handoff

The three independent owned commits are **6e00181**, **e59b307**, and
**bbc6c3d**. The code, borrowed signatures and mandatory strict refusal are
implemented; this is no longer a proposed/stub-only API. No root/S/V files,
shared types, manifests, dependencies or old fixtures changed. S owns final
function acceptance and all counts; P's fixed297 denominator and prior accepted/
candidate totals remain unchanged.

| Evidence | Final result |
| --- | --- |
| cms-unblock-check.log | Package check passes, vm2064 slot0 |
| cms-unblock-affected.log / .json | Nine affected package suites pass182/0failed/0ignored, vm2064 slot0 |
| cms-borrowed-mac-verified.log | Final borrowed suite8/8 including MAC session and state continuation, vm2064 slot0 |
| cms-unblock-root.log | Four affected root suites pass22/0failed/0ignored, vm2064 slot0 |
| cms-unblock-clippy.log | Package all-target clippy -D warnings passes, vm2064 slot0 |
| cms-unblock-docs.log | Strict package docs pass with RUSTDOCFLAGS=-D warnings, local canonical /build/sigis/target |
| cms-unblock-fmt-check.log | Package formatting check passes through the normal wrapper |

All logs are /home/l/.codex/artifacts/sigis/round3/p/. They distinguish fresh
same-output oracle assertions from fixture inputs/source probes. The direct
borrowed case performs the exact upstream val_trusted helper before/after DSS,
plus two empty-root and two changed-digest decisions; it is not source inventory
or committed verdict replay. The digest policy probe runs actual pinned signing
operations with matching denial detail and operation-mechanism counters, plus
real allowed signing and no-VC interrupted preparation controls. There are no
oracle/provider early returns in these new suites. Python policy class names
and Rust policy reasons differ in diagnostic formatting; required semantic
policy rejection and MD5 message fragment agree. No generic mechanism error is
counted as that policy rejection.

Reproduce from the P cwd, retaining normal scheduler/cache configuration:

```sh
/home/l/D/kooky/sigis/tools/cargo-locked.sh check -p sigis-pades-sign
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python /home/l/D/kooky/sigis/tools/cargo-locked.sh test -p sigis-pades-sign --test test_round3_digest_policy --test test_round3_in_place --test test_round3_reserved_region --test test_signing --test test_pades --test test_seed_values --test test_sign_encrypted --test test_round3_mac --test test_round3_reopen
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python /home/l/D/kooky/sigis/tools/cargo-locked.sh test -p sigis --test round3_signing_certless --test round3_signing_skips --test round3_signing_context_policy --test round3_signing_partial_assertions
/home/l/D/kooky/sigis/tools/cargo-locked.sh clippy -p sigis-pades-sign --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' /home/l/D/kooky/sigis/tools/cargo-locked.sh doc -p sigis-pades-sign --no-deps
/home/l/D/kooky/sigis/tools/cargo-locked.sh fmt -p sigis-pades-sign -- --check
```

The only uncommitted generated shared file is Cargo.lock, excluded from every
P commit. PORTING/report are committed in a separate documentation checkpoint;
the final head/status and signature handoff are recorded in cms-unblock-ready.md
under the artifact directory. L is notified only after saving this report.
Earlier S supplemental tests retain their own provenance and are not rewritten
or assigned new P credit. L/S may now add the strict stage and same-Vec assertions
to their exact tests; the full workspace gate and merged lockfile remain L work.

## AA fetched-candidate continuation checkpoint

L's wrapper safety sync is acknowledged: P leaves tools/cargo-locked.sh and
Cargo.lock unstaged, uncommitted and unreverted. At this checkpoint the wrapper
has no working-tree diff; Cargo.lock remains the preserved generated difference.
No final algorithm/feature readiness or S/P count change is inferred from the
coordinator's infrastructure/helper announcements. Final rebase remains a
coordinated L step; current P source checkpoint before this increment is c72dcb9.

A narrow independent AC presign defect is reproduced and repaired in owned
ltv.rs. P fetched an AA intermediate to collect revocation evidence, then omitted
that certificate from the cloned context passed to native validate_ac. A
repeatable fetcher concealed this because the lower path builder fetched the
same issuer again. A one-success-response fetch allowance made the valid chain
fail, and masked the actual caller policy rejection with a path-building error.
The repair retains fetched path certificates as candidate intermediates only,
using existing extended_context/with_revinfo. Trust anchors, holder binding,
algorithm/revocation policy and atomic collection remain authoritative; the
source ValidationContext is unchanged. No public signature, shared API or
dependency change is needed.

Tests preceded implementation: ac-issuer-red.log records two duplicate-request
failures with a repeatable fetcher; ac-issuer-budget-red.log records two real
path failures after the one-call allowance is exhausted. Both ran on vm2064
slot0. ac-issuer-verified.log now passes all10 issuer tests on vm2064 slot0,
including four new supplemental native regressions:

- ac_presign_uses_fetched_aa_intermediate_for_native_validation_and_collection:
  one fetch; native approved role and exact leaf-AA/intermediate-AA/root-AA
  collected path, one OCSP/two CRLs; source context unchanged.
- ac_presign_fetched_aa_keeps_holder_policy_and_atomic_collection: caller
  forbids the fetched intermediate's signature, and wrong signing holder;
  exact policy/holder error fragments and no partially published revinfo.
- ac_presign_does_not_trust_a_fetched_aa_root: fetched self-signed AA root
  cannot become an anchor; bounded requests and empty collected evidence.
- pdf_signing_embeds_the_once_fetched_aa_path_in_dss: actual PdfSigner with
  separate PKI/AA contexts, native CMS integrity and exact DSS7cert/2OCSP/3CRL;
  final strengthening also extracts all three actual AA DER certificates with
  the bounded native reader and validates the same output with fresh Python
  DSS-derived contexts, including empty-AA-root refusal.

Fresh ac_issuer_assertions.py runs pinned Python0.38.1/certvalidator0.33.0
against the same exported certificates and AC. Its allowed, forbidden-policy,
wrong-holder and untrusted-root decisions agree with Rust. The allowed Python
path also needs exactly one issuer request. This is four supplemental decisions
per subprocess, not four upstream functions. Revocation responses and certificate
inputs are fixtures served by the pinned live HTTP harness; decisions are
computed afresh, not replayed. The Rust issuer suite requires this subprocess
and has no oracle/provider early return. ac-issuer-oracle.log records a separate
successful local fresh execution. An initial oracle policy-helper draft compared
ASN.1 object identity; it was corrected to compare public-key DER before any
parity claim. That draft was a harness error, not a validator divergence.

This does not implement automatic AC-specific OCSP/CRL fetching or V's complete
AC/PAdES/LTA status assertions. The seven exact AC IDs above remain pending;
accepted P297/282/3/12 and prior candidate P297/287/3/7 do not change. The
previous concrete default-NotFound fetch_ac_ocsp/fetch_ac_crls requests still
require L-routed shared implementation. Native positive AA-path collection is
not reclassified as a full AC upstream-function port. Package check, affected
AC/PAdES suites, lint and final review evidence follow before this increment
is committed and handed to L.

The source/fixture checkpoint is now **51ef7fc**, Retain fetched AA intermediates
during presign validation. The following current-source checks passed through
the normal absolute system-scheduler wrapper, with no shared source edits:

| Log | Result |
| --- | --- |
| ac-issuer-check.log | Package check passed, vm2064 slot0 |
| ac-issuer-verified.log | Issuer suite10 passed, including mandatory fresh oracle4 decisions; vm2064 slot0 |
| ac-issuer-affected.log | PAdES42 and partial AC11 passed, zero failed/ignored; vm2064 slot0 |
| ac-issuer-clippy.log | All-target clippy -D warnings passed, vm2064 slot0 |
| ac-issuer-fmt.log | Package fmt --check passed through the wrapper |

These are targeted checks for the changed candidate transfer and real signer
callers; the historical complete gate is not rerun or claimed by P. Reproduce:

```sh
/home/l/D/kooky/sigis/tools/cargo-locked.sh check -p sigis-pades-sign
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python /home/l/D/kooky/sigis/tools/cargo-locked.sh test -p sigis-pades-sign --test test_round3_issuer_fetch
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python /home/l/D/kooky/sigis/tools/cargo-locked.sh test -p sigis-pades-sign --test test_round3_ac --test test_pades
/home/l/D/kooky/sigis/tools/cargo-locked.sh clippy -p sigis-pades-sign --all-targets -- -D warnings
/home/l/D/kooky/sigis/tools/cargo-locked.sh fmt -p sigis-pades-sign -- --check
/tmp/pyhanko-oracle/venv/bin/python -I crates/testdata/data/lanes/r3-p/ac/ac_issuer_assertions.py crates/testdata/data
```

The standalone oracle command and the Rust helper prerequisite each execute
four fresh supplemental decisions; the strengthened output test adds two
same-output decisions. None changes the fixed function denominator.
The branch retains its coordinated cef64d3 base and all later P commits.
L coordinates any final rebase, merged lockfile and full integration gate.
Only Cargo.lock remains generated/uncommitted after the owned report checkpoint;
the synchronized wrapper is neither staged nor reverted. Exact final head,
status and source paths are saved in ac-issuer-ready.md/json under the artifact
directory before the lead notification.

Read-only implementation review found no blocker; its exact scope and independent
four-case Python run are in ac-issuer-review.md. An additional output-coverage
review correctly distinguished native DSS counts from Python's standalone AC
decision. P then strengthened the output test to decode and compare exact
leaf-AA/intermediate-AA/root-AA DER from the actual DSS with the bounded native
reader. It also requires fresh Python validation of that same generated PDF.

ac-issuer-output-basic-red.log preserves the failed initial attempt to reuse
the basic no-claimed helper unchanged: this extra scenario deliberately has
the fetched AA chain only in DSS, while basic async_validate_pdf_signature does
not import DSS. The original upstream no-claimed fixture embeds the authorities
in CMS, so that original function/test/assertion tail remains unchanged. No
failure is reclassified as a pass and no broader fail-closed claim follows.
The supplementary output oracle now explicitly constructs its PKI and AA
contexts from the actual DocumentSecurityStore with allow_fetching=False;
candidate AA roots from DSS are never trust anchors. It checks actual signature
integrity/trust/ENTIRE_FILE plus a valid certified role, then keeps signer trust
but requires invalid certified attributes when the AA anchor list is empty.
ac-issuer-output-verified.log passes the strengthened test on vm2064 slot0.
The structured standalone four-case comparison remains separate. This is not
V's native full AC/PAdES/LTA status acceptance, nor new upstream credit.

Final source commits are **51ef7fc** (candidate propagation and tests-first
regressions) and **d5c2829** (exact emitted AA DER and same-output DSS oracle).
ac-issuer-final.log passes10/10 on vm2064 slot0 and records both mandatory
oracle payloads: four standalone AC decisions plus two same-output PDF/AC
decisions. The pre-existing regular issuer test also retains its separate
root/empty-root PDF comparison; no oracle call count is a function count.
ac-issuer-clippy-final.log and ac-issuer-fmt-final.log pass after the final
test extension; clippy is vm2064 slot0. No production change followed the
already passing package check and53 affected PAdES/partial-AC tests. Read-only
review ac-issuer-review.md includes the final corrected output evidence boundary
and does not claim an independent Cargo rerun.

Ready request to L: integrate these two independently reviewable owned commits
alongside the prior consumer/CMS increments and coordinate final rebase when
safe. Route the still-pending AC-specific fetch methods to their shared owners;
their previously published Rust signatures/default-NotFound behavior are
unchanged. S's exact callers and V's complete native validation acceptance
remain separately owned. P reports **297/282/3/12 accepted**, **297/287/3/7
candidate**, with no increase from this supplemental increment. No new dependency,
manifest, shared API, S/V source, old fixture, service or scheduling change.

## Consolidated main sync and exact implementation handoff

This is executable owned source, not a source inventory claim. Small source
increments are: 6e00181 strict digest stage (already curated as mainc69886c),
e59b307 borrowed sink and bounds, bbc6c3d MAC borrowed-session control,
51ef7fc fetched-AA candidate propagation and d5c2829 actual output evidence.
The larger native reader/MAC caller increment remains 90ac9e5 plus its isolated
test-lint/negative-evidence follow-up6abf333, subject to L source/gate acceptance.
The earlier ten inherited-skip and attachment assertions, all13 exact reviews,
parameters, provider exclusions and remaining raw-DSA gap are listed above;
their acceptance is tied to the selected main ledger, never inferred from this
lane report or helper counts. All source/checkpoint commits are local.

The exact stateful signing/timestamp/DSS/MAC signatures and defaults above
remain implemented; no new signature is being promised by this synchronization.
For quick consumer routing, with Result = sigis_pki_core::errors::Result:

```rust
// sigis_pades_sign::pdf::signer::SignOptions
pub decode_limits: sigis_pdf::decode_limits::DecodeLimits; // Default::default()
pub reopen_state: Option<crate::pdf::writer::PdfReopenState>; // None
// sigis_pades_sign::pdf::timestamp::TimestampOptions<'a>
pub decode_limits: sigis_pdf::decode_limits::DecodeLimits; // Default::default()
pub strict: bool; // true
pub reopen_state: Option<crate::pdf::writer::PdfReopenState>; // None
// sigis_pades_sign::pdf::writer
pub struct PdfOperationResult {
    pub pdf: Vec<u8>,
    pub state: PdfReopenState,
}
// sigis_pades_sign::pdf::signer::PdfSigner
pub fn sign_pdf_with_state(
    &self, pdf: &[u8], opts: &SignOptions,
) -> Result<crate::pdf::writer::PdfOperationResult>;
// sigis_pades_sign::pdf::timestamp::PdfTimeStamper
pub fn update_archival_timestamp_chain_with_state(
    &self, pdf: &[u8], ctx: &sigis_pki_certvalidator::ValidationContext,
    default_md: sigis_pki_core::algorithms::DigestAlgorithm,
    state: crate::pdf::writer::PdfReopenState,
) -> Result<crate::pdf::writer::PdfOperationResult>;
// sigis_pades_sign::pdf::dss
pub fn add_dss_with_state(
    pdf: &[u8], content: &DssContent<'_>, force_write: bool,
    state: crate::pdf::writer::PdfReopenState,
) -> Result<crate::pdf::writer::PdfOperationResult>;
// sigis_pades_sign::pdf::mac
impl PdfMacSessions {
    pub fn begin(
        &self, security_handler: &sigis_pdf::crypt::SecurityHandler,
        md_algorithm: &str,
    ) -> Result<Option<PdfMacSigningSession>>;
}
impl PdfMacSigningSession {
    pub fn attach_to_cms(
        &self, document_digest: &[u8], cms_der: &[u8], dry_run: bool,
    ) -> Result<Vec<u8>>;
}
```

PdfReopenState is the private-reader snapshot type exported from
pdf::writer; from_reader(PdfFile) -> Self, reader(&self) -> &PdfFile,
strict(&self) -> bool and decode_context(&self) -> DecodeContext expose its
selected remaining allowance/authentication policy. With Some(state), options'
fresh-input defaults never replace the inherited state. Reopen/final output
validation spends that remaining allowance and returns the state for the exact
output bytes. Existing copy-return wrappers retain defaults, while the concrete
signing -> archival -> DSS and real borrowed caller examples above transfer the
returned state at every step. The borrowed signatures already published above
retain the same caller Vec object and transactionally preserve bytes on errors.

The accepted AC trait defaults now unblock native P consumers with custom
AC-capable fetchers; they do not mean the concrete HTTP implementations or
full AC/PAdES/LTA validation are complete. After the safe sync P will port the
mandatory retrieval/negative assertions before consuming those methods in
owned ltv.rs. All necessary lower HTTP/revinfo changes remain routed through L
to S. No S/V/shared edit or unconditional pass is authorized by the defaults.
