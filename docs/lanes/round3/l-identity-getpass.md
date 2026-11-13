# Accepted bounded CLI identities and password prompting

Accepted source: `4d47f41c1288c99039e2548ff3bf0ebe86ee2e98`.
Baseline: pyHanko0.38.1 /certvalidator0.33.0. All six source-specific workspace
gates and independent current runtime/source reviews precede this acceptance.
Measured Rust results: **2069 discovered /2066 passed
/3 ignored /0 failed**,210 reports. Actual stages:
build0 (3.76s); test0 (1047.65s); clippy0 (11.98s); doc0 (256.46s); layer0 (4.56s); fmt0 (3.25s). Original functions, architecture parameters, wrappers, process
receipts and oracle calls remain separate counts.

Exactly three C original functions are accepted, four architecture parameters
each:12 original cases. Accepted counts are1431/1350/17/64, C252/188/0/64.
P297/296/1/0, S824/808/16/0, V47/47/0/0, L11/11/0/0 and library1168/1151/17/0
retain their counts. No P/S/V/L/CMS completion is credited by this cohort.
Immutable ownership and every preceding acceptance override remain unchanged.

| Immutable ID | Rust mapping | Original cases |
| --- | --- | ---: |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_identity_setup` |`identity_getpass::test_cli_addsig_pemder_with_identity_setup`|4|
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_identity_programmatically` |`identity_programmatic::test_cli_addsig_pemder_with_identity_programmatically`|4|
| `pyhanko-cli/test_cli_signing.py::test_cli_sign_getpass` |`identity_getpass::test_cli_sign_getpass`|4|

## Tests first, current source and product

ROOT first installed exactly seven reviewed tests/helper inputs on clean
accepted main, retaining accepted common/mod.rs and common/signing_record.rs.
It measured unavailable identity API diagnostics separately from the actual
old-CLI behavior RED. The latter used the unchanged accepted91088a34 product;
missing module errors or absent outputs were not labelled passing ports.
The original and supplemental source/ELF/input/result identities are preserved.

The curated production changes touch only four CLI files: new bounded identity
module, narrow dispatch, identity capability in PEM and visible-field P12.
Accepted detached module/direct --detach routing, PEM setup_schema/material
pub(crate) helpers and authenticated ordinary input path remain intact. No
manifest, lock, dependency, feature, build/cache/target, lower-layer library policy/API or
ownership change is included. The original owner source/projection proof is
historical; it is not substituted for ROOT's current producer/runtime gate.

Actual current private CLI is
`6d20a2d32fa8c11c48c1bf75530b9fb1d998f9f237d2a13485083d3a138e3756`,
123880600bytes, produced on this source with13 selected local units/234 input
records. Both VM copies match its absolute path/hash/length/version; copying
is distribution proof, not inferred VM execution. Actual runtime self-hashes,
compiler fingerprints/binary dep-info/source/Git and retained private test ELFs
are reviewed with their precise timing. No older CLI or source is relabelled.

The focused run8RustPASS93.03s/18units251inputs remains a separately retained
observation. Final acceptance uses the actual current full-gate evidence and
retained controls; identical product/test bytes do not erase separate process
or source identities.

## Complete original paths and actual outputs

Configured identities and the direct programmatic callback each execute all
four RSA/ECDSA/Ed25519/Ed448 cases, preserving the complete caller configuration
and effective public properties. The same validated borrowed configuration
reaches the private PEM identity capability. Raw/effective plugin or parameter
conflicts, aliases, unknown mandatory settings, unsupported identities/providers
and invalid parameter shapes reject; no reconstructed empty config or full-engine
fallback projects away requirements. The ordinary public PEM adapter continues
to reject identity-only state; only validated identity dispatch acquires the
private capability. Identity encrypted input remains unsupported, without
weakening the accepted authenticated direct PEM route.

Getpass uses real terminal-backed child processes for all four original cases.
The actual selected CLI child hash, prompt observation, echo-disabled state
before secret submission and absence of the secret from captured transcript
are recorded. The fresh Python original records its one expected getpass call.
This does not claim complete cancellation/error restoration, every terminal
platform, hardware PIN or provider behavior.

Original native results are12 real PDFs: four configured CLI, four direct
programmatic and four getpass paths. Three supplemental policy/visible-field
successes add three PDFs but zero original IDs. All15 actual PDFs receive fresh
same-native-output pinned checks and equal-evidence native empty-root refusal.
The original reference executes the unchanged original body and exact strict
validation helper with manually supplied fixture bindings; this is not claimed
as complete upstream pytest fixture scheduling. There is no fixture-verdict
replacement or unavailable-oracle early-pass credit.

The independently reviewed evidence distinguishes35 process receipts:
four native configured-identity CLI calls, four PTY drivers,12 original-body
reference calls and15 same-output reference checks (12 original plus3
supplemental). The four native programmatic calls and15 native validation/
empty-root pairs are in-process observations, not extra subprocesses. Nine
sentinel-preserving refusal cases and the field-only target add zero IDs.
Current fullgate counts and current selected executable/source evidence are
measured independently of the earlier focused archives.

## Policy, clock and appearance boundaries

The full five-field KU predicate is explicitly used on the new identity and
visible-P12 routes, preserving contextual match-any/implicit-EKU behavior and
forbidden/match-all/empty constraints; missing positive KU retains the intended
NR default. Mandatory configuration/usage requirements remain enforced before
material/network/output where asserted. The old ordinary PEM/P12 contracts,
legacy missing-KU repair and accepted detached behavior are preserved rather
than silently changed to force new parity. Existing raw full-PDF facade/Core
stricter differences remain disclosed separately.

The eight actual CLI clocks are current2026; the four programmatic callbacks
and original-reference/postvalidation controls use fixture2020-08-01+08 and
signed fixture CRLs. This is not current-time trust parity or fresh HTTP PKI
acquisition. Explicit native empty-root denial retains the same evidence and
does not import system roots. Original prevalidation, signer, signature, field,
coverage and modification requirements stay meaningful.

The bounded visible P12 path retains the existing default stamp style and
checks a real visible Sig1 rectangle/AP presence. Complete AP rendering,
page-association compatibility, all field formats or every appearance feature
are not asserted. Actual output writes do not promise atomic rename.

## Remaining work and acceptance limits

C has64 pending originals: other signing/LTV/qualified validation/provider/
reader-state flows remain unfinished. P retains one SafeNet skip plus provider
parameters, V audits beyond its47 originals, and S retains16 skips
(PDF4/certvalidator2/fetch10). L retains11/11 originals and owns integration,
parameter/skip/provenance audits and final service-replacement acceptance.

The measured legacy absent-KU decision was repaired previously and is preserved.
Two optional-EKU raw facade refusals and two forbidden-only Core refusals remain
stricter; provider/empty-PIN and unassigned feature boundaries remain bounded or
unknown. This acceptance does not claim all divergences fail closed, universal
trust parity or a complete port. Historical failed probes, source scopes and
raw malformed parallel logs remain unrepaired; only actual independently
verified clean current evidence supports acceptance. No service restart or
push follows.
