# Required validation context: explicit language-phase adaptation

The pinned Python test validates a genuinely signed PDF with the validation
context omitted, and requires a DeprecationWarning matching operating system's
trust. It does not assert the returned trust result. Rust has no corresponding
omitted-context runtime state: the existing public validator requires a borrowed
ValidationContext. These checks document an explicit type-phase adaptation,
not Python warning/runtime OS trust parity or no-context signing prohibition.
No runtime warning shim, OS trust default, new public function or wrapper exists.

The real existing function and imports must first compile with an explicit
context. This control prevents an unresolved dependency/name from masquerading
as meaningful compile-fail coverage:

```rust
use sigis_pdf::{EmbeddedSignature, PdfFile};
use sigis_pki_certvalidator::ValidationContext;
# fn explicit_context(file: &PdfFile, signature: &EmbeddedSignature, ctx: &ValidationContext) {
let _ = sigis_pades::validate_pdf_signature(file, signature, ctx, None);
# }
```

An explicit None is excluded at the actual context argument. The ordinary-fence
baseline measured E0308 (mismatched types: Option versus the required reference):

```rust
use sigis_pdf::{EmbeddedSignature, PdfFile};
use sigis_pki_certvalidator::ValidationContext;
# fn absent_context(file: &PdfFile, signature: &EmbeddedSignature) {
let _ = sigis_pades::validate_pdf_signature(
    file,
    signature,
    None::<&ValidationContext>,
    None,
);
# }
```

Omitting the context while supplying the intended optional diff-policy argument
is an invalid existing four-argument API call. The ordinary-fence baseline
measured E0061 (four arguments required, three supplied):

```rust
use sigis_pdf::{EmbeddedSignature, PdfFile};
# fn omitted_context(file: &PdfFile, signature: &EmbeddedSignature) {
let _ = sigis_pades::validate_pdf_signature(file, signature, None);
# }
```

The small functions are doctest scopes for real typed inputs, not new library
APIs or fake absent-method wrappers. A valid runtime call additionally requires
actual PDF/signature values: the separate root integration test signs a real
PDF, validates the same bytes with explicit test roots, and denies trust with
explicit empty roots. Signing without a context remains supported and is not
the subject of this original warning test. No runtime behavior change is needed.


## Evidence and boundary

The tests-first ordinary-fence run discovered all three examples: the real
four-argument positive compiled, and the two negative calls failed with E0308
and E0061. A separate fence-only commit changed those two fences without
changing their calls. The installed nightly rustdoc then passed all three,
including the diagnostic-code checks. These are three examples for one original
function, not three additional upstream functions.

The native `round3_default_context` integration test signs `Sig1` with RSA and
SHA256 at 2020-11-01, leaving no-context signing supported. It validates the same
PDF bytes twice using explicit caller contexts with the same time, other
certificates and soft-fail policy. The trusted-root case requires intact and
valid CMS, the exact signing certificate, an exact root/intermediate/leaf path,
entire-file coverage, no modification and a true bottom line. The empty-root
case still requires intact and valid CMS and the same coverage, but rejects
trust and the bottom line with `NO_CERTIFICATE_CHAIN_FOUND`. Retaining the root
as an ordinary untrusted candidate does not turn it into a trust anchor.

Both decisions are checked afresh by pinned pyHanko 0.38.1 and certvalidator
0.33.0 against the actual native PDF, with explicit roots or an explicit empty
root list. The test records interpreter identity, assertion-enabled execution,
actual opened input hashes, output hashes and the executing test ELF. This
same-output comparison is distinct from the separately recorded unchanged
original Python test, whose implicit-context validation emits the deprecated
OS-trust warning and makes no returned-trust assertion.

No OS trust fallback, runtime Rust warning, deprecated shim, public API,
production behavior or dependency is added here. The mapping deliberately
excludes the deprecated state at the type phase; it does not reproduce Python's
runtime warning or ban caller-selected external roots in an explicit context.
The SafeNet hardware test remains separate and unproved. Final upstream credit
belongs to the lead's current-source integration, full gate and acceptance.
