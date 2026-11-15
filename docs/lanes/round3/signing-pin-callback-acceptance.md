# Signing-purpose callback acceptance and remaining exclusions

Source `715d8c29` is curated on accepted main `7868ba83` from P's ready `75df38ef`
batch. Production changes are limited to the lower PKCS11 signer, CLI runtime
and CLI signing adapter. Dedicated tests and mechanical runtime field `None`
adaptations preserve existing caller clocks, fetchers, reader and trust policy.
There is no new dependency, frontend/config behavior or generic validation API.

`Pkcs11Signer::with_signing_pin_callback` supplies a fresh credential per actual
`sign_raw` using the same existing session and selected key. The CLI runtime's
optional `pkcs11_signing_pin_prompt` defaults to `None`, uses a fixed signing-purpose
label and typed cancellation/unavailability errors, and has redacted Debug.
Credentials are not cached or substituted from USER/PDF capabilities. Static/env
precedence remains; callback errors refuse fallback. External exhaustive runtime
literals must add the new field or use Default. This is explicit programmatic
authority, with no implicit terminal/stdin prompt.

The normal wrapper workspace gate passed **2435 / 0 failed / 31 native ignored**,
across 255 test/doc reports. Workspace all-target clippy-Dwarnings and fmt pass.
Root focus passed 27 tests with10 hardware parameters ignored, including fresh same-byte PDF
trust/empty-root/tamper checks. Author 8 runtime and 34 legacy PKCS11 controls also
passed separately. Plain current-source logs are under
`~/.codex/artifacts/sigis/round3-launch/signing-pin-callback-integration/`.

Exactly two C originals become explicit hardware exclusions:
`pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt`
and `::test_cli_addsig_pkcs11_with_setup_and_env_signing_pin`. Complete native
bodies retain all five original labels and replace old ignored panic stubs.
The real SafeNet configuration/provider is unavailable. Fresh unchanged pinned
pyHanko gives 10 genuine SafeNet-on-SoftHSM platform skips. Software
AlwaysAuthenticate controls establish neither hardware execution nor equivalence
of vendor algorithms/multipart signing. The initial missing-module selector and
older dependency-enum setup attempts remain separate failed/setup logs; the
final original run selects the existing real python-pkcs11-0.9.5 dependency.

No original gains passing credit from this supplement. Counts are
1431 total / 1421 passed / 10 skipped / 0 pending: three genuine SafeNet hardware cases,
two reference-fixture raw-ECDSA exclusions and five S language/model contracts.
Future closure needs real providers or explicitly scoped compatibility work;
the current batch leaves no hidden implementation stub classified as a pass.
