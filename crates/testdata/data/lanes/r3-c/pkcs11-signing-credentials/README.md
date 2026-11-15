# Context-specific credential controls

These five supplemental native cases use a fresh process and new private token
store per case. The preparation process imports the pinned original RSA signer1
key with TOKEN, PRIVATE, SIGN, SENSITIVE and ALWAYS_AUTHENTICATE true and
EXTRACTABLE false. It reads back certificate objects and key attributes, never
private key material. The body starts only after provisioning exits.

Two positives exercise configured and environment signing PINs. Environment
signing PIN authority remains distinct from the dedicated USER prompt. Wrong
signing PIN, wrong USER PIN and generic document-password substitution retain
input, config and an existing output sentinel. All PIN environments are scoped
to the child process before provider initialization. No terminal prompt is used.

Positive PDFs require Sig1, exact signer certificate, exact root/intermediate/
signer path, entire-file coverage, intact/valid/trusted status, same-byte empty
root denial, tampering refusal, and the pinned Python validator on the actual
output. Validation uses the original fixture date of 2020-11-01; this does not
introduce a product clock option or timestamp POE.

SoftHSM uses the same secret for USER and ContextSpecific authentication. These
controls demonstrate operation boundaries with an ALWAYS_AUTHENTICATE key;
they do not prove distinct-secret SafeNet hardware behavior or port a new
upstream original. No optional-provider early return or implicit skip exists.
