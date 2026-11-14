# Remaining CLI PKCS11 software-provider fixtures

`prepare.py ABSOLUTE_NEW_DIRECTORY` creates a new isolated token store and
imports the pinned original RSA, ECDSA, Ed25519 and Ed448 signer keys plus actual
root/intermediate/signer certificates. It generates no replacement keys and
never exports a token private key. Run it in a completed separate process before
the native test initializes the module. Outputs are `provider/softhsm2.conf` and
`ALGORITHM/{root,interm,signer1}.der`; token labels are `testALGORITHM`, signer
certificate and key labels are `signer1`, with public test USER PIN1234/SO PIN5678.

The new `testmldsa` token has no key: this SoftHSM version does not advertise
ML-DSA. The unchanged upstream fixture authenticates and then applies its real
missing-mechanism skip. Combined ECDSA is also unavailable; the two upstream raw
ECDSA tests have a `required_mechanism` marker while their fixture reads
`require_mech`, so their unchanged reference skips on combined ECDSA. A native
raw-ECDSA positive is separate supplemental behavior, not a passing original
reference. `available.txt` states the actual selected mechanism capabilities.

Use pinned Python with the existing isolated python-pkcs11 0.9.5 overlay on
PYTHONPATH. `originals.py ABSOLUTE_NEW_DIRECTORY [EXACT_FUNCTION ...]` prepares a
fresh store and runs the eight listed unchanged original functions and complete
fixtures/teardown. It preserves all five collected labels and reports genuine
provider availability exclusions in ordinary text pytest output. No hardware
substitution, implicit token trust anchor or proof/ELF/hash pipeline is involved.

The two SafeNet-only CLI originals are retained as explicit hardware exclusions;
software reauthentication does not establish their platform-specific behavior.
The remaining P library original,
`pyhanko/test_pkcs11.py::test_simple_sign_from_config_with_signing_pin`, also has
an explicit upstream SafeNet-only marker (pinned test_pkcs11.py:388). It requires
its actual configured token and separate signing PIN. No such device is
configured here, so its inherited skip remains; no device is probed.

Configured or environment static signing PINs now reach native context-specific
reauthentication independently of the user-login and document credentials.
`pkcs11-signing-credentials` supplies separate RSA AlwaysAuthenticate software
controls. A per-sign signing-PIN callback still needs a separate runtime/lower
signer interface; the existing user callback is not reused. Explicit whitespace
signing environment values are rejected before a user prompt, whereas Python
falls back to the user PIN. A signing PIN configured with Skip mode is rejected
rather than silently ignored. These bounded stricter differences remain explicit.
