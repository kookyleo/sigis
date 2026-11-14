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
fresh store and runs the seven listed unchanged original functions and complete
fixtures/teardown. It preserves all five collected labels and reports genuine
provider availability exclusions in ordinary text pytest output. No hardware
substitution, implicit token trust anchor or proof/ELF/hash pipeline is involved.
