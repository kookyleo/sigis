# PKCS11 explicit USER-PIN prompt original: source support

This fixture subtree supports exactly one C-owned upstream original:
`pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_pin_prompt`.
Its five root-cert labels are five parameters, all with effective Ed25519
selection and a real EDDSA requirement. This is neither five originals nor five
algorithms. No runtime outcome is established by these source files.

The copied public fixture certificates and original Ed25519 PKCS8 input retain
the exact input hashes in `inputs.json`. The private key is published upstream
test material. No replacement key generation or token private-value readback is
performed. The original EnvPIN fixture, its files and stores remain untouched.

`provision_signing.py ABSOLUTE_NEW_PROVIDER_DIRECTORY` creates one new private
SoftHSM file store, authenticates in that provisioning process, imports the
original Ed25519 private token key and three actual TOKEN certificate objects,
checks public-key binding, actual EDDSA support and all certificate readbacks,
then exits. The original provider files are read-only. Both production PIN
environment names are cleared before first module initialization. The receipt
redacts utility PIN arguments and records source, object, module, process and
readback identity. Native body children must be spawned only after this process
completes; those children must not perform an earlier fixture login.

`run_original_reference.sh ABSOLUTE_NEW_RECORD_DIRECTORY` performs that separate
provisioning and then runs the actual unchanged pinned pytest target with all
five items, complete real fixtures and teardown. The transparent plugin delegates
actual module/session/key operations and DummyPrompter behavior. It records the
exact label and return hash, verifies consumption of the actual fixture prompter,
and preserves the original source. It requires both PIN environment variables
absent before project/provider initialization. The full old fixture cache,
collection/marker closure and actual 2020 clock are recorded, not replaced.
Real high-level sign calls are observed; native FFI C_Sign counts remain unknown.
The verified python-pkcs11 0.9.5 candidate-refresh receipts are recorded separately
from stale historical 0.9.3 metadata.

`run_five_fresh_originals.py ABSOLUTE_NEW_RECORD_DIRECTORY` separately fulfills
the original-process isolation contract: each of the five exact node IDs gets a
new private store, a completed separate provisioning/readback process and then a
fresh pytest process with its unchanged real fixtures/body/full teardown. Both
production PIN environment variables are absent before either child initializes
the provider. `fresh_original_oracle_plugin.py` reuses the transparent observer
but accepts exactly one real collected item. Its fresh-cache/config/DER-count
checks are explicitly supplemental observation checks, not upstream assertions.
The historical `run_original_reference.sh` five-item single-process run and its
shared-cache observations remain separate evidence; they do not establish five
fresh original processes. Neither driver changes an upstream body or fixture.

`validate_outputs.py REQUEST.json` reads actual native outputs and validates them
at the supplied 2020 and actual NOW clocks. It uses explicit root-only or empty
trust, no issuer preload, no fetching, soft-fail revocation and one-second
tolerance, matching the native nonhistorical context profile. It preserves actual
NOW expiry refusals, full path3, Sig1, integrity and changed-byte controls; an
unexpected timestamp is a blocker, not permission to use a Basic fallback.
These peer validations are distinct from the complete original pytest teardown.

`run_adverse_reference.sh ABSOLUTE_NEW_RECORD_DIRECTORY CASE` accepts exactly
`missing-pull-valid-file`, `missing-file-valid-token` or `wrong-user-pin`.
Each invocation provisions a separate private store, completes readback and then
executes one fresh prompted probe. No successful prior body login is shared.
Duplicate source failures have no guessed result: actual exit/output/publication
and validation are recorded, including a possible upstream partial file. Missing
pull uses `absent-certificate-label` to avoid the upstream string-substring
matching confounder. The original string-valued pull semantics are not silently
rewritten. Probes are supplemental and add zero immutable originals.

Scripts require `/tmp/pyhanko-oracle/venv/bin/python` with the existing isolated
0.9.5 overlay selected explicitly. They install nothing, never mutate old token
stores, and do not authorize a hardware probe, terminal fallback, signing-PIN
prompt, software-signing substitution or implicit trust anchor.

## Supplemental strict-policy evidence

`create_policy_revinfo.py` materializes the original pinned Ed25519 architecture
for exact frozen-certificate DER crosschecks and issues two authenticated CRLs
at2020-11-01 from its original CA fixture keys. It never replaces token material,
exports a token key or signs a PDF. The generated public DER/manifest files are
for explicit historical hard-fail policy controls only, not the original five
no-fetcher prompt bodies. The test CrlFetcher binds exact actual target DER and
records returned DER hashes. Missing evidence and signature-only tampered CRLs
remain rejection controls; no context/default/revocation rule is weakened.
Actual fixture generation is recorded separately under lane artifacts; the
manifest retains original generation paths and authenticated byte hashes.
