# Lead acceptance update

Accepted assigned counts: **252 total /98 passed /0 skipped /154 pending**. Only the four reviewed modules are integrated; later owner full-source proposals remain separate. The owner checkpoint below is historical provenance and its zero-accepted figures are superseded by this lead update. See docs/lanes/round3/l-cli-prefix.md for source, immutable executable and gate evidence.

# Lane C independent fields checkpoint

Shared base4a9ae57; full source/assertions archived at4d8c8b7 and backup/r3-c-full-before-module-increments. This coherent projection is independently buildable. Deferred original tests and code remain preserved, and will all be restored after four module commits.

Fixed assignment: sigis-cli **252 total / 98 locally passed /0 skipped /154 pending**. Accepted ledger remains252/0/0/252. Full-source proposal237/0/15 and its two known native failures remain separate; unavailable commands add no credit. Scoped native run:128 passed/0 failed/0 ignored. Exact IDs map in crates/cli/PORTING.md; parameters/exclusions/oracle counts are in CONFIG_PORTING.md, PLUGINS_PORTING.md, CRYPT_PORTING.md and FIELDS_PORTING.md as available. Module ownership remains exclusive.

Evidence root: ~/.codex/artifacts/sigis/round3/c/. Current build/tests/clippy/fmt logs and receipts: increment-fields-*. Current slots: {"build": ["s7.0"], "tests": ["vm2065.0"], "clippy": ["vm2065.0"], "fmt": []}. All commands use tools/cargo-locked.sh with absolute system scheduler and preserved sccache; no repository lock, placement/job override or empty RUSTC_WRAPPER. Reproduce using observe_lane_cargo.py and run_with_runtime.py (exact wrapper argv in receipts); the latter forwards runtime-only Cargo env config across dispatch. Fresh artifact hash/provenance in increment-fields-build-artifact.json. No generated lock is committed; original generated lock stash ea51d5e and exact bytes/patch remain archived. No push/service change/build kill.

Exact dependencies for this projection:

```toml
[package]
name = "sigis-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
publish.workspace = true
description = "Rust command-line interface compatible with pyHanko"

[[bin]]
name = "pyhanko"
path = "src/main.rs"

[dependencies]
clap = { version = "=4.6.7", features = ["derive"] }
serde = { version = "=1.0.229", features = ["derive"] }
serde_yaml = "=0.9.34"
yaml-rust2 = { version = "=0.13.0", default-features = false }
regex = { workspace = true }
serde_json = { workspace = true }
sigis-pades-sign = { workspace = true }
sigis-pki-core = { workspace = true }
sigis-pdf = { workspace = true }
sigis-pki-fetch = { workspace = true }
rpassword = "=7.4.0"
openssl = "=0.10.81"

[dev-dependencies]
lopdf = { workspace = true }
sigis-testdata = { workspace = true }
tempfile = "=3.27.0"
```

Configuration grammar/ABI/OpenSSL encoding limitations are documented separately from trust behavior; no universal fail-closed claim. Signing/validation/LTV/stamp commands remain explicitly unavailable in these four increments, and acquire no credit. Field PdfUpdate budget/auth/strictness propagation remains requested through L/P. The forbidden-only KU repair is accepted in shared mainb81c254 per interfaces-l.md; no API changes outside owned paths.

Commit heads are recorded after commit in increments-4a/progress.json. Owned files only will be committed. Full source restoration remains required.

Completed module commit heads: {"config": "b1e5ad04977b587ddd517dc4c0552663ffcfd794", "plugins": "c8c4cc6d33466e31e96162876ebee9e85bf5408d", "crypt": "79acc88b448ff72a48212ebf23d1ea27c9add16d"}

Exact source decorator/fixture parameters: crates/cli/INCREMENT_PARAMETERS.md (98 functions).


## Scoped CLI prefix acceptance

Source 09ec130 passes all six workspace gates: 1706 discovered,
1698 passed, 8 ignored, zero failed, 150 reports.
Only the reviewed standalone prefix is integrated: configuration57, native
plugin registration/identity11, encryption/decryption23 (including two exact
decode-limit functions), and field management7. The98 immutable IDs and original
parameters are in crates/cli/INCREMENT_PARAMETERS.md and PORTING.md. Other154
CLI functions stay pending; later full-source restoration and its known runtime
or trust-result failures are not imported by this acceptance. No function was
ignored, removed from its inventory, or counted from an empty wrapper.

Three configuration loader functions previously had only raw-signature checks.
They now sign the independent SHA256 digest of Hello world! through the actual
production CMS builder and verify its unique SignerInfo with the loaded
certificate, expected data OID and original digest. Intact and valid must both
hold; a changed expected digest must fail integrity. The focused44 native
configuration tests pass. Four retained native CMS/certificate output cases
received eight fresh pinned Python integrity decisions with matching actual
input hashes. The fourth missing-passphrase function is not counted twice;
it already had complete original loading/refusal assertions. CMS integrity
does not establish certificate trust or CLI signing-command coverage.

The scoped CLI package has128 passed native tests, zero failures/ignores.
Cargo copied its actual ELF into an immutable artifact directory while holding
the build lock. Producer source 09ec130, ELF SHA256 ffc61fff25eacf12cd8f57b67fb6767e9729a6a7efaa5cffd36b22e064738c69,
88102784bytes. Same-path copies on both workers match SHA/version.
Explicit test-only Cargo env selectors chose that executable for every actual
CLI subprocess; its hash is unchanged before/after the full gate. Canonical
targets, compiler flags/profiles/features, sccache and automatic placement are
unchanged. Artifact copy uses the existing nightly Cargo artifact-dir facility.

The existing scoped tests freshly execute17 configuration oracle cases,
36 crypt CLI comparisons plus18 artifact checks, and10 field oracle calls.
The independent loader output comparison adds eight integrity decisions;
these are separate measurements, not new unique functions. Plugin reference
evidence is historical source execution; native11 tests exercise registry/help
and typed identity behavior, using native endpoint interfaces rather than
importing Python modules. They do not execute a signing engine. Field tests
use real lower-layer signing to check occupied fields; they do not establish
a trusted PDF signature. No runtime provider exclusion was added.

PKCS11 commands, other signing/stamping/runtime/validation/LTV functions,
complete reader-state callers and final CLI LTA integration remain pending.
Unsupported commands and mandatory requirements reject explicitly. Known
unmerged CLI trust failures and the retained combined-PKI registry discrepancy
still prevent any universal all-divergences-fail-closed claim. This is a scoped
98-function acceptance, not completion of the252-function CLI or full port.

Accepted C252/98/0/154; overall1431/1229/30/172. Detailed source/binary/fixture
hashes, independent assertion reviews, actual test selectors and full logs:
round3-launch/c-prefix-integration/ and round3-launch/c-prefix-review/.
