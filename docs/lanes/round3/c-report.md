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
