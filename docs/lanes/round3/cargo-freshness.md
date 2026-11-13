# Shared-target source freshness

## Reproduced counterexample

Cargo's relative workspace dep-info and mtime freshness can reuse a foreign
worktree's newer library in the shared canonical target. Root selected a tree
without `rw_common::resolve_reference`, but its new importing test compiled and
passed against a cached library. Verbose Cargo reported that library Fresh.
Changing only the selected source's mtime, without changing its SHA-256, forced
compilation and the correct unresolved-import error. This was a source-identity
failure; the accidental green earns no upstream credit.

The selected missing-API source SHA-256 is
`461fb6e826381599327fc44b32dc158aacfdd5627ccc81a5291d1485aaa19424`.
Its original mtime is1794518556127452839ns. Logs, actual commands and before/after
identity records are under `round3-launch/ria-http-pdf-integration/` in the
artifact tree. The independently reviewed explanation is cargo-freshness-audit.md.

## Persistent correctness configuration

The installed cluster nightly Cargo documents both required keys:

```toml
[unstable]
checksum-freshness = true

[build]
fingerprint = "content"
```

Only enabling the unstable switch leaves the default mtime method unchanged.
The two-key repository `.cargo/config.toml` is authoritative; it is also
transferred with the source tree by normal rust-remote dispatch. A wrapper-only
arbitrary Cargo environment export would not reliably cross that boundary.
The wrapper rejects an accidental environment downgrade of the method.

This changes source freshness checking, without a compiler flag/profile/feature
override, new target path, cleaned cache, repository-wide lock, local-placement
pin, job cap or disabled sccache. rust-target-env and rust-slots remain the
exclusive target/scheduling owners. Acceptance uses the already installed
nightly-2026-09-21 Cargo with this capability; unsupported toolchains do not
establish equivalent source identity.

## Verification and limits

The focused cycle first required an actual missing-API compile failure, then
passed after adding the exact resolver, then failed again after restoring the
original bytes and old mtime. A further equal-length mutation renamed the
exported function while restoring the old mtime; Cargo explicitly reported
`checksum didn't match` and the expected unresolved import. The recorded
fingerprint JSON must use `content`; a mere failing command is insufficient.

These are correctness controls, not new upstream functions. Historical reported
main counts stay on verification hold until a complete source-correct main gate
passes with fresh actual executable/runtime identity checks.

Cargo's documented current limitation is that build-script rerun-if-changed
inputs still use mtimes. There are no project-owned crate/vendor build.rs files
at this checkpoint; external dependencies and future build scripts require a
separate audit. Content freshness does not prove semantic or universal trust
parity, nor every concurrent linker/cache race. Keep the ordinary scheduler,
exclusive per-worktree operation and complete merged gate in use; never solve
this by killing another build or cleaning the shared target.
