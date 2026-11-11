# Vendored crates

## underskrift 0.1.4

- Source: crates.io `underskrift` 0.1.4 (upstream git commit `17bca3c4ac49af475772678f1e9ccd35bfaaa3af`, <https://github.com/kushaldas/underskrift>).
- License: BSD-2-Clause (see `underskrift/Cargo.toml`).
- Used through `[patch.crates-io]` in the root `Cargo.toml`.

The first commit that adds this directory contains the unmodified crate. Later
commits that touch `vendor/underskrift/` hold the Sigis patch, so `git diff`
against that commit shows exactly what to upstream.

Remove this directory and the `[patch.crates-io]` entry when upstream ships an
equivalent change.
