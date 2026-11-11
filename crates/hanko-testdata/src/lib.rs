//! Shared test fixtures of the sigis-hanko crates.
//!
//! Fixtures live under `data/` in this crate; each subdirectory records its
//! origin and license in a `README.md`. This crate is owned by the lead (see
//! `docs/hanko-lanes.md`); lanes request additions or add new subdirectories
//! of their own under `data/<lane>/`.
//!
//! | Directory | Content |
//! | --- | --- |
//! | `data/pyhanko-certvalidator/` | pyhanko-certvalidator test fixtures (NIST PKITS, OpenSSL OCSP, test PKIs) |
//! | `data/sigis-generated/` | Certificates generated for algorithm tests (`generate.sh`) |
//! | `data/pyhanko/` | pyHanko test data (test PKI, PDFs) — imported by the lead |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;

/// Root of the fixture directory.
pub fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data")
}

/// Path of a fixture, given its components below `data/`.
pub fn path(parts: &[&str]) -> PathBuf {
    let mut p = data_dir();
    p.extend(parts);
    p
}

/// Read a fixture; panics with the path on failure (test helper).
#[allow(clippy::panic)]
pub fn read(parts: &[&str]) -> Vec<u8> {
    let p = path(parts);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

/// Path of a pyhanko-certvalidator fixture (`tests/fixtures/...` upstream).
pub fn certvalidator(parts: &[&str]) -> PathBuf {
    let mut p = data_dir().join("pyhanko-certvalidator");
    p.extend(parts);
    p
}

/// Path of a pyHanko fixture (`pkgs/pyhanko/tests/data/...` and the shared
/// `pyhanko_testing_commons` test data upstream).
pub fn pyhanko(parts: &[&str]) -> PathBuf {
    let mut p = data_dir().join("pyhanko");
    p.extend(parts);
    p
}

/// Differential testing against pyHanko (see `tools/pyhanko-oracle/`).
pub mod oracle {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// The oracle's Python interpreter: `$HANKO_ORACLE`, else
    /// `/tmp/pyhanko-oracle/venv/bin/python` if it exists.
    pub fn python() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("HANKO_ORACLE") {
            return Some(PathBuf::from(p));
        }
        let default = PathBuf::from("/tmp/pyhanko-oracle/venv/bin/python");
        default.exists().then_some(default)
    }

    /// Run an oracle script and parse its JSON output.
    ///
    /// Returns `None` (after printing why) when the oracle is not installed,
    /// so differential tests skip instead of failing. A script that runs
    /// but fails is a test failure.
    #[allow(clippy::panic)]
    pub fn run_json(script: &Path, args: &[&str]) -> Option<serde_json::Value> {
        let Some(python) = python() else {
            eprintln!(
                "pyHanko oracle not installed; skipping differential check ({})",
                script.display()
            );
            return None;
        };
        let out = Command::new(&python)
            .arg(script)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("run {}: {e}", python.display()));
        if !out.status.success() {
            panic!(
                "oracle script {} failed: {}",
                script.display(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Some(serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("oracle JSON: {e}")))
    }
}
