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

use std::path::{Path, PathBuf};

/// Environment variable that overrides the fixture directory.
pub const TESTDATA_ENV: &str = "HANKO_TESTDATA";

/// The manifest directory of the crate whose test is running, read at run
/// time.
///
/// Use this instead of `env!("CARGO_MANIFEST_DIR")` in tests. All worktrees
/// share one cargo target directory, so a compiled crate (and the path baked
/// into it at compile time) can come from another worktree; cargo and nextest
/// set `CARGO_MANIFEST_DIR` for every test process, which always names the
/// worktree being tested.
pub fn manifest_dir() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

fn find_data_dir(start: &Path) -> Option<PathBuf> {
    start.ancestors().find_map(|dir| {
        let in_workspace = dir.join("crates/hanko-testdata/data");
        if in_workspace.is_dir() {
            return Some(in_workspace);
        }
        let in_crate = dir.join("data");
        (dir.file_name().is_some_and(|n| n == "hanko-testdata") && in_crate.is_dir()).then_some(in_crate)
    })
}

/// Root of the fixture directory, resolved at run time:
///
/// 1. `$HANKO_TESTDATA`, if set;
/// 2. `crates/hanko-testdata/data` found by walking up from the running
///    test's `CARGO_MANIFEST_DIR` (the worktree being tested);
/// 3. the compile-time location, as a last resort.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(TESTDATA_ENV) {
        return PathBuf::from(dir);
    }
    if let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR").and_then(|d| find_data_dir(Path::new(&d))) {
        return dir;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_data_directory_of_the_running_worktree() {
        let dir = data_dir();
        assert!(dir.join("pyhanko").is_dir(), "{}", dir.display());
        let here = manifest_dir();
        assert!(dir.starts_with(here.parent().and_then(Path::parent).unwrap_or(&here)), "{} vs {}", dir.display(), here.display());
    }

    #[test]
    fn walks_up_from_any_workspace_crate() {
        let root = manifest_dir().join("../..");
        let from_other_crate = find_data_dir(&root.join("crates/hanko-cms")).expect("found");
        assert!(from_other_crate.ends_with("crates/hanko-testdata/data"));
        assert!(find_data_dir(Path::new("/")).is_none());
    }
}
