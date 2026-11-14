//! Select the CLI built by Cargo, with an optional explicit test override.
use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

// Keep these legacy test hooks source-compatible while removing obsolete
// file/executable provenance work. Tests assert product behavior directly.
pub fn record_file(_path: &Path, _kind: &str) {}

pub fn record_test_executable() {}

pub fn cli() -> &'static PathBuf {
    static EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();
    EXECUTABLE.get_or_init(|| {
        let path = std::env::var_os("SIGIS_CLI_TEST_BIN")
            .map(PathBuf::from)
            .or_else(|| {
                // Scheduler workers may remap the canonical target. Select the
                // binary beside THIS test's debug/release directory, rather
                // than a baked client path shared with another worktree.
                let executable = std::env::current_exe().ok()?;
                executable.ancestors().find_map(|parent| {
                    let profile = parent.file_name()?.to_str()?;
                    if !matches!(profile, "debug" | "release") {
                        return None;
                    }
                    let binary = parent.join("pyhanko");
                    binary.is_file().then_some(binary)
                })
            })
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_pyhanko")));
        record_test_executable();
        record_file(&path, "cli_executable");
        path
    })
}
