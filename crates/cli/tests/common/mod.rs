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
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_pyhanko")));
        record_test_executable();
        record_file(&path, "cli_executable");
        path
    })
}
