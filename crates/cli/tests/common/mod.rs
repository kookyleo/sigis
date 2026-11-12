//! Select the executable artifact produced for this worktree's verification.
use std::{path::PathBuf, sync::OnceLock};

pub fn cli() -> &'static PathBuf {
    static EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();
    EXECUTABLE.get_or_init(|| {
        let path = std::env::var_os("SIGIS_CLI_TEST_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_pyhanko")));
        eprintln!("CLI artifact selected: {}", path.display());
        path
    })
}
