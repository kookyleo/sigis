//! Select the executable artifact produced for this worktree's verification.
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

/// Snapshot an actual runtime file before passing its path to the native caller.
/// This is not a production file-read trace or retrospective evidence.
pub fn record_file(path: &Path, kind: &str) {
    static SEEN: OnceLock<Mutex<std::collections::BTreeSet<PathBuf>>> = OnceLock::new();
    let path = path.canonicalize().unwrap();
    if !SEEN
        .get_or_init(Mutex::default)
        .lock()
        .unwrap()
        .insert(path.clone())
    {
        return;
    }
    let bytes = std::fs::read(&path).unwrap();
    let sha256 = openssl::sha::sha256(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    eprintln!(
        "CLI_PROVENANCE {}",
        serde_json::json!({
            "kind":kind,"path":path,"length":bytes.len(),"sha256":sha256,
            "host":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),
            "manifest_dir":std::env::var_os("CARGO_MANIFEST_DIR"),
        })
    );
}

/// Record the native test process, independently of a selected CLI subprocess.
pub fn record_test_executable() {
    record_file(&std::env::current_exe().unwrap(), "native_test_executable");
}

pub fn cli() -> &'static PathBuf {
    static EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();
    EXECUTABLE.get_or_init(|| {
        let path = std::env::var_os("SIGIS_CLI_TEST_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_pyhanko")));
        eprintln!("CLI artifact selected: {}", path.display());
        record_test_executable();
        record_file(&path, "cli_executable");
        path
    })
}
