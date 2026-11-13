//! Per-invocation signing evidence. A receipt records an attempt, not a passing test.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Output,
    sync::atomic::{AtomicU64, Ordering},
};

fn sha256(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn snapshot(path: &Path) -> (serde_json::Value, Vec<u8>) {
    let actual = path.canonicalize().unwrap();
    let bytes = fs::read(&actual).unwrap();
    let record = serde_json::json!({
        "path":actual,"length":bytes.len(),"sha256":sha256(&bytes),
    });
    (record, bytes)
}

/// Capture the actual input bytes' identity before the subprocess can use them.
pub fn before(paths: &[PathBuf]) -> Vec<serde_json::Value> {
    paths
        .iter()
        .map(|path| {
            crate::common::record_file(path, "signing_input_before_use");
            snapshot(path).0
        })
        .collect()
}

/// Archive the output before another process can replace it or the tempdir expires.
#[allow(clippy::too_many_arguments)]
pub fn process(
    stage: &str,
    args: &[String],
    cwd: &Path,
    stdin: &[u8],
    executable: &Path,
    output: &Output,
    inputs: &[serde_json::Value],
    artifacts: &[(&str, &Path)],
) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let archive = std::env::var_os("SIGIS_CLI_SIGNING_RECORD_DIR").map(|base| {
        let path = PathBuf::from(base).join(format!(
            "{}-{:06}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    });
    let files: Vec<_> = artifacts
        .iter()
        .enumerate()
        .map(|(index, (label, path))| {
            let (mut record, bytes) = snapshot(path);
            record["label"] = (*label).into();
            if let Some(archive) = &archive {
                let target = archive.join(format!("artifact-{index:02}.bin"));
                fs::write(&target, bytes).unwrap();
                record["archive_path"] = serde_json::json!(target);
            }
            record
        })
        .collect();
    let input_files: Vec<_> = inputs
        .iter()
        .enumerate()
        .map(|(index, original)| {
            let (mut record, bytes) = snapshot(Path::new(original["path"].as_str().unwrap()));
            assert_eq!(&record, original, "Signing input changed during invocation");
            if let Some(archive) = &archive {
                let target = archive.join(format!("input-{index:02}.bin"));
                fs::write(&target, bytes).unwrap();
                record["archive_path"] = serde_json::json!(target);
            }
            record
        })
        .collect();
    let receipt = serde_json::json!({
        "thread":std::thread::current().name(),
        "stage":stage,"argv":args,"cwd":cwd.canonicalize().unwrap(),
        "stdin_sha256":sha256(stdin),"stdin_length":stdin.len(),
        "executable":snapshot(executable).0,
        "native_test_executable":snapshot(&std::env::current_exe().unwrap()).0,
        "inputs_before_use":input_files,"artifacts":files,
        "stdout":String::from_utf8_lossy(&output.stdout),
        "stderr":String::from_utf8_lossy(&output.stderr),
        "exit_code":output.status.code(),"success":output.status.success(),
        "host":fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),
        "archive_directory":archive,
    });
    if let Some(archive) = &archive {
        fs::write(archive.join("stdout.bin"), &output.stdout).unwrap();
        fs::write(archive.join("stderr.bin"), &output.stderr).unwrap();
        fs::write(
            archive.join("receipt.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
    }
    eprintln!("SIGNING_PROCESS_RECORD {receipt}");
}
