//! Real subprocess controls for the configuration-only PKCS#11 frontend.

use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

const INPUT: &str = "input.pdf";
const OUTPUT: &str = "output.pdf";
const CONFIG: &str = "pyhanko.yml";
pub const SENTINEL: &[u8] = b"PKCS11 configuration refusal must preserve this existing output.\n";
pub const CANARY: &str = "provider-canary.not-a-library";

fn sha256(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn snapshot(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap();
    json!({
        "path":path.canonicalize().unwrap(),
        "length":bytes.len(),"sha256":sha256(&bytes),
    })
}

fn contents(path: &Path) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("{}: {error}", path.display()),
    }
}

fn entries(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

pub struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    pub fn new(config: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]);
        crate::common::record_file(&source, "pkcs11_negative_input_fixture");
        fs::copy(source, dir.path().join(INPUT)).unwrap();
        if let Some(config) = config {
            fs::write(dir.path().join(CONFIG), config).unwrap();
        }
        Self { dir }
    }

    pub fn canary(&self) {
        // Plain text deliberately cannot be a provider. Its unchanged bytes do
        // not prove that it was not opened: the parent separately traces I/O.
        fs::write(self.dir.path().join(CANARY), b"Not a PKCS11 provider.\n").unwrap();
    }

    pub fn existing_output(&self) {
        fs::write(self.dir.path().join(OUTPUT), SENTINEL).unwrap();
    }

    pub fn args(extra: &[&str]) -> Vec<String> {
        let mut args = ["sign", "addsig", "--field", "Sig1", "pkcs11"]
            .map(str::to_owned)
            .to_vec();
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        args.extend([INPUT.to_owned(), OUTPUT.to_owned()]);
        args
    }

    pub fn reject(&self, extra: &[&str], expected: &str) -> String {
        self.reject_args(Self::args(extra), expected)
    }

    pub fn reject_args(&self, args: Vec<String>, expected: &str) -> String {
        let input = self.dir.path().join(INPUT);
        let config = self.dir.path().join(CONFIG);
        let output_path = self.dir.path().join(OUTPUT);
        let canary = self.dir.path().join(CANARY);
        let input_before = contents(&input);
        let config_before = contents(&config);
        let output_before = contents(&output_path);
        let canary_before = contents(&canary);
        let entries_before = entries(self.dir.path());
        let materials_before = json!({
            "input":snapshot(&input),
            "config":config_before.as_ref().map(|bytes|json!({"length":bytes.len(),"sha256":sha256(bytes)})),
        });
        let executable = crate::common::cli();
        let executable_before = snapshot(executable);
        if let Ok(expected) = std::env::var("SIGIS_PKCS11_CONFIG_CLI_SHA256") {
            assert_eq!(
                executable_before["sha256"].as_str(),
                Some(expected.as_str()),
                "Selected CLI bytes do not match the explicit producer identity"
            );
        }
        let output = Command::new(executable)
            .args(&args)
            .current_dir(self.dir.path())
            .env_remove("PYHANKO_PKCS11_PIN")
            .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
            .output()
            .unwrap();
        let executable_after = snapshot(executable);
        self.record(
            &args,
            executable,
            &output,
            &executable_before,
            &materials_before,
            &input,
            &config,
            &output_path,
            output_before.as_deref(),
        );
        assert_eq!(
            executable_before, executable_after,
            "Selected CLI changed during invocation"
        );
        assert_eq!(
            contents(&input),
            input_before,
            "Rejected request changed input"
        );
        assert_eq!(
            contents(&config),
            config_before,
            "Rejected request changed config"
        );
        assert_eq!(
            contents(&output_path),
            output_before,
            "Rejected request changed/created output"
        );
        assert_eq!(
            contents(&canary),
            canary_before,
            "Rejected request changed canary"
        );
        assert_eq!(
            entries(self.dir.path()),
            entries_before,
            "Rejected request created side effects"
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.code(), Some(1), "{args:?}: {combined}");
        assert!(
            combined.contains(expected),
            "{args:?}: expected {expected:?}, got {combined}"
        );
        combined
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        args: &[String],
        executable: &Path,
        output: &Output,
        executable_before: &Value,
        materials_before: &Value,
        input: &Path,
        config: &Path,
        output_path: &Path,
        output_before: Option<&[u8]>,
    ) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let receipt = json!({
            "thread":std::thread::current().name(),
            "kind":"configuration-only PKCS11 CLI rejection",
            "argv":args,"cwd":self.dir.path().canonicalize().unwrap(),
            "cli_before":executable_before,"cli_after":snapshot(executable),
            "native_test_executable":snapshot(&std::env::current_exe().unwrap()),
            "inputs_before_use":materials_before,"input_after":snapshot(input),
            "declared_source_commit":std::env::var("SIGIS_PKCS11_CONFIG_SOURCE_COMMIT").ok(),
            "config":contents(config).map(|bytes|json!({"length":bytes.len(),"sha256":sha256(&bytes)})),
            "output_before":output_before.map(|bytes|json!({"length":bytes.len(),"sha256":sha256(bytes)})),
            "output_after":contents(output_path).map(|bytes|json!({"length":bytes.len(),"sha256":sha256(&bytes)})),
            "exit_code":output.status.code(),
            "stdout":String::from_utf8_lossy(&output.stdout),
            "stderr":String::from_utf8_lossy(&output.stderr),
            "host":fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),
            "slot":std::env::var_os("RUST_SLOTS_HELD"),
            "provider_or_signing_result_claim":false,
        });
        if let Some(base) = std::env::var_os("SIGIS_CLI_PKCS11_RECORD_DIR") {
            let archive = PathBuf::from(base).join(format!(
                "{}-{:06}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&archive).unwrap();
            fs::write(
                archive.join("receipt.json"),
                serde_json::to_vec_pretty(&receipt).unwrap(),
            )
            .unwrap();
            fs::copy(input, archive.join(INPUT)).unwrap();
            if config.exists() {
                fs::copy(config, archive.join(CONFIG)).unwrap();
            }
            fs::write(archive.join("stdout.bin"), &output.stdout).unwrap();
            fs::write(archive.join("stderr.bin"), &output.stderr).unwrap();
        }
        let line = format!("PKCS11_CONFIG_PROCESS {receipt}");
        eprintln!("{line}");
    }
}
