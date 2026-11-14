//! Two original frontend failures through the real top-level CLI entry point.
//! Provider initialization is intentionally unreachable in these argument/config
//! cases; this target claims no token, mechanism or signing-provider coverage.
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

static CWD: Mutex<()> = Mutex::new(());
struct RestoreCwd(PathBuf);
impl Drop for RestoreCwd {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.0).unwrap();
    }
}
fn entries(path: &Path) -> Vec<String> {
    let mut entries = fs::read_dir(path)
        .unwrap()
        .map(|item| item.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}
fn invoke(extra: &[&str], expected: &str, input: &Path, output: &Path) {
    let mut args = ["sign", "addsig", "--field", "Sig1", "pkcs11"]
        .map(str::to_owned)
        .to_vec();
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args.extend([input.display().to_string(), output.display().to_string()]);
    let before_input = fs::read(input).ok();
    let before_output = fs::read(output).ok();
    let result = sigis_cli::run_with_runtime(
        &args,
        &PluginRegistry::default(),
        &ValidationRuntime::default(),
    );
    let text = format!("{}{}", result.stdout, result.stderr);
    assert_eq!(result.code, 1, "{text}");
    assert!(text.contains(expected), "{text}");
    assert_eq!(
        fs::read(input).ok(),
        before_input,
        "preflight changed input"
    );
    assert_eq!(
        fs::read(output).ok(),
        before_output,
        "preflight changed or created output"
    );
}

pub fn run(name: &str, extra: &[&str], expected: &str) {
    // This test binary contains only these two originals. Serialize its own CWD
    // because the real top-level CLI selects absent default pyhanko.yml exactly
    // as CliRunner's isolated filesystem does; no process-wide provider env edit.
    let _lock = CWD.lock().unwrap_or_else(|poison| poison.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let _restore = RestoreCwd(std::env::current_dir().unwrap());
    std::env::set_current_dir(dir.path()).unwrap();
    let input = dir.path().join("input.pdf");
    let output = dir.path().join("output.pdf");
    fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
    let sentinel = dir.path().join("unrelated-sentinel.bin");
    fs::write(
        &sentinel,
        b"Preserve unrelated files during preflight refusal.\n",
    )
    .unwrap();
    let before = fs::read(&sentinel).unwrap();
    let before_entries = entries(dir.path());
    assert!(!dir.path().join("pyhanko.yml").exists());
    assert!(!output.exists());

    // Exact original argv/exit/message assertions, before any provider can load.
    invoke(extra, expected, &input, &output);
    assert_eq!(
        entries(dir.path()),
        before_entries,
        "preflight created a file"
    );

    // Fresh pinned Python CLI peer on the same actual input and absent config.
    // The installed functional 0.9.5 overlay is a dependency path, not hardware
    // evidence or a provenance selector. No provider API is called here.
    let mut args = ["sign", "addsig", "--field", "Sig1", "pkcs11"]
        .map(str::to_owned)
        .to_vec();
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args.extend([input.display().to_string(), output.display().to_string()]);
    let peer = Command::new(
        std::env::var("HANKO_ORACLE")
            .unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into()),
    )
    .current_dir(dir.path())
    .arg("-B")
    .arg("-c")
    .arg(
        r#"
import sys
sys.path[:0]=['/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5',
 '/home/l/.codex/artifacts/sigis/round3/c/oracle-deps']
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from click.testing import CliRunner
from pyhanko.cli import cli_root
result=CliRunner().invoke(cli_root,sys.argv[2:])
assert result.exit_code==1,(result.exit_code,result.output)
assert sys.argv[1] in result.output,result.output
"#,
    )
    .arg(expected)
    .args(&args)
    .env_remove("PYHANKO_PKCS11_PIN")
    .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
    .output()
    .unwrap();
    assert!(
        peer.status.success(),
        "{name}: {}{}",
        String::from_utf8_lossy(&peer.stdout),
        String::from_utf8_lossy(&peer.stderr)
    );
    assert_eq!(
        entries(dir.path()),
        before_entries,
        "reference created a file"
    );
    assert!(!output.exists());
    assert_eq!(fs::read(&sentinel).unwrap(), before);

    // Supplemental ordering controls: a nonexistent input and an existing output
    // cannot outrank required frontend parameters/config. An invalid provider
    // canary with otherwise tempting options must still not reach module load.
    fs::remove_file(&input).unwrap();
    fs::write(&output, b"Preserve existing output on frontend refusal.\n").unwrap();
    invoke(extra, expected, &input, &output);
    let canary = dir.path().join("provider-canary.not-a-library");
    fs::write(&canary, b"Not a PKCS11 module.\n").unwrap();
    let canary_text = canary.display().to_string();
    let mut canary_args = extra.to_vec();
    canary_args.extend(["--lib", canary_text.as_str()]);
    if !extra.is_empty() {
        canary_args.extend(["--cert-label", "signer"]);
    }
    invoke(&canary_args, expected, &input, &output);
    assert_eq!(fs::read(&canary).unwrap(), b"Not a PKCS11 module.\n");
    assert_eq!(fs::read(&sentinel).unwrap(), before);
    assert!(!dir.path().join("pyhanko.yml").exists());
}
