// Port of pyHanko 0.38.1 test_cli_crypt.py (MIT, see LICENSE-pyHanko).
// Unique upstream functions retain their names; parameter cases run in loops.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/mod.rs"]
mod common;

use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};
use sigis_pdf::crypt::{
    AuthStatus, PubKeyEncryptOptions, PubKeyPermissions, RecipientEncryptionPolicy,
};
use sigis_pdf::{PdfFile, PdfHandlerExt, ReaderOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new(pdf: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("in.pdf"),
            sigis_testdata::read(&["pyhanko", "pdf", pdf]),
        )
        .unwrap();
        Self { dir }
    }
    fn oversized(method: &str) -> Self {
        let case = Self::new("minimal.pdf");
        std::fs::write(
            case.dir.path().join("in.pdf"),
            sigis_testdata::read(&["lanes", "r3-c", "crypt", &format!("oversized-{method}.pdf")]),
        )
        .unwrap();
        case
    }
    fn invoke(&self, args: &[&str], pass: &str) -> std::process::Output {
        let mut child = Command::new(common::cli())
            .args(args)
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{pass}\n").as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        self.oracle_command(args, pass, &result);
        result
    }
    fn oracle_command(&self, args: &[&str], pass: &str, rust: &std::process::Output) {
        let Some(python) = sigis_testdata::oracle::python() else {
            eprintln!("Runtime provider skip: HANKO_ORACLE unavailable (command comparison only)");
            return;
        };
        let script = r#"import sys
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from click.testing import CliRunner
from pyhanko.cli import cli_root
from pyhanko.cli._ctx import CLIContext, UXContext, PasswordPrompter
class Prompt(PasswordPrompter):
 def prompt_for_password(self, prompt): return sys.argv[1]
args = ['oracle-out.pdf' if a == 'out.pdf' else a for a in sys.argv[2:]]
result = CliRunner().invoke(cli_root, args, obj=CLIContext(ux=UXContext(prompter=Prompt())))
print(result.exit_code)
print(result.output)
"#;
        let out = Command::new(python)
            .args(["-c", script, pass])
            .args(args)
            .current_dir(self.dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", output(&out));
        let oracle = String::from_utf8(out.stdout).unwrap();
        let (code, diagnostic) = oracle.split_once('\n').unwrap();
        assert_eq!(
            rust.status.code(),
            Some(code.parse::<i32>().unwrap()),
            "Rust: {}\nOracle: {diagnostic}",
            output(rust)
        );
        for needle in [
            "Specify either",
            "Pass --force",
            "File is not encrypted.",
            "File is not encrypted with",
            "File was not encrypted with",
            "didn't match",
            "Failed to decrypt",
            "rerun with --no-decode-limits",
        ] {
            assert_eq!(
                output(rust).contains(needle),
                diagnostic.contains(needle),
                "diagnostic {needle:?}: Rust: {}\nOracle: {diagnostic}",
                output(rust)
            );
        }
    }
    fn creds(&self, mode: &str, wrong: bool, unencrypted: bool) -> Vec<String> {
        let (key_path, cert_path) = if wrong {
            (
                vec!["keys-rsa", "signer.key.pem"],
                vec!["testing-ca", "interm", "decrypter1.cert.pem"],
            )
        } else {
            (vec!["selfsigned.key.pem"], vec!["selfsigned.cert.pem"])
        };
        let crypto = |parts: &[&str]| {
            let mut p = vec!["pyhanko", "crypto"];
            p.extend_from_slice(parts);
            sigis_testdata::read(&p)
        };
        let key = PKey::private_key_from_pem_passphrase(&crypto(&key_path), b"secret").unwrap();
        let cert = X509::from_pem(&crypto(&cert_path)).unwrap();
        if mode == "pemder" {
            let pem = if unencrypted {
                key.private_key_to_pem_pkcs8().unwrap()
            } else {
                key.private_key_to_pem_pkcs8_passphrase(
                    openssl::symm::Cipher::aes_256_cbc(),
                    b"secret",
                )
                .unwrap()
            };
            std::fs::write(self.dir.path().join("recipient.key"), pem).unwrap();
            std::fs::write(
                self.dir.path().join("recipient.crt"),
                cert.to_der().unwrap(),
            )
            .unwrap();
            vec![
                "--key".into(),
                "recipient.key".into(),
                "--cert".into(),
                "recipient.crt".into(),
            ]
        } else {
            let mut builder = Pkcs12::builder();
            builder.pkey(&key).cert(&cert);
            std::fs::write(
                self.dir.path().join("recipient.p12"),
                builder.build2("secret").unwrap().to_der().unwrap(),
            )
            .unwrap();
            vec!["recipient.p12".into()]
        }
    }
    fn private(
        &self,
        mode: &str,
        extra: &[&str],
        pass: &str,
        wrong: bool,
        unencrypted: bool,
    ) -> std::process::Output {
        let creds = self.creds(mode, wrong, unencrypted);
        let mut args = vec!["decrypt", mode];
        args.extend_from_slice(extra);
        args.extend(["in.pdf", "out.pdf"]);
        args.extend(creds.iter().map(String::as_str));
        self.invoke(&args, pass)
    }
    fn forbidden(&self) {
        let data = sigis_testdata::read(&["pyhanko", "pdf", "minimal.pdf"]);
        let r = PdfFile::parse_with(&data, ReaderOptions::default()).unwrap();
        let mut w = sigis_pdf::writer::copy_into_new_writer(&r).unwrap();
        let cert = X509::from_pem(&sigis_testdata::read(&[
            "pyhanko",
            "crypto",
            "selfsigned.cert.pem",
        ]))
        .unwrap()
        .to_der()
        .unwrap();
        w.encrypt_pubkey_with(
            &[cert],
            PubKeyEncryptOptions {
                keylen_bytes: 32,
                perms: !PubKeyPermissions::ALLOW_ENCRYPTION_CHANGE,
                policy: RecipientEncryptionPolicy {
                    ignore_key_usage: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        std::fs::write(self.dir.path().join("in.pdf"), w.write().unwrap()).unwrap();
    }
    fn decrypted(&self, out: std::process::Output) {
        assert!(out.status.success(), "{}", output(&out));
        let path = self.dir.path().join("out.pdf");
        let data = std::fs::read(&path).unwrap();
        let r = PdfFile::parse_with(&data, ReaderOptions::default()).unwrap();
        assert!(!r.encrypted());
        check_first_page(&r);
        oracle(&path, "plain", "");
    }
}

fn output(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
fn error(out: std::process::Output, text: &str) {
    assert_eq!(out.status.code(), Some(1), "{}", output(&out));
    assert!(output(&out).contains(text), "{}", output(&out));
}
fn check_first_page(r: &PdfFile) {
    let pages = r.get_dict(&r.root().unwrap(), b"Pages").unwrap().unwrap();
    let kids = r.get(&pages, b"Kids").unwrap().unwrap();
    let first = kids.as_array().unwrap()[0].as_reference().unwrap();
    let page = r.get_object_at(first, None).unwrap();
    let content = r
        .get(page.as_dict().unwrap(), b"Contents")
        .unwrap()
        .unwrap();
    let content = r.stream_data(content.as_stream().unwrap()).unwrap();
    assert!(content.windows(5).any(|part| part == b"Hello"));
}

// Fresh live artifact comparisons, additional to the Rust assertions above.
fn oracle(path: &Path, mode: &str, password: &str) {
    let Some(python) = sigis_testdata::oracle::python() else {
        eprintln!("Runtime provider skip: HANKO_ORACLE unavailable (artifact comparison only)");
        return;
    };
    let script = r#"import sys
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.crypt import AuthStatus
from pyhanko_testing_commons.test_data.samples import PUBKEY_TEST_DECRYPTER
with open(sys.argv[1], 'rb') as f:
 r = PdfFileReader(f)
 if sys.argv[2] == 'password': assert r.decrypt(sys.argv[3]).status == AuthStatus.OWNER
 elif sys.argv[2] == 'pubkey': assert r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER).status == AuthStatus.USER
 else: assert r.security_handler is None
 assert b'Hello' in r.root['/Pages']['/Kids'][0]['/Contents'].data
print('artifact-agreement')
"#;
    let out = Command::new(python)
        .args(["-c", script])
        .arg(path)
        .args([mode, password])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", output(&out));
}

#[test]
fn test_encrypt_file() {
    let c = Case::new("minimal.pdf");
    let out = c.invoke(
        &["encrypt", "--password", "secret", "in.pdf", "out.pdf"],
        "",
    );
    assert!(out.status.success(), "{}", output(&out));
    let path = c.dir.path().join("out.pdf");
    let r = PdfFile::parse(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(r.decrypt("secret").unwrap().status, AuthStatus::Owner);
    oracle(&path, "password", "secret");
}
#[test]
fn test_encrypt_file_with_stdin_pass() {
    let c = Case::new("minimal.pdf");
    let out = c.invoke(&["encrypt", "in.pdf", "out.pdf"], "secret");
    assert!(out.status.success(), "{}", output(&out));
    let path = c.dir.path().join("out.pdf");
    let r = PdfFile::parse(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(r.decrypt("secret").unwrap().status, AuthStatus::Owner);
    oracle(&path, "password", "secret");
}
#[test]
fn test_encrypt_file_with_recipient_cert() {
    let c = Case::new("minimal.pdf");
    c.creds("pemder", true, false);
    let out = c.invoke(
        &[
            "encrypt",
            "--recipient",
            "recipient.crt",
            "in.pdf",
            "out.pdf",
        ],
        "",
    );
    assert!(out.status.success(), "{}", output(&out));
    let path = c.dir.path().join("out.pdf");
    let r = PdfFile::parse(&std::fs::read(&path).unwrap()).unwrap();
    let key = sigis_pdf::crypt::SimpleEnvelopeKeyDecrypter::load(
        &std::fs::read(c.dir.path().join("recipient.key")).unwrap(),
        &std::fs::read(c.dir.path().join("recipient.crt")).unwrap(),
        Some(b"secret"),
    )
    .unwrap();
    assert_eq!(r.decrypt_pubkey(&key).unwrap().status, AuthStatus::User);
    oracle(&path, "pubkey", "");
}
#[test]
fn test_encrypt_not_both_pubkey_and_password() {
    let c = Case::new("minimal.pdf");
    c.creds("pemder", false, false);
    error(
        c.invoke(
            &[
                "encrypt",
                "--recipient",
                "recipient.crt",
                "--password",
                "blah",
                "in.pdf",
                "out.pdf",
            ],
            "",
        ),
        "Specify either",
    );
}
#[test]
fn test_decrypt_with_owner_password() {
    let c = Case::new("minimal-aes256.pdf");
    c.decrypted(c.invoke(
        &[
            "decrypt",
            "password",
            "--password",
            "ownersecret",
            "in.pdf",
            "out.pdf",
        ],
        "",
    ));
}
#[test]
fn test_decrypt_with_owner_password_on_stdin() {
    let c = Case::new("minimal-aes256.pdf");
    c.decrypted(c.invoke(&["decrypt", "password", "in.pdf", "out.pdf"], "ownersecret"));
}
#[test]
fn test_force_decrypt_with_user_password() {
    let c = Case::new("minimal-aes256.pdf");
    c.decrypted(c.invoke(
        &[
            "decrypt",
            "password",
            "--password",
            "usersecret",
            "--force",
            "in.pdf",
            "out.pdf",
        ],
        "",
    ));
}
#[test]
fn test_decrypt_with_user_password_no_force() {
    let c = Case::new("minimal-aes256.pdf");
    error(
        c.invoke(
            &[
                "decrypt",
                "password",
                "--password",
                "usersecret",
                "in.pdf",
                "out.pdf",
            ],
            "",
        ),
        "Pass --force",
    );
}
#[test]
fn test_attempt_decrypt_unencrypted_file() {
    let c = Case::new("minimal.pdf");
    error(
        c.invoke(
            &[
                "decrypt",
                "password",
                "--password",
                "ownersecret",
                "in.pdf",
                "out.pdf",
            ],
            "",
        ),
        "File is not encrypted",
    );
}
#[test]
fn test_attempt_decrypt_wrong_sh_type() {
    let c = Case::new("minimal-pubkey-aes256.pdf");
    error(
        c.invoke(
            &[
                "decrypt",
                "password",
                "--password",
                "ownersecret",
                "in.pdf",
                "out.pdf",
            ],
            "",
        ),
        "File is not encrypted with",
    );
}
#[test]
fn test_decrypt_with_wrong_password() {
    let c = Case::new("minimal-aes256.pdf");
    error(
        c.invoke(
            &[
                "decrypt",
                "password",
                "--password",
                "wrong_password",
                "in.pdf",
                "out.pdf",
            ],
            "",
        ),
        "didn't match",
    );
}
#[test]
fn test_decrypt_with_private_key() {
    for mode in ["pemder", "pkcs12"] {
        for force in [true, false] {
            let c = Case::new("minimal-pubkey-aes256.pdf");
            c.decrypted(c.private(
                mode,
                if force { &["--force"] } else { &[] },
                "secret",
                false,
                false,
            ));
        }
    }
}
#[test]
fn test_decrypt_with_wrong_key() {
    let c = Case::new("minimal-pubkey-aes256.pdf");
    error(
        c.private("pemder", &[], "secret", true, false),
        "Failed to decrypt the file",
    );
}
#[test]
fn test_decrypt_with_private_key_no_force_change_of_encryption_forbidden() {
    for mode in ["pemder", "pkcs12"] {
        let c = Case::new("minimal.pdf");
        c.forbidden();
        error(c.private(mode, &[], "secret", false, false), "Pass --force");
    }
}
#[test]
fn test_decrypt_with_private_key_force_change_of_encryption_forbidden() {
    for mode in ["pemder", "pkcs12"] {
        let c = Case::new("minimal.pdf");
        c.forbidden();
        c.decrypted(c.private(mode, &["--force"], "secret", false, false));
    }
}
#[test]
fn test_decrypt_with_private_key_and_passfile() {
    for mode in ["pemder", "pkcs12"] {
        let c = Case::new("minimal-pubkey-aes256.pdf");
        std::fs::write(c.dir.path().join("passfile"), "secret").unwrap();
        c.decrypted(c.private(
            mode,
            &["--force", "--passfile", "passfile"],
            "",
            false,
            false,
        ));
    }
}
#[test]
fn test_attempt_decrypt_with_private_key_unencrypted_file() {
    for mode in ["pemder", "pkcs12"] {
        let c = Case::new("minimal.pdf");
        error(
            c.private(mode, &["--force"], "secret", false, false),
            "File is not encrypted",
        );
    }
}
#[test]
fn test_attempt_decrypt_with_private_key_sh_type_mismatch() {
    for mode in ["pemder", "pkcs12"] {
        let c = Case::new("minimal-aes256.pdf");
        error(
            c.private(mode, &["--force"], "secret", false, false),
            "File was not encrypted with",
        );
    }
}
#[test]
fn test_attempt_decrypt_with_non_matching_key() {
    let c = Case::new("minimal-pubkey-aes256.pdf");
    error(
        c.private("pkcs12", &["--force"], "secret", true, false),
        "Failed to decrypt",
    );
}
#[test]
fn test_decrypt_with_private_key_no_pass() {
    let c = Case::new("minimal-pubkey-aes256.pdf");
    c.decrypted(c.private("pemder", &["--no-pass", "--force"], "", false, true));
}
#[test]
fn test_decrypt_with_private_key_empty_pass_on_stdin() {
    for mode in ["pemder", "pkcs12"] {
        let c = Case::new("minimal-pubkey-aes256.pdf");
        let out = c.private(mode, &["--force"], "", false, false);
        assert_eq!(out.status.code(), Some(1), "{}", output(&out));
    }
}

// test_cli_decode_limits.py::test_decrypt_password
#[test]
fn test_decrypt_password() {
    let c = Case::oversized("password");
    error(
        c.invoke(
            &[
                "decrypt",
                "password",
                "--password",
                "ownersecret",
                "in.pdf",
                "out.pdf",
            ],
            "",
        ),
        "rerun with --no-decode-limits",
    );
    c.decrypted(c.invoke(
        &[
            "decrypt",
            "password",
            "--no-decode-limits",
            "--password",
            "ownersecret",
            "in.pdf",
            "out.pdf",
        ],
        "",
    ));
}

// test_cli_decode_limits.py::test_decrypt_pubkey, both original key formats.
#[test]
fn test_decrypt_pubkey() {
    for mode in ["pemder", "pkcs12"] {
        let c = Case::oversized("pubkey");
        std::fs::write(c.dir.path().join("passfile.txt"), "secret").unwrap();
        error(
            c.private(
                mode,
                &["--force", "--passfile", "passfile.txt"],
                "",
                true,
                false,
            ),
            "rerun with --no-decode-limits",
        );
        c.decrypted(c.private(
            mode,
            &[
                "--force",
                "--passfile",
                "passfile.txt",
                "--no-decode-limits",
            ],
            "",
            true,
            false,
        ));
    }
}
