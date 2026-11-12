//! Native command regressions for the injected CLI password prompter.
//! These do not add unique upstream functions to the 23-function crypt subset.
use openssl::{pkcs12::Pkcs12, pkey::PKey, symm::Cipher, x509::X509};
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime, Output};
use sigis_pdf::{crypt::AuthStatus, PdfFile, PdfHandlerExt};
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn invoke(args: &[String], password: &str) -> Output {
    let runtime = ValidationRuntime {
        trusted_list_transport: None,
        now: Moment::now(),
        fetchers: Fetchers::none(),
        password: Some(password.into()),
    };
    sigis_cli::run_with_runtime(args, &PluginRegistry::default(), &runtime)
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
fn output(result: &Output) -> String {
    format!("{}{}", result.stdout, result.stderr)
}
fn success(result: Output) {
    assert_eq!(result.code, 0, "{}", output(&result));
}
fn plain(path: &Path) {
    let pdf = PdfFile::parse(&fs::read(path).unwrap()).unwrap();
    assert!(!pdf.encrypted());
    let pages = pdf
        .get_dict(&pdf.root().unwrap(), b"Pages")
        .unwrap()
        .unwrap();
    let kids = pdf.get(&pages, b"Kids").unwrap().unwrap();
    let first = kids.as_array().unwrap()[0].as_reference().unwrap();
    let page = pdf.get_object_at(first, None).unwrap();
    let stream = pdf
        .get(page.as_dict().unwrap(), b"Contents")
        .unwrap()
        .unwrap();
    let content = pdf.stream_data(stream.as_stream().unwrap()).unwrap();
    assert!(content.windows(5).any(|w| w == b"Hello"));
}
fn prepare(dir: &Path) -> PathBuf {
    let path = dir.join("input.pdf");
    fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &path).unwrap();
    path
}

#[test]
fn encrypt_prompt_uses_injected_password() {
    let dir = tempfile::tempdir().unwrap();
    let input = prepare(dir.path());
    let encrypted = dir.path().join("encrypted.pdf");
    success(invoke(
        &args(&[
            "encrypt",
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ]),
        "injected-owner-secret",
    ));
    let pdf = PdfFile::parse(&fs::read(&encrypted).unwrap()).unwrap();
    assert!(pdf.encrypted());
    assert_eq!(
        pdf.decrypt("injected-owner-secret").unwrap().status,
        AuthStatus::Owner
    );
    // An explicit command argument takes precedence over the injected prompter.
    let explicit = dir.path().join("explicit.pdf");
    success(invoke(
        &args(&[
            "encrypt",
            "--password",
            "explicit-owner-secret",
            input.to_str().unwrap(),
            explicit.to_str().unwrap(),
        ]),
        "wrong-prompt-secret",
    ));
    let pdf = PdfFile::parse(&fs::read(explicit).unwrap()).unwrap();
    assert_eq!(
        pdf.decrypt("wrong-prompt-secret").unwrap().status,
        AuthStatus::Failed
    );
    assert_eq!(
        pdf.decrypt("explicit-owner-secret").unwrap().status,
        AuthStatus::Owner
    );
}

#[test]
fn decrypt_password_prompt_uses_injected_password_and_rejects_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let input = sigis_testdata::pyhanko(&["pdf", "minimal-aes256.pdf"]);
    let decrypted = dir.path().join("plain.pdf");
    success(invoke(
        &args(&[
            "decrypt",
            "password",
            input.to_str().unwrap(),
            decrypted.to_str().unwrap(),
        ]),
        "ownersecret",
    ));
    plain(&decrypted);
    let rejected = dir.path().join("rejected.pdf");
    let result = invoke(
        &args(&[
            "decrypt",
            "password",
            input.to_str().unwrap(),
            rejected.to_str().unwrap(),
        ]),
        "badpassword",
    );
    assert_eq!(result.code, 1, "{}", output(&result));
    assert!(output(&result).contains("Password didn't match."));
    assert!(!rejected.exists());
    let explicit = dir.path().join("explicit.pdf");
    success(invoke(
        &args(&[
            "decrypt",
            "password",
            "--password",
            "ownersecret",
            input.to_str().unwrap(),
            explicit.to_str().unwrap(),
        ]),
        "badpassword",
    ));
    plain(&explicit);
}

#[test]
fn decrypt_public_key_prompt_uses_injected_key_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let input = prepare(dir.path());
    let encrypted = dir.path().join("recipient.pdf");
    // The encryption recipient needs key_encipherment. The upstream
    // decrypter1 certificate shares this RSA key with the signer fixture.
    let key_data = sigis_testdata::read(&["pyhanko", "crypto", "keys-rsa", "signer.key.pem"]);
    let cert_data = sigis_testdata::read(&[
        "pyhanko",
        "crypto",
        "testing-ca",
        "interm",
        "decrypter1.cert.pem",
    ]);
    let key = PKey::private_key_from_pem_passphrase(&key_data, b"secret").unwrap();
    let cert = X509::from_pem(&cert_data).unwrap();
    assert!(key.public_eq(&cert.public_key().unwrap()));
    let recipient = sigis_pki_core::cert::Cert::from_pem_or_der(&cert_data).unwrap();
    assert!(sigis_pki_core::key_usage::cert_key_usages(&recipient)
        .unwrap()
        .contains("key_encipherment"));
    let cert_path = dir.path().join("recipient.crt");
    fs::write(&cert_path, cert.to_der().unwrap()).unwrap();
    let key_path = dir.path().join("recipient.key");
    fs::write(
        &key_path,
        key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"injected-key-secret")
            .unwrap(),
    )
    .unwrap();
    let pfx_path = dir.path().join("recipient.p12");
    let mut builder = Pkcs12::builder();
    builder.pkey(&key).cert(&cert);
    fs::write(
        &pfx_path,
        builder
            .build2("injected-key-secret")
            .unwrap()
            .to_der()
            .unwrap(),
    )
    .unwrap();
    success(invoke(
        &args(&[
            "encrypt",
            "--recipient",
            cert_path.to_str().unwrap(),
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ]),
        "unused-prompt-secret",
    ));
    for mode in ["pemder", "pkcs12"] {
        let credentials = if mode == "pemder" {
            args(&[
                "--key",
                key_path.to_str().unwrap(),
                "--cert",
                cert_path.to_str().unwrap(),
            ])
        } else {
            vec![pfx_path.to_str().unwrap().into()]
        };
        let target = dir.path().join(format!("{mode}-plain.pdf"));
        let mut command = args(&[
            "decrypt",
            mode,
            encrypted.to_str().unwrap(),
            target.to_str().unwrap(),
        ]);
        command.extend(credentials.clone());
        success(invoke(&command, "injected-key-secret"));
        plain(&target);
        let rejected = dir.path().join(format!("{mode}-rejected.pdf"));
        let mut command = args(&[
            "decrypt",
            mode,
            encrypted.to_str().unwrap(),
            rejected.to_str().unwrap(),
        ]);
        command.extend(credentials.clone());
        let result = invoke(&command, "badpassword");
        assert_eq!(result.code, 1, "{}", output(&result));
        assert!(!rejected.exists());
        let passfile = dir.path().join("passphrase.txt");
        fs::write(&passfile, "injected-key-secret").unwrap();
        let target = dir.path().join(format!("{mode}-passfile.pdf"));
        let mut command = args(&[
            "decrypt",
            mode,
            "--passfile",
            passfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
            target.to_str().unwrap(),
        ]);
        command.extend(credentials);
        success(invoke(&command, "badpassword"));
        plain(&target);
    }
    // --no-pass must bypass the injected prompter for an unencrypted PEM key.
    let unencrypted_key = dir.path().join("plain.key");
    fs::write(&unencrypted_key, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let target = dir.path().join("pemder-no-pass.pdf");
    success(invoke(
        &args(&[
            "decrypt",
            "pemder",
            "--no-pass",
            "--key",
            unencrypted_key.to_str().unwrap(),
            "--cert",
            cert_path.to_str().unwrap(),
            encrypted.to_str().unwrap(),
            target.to_str().unwrap(),
        ]),
        "badpassword",
    ));
    plain(&target);
}
