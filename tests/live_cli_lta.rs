// Ported from pyHanko 0.38.1 integration-tests/test_live_certomancer.py (MIT).
//! Exact final L-owned live CLI integration with real current-time PKI.
//! The native command, full original Python baseline and validators all run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/live_pki.rs"]
mod live_pki;

use std::{path::{Path, PathBuf}, process::{Command, Stdio}, time::Duration};
use sigis_pades::ades::{basic::QualificationSpec, lta::lta_validation};
use sigis_pdf::PdfFile;
use sigis_pdf_diff::{ModificationLevel, StandardDiffPolicy};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{algorithms::DigestAlgorithm, cert::Cert, time::Moment};
use sigis_pki_fetch::{FetchLimits, FetcherSettings, HttpFetchers};

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256.digest(bytes).iter().map(|b|format!("{b:02x}")).collect()
}
fn record(path: &Path, kind: &str) -> String {
    let bytes = std::fs::read(path).unwrap();
    let digest = sha(&bytes);
    eprintln!("LIVE_CLI_INPUT {}",serde_json::json!({
        "kind":kind,"path":path.canonicalize().unwrap(),"length":bytes.len(),"sha256":digest
    }));
    digest
}
fn immutable_cli() -> (PathBuf, String) {
    // Root integration tests cannot use another workspace package's
    // CARGO_BIN_EXE macro. Require an explicitly exported immutable ELF.
    let path = PathBuf::from(std::env::var_os("SIGIS_CLI_TEST_BIN")
        .expect("select a Cargo-produced immutable CLI artifact"));
    let expected = std::env::var("SIGIS_CLI_TEST_BIN_SHA256")
        .expect("pin that actual CLI artifact's SHA256");
    assert!(path.is_absolute() && path.is_file());
    let canonical = path.canonicalize().unwrap();
    assert!(!canonical.starts_with("/srv/targets") && !path.starts_with("/build"),
        "export an immutable executable outside the mutable shared Cargo target");
    assert_eq!(expected.len(),64);
    assert!(expected.bytes().all(|b|b.is_ascii_hexdigit()));
    let actual = record(&path,"actual_cli_executable_before");
    assert_eq!(actual,expected.to_ascii_lowercase());
    record(&std::env::current_exe().unwrap(),"actual_root_test_executable");
    (path,actual)
}
fn settings() -> FetcherSettings {
    FetcherSettings {limits:FetchLimits {timeout:Duration::from_secs(5),..Default::default()},..Default::default()}
}
fn count(metrics: &serde_json::Value, method: &str, prefix: &str) -> u64 {
    metrics["requests"].as_array().unwrap().iter()
        .filter(|r|r["method"]==method && r["status"]==200
            && r["path"].as_str().unwrap().starts_with(prefix))
        .map(|r|r["count"].as_u64().unwrap()).sum()
}

#[test]
fn test_pades_lta_live_with_cli() {
    let (cli,cli_sha) = immutable_cli();
    // Separate mandatory ORIGINAL Python CLI baseline: its own PFX/config,
    // isolated filesystem and owned live sidecar, not native-output replay.
    let reference_temp = tempfile::tempdir().unwrap();
    let reference_artifacts = std::env::var_os("SIGIS_LIVE_LTA_ARTIFACT_DIR")
        .map(PathBuf::from).unwrap_or_else(||reference_temp.path().to_owned())
        .join(format!("original-cli-{}-{}",std::process::id(),Moment::now().unix_secs()));
    let reference_script = sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/live_cli_original_reference.py");
    let server_script = sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/live_pki_server.py");
    let crypto = sigis_testdata::pyhanko(&["crypto"]);
    let mut reference_command = Command::new(sigis_testdata::oracle::python().expect("pinned reference Python"));
    reference_command.arg("-I").arg(&reference_script)
        .arg("--server-script").arg(&server_script).arg("--crypto").arg(&crypto)
        .arg("--artifacts").arg(&reference_artifacts);
    if let Some(overlay) = std::env::var_os("SIGIS_CLI_REFERENCE_DEPS") {
        reference_command.arg("--dependency-overlay").arg(overlay);
    }
    let reference_process = reference_command.output().unwrap();
    eprintln!("LIVE_CLI_ORIGINAL_REFERENCE_STDERR {}",String::from_utf8_lossy(&reference_process.stderr));
    assert!(reference_process.status.success(),"{}",String::from_utf8_lossy(&reference_process.stdout));
    let original_reference: serde_json::Value = serde_json::from_slice(&reference_process.stdout).unwrap();
    assert_eq!(original_reference["whole_upstream_function_completed"],true);
    assert_eq!(original_reference["pyhanko"],"0.38.1");
    assert_eq!(original_reference["certvalidator"],"0.33.0");
    eprintln!("LIVE_CLI_ORIGINAL_REFERENCE {original_reference}");
    // Upstream is current-time live, not the fixed-2020 library fixture mode.
    // This starts one test-owned child; existing fixed-mode tests are unchanged.
    let live = live_pki::LivePki::start_live();
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("in.pdf");
    let output_path = dir.path().join("out.pdf");
    let pfx_path = dir.path().join("credential.p12");
    let root_path = dir.path().join("root.crt");
    let config_path = dir.path().join("pyhanko.yml");
    let before_cli = Moment::now();
    assert!(before_cli < Moment::parse_rfc3339("2030-01-01T00:00:00Z").unwrap(),
        "the pinned signer1-long/TSA fixture expires in 2030; do not waive expiry");
    let setup = reqwest::blocking::Client::builder().no_proxy()
        .timeout(Duration::from_secs(5)).build().unwrap();
    let pfx = setup.post(format!("{}/_certomancer/pfx-download/testing-ca",live.url))
        .form(&[("cert","signer1-long"),("passphrase","secret")])
        .send().unwrap().error_for_status().unwrap().bytes().unwrap();
    let root_der = setup.get(format!("{}/_certomancer/any-cert/testing-ca/root.crt",live.url))
        .send().unwrap().error_for_status().unwrap().bytes().unwrap();
    // No outside signer construction, PFX decoding or lower-layer sign call:
    // the actual CLI must load the exact downloaded credential and config.
    std::fs::write(&pfx_path,&pfx).unwrap();
    std::fs::write(&root_path,&root_der).unwrap();
    let input = std::fs::read(sigis_testdata::pyhanko(&["pdf","minimal-with-field.pdf"])).unwrap();
    assert_eq!(sha(&input),"95509970de2a853d540f2abb5a4e17f767e97ec2311d6f55279b09b6764f2858");
    std::fs::write(&input_path,&input).unwrap();
    let config = "pkcs12-setups:\n    test:\n        pfx-file: credential.p12\n        pfx-passphrase: secret\nvalidation-contexts:\n    default:\n        trust: root.crt\n";
    std::fs::write(&config_path,config).unwrap();
    let input_sha = record(&input_path,"MINIMAL_ONE_FIELD");
    let pfx_sha = record(&pfx_path,"downloaded_encrypted_synthetic_PFX");
    let root_sha = record(&root_path,"downloaded_root");
    let config_sha = record(&config_path,"automatic_pyhanko_yml");
    drop(setup); // Upstream closes the setup session before launching the CLI.
    let tsa_url = format!("{}/testing-ca/tsa/tsa",live.url);
    let argv = ["sign","addsig","--with-validation-info","--use-pades-lta",
        "--timestamp-url",&tsa_url,"pkcs12","--p12-setup","test",
        "in.pdf","out.pdf","credential.p12"];
    // The exact original argv: no --config, --field, --trust, --no-revocation,
    // --validation-time or invented native clock override is added.
    let command = Command::new(&cli).current_dir(dir.path()).args(argv)
        .stdin(Stdio::null()).output().unwrap();
    eprintln!("LIVE_CLI_COMMAND {}",serde_json::json!({
        "binary":cli,"binary_sha256":cli_sha,"argv":argv,"cwd":dir.path(),
        "code":command.status.code(),"stdout":String::from_utf8_lossy(&command.stdout),
        "stderr":String::from_utf8_lossy(&command.stderr),"live_url":live.url
    }));
    assert_eq!(record(&cli,"actual_cli_executable_after"),cli_sha);
    assert_eq!(record(&input_path,"input_after_cli"),input_sha);
    assert_eq!(record(&pfx_path,"PFX_after_cli"),pfx_sha);
    assert_eq!(record(&root_path,"root_after_cli"),root_sha);
    assert_eq!(record(&config_path,"config_after_cli"),config_sha);
    // CliRunner's no-exception assertion maps to successful real process exit.
    assert!(command.status.success(),"CLI failed; preserve the actual command receipt");
    assert!(output_path.is_file(),"the command must create the actual output PDF");
    let check = reqwest::blocking::Client::builder().no_proxy()
        .timeout(Duration::from_secs(5)).build().unwrap();
    // Snapshot BEFORE any verifier can make revocation/TSA requests.
    let cli_metrics: serde_json::Value = check.get(format!("{}/_sigis/requests",live.url))
        .send().unwrap().error_for_status().unwrap().json().unwrap();
    assert_eq!(count(&cli_metrics,"POST","/_certomancer/pfx-download/testing-ca"),1);
    assert!(count(&cli_metrics,"POST","/testing-ca/tsa/tsa")>=2,
        "real CLI must obtain signature and archival timestamps");
    assert!(count(&cli_metrics,"POST","/testing-ca/ocsp/")>0);
    assert!(count(&cli_metrics,"GET","/testing-ca/crls/")>0);
    // Match upstream _check's new session and second real root retrieval.
    let check_root = check.get(format!("{}/_certomancer/any-cert/testing-ca/root.crt",live.url))
        .send().unwrap().error_for_status().unwrap().bytes().unwrap();
    assert_eq!(sha(&check_root),root_sha);
    let root = Cert::from_der(&check_root).unwrap();
    let output = std::fs::read(&output_path).unwrap();
    record(&output_path,"actual_cli_output_before_verification");
    let file = PdfFile::parse(&output).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.first().unwrap().field_name,"Sig1");
    let signature = signatures.iter().find(|s|s.field_name=="Sig1").unwrap();
    let validation_time = Moment::now();
    let validation = ValidationContext::builder().trust_root(root)
        .moment(validation_time).point_in_time_validation(false)
        .revocation_mode("require").fetchers(HttpFetchers::new(settings()).as_fetchers())
        .build().unwrap();
    assert!(validation.other_certs().is_empty());
    assert_eq!(validation.crls().count()+validation.ocsps().count(),0);
    let lta = lta_validation(&file,signature,&validation,&QualificationSpec::default()).unwrap();
    let status = lta.api_status.as_ref().expect("original full-LTA API status");
    assert!(status.signature.valid && status.signature.trusted(),"{lta:?}");
    assert!(status.signature.intact);
    let ordinary = sigis_pades::validate_pdf_signature(&file,signature,&validation,Some(&StandardDiffPolicy)).unwrap();
    assert_eq!(ordinary.modification_level(),Some(ModificationLevel::LtaUpdates));
    let dss = file.dss().unwrap().expect("original requires a real DSS");
    assert_eq!(dss.material.crls.len(),1,"exact original unfiltered /CRLs count");
    assert_eq!(dss.material.ocsps.len(),1,"exact original unfiltered /OCSPs count");
    // Independent new context/HTTP backend with no trust root. Embedded
    // certificates/DSS are candidates and must not turn into trust anchors.
    let empty = ValidationContext::builder().moment(validation_time)
        .point_in_time_validation(false).revocation_mode("require")
        .fetchers(HttpFetchers::new(settings()).as_fetchers()).build().unwrap();
    match lta_validation(&file,signature,&empty,&QualificationSpec::default()) {
        Err(_) => {},
        Ok(rejected) => assert!(rejected.api_status.is_none_or(|s|!s.signature.trusted()),"no-root validation must reject trust"),
    }
    let oracle = sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/live_cli_lta_verdict.py");
    let at = validation_time.to_string();
    let verdict = sigis_testdata::oracle::run_json(&oracle,&[
        output_path.to_str().unwrap(),root_path.to_str().unwrap(),&at,
    ]).expect("mandatory fresh pinned public LTA over the actual CLI output");
    assert_eq!(verdict["pyhanko"],"0.38.1");
    assert_eq!(verdict["certvalidator"],"0.33.0");
    assert_eq!(verdict["pdf_sha256"],sha(&output));
    assert_eq!(verdict["root_sha256"],root_sha);
    assert_eq!(verdict["correct"]["valid"],true);
    assert_eq!(verdict["correct"]["trusted"],true);
    assert_eq!(verdict["correct"]["modification_level"],"LTA_UPDATES");
    assert_eq!(verdict["empty_roots"]["trusted"],false);
    assert_eq!(verdict["correct"]["dss_crls"],1);
    assert_eq!(verdict["correct"]["dss_ocsps"],1);
    // Supplemental differential guard; final OK is NOT an extra assertion
    // attributed to the original function body.
    assert_eq!(serde_json::json!(lta.ades_subindic.standard_name()),verdict["correct"]["ades_subindic"]);
    let receipt = serde_json::json!({
        "id":"integration-tests/test_live_certomancer.py::test_pades_lta_live_with_cli",
        "parameter_cases":1,"argv":argv,"cli_path":cli,"cli_sha256":cli_sha,
        "input_sha256":input_sha,"root_sha256":root_sha,"pfx_sha256":pfx_sha,
        "config_sha256":config_sha,"pdf_sha256":sha(&output),
        "live_current_time":true,"before_cli":before_cli.to_string(),"validation_time":at,
        "native_subindication":lta.ades_subindic.standard_name(),"native_valid":status.signature.valid,
        "native_trusted":status.signature.trusted(),"native_modification_level":"LTA_UPDATES",
        "dss_crls":dss.material.crls.len(),"dss_ocsps":dss.material.ocsps.len(),
        "cli_phase_requests":cli_metrics,"original_Python_CLI_baseline":original_reference,"oracle":verdict
    });
    eprintln!("LIVE_CLI_LTA {receipt}");
    if let Some(parent) = std::env::var_os("SIGIS_LIVE_LTA_ARTIFACT_DIR") {
        let target = PathBuf::from(parent).join(format!("cli-{}-{}",std::process::id(),before_cli.unix_secs()));
        std::fs::create_dir_all(PathBuf::from(std::env::var_os("SIGIS_LIVE_LTA_ARTIFACT_DIR").unwrap())).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("out.pdf"),&output).unwrap();
        std::fs::write(target.join("root.crt"),&root_der).unwrap();
        std::fs::write(target.join("receipt.json"),serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
        // Deliberately retain no PFX/private-key bytes outside the tempdir.
    }
}
