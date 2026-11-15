//! Exact AdES qualified CLI assertions from pyHanko 0.38.1 (MIT).
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime};
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use sigis_pki_fetch::{transport::HttpRequest, HttpResponse, HttpTransport, TransportError};
use std::{fs, path::Path, process::Command, sync::Arc};

#[derive(Debug)]
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Network(format!(
            "unexpected uncached request {}",
            request.url
        )))
    }
}
fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
fn invoke(index: usize, extra: &[&str]) -> sigis_cli::Output {
    invoke_with_pdf(index, extra, |_| {})
}
fn invoke_with_pdf(
    index: usize,
    extra: &[&str],
    change: impl FnOnce(&mut Vec<u8>),
) -> sigis_cli::Output {
    invoke_with_pdf_reference(index, extra, change, None)
}
fn invoke_with_pdf_reference(
    index: usize,
    extra: &[&str],
    change: impl FnOnce(&mut Vec<u8>),
    expected_peer_code: Option<i32>,
) -> sigis_cli::Output {
    let source =
        sigis_testdata::path(&["lanes", "r3-c", "qualified-ades"]).join(format!("case-{index}"));
    let dir = tempfile::tempdir().unwrap();
    copy_dir(&source, dir.path());
    let path = dir.path().join("pyhanko.yml");
    let mut config: serde_json::Value = serde_yaml::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["cache-dir"] = serde_json::json!(dir.path().join("cache"));
    let context = &mut config["validation-contexts"]["default"];
    for key in ["trust", "other-certs", "lotl-tlso-certs"] {
        if let Some(value) = context.get_mut(key) {
            if let Some(name) = value.as_str() {
                *value = serde_json::json!(dir.path().join(name));
            } else if let Some(names) = value.as_array_mut() {
                for name in names {
                    *name = serde_json::json!(dir.path().join(name.as_str().unwrap()));
                }
            }
        }
    }
    fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
    let pdf = dir.path().join("to-validate.pdf");
    let mut bytes = fs::read(&pdf).unwrap();
    change(&mut bytes);
    fs::write(&pdf, bytes).unwrap();
    let before = fs::read(&pdf).unwrap();
    let mut args = vec![
        "-c".to_owned(),
        path.display().to_string(),
        "sign".into(),
        "adesverify".into(),
        "--eutl-all".into(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args.push(pdf.display().to_string());
    let runtime = ValidationRuntime {
        now: Moment::from_unix_secs(
            fs::read_to_string(dir.path().join("moment.txt"))
                .unwrap()
                .trim()
                .parse()
                .unwrap(),
        ),
        fetchers: Fetchers::none(),
        password: None,
        trusted_list_transport: Some(Arc::new(Offline)),
        pkcs11_signing_pin_prompt: None,
        pkcs11_user_pin_prompt: None,
    };
    let output = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
    assert_eq!(
        fs::read(&pdf).unwrap(),
        before,
        "validation changed the signed PDF"
    );
    // Fresh original CLI peer on the SAME complete PDF/config/cache bytes. The
    // explicit historical clock matches CliRunner/freezegun in the original,
    // not a product clock option or validity/tolerance extension.
    let oracle = Command::new(
        std::env::var("HANKO_ORACLE")
            .unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into()),
    )
    .arg("-B")
    .arg("-c")
    .arg(
        r#"
import sys
sys.path[:0]=['/home/l/.codex/artifacts/sigis/round3/c/oracle-deps',
 '/tmp/pyhanko-oracle/src/v0.38.1/internal/common-test-utils/src']
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from click.testing import CliRunner
from freezegun import freeze_time
from pyhanko.cli import cli_root
from pyhanko_testing_commons.test_data.samples import TESTING_CA_QUALIFIED
from pyhanko_testing_commons.test_utils.live_http import live_pki_services
from datetime import datetime,timezone
from pathlib import Path
from yaml import safe_load
config=safe_load(Path(sys.argv[3]).read_text())
clock_file=Path(config['cache-dir']).parent/'moment.txt'
with freeze_time(datetime.fromtimestamp(int(clock_file.read_text()),timezone.utc)):
    with live_pki_services() as services:
        services.register(TESTING_CA_QUALIFIED)
        result=CliRunner().invoke(cli_root,['--config' if arg=='-c' else arg for arg in sys.argv[2:]])
assert result.exit_code==int(sys.argv[1]),(result.exit_code,result.output)
print(result.output)
"#,
    )
    .arg(expected_peer_code.unwrap_or(output.code).to_string())
    .args(&args)
    .output()
    .unwrap();
    assert!(
        oracle.status.success(),
        "native: {}{}\nreference: {}{}",
        output.stdout,
        output.stderr,
        String::from_utf8_lossy(&oracle.stdout),
        String::from_utf8_lossy(&oracle.stderr)
    );
    if expected_peer_code == Some(0) && output.code == 1 {
        // Explicit supplemental stricter-native cases only. Original tests
        // always compare equal exit codes and retain all original assertions.
        assert!(String::from_utf8_lossy(&oracle.stdout).contains("judged VALID"));
        println!("STRICTER_TSA_CONTROL native=REJECT pinned_cli=VALID");
    }
    assert_eq!(
        fs::read(&pdf).unwrap(),
        before,
        "reference validation changed the signed PDF"
    );
    output
}
fn text(output: &sigis_cli::Output) -> String {
    format!("{}{}", output.stdout, output.stderr)
}
fn valid(index: usize, pretty: bool) -> String {
    let out = invoke(index, if pretty { &["--pretty-print"] } else { &[] });
    let message = text(&out);
    assert_eq!(out.code, 0, "{message}");
    message
}
/// Four original overloaded_trust × pades_style parameter rows.
#[test]
fn test_validate_eutl_ades() {
    for index in 0..4 {
        let message = valid(index, true);
        for expected in [
            "The signer's certificate is qualified",
            "qualified for electronic signatures",
            "directly identified as a QTST",
            "judged VALID",
        ] {
            assert!(message.contains(expected), "{message}");
        }
    }
}
#[test]
fn test_validate_eutl_ades_qual_required() {
    let out = invoke(4, &["--require-qualified"]);
    let message = text(&out);
    assert_eq!(out.code, 0, "{message}");
    assert!(message.contains("INTACT:TRUSTED"), "{message}");
    assert!(!message.contains("UNTRUSTED"), "{message}");
}
#[test]
fn test_validate_eutl_ades_not_qualified() {
    let message = valid(5, true);
    assert!(
        message.contains("The signer's certificate is not qualified"),
        "{message}"
    );
    assert!(message.contains("judged VALID"), "{message}");
}
#[test]
fn test_validate_eutl_ades_not_qualified_summary() {
    let message = valid(6, false);
    assert!(message.contains("NOT_QUALIFIED"), "{message}");
}
#[test]
fn test_validate_eutl_ades_qualified_summary() {
    let message = valid(7, false);
    assert!(message.contains("QUALIFIED"), "{message}");
    assert!(!message.contains("NOT_QUALIFIED"), "{message}");
}
#[test]
fn test_validate_eutl_ades_not_qualified_required() {
    // The mandatory positive contrasts prevent an always-untrusted adapter from
    // satisfying this negative original. Use the SAME nonqualified PDF bytes.
    test_validate_eutl_ades_qual_required();
    let optional = invoke(8, &["--pretty-print"]);
    let optional_text = text(&optional);
    assert_eq!(optional.code, 0, "{optional_text}");
    assert!(optional_text.contains("judged VALID"), "{optional_text}");
    assert!(
        optional_text.contains("The signer's certificate is not qualified"),
        "{optional_text}"
    );
    let out = invoke(8, &["--require-qualified"]);
    let message = text(&out);
    assert_eq!(out.code, 1, "{message}");
    assert!(message.contains("UNTRUSTED"), "{message}");
    assert!(message.contains("NOT_QUALIFIED"), "{message}");
}
#[test]
fn test_validate_eutl_ades_tsa_not_qualified() {
    let message = valid(9, true);
    for expected in [
        "The signer's certificate is qualified",
        "The time stamping authority is not qualified",
        "judged VALID",
    ] {
        assert!(message.contains(expected), "{message}");
    }
}
#[test]
fn test_validate_eutl_ades_point_in_time_no_revinfo() {
    let out = invoke(
        10,
        &[
            "--pretty-print",
            "--validation-time",
            "2025-03-01T22:00:00Z",
            "--no-revocation-check",
        ],
    );
    let message = text(&out);
    assert_eq!(out.code, 0, "{message}");
    for expected in [
        "The signer's certificate is qualified",
        "qualified for electronic signatures",
        "directly identified as a QTST",
        "judged VALID",
    ] {
        assert!(message.contains(expected), "{message}");
    }
    // This original accepts the historical API conclusion, not archival OK.
    assert!(message.contains("AdES result: NO_POE"), "{message}");
    assert!(message.contains("Failed to get control time"), "{message}");
}

/// A CLI API-status projection must still reject a changed signed preimage.
/// Both native and pinned CLI validate the same mutated PDF, whose header
/// remains syntactically valid; the CMS signature and timestamp are untouched.
#[test]
fn ades_api_projection_rejects_changed_signed_content() {
    let out = invoke_with_pdf(0, &["--pretty-print", "--no-revocation-check"], |bytes| {
        assert!(bytes.starts_with(b"%PDF-1."));
        bytes[7] = if bytes[7] == b'7' { b'6' } else { b'7' };
    });
    let message = text(&out);
    assert_eq!(out.code, 1, "{message}");
    assert!(message.contains("judged INVALID"), "{message}");
    assert!(!message.contains("judged VALID"), "{message}");
}

/// CMS integrity alone cannot authorize an unsigned replacement of its PDF
/// signature dictionary. Preserve PDF coverage/modification constraints too.
#[test]
fn ades_api_projection_rejects_replaced_signature_dictionary() {
    let out = invoke_with_pdf(0, &["--pretty-print", "--no-revocation-check"], |bytes| {
        let file = sigis_pdf::PdfFile::parse(bytes).unwrap();
        let signature = file.embedded_signatures().unwrap().remove(0);
        let mut dictionary = file
            .get_object_at(signature.sig_object, None)
            .unwrap()
            .as_dict()
            .unwrap()
            .clone();
        dictionary.set("Bleh", false);
        let mut writer = sigis_pdf::writer::IncrementalWriter::new(file);
        writer.put(
            signature.sig_object,
            sigis_pdf::lopdf::Object::Dictionary(dictionary),
        );
        *bytes = writer.write().unwrap();
    });
    let message = text(&out);
    assert_eq!(out.code, 1, "{message}");
    assert!(message.contains("judged INVALID"), "{message}");
    assert!(!message.contains("judged VALID"), "{message}");
}

#[test]
fn ades_api_projection_keeps_required_tsa_qualification() {
    // Pinned CLI drops the failed timestamp from its API projection and exits
    // zero. Retain the stronger native mandatory-TSA refusal explicitly.
    let out = invoke_with_pdf_reference(
        9,
        &["--pretty-print", "--require-qualified"],
        |_| {},
        Some(0),
    );
    let message = text(&out);
    assert_eq!(out.code, 1, "{message}");
    assert!(message.contains("judged INVALID"), "{message}");
    assert!(!message.contains("judged VALID"), "{message}");
}

#[test]
fn ades_api_projection_rejects_forged_timestamp() {
    // Pinned CLI likewise discards this invalid timestamp and accepts the
    // current MAIN API status. Never reproduce that timestamp waiver here.
    let out = invoke_with_pdf_reference(
        0,
        &["--pretty-print", "--no-revocation-check"],
        |bytes| forge_signature_timestamp(bytes),
        Some(0),
    );
    let message = text(&out);
    assert_eq!(out.code, 1, "{message}");
    assert!(
        message.contains("The signature is cryptographically sound."),
        "{message}"
    );
    assert!(
        message.contains("The timestamp token is cryptographically unsound."),
        "{message}"
    );
    assert!(message.contains("judged INVALID"), "{message}");
    assert!(!message.contains("judged VALID"), "{message}");
}

const EXPIRED_NO_REVINFO_ARGS: [&str; 4] = [
    "--pretty-print",
    "--validation-time",
    "2025-03-01T22:00:00Z",
    "--no-revocation-check",
];

#[test]
fn expired_profile_rejects_changed_signed_content() {
    let output = invoke_with_pdf(10, &EXPIRED_NO_REVINFO_ARGS, |bytes| {
        assert!(bytes.starts_with(b"%PDF-1."));
        bytes[7] = if bytes[7] == b'7' { b'6' } else { b'7' };
    });
    let message = text(&output);
    assert_eq!(output.code, 1, "{message}");
    assert!(message.contains("judged INVALID"), "{message}");
    assert!(!message.contains("judged VALID"), "{message}");
}

#[test]
fn expired_profile_rejects_forged_timestamp() {
    let output = invoke_with_pdf(10, &EXPIRED_NO_REVINFO_ARGS, |bytes| {
        forge_signature_timestamp(bytes)
    });
    let message = text(&output);
    assert_eq!(output.code, 1, "{message}");
    assert!(
        message.contains("The signature is cryptographically sound."),
        "{message}"
    );
    assert!(message.contains("judged INVALID"), "{message}");
    assert!(!message.contains("judged VALID"), "{message}");
}

#[test]
fn expired_profile_cannot_use_a_future_timestamp() {
    let output = invoke(
        10,
        &[
            "--pretty-print",
            "--validation-time",
            "2010-01-01T00:00:00Z",
            "--no-revocation-check",
        ],
    );
    let message = text(&output);
    assert_eq!(output.code, 1, "{message}");
    assert!(message.contains("judged INVALID"), "{message}");
    assert!(!message.contains("judged VALID"), "{message}");
}

fn forge_signature_timestamp(bytes: &mut [u8]) {
    use sigis_cms::signed_data::find_unique_cms_attribute;
    use sigis_pki_core::asn1::oids;

    let file = sigis_pdf::PdfFile::parse(bytes).unwrap();
    let signature = file.embedded_signatures().unwrap().remove(0);
    let cms = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
    let token = find_unique_cms_attribute(
        cms.signer_infos[0].unsigned_attr_list(),
        oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
    )
    .unwrap();
    let offset = signature
        .contents
        .windows(token.len())
        .position(|window| window == token)
        .unwrap();
    let mut contents = signature.contents.clone();
    // Flip only the final signature bit of the genuine token. Preserve
    // its DER, declared imprint, time and the parent's signed attributes.
    contents[offset + token.len() - 1] ^= 1;
    assert_eq!(signature.byte_range.len(), 4);
    let start = usize::try_from(signature.byte_range[1]).unwrap();
    let end = usize::try_from(signature.byte_range[2]).unwrap();
    assert_eq!(bytes[start], b'<');
    assert_eq!(bytes[end - 1], b'>');
    let hex = contents
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(hex.len() <= end - start - 2);
    bytes[start + 1..end - 1].fill(b'0');
    bytes[start + 1..start + 1 + hex.len()].copy_from_slice(hex.as_bytes());
}

/// Isolate the lower API-status mismatch from CLI rendering and EUTL loading.
/// This uses explicit anchors for the actual CA and token signer; the full
/// original above separately retains authenticated EUTL and qualification.
#[test]
fn expired_leaf_lta_api_status_direct_reproducer() {
    use sigis_cms::signed_data::{extract_certificate_info, find_unique_cms_attribute};
    use sigis_pades::ades::{
        basic::QualificationSpec,
        lta::{lta_validation_with_ades_options, LtaOptions},
        AdesValidationOptions,
    };
    use sigis_pki_certvalidator::{
        policy::{CertRevTrustPolicy, NO_REVOCATION},
        ValidationContext,
    };
    use sigis_pki_core::{asn1::oids, cert::Cert, key_usage::KeyUsageConstraints};

    let directory = sigis_testdata::path(&["lanes", "r3-c", "qualified-ades", "case-10"]);
    let file =
        sigis_pdf::PdfFile::parse(&fs::read(directory.join("to-validate.pdf")).unwrap()).unwrap();
    let signature = file.embedded_signatures().unwrap().remove(0);
    let cms = sigis_cms::SignedData::from_der(
        sigis_pades::cms_from_contents(&signature.contents).unwrap(),
    )
    .unwrap();
    let token = find_unique_cms_attribute(
        cms.signer_infos[0].unsigned_attr_list(),
        oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
    )
    .unwrap();
    let tsa = extract_certificate_info(&sigis_cms::SignedData::from_der(token).unwrap())
        .unwrap()
        .signer_cert;
    let ca = Cert::from_pem_or_der(&fs::read(directory.join("root.cert.pem")).unwrap()).unwrap();
    let context = ValidationContext::builder()
        .trust_root(ca)
        .trust_root(tsa)
        .moment(Moment::parse_rfc3339("2025-03-01T22:00:00Z").unwrap())
        .point_in_time_validation(true)
        .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
        .build()
        .unwrap();
    let mut options = AdesValidationOptions::default();
    options.exact_key_usage_settings = Some(KeyUsageConstraints::default());
    let result = lta_validation_with_ades_options(
        &file,
        &signature,
        &context,
        &QualificationSpec::default(),
        &LtaOptions::default(),
        &options,
    )
    .unwrap();
    let status = result.api_status.as_ref().unwrap();
    assert!(status.signature.intact && status.signature.valid);
    let timestamp = status.timestamp_validity.as_ref().unwrap();
    assert!(timestamp.trusted());
    // A diagnostic companion, never a product fallback or replacement status:
    // the existing CMS API can run full MAIN validation at the authenticated
    // TST bound while keeping TSA validation at the original reference. This
    // does not itself authorize clearing the original operation's typed error.
    let mut timing = *context.timing();
    timing.validation_time = timestamp.timestamp;
    timing.best_signature_time = timestamp.timestamp;
    let historical_context = context.with_timing(timing);
    let cms_options = sigis_cms::CmsValidationOptions {
        exact_key_usage_settings: Some(KeyUsageConstraints::default()),
        validation_order: sigis_cms::CmsValidationOrder::SignerFirst,
        ts_validation_context: Some(&context),
        ..Default::default()
    };
    let historical = sigis_cms::validate_cms_signature_with(
        &signature.contents,
        sigis_cms::SignedContent::Data(&signature.signed_data(&file).unwrap()),
        &historical_context,
        &cms_options,
    )
    .unwrap();
    assert!(historical.bottom_line(), "{historical:?}");
    assert_eq!(
        historical.signature.validation_time,
        Some(timestamp.timestamp)
    );
    assert_eq!(
        historical
            .timestamp_validity
            .as_ref()
            .unwrap()
            .signature
            .validation_time,
        Some(context.moment())
    );
    assert_eq!(
        context.moment(),
        Moment::parse_rfc3339("2025-03-01T22:00:00Z").unwrap()
    );
    assert_eq!(
        result.ades_subindic,
        sigis_pades::ades::AdesIndeterminate::NO_POE.into()
    );
    assert!(
        result
            .failure_msg
            .as_deref()
            .is_some_and(|message| message.contains("Failed to get control time")),
        "{:?}",
        result.failure_msg
    );
    println!("HISTORICAL_MAIN_CONTROL actual_full_main=VALID archival_result=NO_POE");
    assert!(
        status.bottom_line(),
        "sub={:?}; MAIN={:?}; typed_error={:?}; best={:?}; diagnostic={:?}",
        result.ades_subindic,
        status.signature.trust_problem_indic,
        status.signature.trust_problem,
        result.best_signature_time,
        result.failure_msg
    );
}
