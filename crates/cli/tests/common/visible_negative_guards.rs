//! Substantive controls for real field discovery; zero original-function credit.
use crate::{appearance_cases as base, common, signing_record};
use serde_json::{json, Value};
use sigis_cli::{config::CliConfig, runtime::ValidationRuntime};
use sigis_pades_sign::{
    pdf::{fields::append_signature_field, writer::PdfUpdate},
    SigFieldSpec,
};
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

fn runtime() -> ValidationRuntime {
    ValidationRuntime {
        now: sigis_pki_core::time::Moment::parse_rfc3339("2020-08-01T00:00:00+08:00").unwrap(),
        fetchers: sigis_pki_core::fetch::Fetchers::none(),
        password: None,
        trusted_list_transport: None,
    }
}
fn config(c: &base::Case, policy: Option<Value>) -> CliConfig {
    let mut v = json!({"stamp-styles":{"test":{"type":"text","stamp-text":"Selected real field"}}});
    if let Some(policy) = policy {
        v["validation-contexts"] = json!({"default":{
 "trust":c.path("root.cert.pem"),"trust-replace":true,"other-certs":[c.path("interm.cert.pem")],
 "time-tolerance":1,"retroactive-revinfo":false,"signer-key-usage-policy":policy}});
    }
    CliConfig::parse(&serde_yaml::to_string(&v).unwrap()).unwrap()
}
fn write_config(c: &base::Case) {
    fs::write(
        c.path("pyhanko.yml"),
        serde_yaml::to_string(
            &json!({"stamp-styles":{"test":{"type":"text","stamp-text":"Selected real field"}}}),
        )
        .unwrap(),
    )
    .unwrap();
}
fn add_fields(c: &base::Case, specs: &[(&str, Option<(f64, f64, f64, f64)>)]) {
    let input = fs::read(c.path("input.pdf")).unwrap();
    let mut update = PdfUpdate::new(&input).unwrap();
    for (name, bbox) in specs {
        let mut spec = SigFieldSpec::new(*name);
        if let Some(b) = bbox {
            spec = spec.with_box(*b);
        }
        append_signature_field(&mut update, &spec).unwrap();
    }
    fs::write(c.path("input.pdf"), update.write().unwrap().0).unwrap();
}
fn args(c: &base::Case, field: Option<&str>, absolute: bool) -> Vec<String> {
    let mut a: Vec<String> = ["sign", "addsig", "--style-name", "test"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if let Some(field) = field {
        a.extend(["--field".into(), field.into()]);
    }
    a.extend(
        [
            "pemder",
            "--no-pass",
            "--cert",
            "signer.crt",
            "--chain",
            "interm.cert.pem",
            "--key",
            "signer.key.pem",
            "input.pdf",
            "output.pdf",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    if absolute {
        for item in &mut a {
            if [
                "signer.crt",
                "interm.cert.pem",
                "signer.key.pem",
                "input.pdf",
                "output.pdf",
            ]
            .contains(&item.as_str())
            {
                *item = c.path(item).display().to_string();
            }
        }
    }
    a
}
fn native(c: &base::Case, a: Vec<String>, stdin: &[u8]) -> std::process::Output {
    let mut inputs = c.inputs();
    if c.path("pyhanko.yml").exists() {
        inputs.push(c.path("pyhanko.yml"));
    }
    let before = signing_record::before(&inputs);
    let input = fs::read(c.path("input.pdf")).unwrap();
    let mut child = Command::new(common::cli())
        .args(&a)
        .current_dir(c.dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(fs::read(c.path("input.pdf")).unwrap(), input);
    signing_record::process(
        "visible-field-supplemental-actual-CLI",
        &a,
        c.dir.path(),
        stdin,
        common::cli(),
        &result,
        &before,
        &[("native-output-or-sentinel", &c.path("output.pdf"))],
    );
    result
}
fn callback(
    c: &base::Case,
    field: Option<&str>,
    cfg: &CliConfig,
    rt: &ValidationRuntime,
) -> Result<String, String> {
    let a = args(c, field, true);
    invoke_callback(c, &a, cfg, rt)
}
fn invoke_callback(
    c: &base::Case,
    a: &[String],
    cfg: &CliConfig,
    rt: &ValidationRuntime,
) -> Result<String, String> {
    let before = signing_record::before(&c.inputs());
    let config_before = format!("{cfg:?}");
    common::record_test_executable();
    let result = sigis_cli::pemder_signing::run_with_runtime(&a[2..], Some(cfg), rt);
    assert_eq!(format!("{cfg:?}"), config_before);
    for row in &before {
        assert_eq!(
            base::sha(&fs::read(row["path"].as_str().unwrap()).unwrap()),
            row["sha256"]
        );
    }
    let record = json!({"kind":"in-process direct PEM callback; supplemental zero IDs","argv":a,"config":config_before,"runtime_now":rt.now.to_string(),"inputs":before,"result":result,"output_sha256":base::sha(&fs::read(c.path("output.pdf")).unwrap())});
    fs::write(
        c.path("visible-field-callback.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    eprintln!("VISIBLE_FIELD_CALLBACK {record}");
    result
}
fn sentinel(c: &base::Case) {
    assert_eq!(fs::read(c.path("output.pdf")).unwrap(), base::SENTINEL);
}
#[test]
fn actual_named_implicit_and_new_visible_fields_still_sign_and_validate() {
    let mut failures = Vec::new();
    for (mode, field) in [
        ("named", Some("Sig1")),
        ("implicit", None),
        ("new", Some("1/0,0,100,100/Sig1")),
    ] {
        crate::attempt(mode, &mut failures, || {
            let c = base::Case::new("rsa", "supplemental");
            write_config(&c);
            if mode != "new" {
                add_fields(&c, &[("Sig1", Some((0., 0., 100., 100.)))]);
            }
            let out = native(&c, args(&c, field, false), b"");
            assert!(out.status.success(), "{}", base::text(&out));
            c.verify();
            let bytes = fs::read(c.path("output.pdf")).unwrap();
            let pdf = sigis_pdf::PdfFile::parse(&bytes).unwrap();
            let sigs = pdf.embedded_signatures().unwrap();
            assert_eq!(
                sigis_pades::signature_coverage(&pdf, &sigs[0]).unwrap(),
                sigis_pades::SignatureCoverageLevel::EntireFile
            );
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn field_discovery_refuses_before_missing_key_and_preserves_output() {
    let mut failures = Vec::new();
    for (mode, field, expected) in [
        (
            "named",
            Some("Absent.Name"),
            "'Absent.Name' does not exist in the PDF file",
        ),
        ("implicit", None, "did not contain any signature fields"),
        (
            "zero",
            Some("Actual.Name"),
            "the field 'Actual.Name' in the PDF is not a visible one",
        ),
    ] {
        crate::attempt(mode, &mut failures, || {
            let c = base::Case::new("rsa", "supplemental");
            write_config(&c);
            if mode == "zero" {
                add_fields(&c, &[("Actual.Name", Some((3., 7., 3., 70.)))]);
            }
            let mut a = args(&c, field, false);
            let key = a.iter().position(|v| v == "--key").unwrap() + 1;
            a[key] = "missing.key.pem".into();
            let out = native(&c, a, b"");
            assert_eq!(out.status.code(), Some(1));
            assert!(base::text(&out).contains(expected), "{}", base::text(&out));
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn ambiguous_filled_and_malformed_fields_are_not_signed() {
    let mut failures = Vec::new();
    for mode in ["ambiguous", "filled", "malformed", "multiple-widgets"] {
        crate::attempt(mode, &mut failures, || {
            let c = base::Case::new("rsa", "supplemental");
            write_config(&c);
            add_fields(&c, &[("Sig1", Some((0., 0., 100., 100.)))]);
            if mode == "ambiguous" {
                add_fields(&c, &[("Sig2", Some((0., 0., 100., 100.)))]);
            }
            if mode == "filled" {
                let first = native(&c, args(&c, Some("Sig1"), false), b"");
                assert!(first.status.success(), "{}", base::text(&first));
                c.verify();
                fs::copy(c.path("output.pdf"), c.path("input.pdf")).unwrap();
                fs::write(c.path("output.pdf"), base::SENTINEL).unwrap();
            }
            if ["malformed", "multiple-widgets"].contains(&mode) {
                use lopdf::{dictionary, Object};
                let mut doc = lopdf::Document::load(c.path("input.pdf")).unwrap();
                let bytes = fs::read(c.path("input.pdf")).unwrap();
                let pdf = sigis_pdf::PdfFile::parse(&bytes).unwrap();
                let field = sigis_pdf::signatures::enumerate_sig_fields(&pdf, None, Some("Sig1"))
                    .unwrap()[0]
                    .field_ref;
                if mode == "malformed" {
                    doc.get_object_mut(field)
                        .unwrap()
                        .as_dict_mut()
                        .unwrap()
                        .set("Rect", vec![Object::Null, 0.into(), 100.into(), 100.into()]);
                } else {
                    let page = *doc.get_pages().values().next().unwrap();
                    let a=doc.add_object(dictionary!{"Type"=>"Annot","Subtype"=>"Widget","Rect"=>vec![0.into(),0.into(),100.into(),100.into()],"P"=>page});
                    doc.get_object_mut(field)
                        .unwrap()
                        .as_dict_mut()
                        .unwrap()
                        .set("Kids", vec![Object::Reference(a), Object::Reference(a)]);
                }
                doc.save(c.path("input.pdf")).unwrap();
            }
            let out = native(
                &c,
                args(
                    &c,
                    if mode == "ambiguous" {
                        None
                    } else {
                        Some("Sig1")
                    },
                    false,
                ),
                b"",
            );
            assert_eq!(out.status.code(), Some(1), "{mode}: {}", base::text(&out));
            let expected = match mode {
                "ambiguous" => "several empty signature fields",
                "filled" => "filled already",
                "malformed" => "not a visible one",
                _ => "exactly one child annotation",
            };
            assert!(
                base::text(&out).contains(expected),
                "{mode}: {}",
                base::text(&out)
            );
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn actual_existing_style_route_preserves_all_five_main_usage_fields() {
    let policies = [
        json!({"key-usage":["key_cert_sign"]}),
        json!({"key-usage-forbidden":["non_repudiation"]}),
        json!({"key-usage":["non_repudiation"],"extd-key-usage":["email_protection"],"explicit-extd-key-usage-required":true}),
        json!({"key-usage":["non_repudiation","key_cert_sign"],"match-all-key-usages":true}),
        json!({"key-usage":["non_repudiation"],"extd-key-usage":[],"explicit-extd-key-usage-required":true}),
    ];
    let mut failures = Vec::new();
    for (i, policy) in policies.into_iter().enumerate() {
        crate::attempt(&format!("policy{i}"), &mut failures, || {
            let c = base::Case::new("rsa", "supplemental");
            add_fields(&c, &[("Sig1", Some((0., 0., 100., 100.)))]);
            let cfg = config(&c, Some(policy));
            let e = callback(&c, Some("Sig1"), &cfg, &runtime()).unwrap_err();
            assert!(
                e.contains(if i == 1 { "forbidden" } else { "purpose" }),
                "{e}"
            );
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn effective_raw_schema_alias_default_and_provider_guards_remain() {
    let mut failures = Vec::new();
    for mode in 0..8 {
        crate::attempt(&format!("guard{mode}"), &mut failures, || {
            let c = base::Case::new("rsa", "supplemental");
            add_fields(&c, &[("Sig1", Some((0., 0., 100., 100.)))]);
            let mut cfg = config(&c, Some(json!({"key-usage":["non_repudiation"]})));
            let expected = match mode {
                0 => {
                    cfg.raw_config["require-qualified-signature"] = json!(true);
                    "require-qualified-signature"
                }
                1 => {
                    cfg.validation_contexts.get_mut("default").unwrap()
                        ["signer-key-usage-policy"]["require-qualified-signature"] = json!(true);
                    "require-qualified-signature"
                }
                2 => {
                    cfg.raw_config["validation-contexts"]["default"]["signer-key-usage-policy"]
                        ["require-qualified-signature"] = json!(true);
                    "require-qualified-signature"
                }
                3 => {
                    cfg.validation_contexts.get_mut("default").unwrap()["time_tolerance"] =
                        json!(2);
                    "Conflicting configuration aliases"
                }
                4 => {
                    cfg.stamp_styles.get_mut("test").unwrap()["require-qualified-signature"] =
                        json!(true);
                    "require-qualified-signature"
                }
                5 => {
                    cfg.raw_config["stamp-styles"]["test"]["require-qualified-signature"] =
                        json!(true);
                    "require-qualified-signature"
                }
                6 => {
                    cfg.stamp_styles.remove("test");
                    "There is no stamp style named 'test'"
                }
                _ => {
                    cfg.validation_contexts.get_mut("default").unwrap()["trust"] = json!([]);
                    "could not be validated"
                }
            };
            let mut a = args(&c, Some("Sig1"), true);
            a.splice(2..2, ["--validation-context".into(), "default".into()]);
            let before = format!("{cfg:?}");
            let e = invoke_callback(&c, &a, &cfg, &runtime()).unwrap_err();
            assert!(e.contains(expected), "guard{mode}: {e}");
            assert_eq!(before, format!("{cfg:?}"));
            sentinel(&c);
        });
    }
    for provider in ["pkcs11", "pkcs12", "beid", "csc"] {
        crate::attempt(provider, &mut failures, || {
            let c = base::Case::new("rsa", "supplemental");
            let mut a = args(&c, Some("Sig1"), true);
            *a.iter_mut().find(|v| v.as_str() == "pemder").unwrap() = provider.into();
            let cfg = CliConfig::parse("").unwrap();
            let e = invoke_callback(&c, &a, &cfg, &runtime()).unwrap_err();
            assert!(e.contains("requires extended PEM/DER signing"), "{e}");
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn mixed_filled_visible_and_unique_empty_invisible_checks_the_selected_field() {
    let mut failures = Vec::new();
    for variant in [
        "absent-value",
        "indirect-null",
        "false-other",
        "duplicate-name",
        "malformed-name",
        "inherited-non-name-type",
    ] {
        crate::attempt(variant, &mut failures, || {
            let c = base::Case::new("rsa", "supplemental");
            write_config(&c);
            add_fields(&c, &[("Sig1", Some((0., 0., 100., 100.)))]);
            let first = native(&c, args(&c, Some("Sig1"), false), b"");
            assert!(first.status.success(), "{}", base::text(&first));
            c.verify();
            fs::copy(c.path("output.pdf"), c.path("input.pdf")).unwrap();
            let empty_name = if variant == "duplicate-name" {
                "EmptyActual"
            } else {
                "Empty.Actual"
            };
            add_fields(&c, &[(empty_name, Some((0., 0., 0., 100.)))]);
            if variant == "false-other" || variant == "malformed-name" {
                add_fields(&c, &[("False.Other", Some((0., 0., 100., 100.)))]);
            }
            if variant != "absent-value" {
                let input = fs::read(c.path("input.pdf")).unwrap();
                let pdf = sigis_pdf::PdfFile::parse(&input).unwrap();
                let fields = sigis_pdf::signatures::enumerate_sig_fields(&pdf, None, None).unwrap();
                let empty = fields
                    .iter()
                    .find(|f| f.fq_name == empty_name)
                    .unwrap()
                    .field_ref;
                let mut doc = lopdf::Document::load_mem(&input).unwrap();
                match variant {
                    "indirect-null" => {
                        let null = doc.add_object(lopdf::Object::Null);
                        doc.get_object_mut(empty)
                            .unwrap()
                            .as_dict_mut()
                            .unwrap()
                            .set("V", null);
                    }
                    "false-other" => {
                        let other = fields
                            .iter()
                            .find(|f| f.fq_name == "False.Other")
                            .unwrap()
                            .field_ref;
                        doc.get_object_mut(other)
                            .unwrap()
                            .as_dict_mut()
                            .unwrap()
                            .set("V", false);
                    }
                    "inherited-non-name-type" => {
                        let parent = doc
                            .get_object(empty)
                            .unwrap()
                            .as_dict()
                            .unwrap()
                            .get(b"Parent")
                            .unwrap()
                            .as_reference()
                            .unwrap();
                        let signed = fields
                            .iter()
                            .find(|f| f.fq_name == "Sig1")
                            .unwrap()
                            .value
                            .clone()
                            .unwrap();
                        let d = doc.get_object_mut(parent).unwrap().as_dict_mut().unwrap();
                        d.set("FT", "Sig");
                        d.set("V", signed);
                        d.set(
                            "Rect",
                            vec![lopdf::Object::Integer(0), 0.into(), 100.into(), 100.into()],
                        );
                        doc.get_object_mut(empty)
                            .unwrap()
                            .as_dict_mut()
                            .unwrap()
                            .set("FT", 0);
                    }
                    "malformed-name" => {
                        let other = fields
                            .iter()
                            .find(|f| f.fq_name == "False.Other")
                            .unwrap()
                            .field_ref;
                        doc.get_object_mut(other)
                            .unwrap()
                            .as_dict_mut()
                            .unwrap()
                            .set("T", lopdf::Object::Name(b"OtherName".to_vec()));
                    }
                    "duplicate-name" => {
                        let field = doc.get_object_mut(empty).unwrap().as_dict_mut().unwrap();
                        field.set("T", lopdf::Object::string_literal("Sig1"));
                        field.remove(b"Parent");
                    }
                    _ => unreachable!(),
                }
                doc.save(c.path("input.pdf")).unwrap();
            }
            fs::write(c.path("output.pdf"), base::SENTINEL).unwrap();
            let output = native(&c, args(&c, None, false), b"");
            assert_eq!(
                output.status.code(),
                Some(1),
                "{variant}: {}",
                base::text(&output)
            );
            let selected_name = if variant == "duplicate-name" {
                "Sig1"
            } else {
                "Empty.Actual"
            };
            assert!(
                base::text(&output).contains(&format!(
                    "the field '{selected_name}' in the PDF is not a visible one"
                )),
                "{}",
                base::text(&output)
            );
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn finite_decoding_and_strict_reader_refuse_before_key_loading() {
    let mut failures = Vec::new();
    for (sample, expected) in [
        (
            sigis_testdata::path(&["lanes", "r3-c", "decode-limits-simple", "oversized.pdf"]),
            "decod",
        ),
        (
            sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal-slightly-broken.pdf"]),
            "xref",
        ),
    ] {
        crate::attempt(&sample.display().to_string(), &mut failures, || {
            let c = base::Case::new("rsa", "supplemental");
            write_config(&c);
            fs::copy(&sample, c.path("input.pdf")).unwrap();
            let mut a = args(&c, Some("Sig1"), false);
            let key = a.iter().position(|v| v == "--key").unwrap() + 1;
            a[key] = "missing.key.pem".into();
            let result = native(&c, a, b"");
            assert_eq!(result.status.code(), Some(1));
            let text = base::text(&result);
            assert!(text.to_ascii_lowercase().contains(expected), "{text}");
            assert!(!text.contains("missing.key.pem"), "{text}");
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn existing_styled_field_authentication_is_not_bypassed() {
    let mut failures = Vec::new();
    for valid_password in [false, true] {
        crate::attempt(
            &format!("password-valid={valid_password}"),
            &mut failures,
            || {
                let c = base::Case::new("rsa", "supplemental");
                write_config(&c);
                // An actual encrypted input, retaining the original fixture's real
                // security handler; the correct password then reaches field discovery.
                let source =
                    sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal-aes256.pdf"]);
                common::record_file(&source, "actual_encrypted_field_input");
                fs::copy(source, c.path("input.pdf")).unwrap();
                let output = native(
                    &c,
                    args(&c, Some("Missing.Secure"), false),
                    if valid_password {
                        b"ownersecret\n"
                    } else {
                        b"wrong\n"
                    },
                );
                assert_eq!(output.status.code(), Some(1));
                let expected = if valid_password {
                    "'Missing.Secure' does not exist in the PDF file"
                } else {
                    "Invalid password"
                };
                assert!(
                    base::text(&output).contains(expected),
                    "{}",
                    base::text(&output)
                );
                sentinel(&c);
            },
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn mixed_filled_visible_and_unique_empty_visible_still_signs_the_empty_field() {
    let c = base::Case::new("rsa", "supplemental");
    write_config(&c);
    add_fields(&c, &[("Sig1", Some((0., 0., 100., 100.)))]);
    let first = native(&c, args(&c, Some("Sig1"), false), b"");
    assert!(first.status.success(), "{}", base::text(&first));
    c.verify();
    fs::copy(c.path("output.pdf"), c.path("input.pdf")).unwrap();
    add_fields(&c, &[("Empty.Actual", Some((0., 0., 100., 100.)))]);
    fs::write(c.path("output.pdf"), base::SENTINEL).unwrap();
    let result = native(&c, args(&c, None, false), b"");
    assert!(result.status.success(), "{}", base::text(&result));
    let bytes = fs::read(c.path("output.pdf")).unwrap();
    let pdf = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let sigs = pdf.embedded_signatures().unwrap();
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[1].field_name, "Empty.Actual");
    assert_eq!(
        sigis_pades::signature_coverage(&pdf, &sigs[1]).unwrap(),
        sigis_pades::SignatureCoverageLevel::EntireFile
    );
    let evidence = c.revinfo("mixed-positive-revinfo");
    let moment =
        sigis_pki_core::time::Moment::parse_rfc3339(evidence["moment"].as_str().unwrap()).unwrap();
    let root =
        sigis_pki_core::cert::Cert::from_pem_or_der(&fs::read(c.path("root.cert.pem")).unwrap())
            .unwrap();
    let builder = || {
        sigis_pki_certvalidator::ValidationContext::builder()
            .moment(moment)
            .point_in_time_validation(false)
            .time_tolerance(std::time::Duration::from_secs(1))
            .revocation_mode("soft-fail")
    };
    let mut positive = builder().trust_root(root);
    let mut negative = builder();
    for row in evidence["crls"].as_array().unwrap() {
        let crl = fs::read(row["path"].as_str().unwrap()).unwrap();
        assert_eq!(base::sha(&crl), row["sha256"]);
        positive = positive.crl(crl.clone());
        negative = negative.crl(crl);
    }
    let status = sigis_pades::validate_pdf_signature(
        &pdf,
        &sigs[1],
        &positive.build().unwrap(),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    )
    .unwrap();
    assert!(
        status.cms.signature.intact
            && status.cms.signature.valid
            && status.cms.signature.trusted()
            && status.bottom_line(),
        "{status:?}"
    );
    let denied = match sigis_pades::validate_pdf_signature(
        &pdf,
        &sigs[1],
        &negative.build().unwrap(),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    ) {
        Ok(status) => {
            assert!(!status.cms.signature.trusted() && !status.bottom_line());
            json!({"trusted":status.cms.signature.trusted(),"bottom_line":status.bottom_line()})
        }
        Err(e) => json!({"error":e.to_string()}),
    };
    let native_record = json!({"kind":"supplemental last-signature validation; zero original credit","field":"Empty.Actual","output_sha256":base::sha(&bytes),"moment":evidence["moment"],"intact":true,"valid":true,"trusted":true,"bottom_line":true,"coverage":"EntireFile","empty_roots":denied});
    fs::write(
        c.path("mixed-last-native-validation.json"),
        serde_json::to_vec_pretty(&native_record).unwrap(),
    )
    .unwrap();
    let python = sigis_testdata::oracle::python().unwrap();
    let helper = sigis_testdata::path(&["lanes", "r3-c", "visible-negative-four", "oracle.py"]);
    let argv: Vec<String> = [
        helper.display().to_string(),
        "--mode".into(),
        "verify-last".into(),
        "--kind".into(),
        "invisible".into(),
        "--arch".into(),
        "rsa".into(),
        "--named".into(),
        "false".into(),
        "--box".into(),
        "zero-width".into(),
        "--native-fixtures".into(),
        c.dir.path().display().to_string(),
        "--file".into(),
        c.path("output.pdf").display().to_string(),
        "--root".into(),
        c.path("root.cert.pem").display().to_string(),
        "--revinfo".into(),
        c.path("mixed-positive-revinfo/metadata.json")
            .display()
            .to_string(),
    ]
    .into();
    let before = signing_record::before(&[
        helper,
        c.path("output.pdf"),
        c.path("root.cert.pem"),
        c.path("mixed-positive-revinfo/metadata.json"),
    ]);
    let output = Command::new(&python)
        .args(&argv)
        .env("PYTHONOPTIMIZE", "0")
        .current_dir(c.dir.path())
        .output()
        .unwrap();
    fs::write(c.path("mixed-last-reference.json"), &output.stdout).unwrap();
    signing_record::process(
        "mixed-positive-last-same-output-reference",
        &argv,
        c.dir.path(),
        b"",
        &python,
        &output,
        &before,
        &[
            ("same-native-two-signature-output", &c.path("output.pdf")),
            ("fresh-last-reference", &c.path("mixed-last-reference.json")),
            (
                "native-last-full-status",
                &c.path("mixed-last-native-validation.json"),
            ),
        ],
    );
    assert!(output.status.success(), "{}", base::text(&output));
    let reference: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reference["success"], true);
    assert_eq!(reference["last_signature_field"], "Empty.Actual");
    assert_eq!(reference["same_native_output_verified"], true);
}
