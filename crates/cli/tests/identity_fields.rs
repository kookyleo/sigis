//! Tests-first field/annotation regressions for the new default visible path.
#[path = "common/identity_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;
use lopdf::{dictionary, Object};
fn prepare(case: &cases::Case, separate: bool, invalid: bool) {
    let mut doc = lopdf::Document::load(case.path("input.pdf")).unwrap();
    let page = *doc.get_pages().values().next().unwrap();
    let rect = if invalid {
        vec![Object::Null, Object::Null, 100.into(), 100.into()]
    } else {
        vec![0.into(), 0.into(), 100.into(), 100.into()]
    };
    let widget =
        doc.add_object(dictionary! {"Type"=>"Annot","Subtype"=>"Widget","Rect"=>rect,"P"=>page});
    let field = if separate {
        doc.add_object(dictionary!{"FT"=>"Sig","T"=>Object::string_literal("Sig1"),"Kids"=>vec![Object::Reference(widget)]})
    } else {
        let dict = doc.get_object_mut(widget).unwrap().as_dict_mut().unwrap();
        dict.set("FT", "Sig");
        dict.set("T", Object::string_literal("Sig1"));
        widget
    };
    if separate {
        doc.get_object_mut(widget)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("Parent", field);
    }
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Annots", vec![Object::Reference(widget)]);
    let form = doc.add_object(dictionary! {"Fields"=>vec![Object::Reference(field)]});
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_object_mut(root)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("AcroForm", form);
    doc.save(case.path("input.pdf")).unwrap();
}
fn invoke(case: &cases::Case) -> sigis_cli::Output {
    std::fs::write(case.path("empty.yml"), "{}").unwrap();
    let args = vec![
        "--config".into(),
        case.path("empty.yml").display().to_string(),
        "sign".into(),
        "addsig".into(),
        "--field".into(),
        "1/0,0,100,100/Sig1".into(),
        "pkcs12".into(),
        case.path("input.pdf").display().to_string(),
        case.path("output.pdf").display().to_string(),
        case.path("signer.p12").display().to_string(),
    ];
    let runtime = sigis_cli::runtime::ValidationRuntime {
        now: sigis_pki_core::time::Moment::parse_rfc3339("2020-08-01T00:00:00+08:00").unwrap(),
        password: Some("secret".into()),
        fetchers: sigis_pki_core::fetch::Fetchers::none(),
        trusted_list_transport: None,
    };
    sigis_cli::run_with_runtime(
        &args,
        &sigis_cli::plugins::PluginRegistry::default(),
        &runtime,
    )
}
#[test]
fn malformed_rectangle_cannot_satisfy_a_visible_requirement() {
    let case = cases::Case::new("rsa", "getpass");
    prepare(&case, false, true);
    let result = invoke(&case);
    assert_eq!(result.code, 1, "{}{}", result.stdout, result.stderr);
    assert!(result.stderr.contains("not a visible"), "{}", result.stderr);
    assert_eq!(
        std::fs::read(case.path("output.pdf")).unwrap(),
        b"identity-getpass-output-sentinel"
    );
}
#[test]
fn separate_single_widget_is_a_valid_visible_field() {
    let case = cases::Case::new("rsa", "getpass");
    prepare(&case, true, false);
    let result = invoke(&case);
    assert_eq!(result.code, 0, "{}{}", result.stdout, result.stderr);
    case.verify();
}
