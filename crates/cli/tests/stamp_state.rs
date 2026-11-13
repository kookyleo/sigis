//! CLI regressions for carrying the trusted-input reader policy into edits.
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime, Output};
use sigis_pdf::{decode_limits::DecodeLimits, PdfFile, ReaderOptions};
use std::fs;

fn output(result: &Output) -> String {
    format!("{}{}", result.stdout, result.stderr)
}

fn invoke(args: &[String]) -> Output {
    sigis_cli::run_with_runtime(
        args,
        &PluginRegistry::default(),
        &ValidationRuntime::default(),
    )
}

fn assert_bounded_rejection(args: &[String], outfile: &std::path::Path) {
    let result = invoke(args);
    assert_eq!(result.code, 1, "{}", output(&result));
    assert!(output(&result).contains("rerun with --no-decode-limits"));
    assert!(!outfile.exists(), "a rejected edit must not create output");
}

#[test]
fn trusted_stamps_preserve_decode_opt_out() {
    for kind in ["text", "qr"] {
        let dir = tempfile::tempdir().unwrap();
        let input = sigis_testdata::path(&["lanes", "r3-c", "decode-limits", "oversized.pdf"]);
        let outfile = dir.path().join("stamped.pdf");
        let config = dir.path().join("pyhanko.yml");
        fs::write(&config, format!("stamp-styles: {{test: {{type: {kind}}}}}")).unwrap();
        let mut args = vec![
            "--config".into(),
            config.to_string_lossy().into_owned(),
            "stamp".into(),
            "--style-name".into(),
            "test".into(),
        ];
        if kind == "qr" {
            args.extend(["--stamp-url".into(), "https://example.com".into()]);
        }
        args.extend([
            input.to_string_lossy().into_owned(),
            outfile.to_string_lossy().into_owned(),
            "0".into(),
            "0".into(),
        ]);
        assert_bounded_rejection(&args, &outfile);
        args.insert(3, "--no-decode-limits".into());
        let result = invoke(&args);
        assert_eq!(result.code, 0, "style={kind}: {}", output(&result));
        let bytes = fs::read(&outfile).unwrap();
        let reader = PdfFile::parse_with(
            &bytes,
            ReaderOptions {
                decode_limits: DecodeLimits::for_trusted_input(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(reader.total_revisions(), 2);
        assert!(bytes.windows(8).any(|window| window == b"/XObject"));
    }
}
