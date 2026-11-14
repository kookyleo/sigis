//! Exact two default-appearance originals: four positive parameters and fixed RSA.
//! Supplemental checks receive no additional upstream-function credit.
#[path = "common/appearance_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;

fn attempt<T>(label: &str, failures: &mut Vec<String>, action: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(value) => Some(value),
        Err(error) => {
            let message = error
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| error.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic");
            failures.push(format!("{label}: {message}"));
            None
        }
    }
}

#[test]
fn test_cli_sign_visible_no_style() {
    let mut failures = Vec::new();
    for arch in cases::ARCHES {
        let case = cases::Case::new(arch, "visible");
        let native = attempt(&format!("{arch} native attempt"), &mut failures, || {
            case.native()
        });
        // Always run a fresh unchanged Python original, even on a red native case.
        attempt(
            &format!("{arch} fresh Python original"),
            &mut failures,
            || case.reference(),
        );
        if let Some(native) = native {
            attempt(&format!("{arch} native assertions"), &mut failures, || {
                assert!(native.status.success(), "{}", cases::text(&native));
                case.verify();
            });
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn test_cli_new_field_spec_bars_existing_only() {
    let case = cases::Case::new("rsa", "conflict");
    let mut failures = Vec::new();
    let native = attempt("fixed RSA native attempt", &mut failures, || case.native());
    attempt("fixed RSA fresh Python original", &mut failures, || {
        case.reference()
    });
    if let Some(native) = native {
        attempt("fixed RSA exact native diagnostic", &mut failures, || {
            assert_eq!(native.status.code(), Some(1), "{}", cases::text(&native));
            assert!(
                cases::text(&native).contains("incompatible with --existing-only"),
                "{}",
                cases::text(&native)
            );
            // Supplemental preservation requirement, separate from original ID.
            assert_eq!(
                std::fs::read(case.path("output.pdf")).unwrap(),
                cases::SENTINEL
            );
            assert_eq!(
                std::fs::read(case.path("native-output-frozen.pdf")).unwrap(),
                cases::SENTINEL
            );
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

