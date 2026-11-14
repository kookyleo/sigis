//! Four exact visible-signature negative originals, with fourteen native cases.
#[allow(dead_code)]
#[path = "common/appearance_cases.rs"]
mod appearance_cases;
#[allow(dead_code)]
#[path = "common/visible_negative_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;

use cases::{Case, ARCHES, BOXES};

fn attempt<T>(label: &str, failures: &mut Vec<String>, action: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(value) => Some(value),
        Err(error) => {
            let message = error
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| error.downcast_ref::<&str>().copied())
                .unwrap_or("panic");
            failures.push(format!("{label}: {message}"));
            None
        }
    }
}

fn original(case: &Case, failures: &mut Vec<String>) {
    let label = case.label();
    // The native receipt and any output bytes are frozen before either oracle.
    // A failing native assertion must not prevent the remaining native cases or
    // the fresh unchanged original body for this case from executing.
    let output = attempt(&format!("{label} native process"), failures, || {
        case.native()
    });
    attempt(&format!("{label} fresh original"), failures, || {
        case.reference()
    });
    attempt(
        &format!("{label} same native input reference"),
        failures,
        || case.inspect_negative(),
    );
    if let Some(output) = output {
        attempt(
            &format!("{label} native original assertions"),
            failures,
            || {
                cases::assert_negative(case.kind, output.status.code(), &cases::text(&output));
            },
        );
        // Supplemental side-effect assertion: the originals assert diagnostics,
        // not output absence. No preexisting sentinel changes their scenario.
        attempt(
            &format!("{label} supplemental output absence"),
            failures,
            || {
                assert!(!case.path("output.pdf").exists());
            },
        );
    }
}

#[test]
fn test_cli_sign_visible_with_style_but_no_config() {
    let mut failures = Vec::new();
    for arch in ARCHES {
        if let Some(case) = attempt(
            &format!("no-config/{arch} preparation"),
            &mut failures,
            || Case::new(arch, "no-config"),
        ) {
            original(&case, &mut failures);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn test_cli_underspecified_visible_new_field() {
    let case = Case::new("rsa", "missing");
    let mut failures = Vec::new();
    original(&case, &mut failures);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn test_cli_underspecified_visible_new_field_no_name() {
    let case = Case::new("rsa", "unnamed");
    let mut failures = Vec::new();
    original(&case, &mut failures);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn test_cli_explicit_style_but_field_invisible() {
    let mut failures = Vec::new();
    for named in [true, false] {
        for box_key in BOXES {
            let label = format!("invisible/named={named}/{box_key}");
            if let Some(case) = attempt(&format!("{label} preparation"), &mut failures, || {
                Case::invisible(named, box_key)
            }) {
                original(&case, &mut failures);
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[path = "common/visible_negative_guards.rs"]
mod guards;
