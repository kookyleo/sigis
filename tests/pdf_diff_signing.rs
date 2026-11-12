// Ported from pyHanko test_diff_analysis.py (v0.38.1, MIT).
//! Cross-layer signer/validator acceptance belongs to the application test layer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/pdf_diff_signing.rs"]
mod signing;

#[test]
fn test_create_deep_sig_field() {
    signing::create_deep_fields(false);
}

#[test]
fn test_create_multi_deep_sig_field() {
    signing::create_deep_fields(true);
}

#[test]
fn test_deep_non_sig_field() {
    signing::reject_non_signature_fields();
}

#[test]
fn test_simple_sign_with_separate_annot() {
    signing::separate_annotation();
}
