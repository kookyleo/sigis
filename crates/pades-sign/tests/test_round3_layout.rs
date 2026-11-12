//! Exact assertion ports of four pyHanko 0.38.1 `test_internal_utils.py`
//! functions. These functions remain owned and counted by round-3 lane S.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use lopdf::Object;
use sigis_pades_sign::content::{PdfResources, ResourceType};
use sigis_pades_sign::layout::{BoxConstraints, Fraction};
use sigis_pki_core::errors::HankoError;

/// The public Rust representation of `BoxSpecificationError`.
fn assert_box_specification_error<T: std::fmt::Debug>(result: Result<T, HankoError>) {
    let error = result.expect_err("expected BoxSpecificationError");
    assert!(
        matches!(error, HankoError::Layout(ref message)
            if message == "box constraint is over/underspecified"),
        "expected BoxSpecificationError, got {error:?}"
    );
}

#[test]
fn test_box_constraint_over_underspecify() {
    let w = 1600.0;
    let h = 900.0;
    let ar = Fraction::new(16, 9).unwrap();

    assert_box_specification_error(BoxConstraints::new(Some(w), Some(h), Some(ar)));

    let bc = BoxConstraints::new(Some(w), None, None).unwrap();
    assert!(!bc.aspect_ratio_defined());
    assert!(!bc.height_defined());

    let bc = BoxConstraints::new(Some(w), Some(h), None).unwrap();
    assert_eq!(bc.aspect_ratio().unwrap(), ar);

    let mut bc = BoxConstraints::new(Some(w), None, Some(ar)).unwrap();
    assert_eq!(bc.height().unwrap(), h);
    let next_height = bc.height().unwrap() + 1.0;
    assert_box_specification_error(bc.set_height(next_height));

    let mut bc = BoxConstraints::new(None, Some(h), Some(ar)).unwrap();
    assert_eq!(bc.width().unwrap(), w);
    let next_width = bc.width().unwrap() + 1.0;
    assert_box_specification_error(bc.set_width(next_width));

    let mut bc = BoxConstraints::new(None, None, None).unwrap();
    bc.set_width(w).unwrap();
    assert!(bc.width_defined());
    assert!(!bc.height_defined());
    assert!(!bc.aspect_ratio_defined());

    bc.set_height(h).unwrap();
    assert_eq!(bc.aspect_ratio().unwrap(), ar);
}

#[test]
fn test_box_constraint_recalc() {
    let w = 1600.0;
    let h = 900.0;
    let ar = Fraction::new(16, 9).unwrap();

    let mut bc = BoxConstraints::new(None, None, Some(ar)).unwrap();
    assert_eq!(bc.aspect_ratio().unwrap(), ar);
    assert_box_specification_error(bc.height());
    assert_box_specification_error(bc.width());

    bc.set_width(w).unwrap();
    assert!(bc.height_defined());
    assert_eq!(bc.height().unwrap(), h);

    let mut bc = BoxConstraints::new(None, None, Some(ar)).unwrap();
    bc.set_height(h).unwrap();
    assert!(bc.width_defined());
    assert_eq!(bc.width().unwrap(), w);

    let mut bc = BoxConstraints::new(Some(w), None, None).unwrap();
    assert_box_specification_error(bc.aspect_ratio());
    bc.set_height(h).unwrap();
    assert_eq!(bc.aspect_ratio().unwrap(), ar);
}

#[test]
fn test_resource_add_test() {
    let mut res1 = PdfResources::new();
    let mut res2 = PdfResources::new();
    res1.set(ResourceType::XObject, "Bleh", Object::Null);
    res1.set(ResourceType::Pattern, "Blih", Object::Null);
    res2.set(ResourceType::XObject, "Blah", Object::Null);
    res2.set(ResourceType::Font, "Bluh", Object::Null);

    res1.merge(&res2).unwrap();
    let res1_dict = res1.as_pdf_object();
    assert!(res1_dict.has(b"XObject"));
    assert!(res1_dict.has(b"Pattern"));
    assert!(res1_dict.has(b"Font"));
    let xobjects = res1_dict.get(b"XObject").unwrap().as_dict().unwrap();
    assert!(xobjects.has(b"Bleh"));
    assert!(xobjects.has(b"Blah"));
    assert!(!res1_dict.has(b"Shading"));
}

#[test]
fn test_duplicate_resource() {
    let mut res1 = PdfResources::new();
    let mut res2 = PdfResources::new();
    res1.set(ResourceType::XObject, "Bleh", Object::Null);
    res1.set(ResourceType::Pattern, "Blih", Object::Null);
    res2.set(ResourceType::XObject, "Bleh", Object::Null);
    res2.set(ResourceType::Font, "Bluh", Object::Null);

    let error = res1
        .merge(&res2)
        .expect_err("expected ResourceManagementError");
    assert!(
        matches!(error, HankoError::Malformed(ref message)
            if message == "Resource with name /Bleh occurs in both dictionaries."),
        "expected ResourceManagementError, got {error:?}"
    );
}
