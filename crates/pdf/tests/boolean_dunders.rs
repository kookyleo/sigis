// pyHanko 0.38.1 test_internal_utils.py::test_bool_dunders
// (MIT, see LICENSE-pyHanko). L-approved finite language adaptation;
// see lanes/r3-s/boolean-dunders/README.md in sigis-testdata.
#![allow(clippy::unwrap_used)]

use sigis_pdf::generic::{read_object, ParseContext};
use sigis_pdf::lopdf::Object;
use sigis_pdf::misc::Cursor;

#[test]
fn test_bool_dunders() {
    let context = ParseContext::default();
    let mut true_input = Cursor::new(include_bytes!(
        "../../testdata/data/lanes/r3-s/boolean-dunders/true.pdfobj"
    ));
    let mut false_input = Cursor::new(include_bytes!(
        "../../testdata/data/lanes/r3-s/boolean-dunders/false.pdfobj"
    ));
    let mut empty_input = Cursor::new(include_bytes!(
        "../../testdata/data/lanes/r3-s/boolean-dunders/empty-string.pdfobj"
    ));
    let bool_true = read_object(&mut true_input, &context).unwrap();
    let bool_false = read_object(&mut false_input, &context).unwrap();
    let empty_string = read_object(&mut empty_input, &context).unwrap();

    // Setup controls exercise real parsing, rather than a test Boolean model.
    assert_eq!(bool_true, Object::Boolean(true));
    assert_eq!(bool_false, Object::Boolean(false));
    assert!(matches!(&empty_string, Object::String(bytes, _) if bytes.is_empty()));
    assert_eq!(true_input.tell(), true_input.len());
    assert_eq!(false_input.tell(), false_input.len());
    assert_eq!(empty_input.tell(), empty_input.len());

    // B1: bool_true != bool_false.
    assert_ne!(bool_true, bool_false);
    // B2/B3: Python's raw empty str maps to an actual parsed PDF String.
    assert_ne!(bool_true, empty_string);
    assert_ne!(bool_false, empty_string);
    // B4/B5: implicit truthiness maps to the existing scalar projection.
    assert!(bool_true.as_bool().unwrap());
    assert!(!bool_false.as_bool().unwrap());
    // B6/B7: reconstruct the projected scalar in the Object equality domain.
    assert_eq!(bool_true, Object::from(bool_true.as_bool().unwrap()));
    assert_eq!(bool_false, Object::from(bool_false.as_bool().unwrap()));

    // B8/B9 each preserve both comparisons of the upstream comparison chain.
    // Python object str maps to scalar bool Display; Object has no Display.
    // Actual Object Debug and scalar Display are lowercase in this profile.
    let true_debug = format!("{bool_true:?}");
    let true_display = bool_true.as_bool().unwrap().to_string();
    assert_eq!(true_debug, true_display);
    assert_eq!(true_display, "true");
    let false_debug = format!("{bool_false:?}");
    let false_display = bool_false.as_bool().unwrap().to_string();
    assert_eq!(false_debug, false_display);
    assert_eq!(false_display, "false");

    println!(
        "BOOLEAN_DUNDERS_PROFILE true_debug={true_debug:?} true_scalar_display={true_display:?} \
         false_debug={false_debug:?} false_scalar_display={false_display:?}"
    );
}
