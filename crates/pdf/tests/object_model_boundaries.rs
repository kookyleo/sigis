//! Observable native contracts adjacent to three Python-only invalid states.
//!
//! The differing source-model/error contracts remain explicit exclusions.
//! These real parser/writer/mutation controls add no upstream passing IDs.
#![allow(clippy::unwrap_used)]

use sigis_pdf::generic::{self, ParseContext, PdfString};
use sigis_pdf::lopdf::{Dictionary, Object};
use sigis_pdf::misc::Cursor;

#[test]
fn name_normalization_keeps_writer_and_reader_contracts_distinct() {
    let bare = generic::pdf_name("NoSlashHere");
    let prefixed = generic::pdf_name("/NoSlashHere");
    assert_eq!(bare, prefixed);
    let encoded = generic::object_to_bytes(&bare);
    assert_eq!(encoded, b"/NoSlashHere");
    assert_eq!(
        generic::read_object(&mut Cursor::new(&encoded), &ParseContext::default()).unwrap(),
        bare
    );

    // Reader rejection is real, but cannot replace Python's writer refusal.
    let error = generic::read_name(&mut Cursor::new(b"NoSlashHere")).unwrap_err();
    assert!(error.is_read_error());
    assert!(error.to_string().contains("Name object should start with /"));
    println!("OBJECT_BOUNDARY bare_name_writer=ACCEPT bare_name_reader=REJECT");
}

#[test]
fn fresh_text_materializes_bytes_without_losing_unicode_or_empty_values() {
    for text in ["generic text string", "\u{4e16}\u{754c}\u{1f680}", ""] {
        let object = generic::text_string(text);
        let bytes = object.as_str().unwrap();
        match generic::pdf_string(bytes) {
            PdfString::Text(decoded, _) => assert_eq!(decoded, text),
            PdfString::Bytes(_) => panic!("fresh text must remain a text string"),
        }
        let encoded = generic::object_to_bytes(&object);
        assert_eq!(
            generic::read_object(&mut Cursor::new(&encoded), &ParseContext::default()).unwrap(),
            object
        );
        if text.is_empty() {
            assert!(bytes.is_empty()); // Empty bytes are real data, never None.
        }
    }
    println!("OBJECT_BOUNDARY fresh_text_bytes=AVAILABLE");
}

#[test]
fn dictionary_conversion_and_typed_entry_defaults_keep_real_values() {
    let mut converted = Dictionary::new();
    converted.set("A", 1);
    assert_eq!(converted.get(b"A").unwrap(), &Object::Integer(1));
    let mut explicit = Dictionary::new();
    explicit.set("A", Object::Integer(1));
    assert_eq!(converted, explicit);

    // This is the actual typed IndexMap entry API, not an invented
    // Dictionary.setdefault or a raw-value rejection protocol.
    let mut defaults = Dictionary::new();
    let entry = defaults
        .as_hashmap_mut()
        .entry(b"A".to_vec())
        .or_insert(Object::from(1));
    assert_eq!(entry, &Object::Integer(1));
    defaults
        .as_hashmap_mut()
        .entry(b"A".to_vec())
        .or_insert(Object::from(2));
    assert_eq!(defaults, converted);
    converted.set("A", 2);
    assert_eq!(converted.get(b"A").unwrap(), &Object::Integer(2));

    let object = Object::Dictionary(defaults);
    let encoded = generic::object_to_bytes(&object);
    assert_eq!(
        generic::read_object(&mut Cursor::new(&encoded), &ParseContext::default()).unwrap(),
        object
    );
    println!("OBJECT_BOUNDARY raw_integer_set=ACCEPT typed_default=PRESERVE_EXISTING");
}
