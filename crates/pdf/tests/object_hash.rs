// Exact remaining hashing assertions from pyHanko 0.38.1
// test_internal_utils.py (MIT, see LICENSE-pyHanko).
// Pending shared API request: Hash on the existing parser Item, not a wrapper.
#![allow(clippy::unwrap_used)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Once;

use sha2::{Digest, Sha256};
use sigis_pdf::generic::{self, ContentOpReading, Item, ParseContext};
use sigis_pdf::lopdf::{Dictionary, Object, Stream, StringFormat};
use sigis_pdf::misc::Cursor;

fn hash(value: &impl Hash) -> u64 {
    static IDENTITY: Once = Once::new();
    IDENTITY.call_once(|| {
        use std::fmt::Write;
        let executable = std::env::current_exe().unwrap();
        #[cfg(target_os = "linux")]
        let bytes = std::fs::read("/proc/self/exe").unwrap();
        #[cfg(not(target_os = "linux"))]
        let bytes = std::fs::read(&executable).unwrap();
        let mut digest = String::new();
        for byte in Sha256::digest(&bytes) {
            write!(&mut digest, "{byte:02x}").unwrap();
        }
        println!(
            "OBJECT_HASH_RUNTIME executable={} length={} sha256={digest}",
            executable.display(),
            bytes.len(),
        );
    });
    let mut state = DefaultHasher::new();
    value.hash(&mut state);
    state.finish()
}

fn parse(bytes: &[u8]) -> Item {
    generic::read_item(
        &mut Cursor::new(bytes),
        &ParseContext::default(),
        ContentOpReading::GraphicOps,
    )
    .unwrap()
}

#[test]
fn test_all_nulls_same_hash() {
    let first = hash(&Item::Object(Object::Null));
    let second = hash(&Item::Object(Object::Null));
    println!("OBJECT_HASH_ORIGINAL case=null first={first} second={second}");
    assert_eq!(first, second);
}

#[test]
fn test_operator_literal_hash() {
    let text = hash(&Item::Object(generic::text_string("aaa")));
    let operator = hash(&Item::Operator("aaa".into()));
    println!("OBJECT_HASH_ORIGINAL case=operator text={text} operator={operator}");
    assert_ne!(text, operator);
}

#[test]
fn parsed_values_keep_the_same_hash_as_constructed_parser_items() {
    for (bytes, expected) in [
        (b"null ".as_slice(), Item::Object(Object::Null)),
        (
            b"(aaa) ".as_slice(),
            Item::Object(generic::text_string("aaa")),
        ),
        (b"aaa ".as_slice(), Item::Operator("aaa".into())),
    ] {
        let actual = parse(bytes);
        assert_eq!(actual, expected);
        assert_eq!(hash(&actual), hash(&expected));
    }
    assert_ne!(hash(&parse(b"(aaa) ")), hash(&parse(b"aaa ")));
}

#[test]
fn equal_positive_and_negative_zero_keep_equal_hashes() {
    let positive = Item::Object(Object::Real(0.0));
    let negative = Item::Object(Object::Real(-0.0));
    assert_eq!(positive, negative);
    assert_eq!(hash(&positive), hash(&negative));
    // Preserve the real parser model's PartialEq; NaN does not justify Eq.
    let nan = Item::Object(Object::Real(f32::NAN));
    assert_ne!(nan, nan.clone());
}

fn reordered_dictionaries() -> (Dictionary, Dictionary) {
    let mut first = Dictionary::new();
    first.set("A", Object::Integer(1));
    first.set("B", Object::Array(vec![Object::Null, Object::Real(-0.0)]));
    let mut second = Dictionary::new();
    second.set("B", Object::Array(vec![Object::Null, Object::Real(0.0)]));
    second.set("A", Object::Integer(1));
    assert_eq!(first, second);
    (first, second)
}

#[test]
fn equal_dictionaries_ignore_insertion_order_when_hashed() {
    let (first, second) = reordered_dictionaries();
    let first = Item::Object(Object::Dictionary(first));
    let second = Item::Object(Object::Dictionary(second));
    assert_eq!(first, second);
    assert_eq!(hash(&first), hash(&second));
}

#[test]
fn equal_streams_keep_equal_hashes_with_reordered_dictionary_entries() {
    let (first, second) = reordered_dictionaries();
    let first = Item::Object(Object::Stream(Stream::new(
        first,
        b"actual stream".to_vec(),
    )));
    let second = Item::Object(Object::Stream(Stream::new(
        second,
        b"actual stream".to_vec(),
    )));
    assert_eq!(first, second);
    assert_eq!(hash(&first), hash(&second));
}

#[test]
fn equal_clones_cover_every_existing_object_variant() {
    let (dictionary, _) = reordered_dictionaries();
    let objects = [
        Object::Null,
        Object::Boolean(false),
        Object::Boolean(true),
        Object::Integer(i64::MIN),
        Object::Integer(i64::MAX),
        Object::Real(1.5),
        Object::Real(f32::INFINITY),
        Object::Real(f32::NEG_INFINITY),
        Object::Name(b"aaa".to_vec()),
        Object::String(b"aaa".to_vec(), StringFormat::Literal),
        Object::String(b"aaa".to_vec(), StringFormat::Hexadecimal),
        Object::Array(vec![Object::Null, Object::Integer(7)]),
        Object::Dictionary(dictionary.clone()),
        Object::Stream(Stream::new(dictionary, b"actual bytes".to_vec())),
        Object::Reference((7, 2)),
    ];
    for object in objects {
        let value = Item::Object(object);
        let cloned = value.clone();
        assert_eq!(value, cloned);
        assert_eq!(hash(&value), hash(&cloned));
    }
    let operator = parse(b"aaa ");
    assert_eq!(hash(&operator), hash(&operator.clone()));
}

#[test]
fn selected_type_and_stream_state_changes_affect_default_hashes() {
    // These concrete controls do not promise collision freedom for arbitrary
    // values or for every Hasher. They expose omitted fields in this model.
    for (left, right) in [
        (Object::Integer(1), Object::Real(1.0)),
        (Object::Name(b"aaa".to_vec()), generic::text_string("aaa")),
        (
            Object::String(b"aaa".to_vec(), StringFormat::Literal),
            Object::String(b"aaa".to_vec(), StringFormat::Hexadecimal),
        ),
        (Object::Reference((7, 0)), Object::Reference((7, 1))),
        (
            Object::Array(vec![Object::Integer(1), Object::Integer(2)]),
            Object::Array(vec![Object::Integer(2), Object::Integer(1)]),
        ),
    ] {
        let left = Item::Object(left);
        let right = Item::Object(right);
        assert_ne!(left, right);
        assert_ne!(hash(&left), hash(&right));
    }

    let base = Stream::new(Dictionary::new(), b"actual bytes".to_vec());
    let mut dictionary = base.clone();
    dictionary.dict.set("Marker", Object::Integer(91));
    let mut content = base.clone();
    content.content.push(b'!');
    let mut compression = base.clone();
    compression.allows_compression = !compression.allows_compression;
    let mut position = base.clone();
    position.start_position = Some(17);
    let base = Item::Object(Object::Stream(base));
    for changed in [dictionary, content, compression, position] {
        let changed = Item::Object(Object::Stream(changed));
        assert_ne!(base, changed);
        assert_ne!(hash(&base), hash(&changed));
    }
}

#[test]
fn hashing_does_not_require_relaxing_operator_parser_refusals() {
    assert!(generic::read_object(&mut Cursor::new(b"aaa "), &ParseContext::default()).is_err());
    for bytes in [b"a\xff ".as_slice(), b"R ".as_slice()] {
        assert!(generic::read_item(
            &mut Cursor::new(bytes),
            &ParseContext::default(),
            ContentOpReading::GraphicOps,
        )
        .is_err());
    }
}

#[test]
fn nested_dictionaries_compare_raw_keys_independent_of_insertion_order() {
    let mut inner_first = Dictionary::new();
    inner_first.set(vec![0xff, 0], Object::Real(-0.0));
    inner_first.set(vec![0, 0x80], Object::Integer(7));
    let mut inner_second = Dictionary::new();
    inner_second.set(vec![0, 0x80], Object::Integer(7));
    inner_second.set(vec![0xff, 0], Object::Real(0.0));
    let mut first = Dictionary::new();
    first.set(vec![0x80], Object::Dictionary(inner_first));
    first.set(vec![0], Object::Null);
    let mut second = Dictionary::new();
    second.set(vec![0], Object::Null);
    second.set(vec![0x80], Object::Dictionary(inner_second));
    let first = Item::Object(Object::Dictionary(first));
    let second = Item::Object(Object::Dictionary(second));
    assert_eq!(first, second);
    assert_eq!(hash(&first), hash(&second));
}

#[test]
fn materialized_stream_hash_never_decodes_or_mutates_its_bytes() {
    let mut dictionary = Dictionary::new();
    dictionary.set("Filter", Object::Name(b"NeverDecodeThisFilter".to_vec()));
    dictionary.set("DecodeParms", Object::Null);
    let mut stream = Stream::new(dictionary, b"not compressed\x00\xff".to_vec());
    stream.allows_compression = false;
    stream.start_position = Some(123);
    let value = Item::Object(Object::Stream(stream));
    let before = value.clone();
    let first = hash(&value);
    assert_eq!(value, before);
    assert_eq!(first, hash(&value));
    assert_eq!(value, before);
}
