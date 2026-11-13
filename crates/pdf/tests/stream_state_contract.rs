//! Positive controls for the native constructor-time adaptation of pyHanko
//! 0.38.1 test_internal_utils.py::test_stream_pathological_encode_decode.
//!
//! The two real-constructor rejection doctests live in stream.rs. These tests
//! preserve valid empty/nonempty data in both directions; they do not reproduce
//! Python's runtime errors or create an optional-buffer model. One original
//! function owns this adaptation, regardless of the number of controls.

use sigis_pdf::lopdf::{Dictionary, Object, Stream};
use sigis_pdf::stream::{encoded_stream, DecodedStream};

const PAYLOADS: [&[u8]; 2] = [b"", b"materialized\0bytes\xff"];

#[test]
fn raw_constructor_preserves_empty_and_nonempty_data() -> Result<(), Box<dyn std::error::Error>> {
    for data in PAYLOADS {
        let stream = Stream::new(Dictionary::new(), data.to_vec());
        assert_eq!(stream.content, data);
        assert_eq!(
            stream.dict.get(b"Length")?,
            &Object::Integer(data.len() as i64)
        );
        assert_eq!(DecodedStream::from_stream(&stream)?.data, data);
    }
    Ok(())
}

#[test]
fn decoded_constructor_roundtrips_unfiltered_data() -> Result<(), Box<dyn std::error::Error>> {
    for data in PAYLOADS {
        let decoded = DecodedStream::new(Dictionary::new(), data.to_vec());
        assert_eq!(decoded.data, data);
        let encoded = decoded.to_stream()?;
        assert_eq!(encoded.content, data);
        assert!(!encoded.dict.has(b"Filter"));
        assert_eq!(DecodedStream::from_stream(&encoded)?.data, data);
    }
    Ok(())
}

#[test]
fn encoded_factory_roundtrips_materialized_data() -> Result<(), Box<dyn std::error::Error>> {
    for data in PAYLOADS {
        let object = encoded_stream(Dictionary::new(), data.to_vec());
        let stream = object.as_stream()?;
        assert_eq!(stream.content, data);
        assert_eq!(DecodedStream::from_stream(stream)?.data, data);
    }
    Ok(())
}

#[test]
fn flate_roundtrips_empty_and_nonempty_data() -> Result<(), Box<dyn std::error::Error>> {
    for data in PAYLOADS {
        let mut decoded = DecodedStream::new(Dictionary::new(), data.to_vec());
        decoded.compress()?;
        let encoded = decoded.to_stream()?;
        assert_eq!(
            encoded.dict.get(b"Filter")?,
            &Object::Name(b"FlateDecode".to_vec())
        );
        assert!(!encoded.content.is_empty());
        assert_eq!(DecodedStream::from_stream(&encoded)?.data, data);

        let rebuilt = encoded_stream(encoded.dict.clone(), encoded.content.clone());
        assert_eq!(DecodedStream::from_stream(rebuilt.as_stream()?)?.data, data);
    }
    Ok(())
}

#[test]
fn positioned_empty_stream_remains_valid_data() -> Result<(), Box<dyn std::error::Error>> {
    let positioned = Stream::with_position(Dictionary::new(), 123);
    assert!(positioned.content.is_empty());
    assert_eq!(positioned.start_position, Some(123));

    let decoded = DecodedStream::from_stream(&positioned)?;
    assert!(decoded.data.is_empty());
    assert!(decoded.to_stream()?.content.is_empty());
    assert_eq!(positioned.start_position, Some(123));
    Ok(())
}
