// Exact unbound-reference assertion from pyHanko 0.38.1 test_internal_utils.py
// and additional bound-handler policy controls (MIT, see LICENSE-pyHanko).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fmt::Write;

use common::{first_page, read, read_lenient};
use sha2::{Digest, Sha256};
use sigis_pdf::crypt::api::AuthStatus;
use sigis_pdf::lopdf::{Dictionary, Object, ObjectId};
use sigis_pdf::rw_common::resolve_reference;
use sigis_pdf::{IncrementalWriter, PdfError, PdfFile, PdfHandler, PdfResult};

fn input(name: &str) -> Vec<u8> {
    let path = sigis_testdata::path(&["pyhanko", "pdf", name]);
    let bytes = std::fs::read(&path).unwrap();
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(&bytes) {
        write!(&mut digest, "{byte:02x}").unwrap();
    }
    println!(
        "REFERENCE_INPUT path={} length={} sha256={}",
        path.display(),
        bytes.len(),
        digest
    );
    bytes
}

#[test]
fn test_unbound_reference() {
    // The complete upstream assertion: Reference(1, 0).get_object() == Null.
    assert_eq!(resolve_reference((1, 0), None).unwrap(), Object::Null);
}

#[test]
fn bound_reference_preserves_the_actual_reader_and_generation() {
    let reader = read(&input("minimal.pdf"));
    let root = reader.root_ref().unwrap();
    let resolved = resolve_reference(root, Some(&reader)).unwrap();
    assert_eq!(resolved, reader.get_object(root).unwrap());
    let dict = resolved.as_dict().unwrap();
    assert_eq!(
        dict.get(b"Type").unwrap(),
        &Object::Name(b"Catalog".to_vec())
    );
    assert!(matches!(
        resolve_reference((root.0, root.1 + 1), Some(&reader)),
        Err(PdfError::StrictRead(_))
    ));
}

#[test]
fn missing_bound_reference_keeps_strict_and_lenient_policy() {
    let bytes = input("minimal.pdf");
    let strict = read(&bytes);
    let lenient = read_lenient(&bytes);
    let missing = (999_999, 0);
    assert!(matches!(
        resolve_reference(missing, Some(&strict)),
        Err(PdfError::StrictRead(_))
    ));
    assert_eq!(
        resolve_reference(missing, Some(&lenient)).unwrap(),
        Object::Null
    );
}

#[test]
fn historical_binding_does_not_switch_to_the_latest_revision() {
    let base = read(&input("minimal.pdf"));
    let root = base.root_ref().unwrap();
    let original = base.get_object(root).unwrap();
    let mut updated = original.as_dict().unwrap().clone();
    updated.set("ReferenceRevisionMarker", Object::Integer(42));
    let mut writer = IncrementalWriter::new(base);
    writer.update_object(root, Object::Dictionary(updated));
    let bytes = writer.write().unwrap();
    let reader = PdfFile::parse(&bytes).unwrap();
    let historical = reader.historical_resolver(0);
    assert_eq!(
        resolve_reference(root, Some(&historical)).unwrap(),
        original
    );
    let current = resolve_reference(root, Some(&reader)).unwrap();
    assert_eq!(
        current
            .as_dict()
            .unwrap()
            .get(b"ReferenceRevisionMarker")
            .unwrap(),
        &Object::Integer(42)
    );
}

#[test]
fn bound_encrypted_stream_requires_the_existing_authentication() {
    let reader = read(&input("minimal-aes256.pdf"));
    let (_, page) = first_page(&reader);
    let Object::Reference(contents) = page.get(b"Contents").unwrap() else {
        panic!("fixture must use an indirect page content stream");
    };
    assert!(matches!(
        resolve_reference(*contents, Some(&reader)),
        Err(PdfError::KeyNotAvailable(_))
    ));
    assert_eq!(
        reader.decrypt("wrong-password").unwrap().status,
        AuthStatus::Failed
    );
    assert!(matches!(
        resolve_reference(*contents, Some(&reader)),
        Err(PdfError::KeyNotAvailable(_))
    ));
    assert_eq!(
        reader.decrypt("usersecret").unwrap().status,
        AuthStatus::User
    );
    let result = resolve_reference(*contents, Some(&reader)).unwrap();
    assert!(matches!(&result, Object::Stream(_)));
    assert_eq!(result, reader.get_object(*contents).unwrap());
}

struct CyclingHandler;

impl PdfHandler for CyclingHandler {
    fn get_object(&self, id: ObjectId) -> PdfResult<Object> {
        Ok(Object::Reference(if id == (1, 0) {
            (2, 0)
        } else {
            (1, 0)
        }))
    }

    fn trailer_view(&self) -> PdfResult<Dictionary> {
        Ok(Dictionary::new())
    }

    fn root_ref(&self) -> PdfResult<ObjectId> {
        Ok((1, 0))
    }
}

#[test]
fn cyclic_bound_references_retain_the_chain_limit_error() {
    assert_eq!(
        resolve_reference((1, 0), Some(&CyclingHandler)),
        Err(PdfError::Read("Reference chain too long".into()))
    );
}
