// Exact test_trailer_refs assertion and substantive container controls from
// pyHanko 0.38.1 test_xref.py (MIT, see LICENSE-pyHanko).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{first_page, read};
use sha2::{Digest, Sha256};
use sigis_pdf::crypt::api::AuthStatus;
use sigis_pdf::lopdf::{Dictionary, Object, ObjectId};
use sigis_pdf::writer::{ContainedObject, ContainerReference};
use sigis_pdf::{IncrementalWriter, PdfError, PdfFile, PdfFileWriter, PdfHandler, PdfHandlerExt};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").unwrap();
    }
    value
}

fn input(name: &str) -> Vec<u8> {
    let path = sigis_testdata::path(&["pyhanko", "pdf", name]);
    let bytes = std::fs::read(&path).unwrap();
    println!(
        "TRAILER_INPUT path={} length={} sha256={}",
        path.display(),
        bytes.len(),
        hex(&Sha256::digest(&bytes))
    );
    bytes
}

fn pages_id(reader: &PdfFile) -> ObjectId {
    reader
        .root()
        .unwrap()
        .get(b"Pages")
        .unwrap()
        .as_reference()
        .unwrap()
}

fn seed() -> (Vec<u8>, ObjectId) {
    let source = read(&input("minimal.pdf"));
    let id = pages_id(&source);
    let mut pages = source.get_object(id).unwrap().as_dict().unwrap().clone();
    let mut nested = Dictionary::new();
    nested.set("Leaf", Object::Integer(1));
    pages.set("EditNode", Object::Dictionary(nested));
    pages.set("ForeignMarker", Object::Integer(91));
    let mut writer = IncrementalWriter::new(source);
    writer.update_object(id, Object::Dictionary(pages));
    (writer.write().unwrap(), id)
}

fn emit(case: &str, input: &[u8], output: &[u8], source: Option<&[u8]>) {
    println!(
        "TRAILER_CASE case={case} input_hex={} output_hex={} source_hex={} input_sha256={} output_sha256={}",
        hex(input),
        hex(output),
        source.map(hex).unwrap_or_else(|| "-".into()),
        hex(&Sha256::digest(input)),
        hex(&Sha256::digest(output)),
    );
}

#[test]
fn test_trailer_refs() {
    let bytes = input("minimal.pdf");
    let reader = read(&bytes);
    let root = reader.root_ref().unwrap();
    let mut writer = IncrementalWriter::new(reader);
    let raw_root = writer.raw_trailer_object(b"Root").unwrap();
    let Some(ContainerReference::Trailer(container)) = raw_root.container_ref() else {
        panic!("raw Root token must be contained in the trailer, not the catalog");
    };
    assert_eq!(container.source().bytes(), bytes);
    assert_eq!(
        container.get_object().raw_get(b"Root", None),
        Some(Object::Reference(root))
    );
    assert_eq!(raw_root.value().unwrap(), &Object::Reference(root));
    writer.update_container(&raw_root).unwrap();
    assert!(writer.objects().is_empty());
    let output = writer.write().unwrap();
    assert_eq!(output, bytes);
    emit("trailer_noop", &bytes, &output, None);
}

#[test]
fn numbered_reference_marks_its_container_not_the_referent() {
    let bytes = input("minimal.pdf");
    let reader = read(&bytes);
    let pages = pages_id(&reader);
    let raw = ContainedObject::from_reader(&reader, pages)
        .unwrap()
        .raw_get(b"Kids")
        .unwrap()
        .raw_item(0)
        .unwrap();
    let referent = raw.value().unwrap().as_reference().unwrap();
    assert_ne!(referent, pages);
    assert!(
        matches!(raw.container_ref(), Some(ContainerReference::Indirect { object_id, .. }) if object_id == pages)
    );
    let mut writer = IncrementalWriter::new(reader);
    writer.update_container(&raw).unwrap();
    assert!(writer.objects().contains_key(&(pages.1, pages.0)));
    assert!(!writer.objects().contains_key(&(referent.1, referent.0)));
    let output = writer.write().unwrap();
    assert_eq!(read(&output).xrefs().sections().len(), 2);
    emit("numbered_reference", &bytes, &output, None);
}

#[test]
fn replacing_a_nested_leaf_commits_the_complete_numbered_container() {
    let (bytes, pages) = seed();
    let reader = read(&bytes);
    let mut leaf = ContainedObject::from_reader(&reader, pages)
        .unwrap()
        .raw_get(b"EditNode")
        .unwrap()
        .raw_get(b"Leaf")
        .unwrap();
    assert_eq!(leaf.value().unwrap(), &Object::Integer(1));
    leaf.replace_value(Object::Integer(2)).unwrap();
    let mut writer = IncrementalWriter::new(reader);
    writer.update_container(&leaf).unwrap();
    let output = writer.write().unwrap();
    let reopened = read(&output);
    let pages = reopened.get_object(pages).unwrap();
    let pages = pages.as_dict().unwrap();
    assert_eq!(pages.get(b"ForeignMarker").unwrap(), &Object::Integer(91));
    assert_eq!(
        pages
            .get(b"EditNode")
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"Leaf")
            .unwrap(),
        &Object::Integer(2)
    );
    assert_eq!(reopened.xrefs().sections().len(), 3);
    emit("nested_mutation", &bytes, &output, None);
}

#[test]
fn detached_mutation_without_update_does_not_persist() {
    let (bytes, pages) = seed();
    let reader = read(&bytes);
    let mut leaf = ContainedObject::from_reader(&reader, pages)
        .unwrap()
        .raw_get(b"EditNode")
        .unwrap()
        .raw_get(b"Leaf")
        .unwrap();
    leaf.replace_value(Object::Integer(2)).unwrap();
    let mut writer = IncrementalWriter::new(reader);
    let output = writer.write().unwrap();
    assert_eq!(output, bytes);
    emit("without_update", &bytes, &output, None);
}

#[test]
fn foreign_numbered_container_uses_its_actual_source_snapshot() {
    let bytes = input("minimal.pdf");
    let (foreign, pages) = seed();
    let source = read(&foreign);
    let raw = ContainedObject::from_reader(&source, pages)
        .unwrap()
        .raw_get(b"ForeignMarker")
        .unwrap();
    let Some(ContainerReference::Indirect { source, .. }) = raw.container_ref() else {
        panic!("numbered provenance must retain its actual reader");
    };
    assert_eq!(source.bytes(), foreign);
    let mut writer = IncrementalWriter::new(read(&bytes));
    writer.update_container(&raw).unwrap();
    let output = writer.write().unwrap();
    assert_eq!(
        read(&output)
            .get_object(pages)
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"ForeignMarker")
            .unwrap(),
        &Object::Integer(91)
    );
    emit("foreign_container", &bytes, &output, Some(&foreign));
}

#[test]
fn no_provenance_and_fresh_writer_keep_their_real_noop_branches() {
    let bytes = input("minimal.pdf");
    let reader = read(&bytes);
    let detached = ContainedObject::new(Object::Integer(37));
    assert!(detached.container_ref().is_none());
    let mut writer = IncrementalWriter::new(reader.clone());
    writer.update_container(&detached).unwrap();
    assert!(writer.objects().is_empty());
    let id = writer
        .add_object(detached.value().unwrap().clone())
        .unwrap();
    writer.update_container(&detached).unwrap();
    assert_eq!(writer.objects().len(), 1);
    let output = writer.write().unwrap();
    assert_eq!(read(&output).get_object(id).unwrap(), Object::Integer(37));
    let numbered = ContainedObject::from_reader(&reader, pages_id(&reader)).unwrap();
    let mut fresh = PdfFileWriter::new(false, true).unwrap();
    let original = fresh.objects().clone();
    fresh.update_container(&numbered).unwrap();
    assert_eq!(fresh.objects(), &original);
    emit("uncontained", &bytes, &output, None);
}

#[test]
fn provenance_does_not_bypass_reader_errors_or_forge_live_trailer_mutation() {
    let reader = read(&input("minimal.pdf"));
    let writer = IncrementalWriter::new(reader.clone());
    assert!(matches!(
        writer.raw_trailer_object(b"Absent"),
        Err(PdfError::Value(_))
    ));
    let mut trailer = writer.raw_trailer_object(b"Root").unwrap();
    assert!(matches!(
        trailer.replace_value(Object::Null),
        Err(PdfError::Value(_))
    ));
    assert!(matches!(
        ContainedObject::from_reader(&reader, (9999, 0)),
        Err(PdfError::StrictRead(_))
    ));
    let pages = ContainedObject::from_reader(&reader, pages_id(&reader)).unwrap();
    assert!(matches!(pages.raw_get(b"Absent"), Err(PdfError::Value(_))));
    assert!(matches!(
        pages.raw_get(b"Kids").unwrap().raw_item(99),
        Err(PdfError::Value(_))
    ));

    let encrypted = read(&input("minimal-aes256.pdf"));
    let (_, page) = first_page(&encrypted);
    let contents = page.get(b"Contents").unwrap().as_reference().unwrap();
    assert!(matches!(
        ContainedObject::from_reader(&encrypted, contents),
        Err(PdfError::KeyNotAvailable(_))
    ));
    assert_eq!(
        encrypted.decrypt("wrong-password").unwrap().status,
        AuthStatus::Failed
    );
    assert!(matches!(
        ContainedObject::from_reader(&encrypted, contents),
        Err(PdfError::KeyNotAvailable(_))
    ));
    assert_eq!(
        encrypted.decrypt("usersecret").unwrap().status,
        AuthStatus::User
    );
    let decrypted = ContainedObject::from_reader(&encrypted, contents).unwrap();
    assert!(matches!(decrypted.value().unwrap(), Object::Stream(_)));
}
