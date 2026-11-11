// Sigis-specific tests of the lane interface (`docs/hanko-lanes.md` §4):
// revisions, historical objects, signature and DSS discovery, incremental
// writing. Not derived from a pyHanko test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use hanko_pdf::lopdf::Object;
use hanko_pdf::{IncrementalWriter, PdfFile, PdfHandler, SignatureKind};

#[test]
fn signed_twice_signatures_and_revisions() {
    let data = pdf("minimal-signed-twice-both-created.pdf");
    let f = PdfFile::parse(&data).unwrap();
    let revs = f.revisions().unwrap();
    assert!(revs.len() >= 3, "{revs:?}");
    assert_eq!(revs.last().unwrap().end_offset, data.len());
    let sigs = f.embedded_signatures().unwrap();
    assert_eq!(sigs.len(), 2);
    assert!(sigs[0].signed_revision < sigs[1].signed_revision);
    for s in &sigs {
        assert_eq!(s.kind, SignatureKind::Signature);
        let signed = s.signed_data(&f).unwrap();
        let br = s.byte_range;
        assert_eq!(signed.len() as u64, br[1] + br[3]);
        // the gap holds exactly the hex-encoded /Contents
        assert_eq!(data[br[1] as usize], b'<');
        assert_eq!(data[(br[2] - 1) as usize], b'>');
        assert_eq!(s.contents[0], 0x30);
        // the signature dictionary is present in its signed revision
        let sig = f.object_in_revision(s.sig_object, s.signed_revision).unwrap();
        assert!(matches!(sig, Some(Object::Dictionary(_))));
        assert!(f.objects_written_in(s.signed_revision).unwrap().contains(&s.sig_object));
        // but not in the original document
        assert_eq!(f.object_in_revision(s.sig_object, 0).unwrap(), None);
        // signed revisions end where the byte range ends
        assert_eq!(revs[s.signed_revision].end_offset as u64, br[2] + br[3]);
    }
    let t0 = f.trailer_in_revision(0).unwrap();
    assert!(t0.has(b"Root"));
}

#[test]
fn dss_with_indirect_arrays() {
    let f = PdfFile::parse(&pdf("pades-lta-dss-indirect-arrs-test.pdf")).unwrap();
    let dss = f.dss().unwrap().expect("DSS present");
    assert!(!dss.material.certs.is_empty());
    for c in &dss.material.certs {
        assert_eq!(c[0], 0x30);
    }
    let sigs = f.embedded_signatures().unwrap();
    assert!(sigs.iter().any(|s| s.kind == SignatureKind::DocTimeStamp));
}

#[test]
fn no_dss_in_plain_file() {
    let f = PdfFile::parse(&minimal()).unwrap();
    assert_eq!(f.dss().unwrap(), None);
    assert!(f.embedded_signatures().unwrap().is_empty());
}

#[test]
fn incremental_writer_interface() {
    let base = PdfFile::parse(&minimal()).unwrap();
    let mut w = IncrementalWriter::new(base.clone());
    // no changes: output is the input
    assert_eq!(w.write().unwrap(), minimal());
    let id = w.allocate().unwrap();
    w.put(id, hanko_pdf::generic::text_string("hello"));
    let out = w.write().unwrap();
    assert!(out.starts_with(&minimal()));
    let f = PdfFile::parse(&out).unwrap();
    assert_eq!(f.total_revisions(), 2);
    assert!(f.objects_written_in(1).unwrap().contains(&id));
    assert_eq!(text(&f.get_object(id).unwrap()), "hello");
    assert_eq!(w.base().bytes(), base.bytes());
}


#[test]
fn lane_c_and_e_requests() {
    let data = pdf("minimal-signed-twice-both-created.pdf");
    let f = PdfFile::parse(&data).unwrap();
    for s in f.embedded_signatures().unwrap() {
        let rev = s.signed_revision;
        assert_eq!(f.last_change(s.sig_object).unwrap(), Some(rev));
        assert_eq!(f.introducing_revision(s.sig_object).unwrap(), Some(rev));
        assert!(f.resolves_in(s.sig_object, rev).unwrap());
        assert!(!f.resolves_in(s.sig_object, 0).unwrap());
        let x = f.xref_section(rev).unwrap();
        assert!(x.explicit_refs.contains(&s.sig_object));
        assert!(x.stream_ref.is_some());
        let loc = f.xref_location(rev).unwrap();
        assert!(loc.start <= loc.end && loc.end <= data.len() as u64);
        let field = f.signature_field_ref(s.sig_object).unwrap().expect("field");
        let Object::Dictionary(fd) = f.get_object(field).unwrap() else { panic!() };
        assert_eq!(fd.get(b"V").unwrap(), &Object::Reference(s.sig_object));
    }
    // own trailer vs effective trailer
    let r = PdfFile::parse(&pdf("minimal-with-field.pdf")).unwrap();
    let own = r.trailer_in_revision(1).unwrap();
    assert!(own.has(b"Prev"));
    let eff = r.effective_trailer_in_revision(1).unwrap();
    assert!(eff.has(b"Root"));
    assert!(r.trailer_in_revision(2).is_err());
}

#[test]
fn lead_round1_b2_fields() {
    let data = pdf("minimal-signed-twice-both-created.pdf");
    let f = PdfFile::parse(&data).unwrap();
    let revs = f.revisions().unwrap();
    for (ix, r) in revs.iter().enumerate() {
        let loc = f.xref_location(ix).unwrap();
        assert_eq!(r.startxref, loc.declared_startxref);
        assert_eq!(r.xref_end, loc.end);
    }
    for s in f.embedded_signatures().unwrap() {
        assert_eq!(Some(s.field_object), f.signature_field_ref(s.sig_object).unwrap());
    }
}

#[test]
fn lead_round1_b4_spans_and_plain_signature_contents() {
    use hanko_pdf::lopdf::{Dictionary, StringFormat};
    let mut w = hanko_pdf::writer::copy_into_new_writer(&PdfFile::parse(&minimal()).unwrap()).unwrap();
    w.encrypt("secret", None).unwrap();
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"Sig".to_vec()));
    sig.set("ByteRange", Object::Array(vec![0.into(), 0.into(), 0.into(), 0.into()]));
    sig.set("Contents", Object::String(vec![0u8; 16], StringFormat::Hexadecimal));
    sig.set("Name", hanko_pdf::generic::text_string("signer"));
    let id = w.add_object(Object::Dictionary(sig)).unwrap();
    let out = w.write().unwrap();
    let span = w.written_object_spans().get(&id).cloned().expect("span");
    let body = &out[span];
    let needle = b"/Contents <00000000000000000000000000000000>";
    assert!(body.windows(needle.len()).any(|x| x == needle), "{}", String::from_utf8_lossy(body));
    // other strings are still encrypted
    assert!(!body.windows(6).any(|x| x == b"signer"));
    let r = PdfFile::parse(&out).unwrap();
    r.decrypt("secret").unwrap();
    let Object::Dictionary(d) = r.get_object(id).unwrap() else { panic!() };
    assert_eq!(d.get(b"Contents").unwrap(), &Object::String(vec![0u8; 16], StringFormat::Hexadecimal));
    assert_eq!(text(d.get(b"Name").unwrap()), "signer");
}
