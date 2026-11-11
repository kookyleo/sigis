// Test helpers mirroring pyhanko_testing_commons.test_data.samples
// (MIT, see LICENSE-pyHanko).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pdf::generic::decode_text;
use sigis_pdf::lopdf::{Dictionary, Object};
use sigis_pdf::{PdfError, PdfFile, PdfHandler, PdfHandlerExt, ReaderOptions};

/// Bytes of a pyHanko test PDF (`PDF_DATA_DIR/name`).
pub fn pdf(name: &str) -> Vec<u8> {
    sigis_testdata::read(&["pyhanko", "pdf", name])
}

pub fn minimal() -> Vec<u8> {
    pdf("minimal.pdf")
}

pub fn read(data: &[u8]) -> PdfFile {
    PdfFile::parse_with(data, ReaderOptions::default()).unwrap()
}

pub fn read_lenient(data: &[u8]) -> PdfFile {
    PdfFile::parse_with(data, ReaderOptions::lenient()).unwrap()
}

pub fn try_read(data: &[u8], strict: bool) -> Result<PdfFile, PdfError> {
    let opts = if strict {
        ReaderOptions::default()
    } else {
        ReaderOptions::lenient()
    };
    PdfFile::parse_with(data, opts)
}

/// Assert that `res` is an error whose message matches `pattern` (a simple
/// regex subset: `.*` wildcards only, as used in the pyHanko tests).
#[track_caller]
pub fn assert_err_matches<T: std::fmt::Debug>(res: Result<T, PdfError>, pattern: &str) -> PdfError {
    match res {
        Ok(v) => panic!("expected error matching {pattern:?}, got Ok({v:?})"),
        Err(e) => {
            assert!(
                search(pattern, e.message()),
                "error {e:?} does not match {pattern:?}"
            );
            e
        }
    }
}

/// `re.search` for patterns that only use `.*` and literal text.
pub fn search(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split(".*").collect();
    let mut pos = 0;
    for (i, p) in parts.iter().enumerate() {
        let p = p.replace('\\', "");
        match text[pos..].find(&p) {
            Some(ix) => pos += ix + p.len(),
            None => return false,
        }
        let _ = i;
    }
    true
}

pub fn as_dict(o: Object) -> Dictionary {
    match o {
        Object::Dictionary(d) => d,
        Object::Stream(s) => s.dict,
        other => panic!("not a dictionary: {other:?}"),
    }
}

pub fn text(o: &Object) -> String {
    match o {
        Object::String(s, _) => decode_text(s).expect("text string"),
        other => panic!("not a string: {other:?}"),
    }
}

/// `handler.get(d, key)` unwrapped.
pub fn get(h: &dyn PdfHandler, d: &Dictionary, key: &str) -> Object {
    h.get(d, key.as_bytes())
        .unwrap()
        .unwrap_or_else(|| panic!("missing {key}"))
}

/// `fmt_dummy_xrefs` from test_xref.py.
pub fn fmt_dummy_xrefs(xrefs: &[&[&[u8]]], sep: &[u8], manual_size: Option<usize>) -> Vec<u8> {
    let dummy_hdr: &[u8] = b"%PDF-1.7\n%owqi";
    let mut parts: Vec<Vec<u8>> = vec![dummy_hdr.to_vec()];
    let mut offset = dummy_hdr.len() + 1;
    let init = xrefs[0];
    let sz = manual_size.unwrap_or(init.len());
    let join = |entries: &[&[u8]]| entries.join(sep);
    let mut section = b"xref\n".to_vec();
    section.extend(join(init));
    section.extend_from_slice(sep);
    section.extend_from_slice(format!("trailer<</Size {sz}>>").as_bytes());
    let mut startxref = offset;
    offset += section.len() + 1;
    parts.push(section);
    for s in &xrefs[1..] {
        let mut section = b"xref\n".to_vec();
        section.extend(join(s));
        section.extend_from_slice(sep);
        section.extend_from_slice(format!("trailer<</Prev {startxref}/Size {sz}>>").as_bytes());
        startxref = offset;
        offset += section.len() + 1;
        parts.push(section);
    }
    parts.push(format!("startxref\n{startxref}").into_bytes());
    parts.push(b"%%EOF".to_vec());
    parts.join(&b"\n"[..])
}

/// The first page of a document, as (reference, dictionary).
pub fn first_page(h: &dyn PdfHandler) -> (sigis_pdf::lopdf::ObjectId, Dictionary) {
    let root = h.root().unwrap();
    let pages = as_dict(get(h, &root, "Pages"));
    let kids = match pages.get(b"Kids").unwrap() {
        Object::Array(a) => a.clone(),
        Object::Reference(r) => match h.get_object(*r).unwrap() {
            Object::Array(a) => a,
            _ => panic!(),
        },
        _ => panic!(),
    };
    let Object::Reference(r) = kids[0] else {
        panic!()
    };
    (r, as_dict(h.get_object(r).unwrap()))
}

pub mod crypt;
