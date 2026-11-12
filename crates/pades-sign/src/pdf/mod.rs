//! PDF-level signing (`pyhanko.sign.signers.pdf_signer`, `pyhanko.sign.fields`).

pub mod dss;
pub mod embedded;
pub mod fields;
pub mod seed;
pub mod signer;
pub mod timestamp;
pub mod util;
pub mod writer;

use lopdf::{Dictionary, Object, Stream};

/// A form XObject with a `/BBox` of `w` x `h` (`RawContent.as_form_xobject`).
pub fn util_form_xobject(content: Vec<u8>, w: f64, h: f64) -> Object {
    let mut d = Dictionary::new();
    d.set("Type", util::name("XObject"));
    d.set("Subtype", util::name("Form"));
    d.set(
        "BBox",
        Object::Array(vec![
            util::number(0.0),
            util::number(0.0),
            util::number(w),
            util::number(h),
        ]),
    );
    d.set("Resources", Object::Dictionary(Dictionary::new()));
    Object::Stream(Stream::new(d, content))
}
