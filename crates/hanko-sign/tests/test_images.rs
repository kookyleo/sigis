//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_images.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use sigis_pades_sign::content::{find_page_for_modification, ContentWriter, PageResources, PdfContent};
use sigis_pades_sign::images::{pil_image, Image, PdfImage};
use sigis_pades_sign::pdf::writer::PdfUpdate;
use lopdf::{Dictionary, Object};
use support::*;

const IMAGES: [&str; 2] = ["stamp.png", "stamp-indexed.png"];

#[test]
fn test_image_direct_embed() {
    for infile in IMAGES {
        let img = Image::open(data_path(&["pyhanko", "img", infile])).unwrap();
        let base = pdf("minimal.pdf");
        let mut w = PdfUpdate::new(&base).unwrap();
        let image_ref = pil_image(&img, &mut w).unwrap();
        let (page, resources) = find_page_for_modification(&w, 0).unwrap();
        let mut xobjs = Dictionary::new();
        xobjs.set("Img", Object::Reference(image_ref));
        match resources {
            PageResources::Indirect(rid) => {
                w.get_dict_mut(rid).unwrap().set("XObject", Object::Dictionary(xobjs));
            }
            PageResources::Direct(mut d) => {
                d.set("XObject", Object::Dictionary(xobjs));
                w.get_dict_mut(page).unwrap().set("Resources", Object::Dictionary(d));
            }
        }
        let cref = w.get_dict(page).unwrap().get(b"Contents").unwrap().as_reference().unwrap();
        let Object::Stream(cs) = w.get_mut(cref).unwrap() else { panic!("contents") };
        let mut data = cs.decompressed_content().unwrap_or_else(|_| cs.content.clone());
        data.extend_from_slice(b" q 50 0 0 50 5 5 cm /Img Do Q");
        cs.dict.remove(b"Filter");
        cs.set_plain_content(data);
        let (out, _) = w.write().unwrap();
        let doc = lopdf::Document::load_mem(&out).unwrap();
        let image_obj = doc.get_object(image_ref).unwrap().as_stream().unwrap();
        if infile.contains("indexed") {
            assert!(image_obj.dict.get(b"SMask").is_err());
        } else {
            assert!(image_obj.dict.get(b"SMask").is_ok());
        }
    }
}

#[test]
fn test_image_content_embed() {
    for infile in IMAGES {
        let base = pdf("minimal.pdf");
        let mut update = PdfUpdate::new(&base).unwrap();
        let mut w = ContentWriter::new(&mut update);
        let img = Image::open(data_path(&["pyhanko", "img", infile])).unwrap();
        let mut content = PdfImage::new(img, None, Some(0.6), None);
        content.add_to_page(&mut w, 0, true).unwrap();
        let out = w.write().unwrap();
        lopdf::Document::load_mem(&out).unwrap();
    }
}
