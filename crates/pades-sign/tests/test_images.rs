//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_images.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use lopdf::{Dictionary, Object};
use sigis_pades_sign::content::{
    find_page_for_modification, ContentWriter, PageResources, PdfContent,
};
use sigis_pades_sign::images::{pil_image, Image, PdfImage};
use sigis_pades_sign::pdf::writer::PdfUpdate;
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
                w.get_dict_mut(rid)
                    .unwrap()
                    .set("XObject", Object::Dictionary(xobjs));
            }
            PageResources::Direct(mut d) => {
                d.set("XObject", Object::Dictionary(xobjs));
                w.get_dict_mut(page)
                    .unwrap()
                    .set("Resources", Object::Dictionary(d));
            }
        }
        let cref = w
            .get_dict(page)
            .unwrap()
            .get(b"Contents")
            .unwrap()
            .as_reference()
            .unwrap();
        let Object::Stream(cs) = w.get_mut(cref).unwrap() else {
            panic!("contents")
        };
        let mut data = cs
            .decompressed_content()
            .unwrap_or_else(|_| cs.content.clone());
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

/// Preserve Pillow's mode checks before converting pixels to 8-bit data.
#[test]
fn png_modes_match_pillow_rejections() {
    let cases = [
        (png::ColorType::Grayscale, png::BitDepth::One, false),
        (png::ColorType::Grayscale, png::BitDepth::Two, true),
        (png::ColorType::Grayscale, png::BitDepth::Four, true),
        (png::ColorType::Grayscale, png::BitDepth::Eight, true),
        (png::ColorType::Grayscale, png::BitDepth::Sixteen, false),
        (png::ColorType::Rgb, png::BitDepth::Sixteen, true),
        (png::ColorType::Rgba, png::BitDepth::Sixteen, true),
        (png::ColorType::Indexed, png::BitDepth::One, true),
    ];
    let mut paths = Vec::new();
    for (color, depth, accepted) in cases {
        let mut encoded = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut encoded, 1, 1);
            encoder.set_color(color);
            encoder.set_depth(depth);
            if color == png::ColorType::Indexed {
                encoder.set_palette(vec![0, 0, 0, 255, 255, 255]);
            }
            let mut writer = encoder.write_header().unwrap();
            let row_bytes = (color.samples() * depth as usize).div_ceil(8);
            writer.write_image_data(&vec![0; row_bytes]).unwrap();
        }
        let result = Image::decode(&encoded);
        assert_eq!(result.is_ok(), accepted, "{color:?}/{depth:?}: {result:?}");
        if !accepted {
            assert!(matches!(
                result,
                Err(sigis_pki_core::errors::HankoError::Unsupported(_))
            ));
        }
        paths.push(temp_file("image-mode.png", &encoded));
    }
    let args: Vec<&str> = paths.iter().map(|p| path_str(p)).collect();
    if let Some(verdicts) = oracle("image_modes.py", &args) {
        let verdicts = verdicts.as_array().unwrap();
        assert_eq!(verdicts.len(), cases.len());
        for ((color, depth, accepted), verdict) in cases.into_iter().zip(verdicts) {
            assert_eq!(
                verdict["accepted"], accepted,
                "{color:?}/{depth:?}: {verdict}"
            );
        }
    }
}
