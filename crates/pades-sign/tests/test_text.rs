//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_text.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use lopdf::{dictionary, Object, Stream};
use sigis_pades_sign::content::{add_stream_to_page, ContentWriter, PdfContent, ResourceType};
use sigis_pades_sign::font::{
    FontEngineFactory, FontHandle, GlyphAccumulator, GlyphAccumulatorFactory,
    GlyphAccumulatorOptions,
};
use sigis_pades_sign::form_tools::{is_form_filling_error, populate_static_text_field};
use sigis_pades_sign::layout::{AxisAlignment, BoxConstraints, SimpleBoxLayoutRule};
use sigis_pades_sign::pdf::writer::PdfUpdate;
use sigis_pades_sign::text::{TextBox, TextBoxStyle};
use support::layout::compare_output;
use support::*;

fn noto_serif_jp() -> std::path::PathBuf {
    data_path(&["pyhanko", "fonts", "NotoSerifJP-Regular.otf"])
}

fn font_bytes(name: &str) -> Arc<Vec<u8>> {
    Arc::new(pyhanko_data(&["fonts", name]))
}

fn minimal() -> Vec<u8> {
    pdf("minimal.pdf")
}

fn ga<'w>(w: &'w mut ContentWriter<'_>, h: FontHandle) -> &'w mut GlyphAccumulator {
    w.font(h)
        .unwrap()
        .as_any_mut()
        .downcast_mut::<GlyphAccumulator>()
        .unwrap()
}

fn load_ga(w: &mut ContentWriter<'_>, name: &str, opts: &GlyphAccumulatorOptions) -> FontHandle {
    GlyphAccumulator::load(w, font_bytes(name), 10.0, opts).unwrap()
}

#[test]
fn test_simple_textbox_render() {
    for (with_border, natural_size) in [(true, true), (false, false), (true, false)] {
        let base = minimal();
        let mut update = PdfUpdate::new(&base).unwrap();
        let mut w = ContentWriter::new(&mut update);
        let tbs = TextBoxStyle {
            border_width: if with_border { 1.0 } else { 0.0 },
            ..TextBoxStyle::default()
        };
        let bc = (!natural_size).then(|| BoxConstraints::fixed(1600.0, 900.0));
        let mut tb = TextBox::new(tbs, &mut w, bc).unwrap();
        tb.set_content(
            &mut w,
            "This is a textbox with some text.\nAnd multiple lines",
        )
        .unwrap();
        let xobj = tb.as_form_xobject(&mut w).unwrap();
        let bbox: Vec<f64> = xobj
            .dict
            .get(b"BBox")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|o| sigis_pades_sign::pdf::util::as_number(o).unwrap())
            .collect();
        assert!(tb.resources().contains(ResourceType::Font, "F1"));
        if !natural_size {
            assert_eq!((bbox[0] - bbox[2]).abs(), 1600.0);
            assert_eq!((bbox[1] - bbox[3]).abs(), 900.0);
        }
    }
}

#[test]
fn test_simple_textbox_color() {
    let base = minimal();
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let tbs = TextBoxStyle {
        text_color: Some([0.5, 0.5, 0.5]),
        ..TextBoxStyle::default()
    };
    let mut tb = TextBox::new(tbs, &mut w, None).unwrap();
    tb.set_content(
        &mut w,
        "This is a textbox with some text.\nAnd multiple lines",
    )
    .unwrap();
    let cs = tb.render(&mut w).unwrap();
    assert!(String::from_utf8_lossy(&cs).contains("0.5 0.5 0.5 rg"));
}

#[test]
fn test_multiline_textbox_no_drift_with_nondefault_font_size() {
    let style = TextBoxStyle {
        font: FontEngineFactory::OpenType(GlyphAccumulatorFactory::new(noto_serif_jp())),
        font_size: 8.0,
        ..TextBoxStyle::default()
    };
    let base = minimal();
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let mut tb = TextBox::new(style.clone(), &mut w, None).unwrap();
    // the engine's font size must match the style's after construction
    assert_eq!(
        w.font(tb.font_engine()).unwrap().font_size(),
        style.font_size
    );
    tb.set_content(&mut w, "Line one\nLine two").unwrap();
    let content = String::from_utf8_lossy(&tb.render(&mut w).unwrap()).into_owned();
    let toks: Vec<&str> = content.split_whitespace().collect();
    let mut x_running = 0.0;
    for (i, t) in toks.iter().enumerate() {
        if *t == "Td" && i >= 2 {
            if let (Ok(x), Ok(_)) = (toks[i - 2].parse::<f64>(), toks[i - 1].parse::<f64>()) {
                x_running += x;
            }
        }
    }
    assert!(x_running.abs() < 1e-6, "Drift! {x_running}");
}

fn font_object(doc: &lopdf::Document, id: lopdf::ObjectId) -> lopdf::Dictionary {
    doc.get_dictionary(id).unwrap().clone()
}

fn stream_data(doc: &lopdf::Document, o: &Object) -> Vec<u8> {
    let s = doc
        .get_object(o.as_reference().unwrap())
        .unwrap()
        .as_stream()
        .unwrap();
    s.decompressed_content()
        .unwrap_or_else(|_| s.content.clone())
}

#[test]
fn test_embed_subset() {
    let base = minimal();
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let h = load_ga(&mut w, "NotoSerifJP-Regular.otf", &Default::default());
    let res = ga(&mut w, h).shape_text("版", true).unwrap();
    assert!(String::from_utf8_lossy(&res.graphics_ops).contains("[<66eb>] TJ"));
    let res = ga(&mut w, h).shape_text("テスト", true).unwrap();
    assert!(String::from_utf8_lossy(&res.graphics_ops).contains("[<0637> 40 <062a0639>] TJ"));
    // check the 'ffi' ligature
    let res = ga(&mut w, h).shape_text("difficult", true).unwrap();
    assert!(
        String::from_utf8_lossy(&res.graphics_ops).contains("[<0045004ae9e200440056004d0055>] TJ")
    );
    let font_ref = ga(&mut w, h).font_ref();
    let out = w.write().unwrap();
    let doc = lopdf::Document::load_mem(&out).unwrap();
    let font = font_object(&doc, font_ref);
    let df_ref = font.get(b"DescendantFonts").unwrap().as_array().unwrap()[0]
        .as_reference()
        .unwrap();
    let df = font_object(&doc, df_ref);
    let fd = font_object(
        &doc,
        df.get(b"FontDescriptor").unwrap().as_reference().unwrap(),
    );
    let font_file = stream_data(&doc, fd.get(b"FontFile3").unwrap());
    let tu = stream_data(&doc, font.get(b"ToUnicode").unwrap());
    let tu = String::from_utf8_lossy(&tu);
    // no ToUnicode assignment for 'f'
    assert!(!tu.contains("\n<0066>"));
    // a ToUnicode assignment for the 'ffi' ligature
    assert!(tu.contains("\n<e9e2> <006600660069>"), "{tu}");
    assert!(font_file.len() < 4000, "{}", font_file.len());
}

#[test]
fn test_actual_text_toggle() {
    let base = minimal();
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let h = load_ga(&mut w, "NotoSerifJP-Regular.otf", &Default::default());
    let res = String::from_utf8_lossy(
        &ga(&mut w, h)
            .shape_text("difficult", true)
            .unwrap()
            .graphics_ops,
    )
    .into_owned();
    assert!(res.contains("[<0045004ae9e200440056004d0055>] TJ"));
    assert!(res.contains("ActualText"));
    let res = String::from_utf8_lossy(
        &ga(&mut w, h)
            .shape_text("difficult", false)
            .unwrap()
            .graphics_ops,
    )
    .into_owned();
    assert!(res.contains("[<0045004ae9e200440056004d0055>] TJ"));
    assert!(!res.contains("ActualText"));
}

fn write_embedded_string(
    base: &[u8],
    obj_stream: bool,
) -> (Vec<u8>, lopdf::ObjectId, lopdf::ObjectId) {
    let mut update = PdfUpdate::new(base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let opts = GlyphAccumulatorOptions {
        obj_stream,
        ..Default::default()
    };
    let h = load_ga(&mut w, "NotoSerifJP-Regular.otf", &opts);
    // shape the string, just to register the glyphs as used
    ga(&mut w, h).shape_text("テスト", true).unwrap();
    let cid_hx = "0637062a0639";
    let font_ref = ga(&mut w, h).font_ref();
    let stream_ref = w.add(Object::Stream(Stream::new(
        dictionary! {},
        format!("BT /FEmb 18 Tf 0 100 Td <{cid_hx}> Tj ET").into_bytes(),
    )));
    let res = dictionary! { "Font" => dictionary! { "FEmb" => font_ref } };
    add_stream_to_page(w.update(), 0, stream_ref, Some(res), false).unwrap();
    let out = w.write().unwrap();
    (out, stream_ref, font_ref)
}

fn page_contents(doc: &lopdf::Document) -> Vec<lopdf::ObjectId> {
    let page = *doc.get_pages().values().next().unwrap();
    let pd = doc.get_dictionary(page).unwrap();
    let c = pd.get(b"Contents").unwrap();
    let arr = match c {
        Object::Reference(r) => doc.get_object(*r).unwrap().as_array().unwrap().clone(),
        Object::Array(a) => a.clone(),
        _ => panic!("contents"),
    };
    arr.iter().map(|o| o.as_reference().unwrap()).collect()
}

#[test]
fn test_write_embedded_string() {
    let (out, stream_ref, _) = write_embedded_string(&minimal(), false);
    let doc = lopdf::Document::load_mem(&out).unwrap();
    let conts = page_contents(&doc);
    assert_eq!(conts.len(), 2);
    assert!(conts.contains(&stream_ref));
}

#[test]
fn test_write_embedded_string_objstream() {
    let (out, stream_ref, font_ref) = write_embedded_string(&pdf("minimal-xref.pdf"), true);
    let doc = lopdf::Document::load_mem(&out).unwrap();
    let conts = page_contents(&doc);
    assert_eq!(conts.len(), 2);
    assert!(conts.contains(&stream_ref));
    assert!(matches!(
        doc.reference_table.get(font_ref.0),
        Some(lopdf::xref::XrefEntry::Compressed { .. })
    ));
    // the font can be read from the object stream
    let font = doc.get_dictionary(font_ref).unwrap();
    assert_eq!(font.get(b"Type").unwrap().as_name().unwrap(), b"Font");
}

#[test]
fn test_opentype_with_langsys() {
    let base = minimal();
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    // subset rigged for exactly this test
    let h1 = load_ga(&mut w, "NotoSerifSubset.otf", &Default::default());
    let opts = GlyphAccumulatorOptions {
        ot_language_tag: Some("ZHT ".into()),
        ot_script_tag: Some("hani".into()),
        ..Default::default()
    };
    let h2 = load_ga(&mut w, "NotoSerifSubset.otf", &opts);
    let r1 = ga(&mut w, h1).shape_text("骨", true).unwrap();
    let r2 = ga(&mut w, h2).shape_text("骨", true).unwrap();
    assert!(String::from_utf8_lossy(&r1.graphics_ops).contains("<b04c>"));
    assert!(String::from_utf8_lossy(&r2.graphics_ops).contains("<b04e>"));
}

fn ga_error(opts: GlyphAccumulatorOptions) -> String {
    let base = minimal();
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    GlyphAccumulator::load(&mut w, font_bytes("NotoSerifSubset.otf"), 10.0, &opts)
        .unwrap_err()
        .to_string()
}

#[test]
fn test_opentype_langsys_tag_too_long() {
    let e = ga_error(GlyphAccumulatorOptions {
        ot_language_tag: Some("ZHT a".into()),
        ot_script_tag: Some("hani".into()),
        ..Default::default()
    });
    assert!(e.contains("4 bytes long"), "{e}");
}

#[test]
fn test_opentype_langsys_tag_not_ascii() {
    let e = ga_error(GlyphAccumulatorOptions {
        ot_language_tag: Some("ZHTあ".into()),
        ot_script_tag: Some("hani".into()),
        ..Default::default()
    });
    assert!(e.contains("encodable"), "{e}");
}

#[test]
fn test_opentype_invalid_writing_direction() {
    let e = ga_error(GlyphAccumulatorOptions {
        writing_direction: Some("foobar".into()),
        ..Default::default()
    });
    assert!(e.contains("direction must be one of"), "{e}");
}

fn jp_style() -> TextBoxStyle {
    TextBoxStyle {
        font: FontEngineFactory::OpenType(GlyphAccumulatorFactory::new(noto_serif_jp())),
        ..TextBoxStyle::default()
    }
}

#[test]
fn test_fill_form_field() {
    let base = pdf("minimal-with-simple-form.pdf");
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let style = TextBoxStyle {
        box_layout_rule: Some(SimpleBoxLayoutRule::new(
            AxisAlignment::AlignMin,
            AxisAlignment::AlignMid,
        )),
        ..jp_style()
    };
    populate_static_text_field(&mut w, "TextField1", &style, "文字").unwrap();
    let out = w.write().unwrap();
    let doc = lopdf::Document::load_mem(&out).unwrap();
    let root = doc.catalog().unwrap();
    let form = match root.get(b"AcroForm").unwrap() {
        Object::Reference(r) => doc.get_dictionary(*r).unwrap(),
        Object::Dictionary(d) => d,
        _ => panic!(),
    };
    let field_ref = form.get(b"Fields").unwrap().as_array().unwrap()[1]
        .as_reference()
        .unwrap();
    let field = doc.get_dictionary(field_ref).unwrap();
    assert_eq!(field.get(b"FT").unwrap().as_name().unwrap(), b"Tx");
    assert!(field.get(b"DA").is_err());
    assert_eq!(field.get(b"Ff").unwrap().as_i64().unwrap() & 1, 1);
    compare_output(&out, "form-fill-result.pdf");
}

fn fill_err(base: &[u8], name: &str) -> sigis_pki_core::errors::HankoError {
    let mut update = PdfUpdate::new(base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    populate_static_text_field(&mut w, name, &jp_style(), "文字").unwrap_err()
}

#[test]
fn test_fill_form_field_error_on_nonexisting() {
    let e = fill_err(&pdf("minimal-with-simple-form.pdf"), "TextField2");
    assert!(is_form_filling_error(&e));
    assert!(e.to_string().contains("No empty text field"));
}

#[test]
fn test_fill_form_field_error_on_filled_field() {
    let e = fill_err(
        &pyhanko_data(&["pdf", "layout-tests", "form-fill-result.pdf"]),
        "TextField1",
    );
    assert!(is_form_filling_error(&e));
    assert!(e.to_string().contains("No empty text field"));
}

#[test]
fn test_fill_form_field_error_on_nonexisting_acro_form() {
    let e = fill_err(&minimal(), "TextField2");
    assert!(is_form_filling_error(&e));
    assert!(e.to_string().contains("No AcroForm present"));
}
