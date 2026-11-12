//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_stamp.py`.
//!
//! Layout comparisons render with `pdftoppm` and compare with ImageMagick
//! (`support::layout::compare_output`), as pyHanko does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;

use sigis_pades_sign::content::{Content, ContentWriter, ImportedPdfPage, RawContent};
use sigis_pades_sign::font::{FontEngineFactory, GlyphAccumulatorFactory};
use sigis_pades_sign::images::PdfImage;
use sigis_pades_sign::layout::{
    is_layout_error, AxisAlignment, BoxConstraints, Fraction, InnerScaling, Margins, SimpleBoxLayoutRule,
};
use sigis_pades_sign::pdf::writer::PdfUpdate;
use sigis_pades_sign::stamp::{
    qr_stamp_file, stamp_art_content, text_stamp_file, CoordinateSystem, QrPosition, QrStampStyle, Stamp,
    StampStyle, StaticStampStyle, TextStampStyle, STAMP_ART_DATA,
};
use sigis_pades_sign::text::TextBoxStyle;
use support::layout::{compare_output, empty_page, with_writer};
use support::*;

fn font(name: &str) -> std::path::PathBuf {
    data_path(&["pyhanko", "fonts", name])
}

const NOTO_SERIF_JP: &str = "NotoSerifJP-Regular.otf";
const NOTO_SANS_ARABIC: &str = "NotoSansArabic-Regular.ttf";
const NOTO_SANS: &str = "NotoSans-Regular.ttf";
const SOURCE_SERIF: &str = "SourceSerif4-Regular.otf";

fn minimal_path() -> std::path::PathBuf {
    data_path(&["pyhanko", "pdf", "minimal.pdf"])
}

fn out_path(name: &str) -> std::path::PathBuf {
    temp_file(name, b"")
}

fn gaf(name: &str) -> GlyphAccumulatorFactory {
    GlyphAccumulatorFactory::new(font(name))
}

fn tbs_font(f: GlyphAccumulatorFactory) -> TextBoxStyle {
    TextBoxStyle {
        font: FontEngineFactory::OpenType(f),
        ..TextBoxStyle::default()
    }
}

fn apply(w: &mut ContentWriter<'_>, stamp: &mut Stamp, x: f64, y: f64) {
    stamp.apply(w, 0, x, y, CoordinateSystem::PageDefault).unwrap();
}

#[test]
fn test_simple_text_stamp() {
    let out = out_path("test-out.pdf");
    text_stamp_file(minimal_path(), &out, &TextStampStyle::with_text("Hi, it's\n%(ts)s"), 0, 70.0, 50.0, None)
        .unwrap();
    assert!(std::fs::metadata(&out).unwrap().len() > 0);
}

#[test]
fn test_simple_text_stamp_missing_params() {
    let out = out_path("test-out.pdf");
    let e = text_stamp_file(minimal_path(), &out, &TextStampStyle::with_text("%(foo)s missing"), 0, 70.0, 50.0, None)
        .unwrap_err();
    assert!(is_layout_error(&e));
    assert!(e.to_string().contains("Stamp text parameter 'foo' is missing"), "{e}");
}

#[test]
fn test_simple_qr_stamp() {
    let out = out_path("test-out.pdf");
    qr_stamp_file(
        minimal_path(),
        &out,
        &QrStampStyle::with_text("Hi, it's\n%(ts)s"),
        0,
        70.0,
        50.0,
        "https://example.com",
        None,
    )
    .unwrap();
}

#[test]
fn test_simple_qr_noto_stamp() {
    let out = out_path("test-out.pdf");
    let mut style = QrStampStyle::with_text("Hi, it's\n%(ts)s");
    style.text.text_box_style = tbs_font(gaf(NOTO_SERIF_JP));
    qr_stamp_file(minimal_path(), &out, &style, 0, 70.0, 50.0, "https://example.com", None).unwrap();
}

#[test]
fn test_stamp_file_decode_limits() {
    // pyHanko passes DecodeLimits.for_trusted_input(); the port's reader
    // (lopdf) applies no decode limits.
    let infile = out_path("test-in.pdf");
    if oracle("oversized_objstm.py", &[path_str(&infile)]).is_none() {
        return;
    }
    let style = QrStampStyle::with_text("Hi");
    for qr in [false, true] {
        let outfile = out_path("test-out.pdf");
        if qr {
            qr_stamp_file(&infile, &outfile, &style, 0, 70.0, 50.0, "https://example.com", None).unwrap();
        } else {
            text_stamp_file(&infile, &outfile, &style.text, 0, 70.0, 50.0, None).unwrap();
        }
        assert!(std::fs::metadata(&outfile).unwrap().len() > std::fs::metadata(&infile).unwrap().len());
    }
}

fn arabic_style() -> TextStampStyle {
    TextStampStyle {
        stamp_text: "اَلْفُصْحَىٰ".into(),
        text_box_style: tbs_font(gaf(NOTO_SANS_ARABIC)),
        inner_content_layout: Some(
            SimpleBoxLayoutRule::new(AxisAlignment::AlignMid, AxisAlignment::AlignMid)
                .with_scaling(InnerScaling::StretchToFit)
                .with_margins(Margins::uniform(5.0)),
        ),
        ..TextStampStyle::default()
    }
}

fn arabic_text_page(w: &mut ContentWriter<'_>) {
    let mut ts = Stamp::text(arabic_style(), Some(BoxConstraints::fixed(300.0, 200.0)), None);
    apply(w, &mut ts, 10.0, 60.0);
}

#[test]
fn test_text_stamp_color() {
    let out = with_writer(&empty_page(false), |w| {
        let style = TextStampStyle {
            stamp_text: "some text".into(),
            text_box_style: TextBoxStyle {
                text_color: Some([0.5, 0.43, 0.1]),
                ..TextBoxStyle::default()
            },
            base: sigis_pades_sign::stamp::BaseStampStyle {
                border_color: Some([0.29, 0.404, 0.839]),
                ..Default::default()
            },
            ..TextStampStyle::default()
        };
        let mut ts = Stamp::text(style, None, None);
        apply(w, &mut ts, 10.0, 800.0);
    });
    compare_output(&out, "text-stamp-color.pdf");
}

#[test]
fn test_arabic_box() {
    let out = with_writer(&empty_page(false), arabic_text_page);
    compare_output(&out, "arabic-box.pdf");
}

#[test]
fn test_fonts_with_obj_streams() {
    let out = with_writer(&empty_page(true), arabic_text_page);
    compare_output(&out, "arabic-box.pdf");
    // objs_in_streams: the update section has compressed entries
    let doc = lopdf::Document::load_mem(&out).unwrap();
    let in_streams = doc
        .reference_table
        .entries
        .values()
        .any(|e| matches!(e, lopdf::xref::XrefEntry::Compressed { .. }));
    assert!(in_streams);
}

#[test]
fn test_font_rewrite_idempotent() {
    for stream_xrefs in [true, false] {
        let base = empty_page(stream_xrefs);
        let mut update = PdfUpdate::new(&base).unwrap();
        let mut w = ContentWriter::new(&mut update);
        arabic_text_page(&mut w);
        let out1 = w.write().unwrap();
        let out2 = w.write().unwrap();
        assert!(out1.len().abs_diff(out2.len()) < 100);
    }
}

fn four_qr_stamps(fixed_size: bool) {
    let gaf = gaf(NOTO_SANS).with_font_size(10.0);
    let positions = [(10.0, 700.0), (10.0, 500.0), (10.0, 10.0), (260.0, 10.0)];
    let out = with_writer(&empty_page(false), |w| {
        for (qr_pos, (x, y)) in QrPosition::ALL.into_iter().zip(positions) {
            let mut style = QrStampStyle::with_text("Test stamp text\nAnother line of text");
            style.text.text_box_style = tbs_font(gaf.clone());
            style.qr_position = qr_pos;
            style.text.base.background = Some(stamp_art_content());
            style.text.base.background_opacity = 0.4;
            let bbox = fixed_size.then(|| {
                if qr_pos.horizontal_flow() {
                    BoxConstraints::fixed(300.0, 100.0)
                } else {
                    BoxConstraints::fixed(100.0, 300.0)
                }
            });
            let mut ts = Stamp::qr(style, "https://example.com", bbox, None);
            apply(w, &mut ts, x, y);
        }
    });
    let postfix = if fixed_size { "fixed" } else { "natural" };
    compare_output(&out, &format!("four-stamps-{postfix}.pdf"));
}

#[test]
fn test_four_qr_stamps() {
    four_qr_stamps(true);
    four_qr_stamps(false);
}

#[test]
fn test_fancy_qr_stamp() {
    let out = with_writer(&empty_page(false), |w| {
        let mut style = QrStampStyle::with_text("Test stamp text\nAnother line of text");
        style.qr_inner_content = Some(stamp_art_content());
        let mut s = Stamp::qr(style, "https://example.com", Some(BoxConstraints::fixed(300.0, 100.0)), None);
        apply(w, &mut s, 10.0, 500.0);
    });
    compare_output(&out, "fancy-qr-stamp-test.pdf");
}

#[test]
fn test_japanese_vertical_text_stamp() {
    let mut gaf = gaf(NOTO_SERIF_JP).with_font_size(10.0);
    gaf.writing_direction = Some("ttb".into());
    gaf.bcp47_lang_code = Some("ja_JP".into());
    let out = with_writer(&empty_page(false), |w| {
        let mut style = QrStampStyle::with_text(
            "テスト\n縦書きテスト\n改行してみましょう（括弧）\nPDF\nちょっと長めの文を書いてみた。",
        );
        style.text.text_box_style = TextBoxStyle {
            vertical_text: true,
            ..tbs_font(gaf.clone())
        };
        style.qr_position = QrPosition::AboveText;
        style.text.base.background = Some(stamp_art_content());
        style.text.base.background_opacity = 0.4;
        let mut ts = Stamp::qr(style.clone(), "https://example.com", Some(BoxConstraints::fixed(100.0, 300.0)), None);
        apply(w, &mut ts, 10.0, 415.0);
        let mut ts = Stamp::qr(style, "https://example.com", None, None);
        apply(w, &mut ts, 400.0, 415.0);
    });
    compare_output(&out, "ja-vert-stamps.pdf");
}

fn bitmap_bg() -> Content {
    Content::Image(PdfImage::open(data_path(&["pyhanko", "img", "stamp-indexed.png"])).unwrap())
}

#[test]
fn test_stamp_with_unscaled_bitmap_bg() {
    let long_text = vec!["Test test test test test test test test test on a bitmap background!"; 60].join("\n");
    let out = with_writer(&empty_page(false), |w| {
        let mut style = TextStampStyle::with_text(long_text);
        style.base.background = Some(bitmap_bg());
        let mut ts = Stamp::text(style, None, None);
        apply(w, &mut ts, 30.0, 120.0);
    });
    compare_output(&out, "bitmap-bg.pdf");
}

#[test]
fn test_stamp_with_scaled_bitmap_bg() {
    let text = ["Test test test test on a bitmap background!"; 3].join("\n");
    let out = with_writer(&empty_page(false), |w| {
        let mut style = TextStampStyle::with_text(text);
        style.base.background = Some(bitmap_bg());
        let mut ts = Stamp::text(style, Some(BoxConstraints::fixed(400.0, 100.0)), None);
        apply(w, &mut ts, 30.0, 600.0);
    });
    compare_output(&out, "scaled-bitmap-bg.pdf");
}

#[test]
fn test_stamp_with_undefined_bg_size() {
    let long_text =
        vec!["Test test test test test test test test test on an ill-defined background!"; 60].join("\n");
    let out = with_writer(&empty_page(false), |w| {
        let mut style = TextStampStyle::with_text(long_text);
        style.base.background = Some(Content::Raw(RawContent::new(STAMP_ART_DATA, None, None)));
        let mut ts = Stamp::text(style, None, None);
        apply(w, &mut ts, 30.0, 120.0);
    });
    compare_output(&out, "undef-bg-size.pdf");
}

fn pdf_bg_path() -> std::path::PathBuf {
    data_path(&["pyhanko", "pdf", "pdf-background-test.pdf"])
}

#[test]
fn test_stamp_with_scaled_pdf_bg() {
    let text = ["Test test test test on a PDF background!"; 3].join("\n");
    let out = with_writer(&empty_page(false), |w| {
        let mut style = TextStampStyle::with_text(text);
        style.base.background = Some(Content::ImportedPage(ImportedPdfPage::new(pdf_bg_path(), 0)));
        let mut ts = Stamp::text(style, Some(BoxConstraints::fixed(200.0, 50.0)), None);
        apply(w, &mut ts, 30.0, 600.0);
    });
    compare_output(&out, "stamp-on-pdf-bg.pdf");
}

#[test]
fn test_stamp_with_fixed_pdf_content() {
    let out = with_writer(&empty_page(false), |w| {
        let style = StampStyle::Static(StaticStampStyle::from_pdf_file(pdf_bg_path(), 0));
        let mut stamp = style
            .create_stamp(BoxConstraints::fixed(200.0, 50.0), &BTreeMap::new())
            .unwrap()
            .unwrap();
        apply(w, &mut stamp, 30.0, 600.0);
    });
    compare_output(&out, "stamp-from-static-pdf.pdf");
}

#[test]
fn test_static_stamp_enforce_box_defined() {
    let boxes = [
        BoxConstraints::default(),
        BoxConstraints::new(Some(200.0), None, None).unwrap(),
        BoxConstraints::new(None, Some(50.0), None).unwrap(),
        BoxConstraints::new(None, None, Fraction::new(4, 1)).unwrap(),
        BoxConstraints::new(None, None, None).unwrap(),
    ];
    let style = StampStyle::Static(StaticStampStyle::from_pdf_file(pdf_bg_path(), 0));
    for b in boxes {
        let e = style.create_stamp(b, &BTreeMap::new()).unwrap_err();
        assert!(is_layout_error(&e));
        assert!(e.to_string().contains("predetermined bounding box"));
    }
}

#[test]
fn test_simple_text_stamp_string_keyed_font() {
    let out = with_writer(&empty_page(false), |w| {
        let mut style = TextStampStyle::with_text(
            "Hi, this is a string-keyed font test.\nThis should have a ligature: difficult",
        );
        style.text_box_style = tbs_font(gaf(SOURCE_SERIF).with_font_size(10.0));
        let mut ts = Stamp::text(style, Some(BoxConstraints::fixed(200.0, 50.0)), None);
        apply(w, &mut ts, 70.0, 50.0);
    });
    compare_output(&out, "source-serif-test.pdf");
}

#[test]
fn test_double_newline() {
    let out = with_writer(&empty_page(false), |w| {
        let mut style = TextStampStyle::with_text(
            "Hi, this is a test. There should be two newlines here:\n\nAnd now a single newline:\nSee?",
        );
        style.text_box_style = tbs_font(gaf(SOURCE_SERIF).with_font_size(10.0));
        let mut ts = Stamp::text(style, Some(BoxConstraints::fixed(200.0, 50.0)), None);
        apply(w, &mut ts, 70.0, 50.0);
    });
    compare_output(&out, "double-newline.pdf");
}

#[test]
fn test_zero_width_error() {
    let base = empty_page(false);
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let zero_margins = SimpleBoxLayoutRule::new(AxisAlignment::AlignMid, AxisAlignment::AlignMid);
    let mut style = TextStampStyle::with_text("");
    style.base.border_width = 0.0;
    style.inner_content_layout = Some(zero_margins);
    style.text_box_style.box_layout_rule = Some(zero_margins);
    let mut stamp = Stamp::text(style, Some(BoxConstraints::fixed(100.0, 100.0)), None);
    let (_cmds, (inn_width, _)) = stamp.inner_layout_natural_size(&mut w).unwrap();
    assert_eq!(inn_width, 0.0);
    // ...this shouldn't throw a division by zero error
    stamp.apply(&mut w, 0, 10.0, 500.0, CoordinateSystem::PageDefault).unwrap();
}

fn leaky(coords: CoordinateSystem, expected: &str) {
    let out = with_writer(&pdf("leaky-graphics-state-doc.pdf"), |w| {
        let mut stamp = Stamp::text(TextStampStyle::with_text("Hi, it's me"), None, None);
        stamp.apply(w, 0, 70.0, 50.0, coords).unwrap();
    });
    compare_output(&out, expected);
}

#[test]
fn test_simple_text_stamp_on_page_with_leaky_graphics_state() {
    leaky(CoordinateSystem::PageDefault, "leaky-graphics-state-stamp-result.pdf");
}

#[test]
fn test_simple_text_stamp_on_page_with_leaky_graphics_state_without_coord_correction() {
    leaky(CoordinateSystem::Ambient, "leaky-graphics-state-stamp-no-corr-result.pdf");
}

#[test]
fn test_multiline_textbox_with_nondefault_font_size() {
    let cfg = serde_json::json!({
        "stamp-text": "Test Test\ntest test",
        "text-box-style": {"font": font(NOTO_SERIF_JP).to_str().unwrap(), "font-size": 8},
    });
    let style = TextStampStyle::from_config(&cfg).unwrap();
    let out = with_writer(&empty_page(false), |w| {
        let mut ts = Stamp::text(style, None, None);
        apply(w, &mut ts, 30.0, 120.0);
    });
    compare_output(&out, "multiline-textbox-nondefault-fs.pdf");
}

#[test]
fn test_default_text_box_style_font_config() {
    let cfg = serde_json::json!({"stamp-text": "Test Test\ntest test", "text-box-style": {}});
    let style = TextStampStyle::from_config(&cfg).unwrap();
    let out = with_writer(&empty_page(false), |w| {
        let mut ts = Stamp::text(style, None, None);
        apply(w, &mut ts, 30.0, 120.0);
    });
    compare_output(&out, "default-font.pdf");
}
