// Derived from pyHanko `pdf_utils/font/opentype.py` (MIT, see LICENSE-pyHanko).

//! Embedded OpenType/TrueType fonts (`GlyphAccumulator`).
//!
//! Shaping uses `rustybuzz` (a port of HarfBuzz, which pyHanko uses through
//! `uharfbuzz`), metrics come from `ttf-parser`, and subsetting from the
//! `subsetter` crate instead of fontTools:
//!
//! * CFF fonts are embedded as `/CIDFontType0C`. The subset is rebuilt in
//!   fontTools' layout (see [`super::cff::rebuild_subset`]) with a charset
//!   that keeps the original CIDs (CID-keyed fonts) or glyph ids
//!   (name-keyed fonts), which is what pyHanko writes into content streams,
//!   and with the subset's bounding box; poppler renders such subsets
//!   exactly like pyHanko's.
//! * TrueType fonts are embedded as `/CIDFontType2` with CIDs equal to the
//!   original glyph ids. `subsetter` renumbers glyphs, so the CID-to-GID
//!   mapping is a `/CIDToGIDMap` stream rather than pyHanko's `/Identity`
//!   (fontTools keeps glyph ids).

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};
use rustybuzz::ttf_parser;
use sigis_pki_core::errors::{HankoError, Result};

use super::{cff, FontEngine, FontHandle, ShapeResult};
use crate::content::ops::{fmt_g, text_string_literal};
use crate::content::{compressed, ContentWriter};
use crate::pdf::writer::PdfUpdate;

fn value_error(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(msg.into())
}

/// Optional settings of a [`GlyphAccumulator`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GlyphAccumulatorOptions {
    /// OpenType script tag; guessed by the shaper if not given.
    pub ot_script_tag: Option<String>,
    /// OpenType language tag; the script's default language system if not
    /// given.
    pub ot_language_tag: Option<String>,
    /// Writing direction: `ltr`, `rtl`, `ttb` or `btt`; guessed if not
    /// given.
    pub writing_direction: Option<String>,
    /// BCP 47 language code to tag strings with (`/Lang`).
    pub bcp47_lang_code: Option<String>,
    /// Put the font's dictionaries into an object stream (when the update
    /// uses an xref stream).
    pub obj_stream: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outlines {
    TrueType,
    Cff { ros: Option<(String, String, i64)> },
}

/// Collects and measures glyphs of an OpenType/TrueType font, and embeds a
/// subset when the document is written (`GlyphAccumulator`).
#[derive(Debug)]
pub struct GlyphAccumulator {
    font: Arc<Vec<u8>>,
    font_size: f64,
    base_ps_name: String,
    subset_prefix: String,
    font_ref: ObjectId,
    outlines: Outlines,
    use_raw_gids: bool,
    units_per_em: f64,
    glyphs: BTreeMap<u16, (u16, u16)>,
    cid_to_unicode: BTreeMap<u16, String>,
    reverse_cmap: Option<HashMap<u16, Vec<u32>>>,
    script: Option<rustybuzz::Script>,
    language: Option<rustybuzz::Language>,
    direction: Option<rustybuzz::Direction>,
    bcp47_lang_code: Option<String>,
    obj_stream: bool,
    write_prepared: bool,
}

fn check_ot_tag(tag: Option<&str>) -> Result<Option<String>> {
    let Some(tag) = tag else { return Ok(None) };
    if tag.chars().count() != 4 {
        return Err(value_error("OpenType tags must be 4 bytes long"));
    }
    if !tag.is_ascii() {
        return Err(value_error("OpenType tags must be ASCII-encodable"));
    }
    Ok(Some(tag.to_owned()))
}

/// `hb_ot_tag_to_script`.
fn script_from_ot_tag(tag: &str) -> Option<rustybuzz::Script> {
    let b = tag.as_bytes();
    if b.len() != 4 || tag == "DFLT" {
        return None;
    }
    let iso: [u8; 4] = match b[3] {
        b'2' | b'3' => {
            // new-style Indic tags
            let base: &[u8; 4] = match &b[..3] {
                b"bng" => b"Beng",
                b"dev" => b"Deva",
                b"gjr" => b"Gujr",
                b"gur" => b"Guru",
                b"knd" => b"Knda",
                b"mlm" => b"Mlym",
                b"ory" => b"Orya",
                b"tml" => b"Taml",
                b"tel" => b"Telu",
                b"mym" => b"Mymr",
                _ => return None,
            };
            *base
        }
        _ => {
            let mut t = [b[0], b[1], b[2], b[3]];
            if t[2] == b' ' {
                t[2] = t[1];
            }
            if t[3] == b' ' {
                t[3] = t[2];
            }
            t[0] = t[0].to_ascii_uppercase();
            t
        }
    };
    rustybuzz::Script::from_iso15924_tag(ttf_parser::Tag::from_bytes(&iso))
}

/// `hb_ot_tag_to_language`, through HarfBuzz's private-use language subtag.
fn language_from_ot_tag(tag: &str) -> Option<rustybuzz::Language> {
    if tag == "dflt" {
        return None;
    }
    let t = tag.trim_end().to_ascii_lowercase();
    rustybuzz::Language::from_str(&format!("x-hbot{t}")).ok()
}

/// The PostScript name of a font (`_read_ps_name`).
fn read_ps_name(face: &ttf_parser::Face<'_>) -> Result<String> {
    let rec = face
        .names()
        .into_iter()
        .find(|n| n.name_id == ttf_parser::name_id::POST_SCRIPT_NAME);
    let name = rec.and_then(|n| {
        n.to_string().or_else(|| {
            // Macintosh Roman: PostScript names are ASCII
            n.name
                .is_ascii()
                .then(|| String::from_utf8_lossy(n.name).into_owned())
        })
    });
    name.ok_or_else(|| {
        HankoError::Unsupported(
            "Could not deduce PostScript name for font; only unicode-compatible encodings in the name table are supported"
                .into(),
        )
    })
}

fn parse_face(data: &[u8]) -> Result<ttf_parser::Face<'_>> {
    ttf_parser::Face::parse(data, 0).map_err(|e| value_error(format!("could not parse font: {e}")))
}

fn hex_cids(cids: &[u16]) -> String {
    cids.iter().map(|c| format!("{c:04x}")).collect()
}

/// `_format_simple_glyphline_from_buffer`: one `TJ` with kerning
/// adjustments; returns the operators and the total advance.
fn format_simple_glyphline(
    glyphs: &[(u16, rustybuzz::GlyphPosition)],
    mut cid_width: impl FnMut(u16) -> (u16, u16),
) -> (Vec<u8>, i64) {
    let mut total_len: i64 = 0;
    let mut subsgmt: Vec<u16> = Vec::new();
    let mut tj_adjust: i64 = 0;
    let mut segments: Vec<String> = Vec::new();
    let emit = |subsgmt: &mut Vec<u16>, segments: &mut Vec<String>, tj_adjust: i64| {
        segments.push(format!("<{}>", hex_cids(subsgmt)));
        subsgmt.clear();
        if tj_adjust != 0 {
            segments.push(tj_adjust.to_string());
        }
    };
    for (gid, pos) in glyphs {
        let (cid, width) = cid_width(*gid);
        tj_adjust -= i64::from(pos.x_offset);
        if tj_adjust != 0 {
            emit(&mut subsgmt, &mut segments, tj_adjust);
        }
        subsgmt.push(cid);
        tj_adjust = i64::from(width) - i64::from(pos.x_advance) + i64::from(pos.x_offset);
        total_len += i64::from(pos.x_advance);
    }
    if !subsgmt.is_empty() {
        emit(&mut subsgmt, &mut segments, tj_adjust);
    }
    (
        format!("[{}] TJ", segments.join(" ")).into_bytes(),
        total_len,
    )
}

/// `_format_cid_glyphline_from_buffer`.
fn format_cid_glyphline(
    glyphs: &[(u16, rustybuzz::GlyphPosition)],
    mut cid_width: impl FnMut(u16) -> (u16, u16),
    units_per_em: f64,
    font_size: f64,
    vertical: bool,
) -> (Vec<u8>, (i64, i64)) {
    let to_user = |n: i64| (n as f64 / units_per_em) * font_size;
    let no_complex = !vertical && glyphs.iter().all(|(_, p)| p.y_offset == 0);
    if no_complex {
        let (ops, total) = format_simple_glyphline(glyphs, cid_width);
        let mut out = ops;
        out.extend_from_slice(format!(" {} 0 Td", fmt_g(to_user(total))).as_bytes());
        return (out, (total, 0));
    }
    let mut commands: Vec<String> = Vec::new();
    let (mut total_x, mut total_y) = (0i64, 0i64);
    let (mut x_pos, mut y_pos) = (0i64, 0i64);
    for (gid, pos) in glyphs {
        let (cid, _) = cid_width(*gid);
        x_pos += i64::from(pos.x_offset);
        y_pos += i64::from(pos.y_offset);
        if x_pos != 0 || y_pos != 0 {
            commands.push(format!(
                "{} {} Td",
                fmt_g(to_user(x_pos)),
                fmt_g(to_user(y_pos))
            ));
        }
        commands.push(format!("<{cid:04x}> Tj"));
        x_pos = i64::from(pos.x_advance) - i64::from(pos.x_offset);
        y_pos = i64::from(pos.y_advance) - i64::from(pos.y_offset);
        total_x += i64::from(pos.x_advance);
        total_y += i64::from(pos.y_advance);
    }
    if x_pos != 0 || y_pos != 0 {
        commands.push(format!(
            "{} {} Td",
            fmt_g(to_user(x_pos)),
            fmt_g(to_user(y_pos))
        ));
    }
    (commands.join(" ").into_bytes(), (total_x, total_y))
}

/// Tight bounds of glyph outlines (fontTools' `BoundsPen`).
#[derive(Default)]
struct Bounds {
    rect: Option<[f64; 4]>,
    cur: (f64, f64),
}

impl Bounds {
    fn add(&mut self, x: f64, y: f64) {
        self.rect = Some(match self.rect {
            None => [x, y, x, y],
            Some([a, b, c, d]) => [a.min(x), b.min(y), c.max(x), d.max(y)],
        });
    }

    /// Add the end point and the extrema of a cubic curve.
    fn cubic(&mut self, p: [(f64, f64); 4]) {
        self.add(p[3].0, p[3].1);
        let point = |t: f64| {
            let mt = 1.0 - t;
            let f = |a: f64, b: f64, c: f64, d: f64| {
                mt * mt * mt * a + 3.0 * mt * mt * t * b + 3.0 * mt * t * t * c + t * t * t * d
            };
            (
                f(p[0].0, p[1].0, p[2].0, p[3].0),
                f(p[0].1, p[1].1, p[2].1, p[3].1),
            )
        };
        for axis in 0..2 {
            let c = |i: usize| if axis == 0 { p[i].0 } else { p[i].1 };
            let a = -c(0) + 3.0 * c(1) - 3.0 * c(2) + c(3);
            let b = 2.0 * (c(0) - 2.0 * c(1) + c(2));
            let cc = c(1) - c(0);
            let mut ts = Vec::new();
            if a.abs() < 1e-12 {
                if b.abs() > 1e-12 {
                    ts.push(-cc / b);
                }
            } else {
                let disc = b * b - 4.0 * a * cc;
                if disc >= 0.0 {
                    let r = disc.sqrt();
                    ts.push((-b + r) / (2.0 * a));
                    ts.push((-b - r) / (2.0 * a));
                }
            }
            for t in ts.into_iter().filter(|t| *t > 0.0 && *t < 1.0) {
                let (x, y) = point(t);
                self.add(x, y);
            }
        }
    }
}

impl ttf_parser::OutlineBuilder for Bounds {
    fn move_to(&mut self, x: f32, y: f32) {
        self.cur = (f64::from(x), f64::from(y));
        self.add(self.cur.0, self.cur.1);
    }
    fn line_to(&mut self, x: f32, y: f32) {
        self.cur = (f64::from(x), f64::from(y));
        self.add(self.cur.0, self.cur.1);
    }
    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        let (x0, y0) = self.cur;
        let (x1, y1, x, y) = (f64::from(x1), f64::from(y1), f64::from(x), f64::from(y));
        let c1 = (x0 + 2.0 / 3.0 * (x1 - x0), y0 + 2.0 / 3.0 * (y1 - y0));
        let c2 = (x + 2.0 / 3.0 * (x1 - x), y + 2.0 / 3.0 * (y1 - y));
        self.cubic([(x0, y0), c1, c2, (x, y)]);
        self.cur = (x, y);
    }
    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        let p = [
            self.cur,
            (f64::from(x1), f64::from(y1)),
            (f64::from(x2), f64::from(y2)),
            (f64::from(x), f64::from(y)),
        ];
        self.cubic(p);
        self.cur = p[3];
    }
    fn close(&mut self) {}
}

/// The font bounding box of the glyphs of a subset, rounded outwards
/// (fontTools' `recalcFontBBox`; fontTools empties `.notdef` when
/// subsetting, so it does not count).
fn subset_bbox(face: &ttf_parser::Face<'_>, glyphs: impl Iterator<Item = u16>) -> Option<[i64; 4]> {
    let mut b = Bounds::default();
    for g in glyphs.filter(|g| *g != 0) {
        let _ = face.outline_glyph(ttf_parser::GlyphId(g), &mut b);
    }
    b.rect.map(|[a, c, d, e]| {
        [
            a.floor() as i64,
            c.floor() as i64,
            d.ceil() as i64,
            e.ceil() as i64,
        ]
    })
}

/// Python's `s[start:end]` on code points.
fn py_slice(chars: &[char], start: usize, end: Option<usize>) -> String {
    let end = end.unwrap_or(chars.len()).min(chars.len());
    if start >= end {
        return String::new();
    }
    chars[start..end].iter().collect()
}

/// `_breakdown_cmap` + `_segment_cmap`: the body of a ToUnicode CMap.
fn segment_cmap(mappings: &BTreeMap<u16, Vec<u8>>) -> Vec<String> {
    // group contiguous source codes
    let mut groups: Vec<(u16, Vec<&Vec<u8>>)> = Vec::new();
    let mut prev: Option<u16> = None;
    for (src, tgt) in mappings {
        match (prev, groups.last_mut()) {
            (Some(p), Some(last)) if u32::from(*src) == u32::from(p) + 1 => last.1.push(tgt),
            _ => groups.push((*src, vec![tgt])),
        }
        prev = Some(*src);
    }
    let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    let mut out = Vec::new();
    let mut heading = "char";
    let mut decls: Vec<(u16, Vec<&Vec<u8>>)> = Vec::new();
    let emit = |out: &mut Vec<String>, heading: &str, decls: &[(u16, Vec<&Vec<u8>>)]| {
        out.push(format!("{} beginbf{heading}", decls.len()));
        for (start, targets) in decls {
            if heading == "range" {
                let end = usize::from(*start) + targets.len() - 1;
                let vals: Vec<String> = targets.iter().map(|t| format!("<{}>", hex(t))).collect();
                out.push(format!("<{start:04x}> <{end:04x}> [{}]", vals.join(" ")));
            } else {
                out.push(format!("<{start:04x}> <{}>", hex(targets[0])));
            }
        }
        out.push(format!("endbf{heading}"));
    };
    for g in groups {
        let current = if g.1.len() == 1 { "char" } else { "range" };
        if (!decls.is_empty() && heading != current) || decls.len() >= 100 {
            emit(&mut out, heading, &decls);
            decls.clear();
        }
        heading = current;
        decls.push(g);
    }
    if !decls.is_empty() {
        emit(&mut out, heading, &decls);
    }
    out
}

impl GlyphAccumulator {
    /// Load a font and register an accumulator for it with `w`.
    pub fn load(
        w: &mut ContentWriter<'_>,
        font: Arc<Vec<u8>>,
        font_size: f64,
        options: &GlyphAccumulatorOptions,
    ) -> Result<FontHandle> {
        let ga = Self::create(w, font, font_size, options)?;
        Ok(w.register_font(Box::new(ga)))
    }

    fn create(
        w: &mut ContentWriter<'_>,
        font: Arc<Vec<u8>>,
        font_size: f64,
        options: &GlyphAccumulatorOptions,
    ) -> Result<Self> {
        let face = parse_face(&font)?;
        let base_ps_name = read_ps_name(&face)?;
        let units_per_em = f64::from(face.units_per_em());
        let outlines = if face.tables().glyf.is_some() {
            Outlines::TrueType
        } else {
            let raw = face
                .raw_face()
                .table(ttf_parser::Tag::from_bytes(b"CFF "))
                .ok_or_else(|| {
                    HankoError::Unsupported("fonts without glyf or CFF outlines".into())
                })?;
            Outlines::Cff {
                ros: cff::read_ros(raw),
            }
        };
        let use_raw_gids = !matches!(outlines, Outlines::Cff { ros: Some(_) });
        let ot_language_tag = check_ot_tag(options.ot_language_tag.as_deref())?;
        let ot_script_tag = check_ot_tag(options.ot_script_tag.as_deref())?;
        let direction = match options.writing_direction.as_deref() {
            None => None,
            Some("ltr") => Some(rustybuzz::Direction::LeftToRight),
            Some("rtl") => Some(rustybuzz::Direction::RightToLeft),
            Some("ttb") => Some(rustybuzz::Direction::TopToBottom),
            Some("btt") => Some(rustybuzz::Direction::BottomToTop),
            Some(_) => {
                return Err(value_error(
                    "Writing direction must be one of 'ltr', 'rtl', 'ttb' or 'btt'.",
                ))
            }
        };
        let subset_prefix = w.fonts().add_subset(&base_ps_name);
        let font_ref = w.add(Object::Null);
        let obj_stream = options.obj_stream;
        Ok(Self {
            font,
            font_size,
            base_ps_name,
            subset_prefix,
            font_ref,
            outlines,
            use_raw_gids,
            units_per_em,
            glyphs: BTreeMap::new(),
            cid_to_unicode: BTreeMap::new(),
            reverse_cmap: None,
            script: ot_script_tag.as_deref().and_then(script_from_ot_tag),
            language: ot_language_tag.as_deref().and_then(language_from_ot_tag),
            direction,
            bcp47_lang_code: options.bcp47_lang_code.clone(),
            obj_stream,
            write_prepared: false,
        })
    }

    /// The subset prefix (six capital letters).
    pub fn subset_prefix(&self) -> &str {
        &self.subset_prefix
    }

    /// The reference reserved for the font dictionary.
    pub fn font_ref(&self) -> ObjectId {
        self.font_ref
    }

    fn cid_and_width(&mut self, gid: u16) -> (u16, u16) {
        if let Some(r) = self.glyphs.get(&gid) {
            return *r;
        }
        let (cid, width) = match parse_face(&self.font) {
            Ok(face) => {
                let g = ttf_parser::GlyphId(gid);
                let cid = if self.use_raw_gids {
                    gid
                } else {
                    face.tables()
                        .cff
                        .and_then(|c| c.glyph_cid(g))
                        .unwrap_or(gid)
                };
                (cid, face.glyph_hor_advance(g).unwrap_or(0))
            }
            Err(_) => (gid, 0),
        };
        self.glyphs.insert(gid, (cid, width));
        (cid, width)
    }

    fn reverse_cmap(&mut self) -> &HashMap<u16, Vec<u32>> {
        if self.reverse_cmap.is_none() {
            let mut map: HashMap<u16, BTreeSet<u32>> = HashMap::new();
            if let Ok(face) = parse_face(&self.font) {
                if let Some(cmap) = face.tables().cmap {
                    for st in cmap.subtables {
                        if !st.is_unicode() {
                            continue;
                        }
                        st.codepoints(|cp| {
                            if let Some(g) = st.glyph_index(cp) {
                                map.entry(g.0).or_default().insert(cp);
                            }
                        });
                    }
                }
            }
            self.reverse_cmap = Some(
                map.into_iter()
                    .map(|(k, v)| (k, v.into_iter().collect()))
                    .collect(),
            );
        }
        static EMPTY: std::sync::OnceLock<HashMap<u16, Vec<u32>>> = std::sync::OnceLock::new();
        match &self.reverse_cmap {
            Some(m) => m,
            None => EMPTY.get_or_init(HashMap::new),
        }
    }

    /// The `/Span` property list (`marked_content_property_list`).
    fn marked_content_property_list(&self, txt: &str) -> Vec<u8> {
        let mut out = b"<<\n/ActualText ".to_vec();
        out.extend(text_string_literal(txt));
        out.push(b'\n');
        if let Some(lang) = &self.bcp47_lang_code {
            out.extend_from_slice(b"/Lang ");
            out.extend(text_string_literal(lang));
            out.push(b'\n');
        }
        out.extend_from_slice(b">>");
        out
    }

    /// Shape `txt`; with `with_actual_text`, the operators are wrapped in a
    /// `/Span` with `/ActualText`.
    pub fn shape_text(&mut self, txt: &str, with_actual_text: bool) -> Result<ShapeResult> {
        if txt.is_empty() {
            return Ok(ShapeResult {
                graphics_ops: Vec::new(),
                x_advance: 0.0,
                y_advance: 0.0,
            });
        }
        let font = self.font.clone();
        let face = rustybuzz::Face::from_slice(&font, 0)
            .ok_or_else(|| value_error("could not parse font for shaping"))?;
        let mut buf = rustybuzz::UnicodeBuffer::new();
        // clusters are code point indices, as with uharfbuzz's add_str
        for (i, c) in txt.chars().enumerate() {
            buf.add(c, u32::try_from(i).unwrap_or(u32::MAX));
        }
        if let Some(s) = self.script {
            buf.set_script(s);
        }
        if let Some(l) = &self.language {
            buf.set_language(l.clone());
        }
        if let Some(d) = self.direction {
            buf.set_direction(d);
        }
        buf.guess_segment_properties();
        let vertical = matches!(
            buf.direction(),
            rustybuzz::Direction::TopToBottom | rustybuzz::Direction::BottomToTop
        );
        let shaped = rustybuzz::shape(&face, &[], buf);
        let glyphs: Vec<(u16, rustybuzz::GlyphPosition)> = shaped
            .glyph_infos()
            .iter()
            .zip(shaped.glyph_positions())
            .map(|(i, p)| (u16::try_from(i.glyph_id).unwrap_or(0), *p))
            .collect();
        let clusters: Vec<u32> = shaped.glyph_infos().iter().map(|i| i.cluster).collect();
        let (upem, font_size) = (self.units_per_em, self.font_size);
        let (text_ops, (total_x, total_y)) = format_cid_glyphline(
            &glyphs,
            |g| self.cid_and_width(g),
            upem,
            font_size,
            vertical,
        );
        // ToUnicode bookkeeping (`_gids_by_cluster`)
        let chars: Vec<char> = txt.chars().collect();
        let mut groups: Vec<(usize, Option<usize>, Vec<u16>)> = Vec::new();
        let mut cur_cluster = 0usize;
        let mut cur_glyphs: Vec<u16> = Vec::new();
        for (gi, cl) in glyphs.iter().zip(&clusters) {
            let cl = *cl as usize;
            if cl != cur_cluster {
                groups.push((cur_cluster, Some(cl), std::mem::take(&mut cur_glyphs)));
                cur_cluster = cl;
            }
            cur_glyphs.push(gi.0);
        }
        groups.push((cur_cluster, None, cur_glyphs));
        for (cluster, next_cluster, gids) in groups {
            let unicode_str = py_slice(&chars, cluster, next_cluster);
            if gids.len() == 1 {
                let gid = gids[0];
                if gid == 0 {
                    continue;
                }
                let (cid, _) = self.cid_and_width(gid);
                self.cid_to_unicode.insert(cid, unicode_str);
            } else {
                let relevant: BTreeSet<u32> = unicode_str.chars().map(u32::from).collect();
                for gid in gids {
                    if gid == 0 {
                        continue;
                    }
                    let (cid, _) = self.cid_and_width(gid);
                    if self.cid_to_unicode.contains_key(&cid) {
                        continue;
                    }
                    let cps = self.reverse_cmap().get(&gid).cloned().unwrap_or_default();
                    for cp in cps {
                        if relevant.contains(&cp) {
                            if let Some(c) = char::from_u32(cp) {
                                self.cid_to_unicode.insert(cid, c.to_string());
                            }
                        }
                    }
                }
            }
        }
        let graphics_ops = if with_actual_text {
            let mut v = b"/Span ".to_vec();
            v.extend(self.marked_content_property_list(txt));
            v.extend_from_slice(b" BDC ");
            v.extend(text_ops);
            v.extend_from_slice(b" EMC");
            v
        } else {
            text_ops
        };
        Ok(ShapeResult {
            graphics_ops,
            x_advance: total_x as f64 / self.units_per_em,
            y_advance: total_y as f64 / self.units_per_em,
        })
    }

    fn tounicode_cmap(&self) -> Stream {
        let header = "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo <<\n/Registry (Adobe)\n/Ordering (UCS2)\n/Supplement 0\n>> def\n/CMapName /Adobe-Identity-UCS2 def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n";
        let mappings: BTreeMap<u16, Vec<u8>> = self
            .cid_to_unicode
            .iter()
            .map(|(cid, s)| (*cid, s.encode_utf16().flat_map(u16::to_be_bytes).collect()))
            .collect();
        let body = segment_cmap(&mappings).join("\n");
        let footer = "\nendcmap\nCMapName\ncurrentdict\n/CMap defineresource\npop\nend\nend";
        compressed(Stream::new(
            Dictionary::new(),
            format!("{header}{body}{footer}").into_bytes(),
        ))
    }

    fn add_dict(&self, update: &mut PdfUpdate, d: Dictionary) -> ObjectId {
        if self.obj_stream {
            update.add_in_object_stream(Object::Dictionary(d))
        } else {
            update.add(Object::Dictionary(d))
        }
    }

    fn font_descriptor(&self, face: &ttf_parser::Face<'_>, name: &str) -> Dictionary {
        let t = face.tables();
        let bbox = t.head.global_bbox;
        let weight = t
            .os2
            .map(|o| f64::from(o.weight().to_number()))
            .unwrap_or(400.0);
        let stemv = (10.0 + 220.0 * (weight - 50.0) / 900.0).trunc() as i64;
        let mut fd = Dictionary::new();
        fd.set("Type", Object::Name(b"FontDescriptor".to_vec()));
        fd.set("FontName", Object::Name(name.as_bytes().to_vec()));
        fd.set("Ascent", Object::Integer(i64::from(t.hhea.ascender)));
        fd.set("Descent", Object::Integer(i64::from(t.hhea.descender)));
        fd.set(
            "FontBBox",
            Object::Array(
                [bbox.x_min, bbox.y_min, bbox.x_max, bbox.y_max]
                    .into_iter()
                    .map(|v| Object::Integer(i64::from(v)))
                    .collect(),
            ),
        );
        fd.set("Flags", Object::Integer(0b110));
        fd.set("StemV", Object::Integer(stemv));
        fd.set("ItalicAngle", Object::Real(face.italic_angle()));
        fd.set(
            "CapHeight",
            Object::Integer(
                t.os2
                    .and_then(|o| o.capital_height())
                    .map_or(750, i64::from),
            ),
        );
        fd
    }

    fn embed(&mut self, update: &mut PdfUpdate) -> Result<()> {
        let font = self.font.clone();
        let face = parse_face(&font)?;
        let used: Vec<u16> = self.glyphs.keys().copied().collect();
        let mut remapper = subsetter::GlyphRemapper::new();
        for g in &used {
            remapper.remap(*g);
        }
        let subset = subsetter::subset(&font, 0, &remapper)
            .map_err(|e| HankoError::Unsupported(format!("font subsetting failed: {e}")))?;
        let name = format!("{}+{}", self.subset_prefix, self.base_ps_name);
        let mut fd = self.font_descriptor(&face, &name);
        let mut cidfont = Dictionary::new();
        cidfont.set("Type", Object::Name(b"Font".to_vec()));
        let (registry, ordering, supplement) = match &self.outlines {
            Outlines::Cff {
                ros: Some((r, o, s)),
            } => (r.clone(), o.clone(), *s),
            _ => ("Adobe".to_owned(), "Identity".to_owned(), 0),
        };
        match &self.outlines {
            Outlines::Cff { .. } => {
                let sub_face = ttf_parser::RawFace::parse(&subset, 0)
                    .map_err(|e| value_error(format!("font subset: {e}")))?;
                let cff_data = sub_face
                    .table(ttf_parser::Tag::from_bytes(b"CFF "))
                    .ok_or_else(|| value_error("font subset without CFF table"))?;
                let mut cids = vec![0u16; usize::from(remapper.num_gids())];
                for (gid, (cid, _)) in &self.glyphs {
                    if let Some(new) = remapper.get(*gid) {
                        if let Some(slot) = cids.get_mut(usize::from(new)) {
                            *slot = *cid;
                        }
                    }
                }
                let bbox = subset_bbox(&face, self.glyphs.keys().copied());
                let cff_data = cff::rebuild_subset(cff_data, &cids, bbox)?;
                let mut d = Dictionary::new();
                d.set("Subtype", Object::Name(b"CIDFontType0C".to_vec()));
                let ff = update.add(Object::Stream(compressed(Stream::new(d, cff_data))));
                fd.set("FontFile3", Object::Reference(ff));
                cidfont.set("Subtype", Object::Name(b"CIDFontType0".to_vec()));
            }
            Outlines::TrueType => {
                let ff = update.add(Object::Stream(compressed(Stream::new(
                    Dictionary::new(),
                    subset,
                ))));
                fd.set("FontFile2", Object::Reference(ff));
                cidfont.set("Subtype", Object::Name(b"CIDFontType2".to_vec()));
                // CIDs are the original glyph ids
                let max_cid = self.glyphs.keys().copied().max().unwrap_or(0);
                let mut map = vec![0u8; 2 * (usize::from(max_cid) + 1)];
                for gid in self.glyphs.keys() {
                    let new = remapper.get(*gid).unwrap_or(0);
                    let at = 2 * usize::from(*gid);
                    map[at..at + 2].copy_from_slice(&new.to_be_bytes());
                }
                let m = update.add(Object::Stream(compressed(Stream::new(
                    Dictionary::new(),
                    map,
                ))));
                cidfont.set("CIDToGIDMap", Object::Reference(m));
            }
        }
        let fd_ref = self.add_dict(update, fd);
        let mut sysinfo = Dictionary::new();
        sysinfo.set(
            "Registry",
            Object::String(registry.into_bytes(), StringFormat::Literal),
        );
        sysinfo.set(
            "Ordering",
            Object::String(ordering.into_bytes(), StringFormat::Literal),
        );
        sysinfo.set("Supplement", Object::Integer(supplement));
        cidfont.set("CIDSystemInfo", Object::Dictionary(sysinfo));
        cidfont.set("BaseFont", Object::Name(name.as_bytes().to_vec()));
        cidfont.set("FontDescriptor", Object::Reference(fd_ref));
        // widths
        let mut by_cid: Vec<(u16, u16)> = self.glyphs.values().copied().collect();
        by_cid.sort_by_key(|t| t.0);
        let mut w: Vec<Object> = Vec::new();
        let mut chunk: Vec<Object> = Vec::new();
        let mut first_cid = by_cid.first().map_or(0, |t| t.0);
        let mut prev: Option<u16> = None;
        for (cid, width) in &by_cid {
            if let Some(p) = prev {
                if !chunk.is_empty() && u32::from(*cid) != u32::from(p) + 1 {
                    w.push(Object::Integer(i64::from(first_cid)));
                    w.push(Object::Array(std::mem::take(&mut chunk)));
                    first_cid = *cid;
                }
            }
            chunk.push(Object::Integer(i64::from(*width)));
            prev = Some(*cid);
        }
        if !chunk.is_empty() {
            w.push(Object::Integer(i64::from(first_cid)));
            w.push(Object::Array(chunk));
        }
        cidfont.set("W", Object::Array(w));
        let cidfont_ref = self.add_dict(update, cidfont);
        let encoding = "Identity-H";
        let mut type0 = Dictionary::new();
        type0.set("Type", Object::Name(b"Font".to_vec()));
        type0.set("Subtype", Object::Name(b"Type0".to_vec()));
        type0.set(
            "DescendantFonts",
            Object::Array(vec![Object::Reference(cidfont_ref)]),
        );
        type0.set("Encoding", Object::Name(encoding.as_bytes().to_vec()));
        type0.set(
            "BaseFont",
            Object::Name(format!("{name}-{encoding}").into_bytes()),
        );
        let tu = update.add(Object::Stream(self.tounicode_cmap()));
        type0.set("ToUnicode", Object::Reference(tu));
        if self.obj_stream {
            update.update_in_object_stream(self.font_ref, Object::Dictionary(type0));
        } else {
            update.update(self.font_ref, Object::Dictionary(type0));
        }
        Ok(())
    }
}

impl FontEngine for GlyphAccumulator {
    fn font_size(&self) -> f64 {
        self.font_size
    }

    fn set_font_size(&mut self, size: f64) {
        self.font_size = size;
    }

    fn shape(&mut self, txt: &str) -> Result<ShapeResult> {
        self.shape_text(txt, true)
    }

    fn as_resource(&mut self, _update: &mut PdfUpdate) -> Result<Object> {
        Ok(Object::Reference(self.font_ref))
    }

    /// Embed the subset of the glyphs used so far (`prepare_write`).
    /// Idempotent.
    fn prepare_write(&mut self, update: &mut PdfUpdate) -> Result<()> {
        if self.write_prepared {
            return Ok(());
        }
        self.embed(update)?;
        self.write_prepared = true;
        Ok(())
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Creates [`GlyphAccumulator`]s for a font file (`GlyphAccumulatorFactory`).
#[derive(Clone, Debug, PartialEq)]
pub struct GlyphAccumulatorFactory {
    /// Path of the OTF/TTF font.
    pub font_file: PathBuf,
    /// Font size.
    pub font_size: f64,
    /// OpenType script tag.
    pub ot_script_tag: Option<String>,
    /// OpenType language tag.
    pub ot_language_tag: Option<String>,
    /// Writing direction (`ltr`, `rtl`, `ttb`, `btt`).
    pub writing_direction: Option<String>,
    /// BCP 47 language code.
    pub bcp47_lang_code: Option<String>,
    /// Put the font objects into an object stream if the writer uses xref
    /// streams.
    pub create_objstream_if_needed: bool,
}

impl GlyphAccumulatorFactory {
    /// A factory for `font_file` at size 10.
    pub fn new(font_file: impl Into<PathBuf>) -> Self {
        Self {
            font_file: font_file.into(),
            font_size: 10.0,
            ot_script_tag: None,
            ot_language_tag: None,
            writing_direction: None,
            bcp47_lang_code: None,
            create_objstream_if_needed: true,
        }
    }

    /// The same factory with another font size.
    pub fn with_font_size(mut self, size: f64) -> Self {
        self.font_size = size;
        self
    }

    /// Create and register an accumulator (`create_font_engine`).
    pub fn create_font_engine(&self, w: &mut ContentWriter<'_>) -> Result<FontHandle> {
        let data = std::fs::read(&self.font_file)?;
        let opts = GlyphAccumulatorOptions {
            ot_script_tag: self.ot_script_tag.clone(),
            ot_language_tag: self.ot_language_tag.clone(),
            writing_direction: self.writing_direction.clone(),
            bcp47_lang_code: self.bcp47_lang_code.clone(),
            obj_stream: w.stream_xrefs() && self.create_objstream_if_needed,
        };
        GlyphAccumulator::load(w, Arc::new(data), self.font_size, &opts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmap_segments() {
        let mut m = BTreeMap::new();
        m.insert(1u16, vec![0, 0x41]);
        m.insert(2u16, vec![0, 0x42]);
        m.insert(5u16, vec![0, 0x43]);
        let s = segment_cmap(&m);
        assert_eq!(
            s,
            vec![
                "1 beginbfrange",
                "<0001> <0002> [<0041> <0042>]",
                "endbfrange",
                "1 beginbfchar",
                "<0005> <0043>",
                "endbfchar"
            ]
        );
    }

    #[test]
    fn scripts() {
        assert_eq!(script_from_ot_tag("hani"), Some(rustybuzz::script::HAN));
        assert_eq!(script_from_ot_tag("arab"), Some(rustybuzz::script::ARABIC));
    }
}
