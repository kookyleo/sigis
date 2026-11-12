// Derived from pyHanko `pdf_utils/font/basic.py` (MIT, see LICENSE-pyHanko).

//! Standard (non-embedded) fonts (`SimpleFontEngine`), Courier by default.

use std::any::Any;

use lopdf::{Dictionary, Object};
use sigis_pki_core::errors::Result;

use super::{FontEngine, FontHandle, ShapeResult};
use crate::content::ops::text_string_literal;
use crate::content::ContentWriter;
use crate::pdf::writer::PdfUpdate;

/// Metrics of a simple font (`SimpleFontMeta`).
#[derive(Clone, Debug, PartialEq)]
pub struct SimpleFontMeta {
    /// `/FirstChar`.
    pub first_char: i64,
    /// `/LastChar`.
    pub last_char: i64,
    /// `/Widths`.
    pub widths: Vec<i64>,
    /// The font descriptor.
    pub descriptor: Dictionary,
}

/// Metrics for Courier (`COURIER_META`).
pub fn courier_meta() -> SimpleFontMeta {
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"FontDescriptor".to_vec()));
    d.set("FontName", Object::Name(b"Courier".to_vec()));
    // fixed pitch, serif and nonsymbolic
    d.set("Flags", Object::Integer(0b100011));
    d.set(
        "FontBBox",
        Object::Array(
            [-23, -250, 715, 805]
                .into_iter()
                .map(Object::Integer)
                .collect(),
        ),
    );
    d.set("Ascent", Object::Integer(629));
    d.set("Descent", Object::Integer(-157));
    d.set("CapHeight", Object::Integer(629));
    d.set("ItalicAngle", Object::Integer(0));
    d.set("StemV", Object::Integer(51));
    d.set("MissingWidth", Object::Integer(600));
    d.set("AvgWidth", Object::Integer(600));
    d.set("MaxWidth", Object::Integer(600));
    SimpleFontMeta {
        first_char: 32,
        last_char: 32,
        widths: vec![600],
        descriptor: d,
    }
}

/// A font engine for standard fonts that ignores metrics except for an
/// average width (`SimpleFontEngine`). Best used with monospaced fonts.
#[derive(Clone, Debug)]
pub struct SimpleFontEngine {
    /// The base font name.
    pub name: String,
    /// The average glyph width in em units.
    pub avg_width: f64,
    /// Metrics to embed in the font dictionary.
    pub meta: Option<SimpleFontMeta>,
    font_size: f64,
}

impl FontEngine for SimpleFontEngine {
    fn uses_complex_positioning(&self) -> bool {
        false
    }

    fn font_size(&self) -> f64 {
        self.font_size
    }

    fn set_font_size(&mut self, size: f64) {
        self.font_size = size;
    }

    fn shape(&mut self, txt: &str) -> Result<ShapeResult> {
        let mut ops = text_string_literal(txt);
        ops.extend_from_slice(b" Tj");
        Ok(ShapeResult {
            graphics_ops: ops,
            x_advance: txt.chars().count() as f64 * self.avg_width,
            y_advance: 0.0,
        })
    }

    fn as_resource(&mut self, update: &mut PdfUpdate) -> Result<Object> {
        let mut d = Dictionary::new();
        d.set("Type", Object::Name(b"Font".to_vec()));
        d.set("BaseFont", Object::Name(self.name.as_bytes().to_vec()));
        d.set("Subtype", Object::Name(b"Type1".to_vec()));
        d.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
        if let Some(meta) = &self.meta {
            d.set("FirstChar", Object::Integer(meta.first_char));
            d.set("LastChar", Object::Integer(meta.last_char));
            d.set(
                "Widths",
                Object::Array(meta.widths.iter().copied().map(Object::Integer).collect()),
            );
            let fd = update.add(Object::Dictionary(meta.descriptor.clone()));
            d.set("FontDescriptor", Object::Reference(fd));
        }
        Ok(Object::Dictionary(d))
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Creates [`SimpleFontEngine`]s (`SimpleFontEngineFactory`).
#[derive(Clone, Debug, PartialEq)]
pub struct SimpleFontEngineFactory {
    /// The base font name.
    pub name: String,
    /// The average glyph width in em units.
    pub avg_width: f64,
    /// Metrics to embed in the font dictionary.
    pub meta: Option<SimpleFontMeta>,
}

impl SimpleFontEngineFactory {
    /// A factory for `name`.
    pub fn new(name: impl Into<String>, avg_width: f64, meta: Option<SimpleFontMeta>) -> Self {
        Self {
            name: name.into(),
            avg_width,
            meta,
        }
    }

    /// Courier as a non-embedded standard font (`default_factory`).
    pub fn default_factory() -> Self {
        Self::new("Courier", 0.6, Some(courier_meta()))
    }

    /// Create and register an engine.
    pub fn create_font_engine(&self, w: &mut ContentWriter<'_>) -> FontHandle {
        w.register_font(Box::new(SimpleFontEngine {
            name: self.name.clone(),
            avg_width: self.avg_width,
            meta: self.meta.clone(),
            font_size: 10.0,
        }))
    }
}

/// A Courier font resource dictionary (`get_courier`).
pub fn get_courier(update: &mut PdfUpdate) -> Result<Object> {
    let f = SimpleFontEngineFactory::default_factory();
    SimpleFontEngine {
        name: f.name,
        avg_width: f.avg_width,
        meta: f.meta,
        font_size: 10.0,
    }
    .as_resource(update)
}
