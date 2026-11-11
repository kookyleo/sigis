// Derived from pyHanko `pdf_utils/font/__init__.py` and `pdf_utils/font/api.py`
// (MIT, see LICENSE-pyHanko).

//! Fonts for text rendering (`pyhanko.pdf_utils.font`): the standard Courier
//! font and embedded OpenType/TrueType subsets.

pub mod basic;
pub mod cff;
pub mod opentype;

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

use hanko_core::errors::{HankoError, Result};
use lopdf::Object;

use crate::content::ContentWriter;
use crate::pdf::writer::PdfUpdate;

pub use basic::{SimpleFontEngine, SimpleFontEngineFactory, SimpleFontMeta};
pub use opentype::{GlyphAccumulator, GlyphAccumulatorFactory, GlyphAccumulatorOptions};

/// Result of shaping a string (`ShapeResult`).
#[derive(Clone, Debug, PartialEq)]
pub struct ShapeResult {
    /// Operators that show the glyphs.
    pub graphics_ops: Vec<u8>,
    /// Total horizontal advance in em units.
    pub x_advance: f64,
    /// Total vertical advance in em units.
    pub y_advance: f64,
}

/// Text shaping and font metrics (`FontEngine`).
pub trait FontEngine: std::fmt::Debug + Any {
    /// The engine positions glyphs itself and keeps the line matrix equal
    /// to the text matrix (`uses_complex_positioning`).
    fn uses_complex_positioning(&self) -> bool {
        true
    }

    /// The font size used for positioning.
    fn font_size(&self) -> f64;

    /// Set the font size used for positioning.
    fn set_font_size(&mut self, size: f64);

    /// Shape `txt` (`shape`).
    fn shape(&mut self, txt: &str) -> Result<ShapeResult>;

    /// The value to put into a `/Font` resource dictionary (`as_resource`).
    fn as_resource(&mut self, update: &mut PdfUpdate) -> Result<Object>;

    /// Embed what has to be embedded before writing (`prepare_write`).
    fn prepare_write(&mut self, _update: &mut PdfUpdate) -> Result<()> {
        Ok(())
    }

    /// Downcasting support.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Handle of a font engine registered with a [`ContentWriter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FontHandle(pub(crate) usize);

/// The font engines of a writer, grouped into subset collections per
/// PostScript name (`FontSubsetCollection`).
#[derive(Debug, Default)]
pub struct FontRegistry {
    engines: Vec<Box<dyn FontEngine>>,
    prefixes: BTreeMap<String, BTreeSet<String>>,
}

const ALPHABET: &[u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn generate_subset_prefix() -> String {
    let mut b = [0u8; 6];
    if getrandom::fill(&mut b).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
            .to_le_bytes();
        b[..4].copy_from_slice(&t);
    }
    b.iter().map(|x| char::from(ALPHABET[usize::from(*x) % 26])).collect()
}

impl FontRegistry {
    /// A fresh subset prefix for `base_postscript_name`
    /// (`FontSubsetCollection.add_subset`).
    pub fn add_subset(&mut self, base_postscript_name: &str) -> String {
        let taken = self.prefixes.entry(base_postscript_name.to_owned()).or_default();
        loop {
            let p = generate_subset_prefix();
            if taken.insert(p.clone()) {
                return p;
            }
        }
    }

    /// Register an engine.
    pub fn register(&mut self, engine: Box<dyn FontEngine>) -> FontHandle {
        self.engines.push(engine);
        FontHandle(self.engines.len() - 1)
    }

    /// The engine behind `h`.
    pub fn engine_mut(&mut self, h: FontHandle) -> Result<&mut (dyn FontEngine + 'static)> {
        self.engines
            .get_mut(h.0)
            .map(|b| b.as_mut())
            .ok_or_else(|| HankoError::Malformed("unknown font handle".into()))
    }

    /// `prepare_write` on every engine.
    pub fn prepare_write(&mut self, update: &mut PdfUpdate) -> Result<()> {
        for e in &mut self.engines {
            e.prepare_write(update)?;
        }
        Ok(())
    }
}

/// How to create font engines (`FontEngineFactory`).
#[derive(Clone, Debug, PartialEq)]
pub enum FontEngineFactory {
    /// A standard (non-embedded) font.
    Simple(SimpleFontEngineFactory),
    /// An embedded OpenType/TrueType font.
    OpenType(GlyphAccumulatorFactory),
}

impl Default for FontEngineFactory {
    /// Courier (`SimpleFontEngineFactory.default_factory`).
    fn default() -> Self {
        Self::Simple(SimpleFontEngineFactory::default_factory())
    }
}

impl FontEngineFactory {
    /// Create a font engine registered with `w` (`create_font_engine`).
    pub fn create_font_engine(&self, w: &mut ContentWriter<'_>) -> Result<FontHandle> {
        match self {
            Self::Simple(f) => Ok(f.create_font_engine(w)),
            Self::OpenType(f) => f.create_font_engine(w),
        }
    }
}
