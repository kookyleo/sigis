// Derived from pyHanko `config/api.py` (`ConfigurableMixin.from_config`) and
// the `process_entries` hooks of `stamp/base.py`, `stamp/qr.py`,
// `pdf_utils/text.py` and `pdf_utils/layout.py` (MIT, see LICENSE-pyHanko).

//! Stamp styles from configuration dictionaries (`from_config`).
//!
//! Keys may use dashes or underscores; unknown keys are errors.

use sigis_pki_core::errors::{HankoError, Result};
use serde_json::{Map, Value};

use super::{BaseStampStyle, QrPosition, QrStampStyle, StaticStampStyle, TextStampStyle};
use crate::content::{Content, ImportedPdfPage};
use crate::font::{FontEngineFactory, GlyphAccumulatorFactory};
use crate::images::PdfImage;
use crate::layout::{AxisAlignment, InnerScaling, Margins, SimpleBoxLayoutRule};
use crate::text::TextBoxStyle;

/// Prefix of the messages of configuration errors (`ConfigurationError`).
pub const CONFIG_ERROR_PREFIX: &str = "configuration error: ";

/// A configuration error (`ConfigurationError`), reported as
/// [`HankoError::Malformed`] with the prefix [`CONFIG_ERROR_PREFIX`].
pub fn config_error(msg: impl AsRef<str>) -> HankoError {
    HankoError::Malformed(format!("{CONFIG_ERROR_PREFIX}{}", msg.as_ref()))
}

type Dict = Map<String, Value>;

/// Normalise keys to underscores after checking them against `allowed`
/// (`check_config_keys`).
fn normalise(name: &str, v: &Value, allowed: &[&str]) -> Result<Dict> {
    let Value::Object(m) = v else {
        return Err(config_error(format!("{name} requires a dictionary to initialise.")));
    };
    let mut unexpected: Vec<String> = Vec::new();
    let mut out = Dict::new();
    for (k, v) in m {
        let key = k.replace('-', "_");
        if !allowed.contains(&key.as_str()) {
            unexpected.push(k.replace('_', "-"));
        }
        out.insert(key, v.clone());
    }
    if !unexpected.is_empty() {
        unexpected.sort();
        return Err(config_error(format!(
            "Unexpected {} in configuration for {name}: {}.",
            if unexpected.len() == 1 { "key" } else { "keys" },
            unexpected.join(", ")
        )));
    }
    Ok(out)
}

fn num(d: &Dict, k: &str) -> Result<Option<f64>> {
    match d.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => Ok(n.as_f64()),
        Some(_) => Err(config_error(format!("'{k}' must be a number"))),
    }
}

fn string(d: &Dict, k: &str) -> Result<Option<String>> {
    match d.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(config_error(format!("'{k}' must be a string"))),
    }
}

fn boolean(d: &Dict, k: &str) -> Result<Option<bool>> {
    match d.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(config_error(format!("'{k}' must be a boolean"))),
    }
}

fn color(d: &Dict, k: &str) -> Result<Option<[f64; 3]>> {
    match d.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) if a.len() == 3 => {
            let v: Vec<f64> = a.iter().filter_map(Value::as_f64).collect();
            if v.len() != 3 {
                return Err(config_error(format!("'{k}' must be three numbers")));
            }
            Ok(Some([v[0], v[1], v[2]]))
        }
        Some(_) => Err(config_error(format!("'{k}' must be an RGB triple"))),
    }
}

/// `Margins.from_config` (a dictionary or a `[left, right, top, bottom]`
/// list).
pub fn margins_from_config(v: &Value) -> Result<Margins> {
    let d = match v {
        Value::Array(a) => {
            let mut m = Dict::new();
            for (k, x) in ["left", "right", "top", "bottom"].iter().zip(a) {
                m.insert((*k).to_owned(), x.clone());
            }
            Value::Object(m)
        }
        other => other.clone(),
    };
    let d = normalise("Margins", &d, &["left", "right", "top", "bottom"])?;
    Ok(Margins {
        left: num(&d, "left")?.unwrap_or(0.0),
        right: num(&d, "right")?.unwrap_or(0.0),
        top: num(&d, "top")?.unwrap_or(0.0),
        bottom: num(&d, "bottom")?.unwrap_or(0.0),
    })
}

/// `SimpleBoxLayoutRule.from_config`; alignments default to `mid`.
pub fn layout_rule_from_config(v: &Value) -> Result<SimpleBoxLayoutRule> {
    let d = normalise(
        "SimpleBoxLayoutRule",
        v,
        &["x_align", "y_align", "margins", "inner_content_scaling"],
    )?;
    let x_align = match string(&d, "x_align")? {
        Some(s) => AxisAlignment::from_x_align(&s)?,
        None => AxisAlignment::AlignMid,
    };
    let y_align = match string(&d, "y_align")? {
        Some(s) => AxisAlignment::from_y_align(&s)?,
        None => AxisAlignment::AlignMid,
    };
    let margins = match d.get("margins") {
        Some(m) if !m.is_null() => margins_from_config(m)?,
        _ => Margins::default(),
    };
    let inner_content_scaling = match string(&d, "inner_content_scaling")? {
        Some(s) => InnerScaling::from_config(&s)?,
        None => InnerScaling::ShrinkToFit,
    };
    Ok(SimpleBoxLayoutRule {
        x_align,
        y_align,
        margins,
        inner_content_scaling,
    })
}

const TEXT_BOX_KEYS: &[&str] = &[
    "font",
    "font_size",
    "leading",
    "border_width",
    "box_layout_rule",
    "vertical_text",
    "text_color",
];

/// `TextBoxStyle.from_config`; `font` is the path of an OpenType/TrueType
/// font.
pub fn text_box_style_from_config(v: &Value) -> Result<TextBoxStyle> {
    let d = normalise("TextBoxStyle", v, TEXT_BOX_KEYS)?;
    let mut s = TextBoxStyle::default();
    if let Some(fs) = num(&d, "font_size")? {
        s.font_size = fs;
    }
    match d.get("font") {
        None | Some(Value::Null) => {}
        Some(Value::String(f)) if f.ends_with(".otf") || f.ends_with(".ttf") => {
            let mut fac = GlyphAccumulatorFactory::new(f);
            if let Some(fs) = num(&d, "font_size")? {
                fac.font_size = fs;
            }
            s.font = FontEngineFactory::OpenType(fac);
        }
        Some(_) => {
            return Err(config_error(
                "'font' must be a path to an OpenType or TrueType font file.",
            ))
        }
    }
    s.leading = num(&d, "leading")?;
    if let Some(b) = num(&d, "border_width")? {
        s.border_width = b;
    }
    if let Some(r) = d.get("box_layout_rule").filter(|v| !v.is_null()) {
        s.box_layout_rule = Some(layout_rule_from_config(r)?);
    }
    if let Some(b) = boolean(&d, "vertical_text")? {
        s.vertical_text = b;
    }
    s.text_color = color(&d, "text_color")?;
    Ok(s)
}

/// A background specification (`_get_background_content`): `__stamp__`,
/// a PDF file (first page) or an image file.
pub fn background_from_config(spec: &Value) -> Result<Content> {
    let Value::String(s) = spec else {
        return Err(config_error("Background specification must be a string"));
    };
    if s == "__stamp__" {
        Ok(super::art::stamp_art_content())
    } else if s.ends_with(".pdf") {
        Ok(Content::ImportedPage(ImportedPdfPage::new(s, 0)))
    } else {
        Ok(Content::Image(PdfImage::open(s)?))
    }
}

const BASE_KEYS: &[&str] = &[
    "border_width",
    "border_color",
    "background",
    "background_layout",
    "background_opacity",
];

fn apply_base(d: &Dict, base: &mut BaseStampStyle) -> Result<()> {
    if let Some(b) = num(d, "border_width")? {
        base.border_width = b;
    }
    if let Some(c) = color(d, "border_color")? {
        base.border_color = Some(c);
    }
    if let Some(bg) = d.get("background").filter(|v| !v.is_null()) {
        base.background = Some(background_from_config(bg)?);
    }
    if let Some(r) = d.get("background_layout").filter(|v| !v.is_null()) {
        base.background_layout = layout_rule_from_config(r)?;
    }
    if let Some(o) = num(d, "background_opacity")? {
        base.background_opacity = o;
    }
    Ok(())
}

const TEXT_KEYS: &[&str] = &["text_box_style", "inner_content_layout", "stamp_text", "timestamp_format"];

fn apply_text(d: &Dict, s: &mut TextStampStyle) -> Result<()> {
    apply_base(d, &mut s.base)?;
    if let Some(t) = d.get("text_box_style").filter(|v| !v.is_null()) {
        s.text_box_style = text_box_style_from_config(t)?;
    }
    if let Some(r) = d.get("inner_content_layout").filter(|v| !v.is_null()) {
        s.inner_content_layout = Some(layout_rule_from_config(r)?);
    }
    if let Some(t) = string(d, "stamp_text")? {
        s.stamp_text = t;
    }
    if let Some(t) = string(d, "timestamp_format")? {
        s.timestamp_format = t;
    }
    Ok(())
}

impl TextStampStyle {
    /// `TextStampStyle.from_config`.
    pub fn from_config(v: &Value) -> Result<Self> {
        let keys: Vec<&str> = BASE_KEYS.iter().chain(TEXT_KEYS).copied().collect();
        let d = normalise("TextStampStyle", v, &keys)?;
        let mut s = Self::default();
        apply_text(&d, &mut s)?;
        Ok(s)
    }
}

impl QrStampStyle {
    /// `QRStampStyle.from_config`.
    pub fn from_config(v: &Value) -> Result<Self> {
        let keys: Vec<&str> = BASE_KEYS
            .iter()
            .chain(TEXT_KEYS)
            .chain(&["innsep", "qr_inner_size", "qr_position"])
            .copied()
            .collect();
        let d = normalise("QRStampStyle", v, &keys)?;
        let mut s = Self::default();
        apply_text(&d, &mut s.text)?;
        if let Some(i) = num(&d, "innsep")? {
            s.innsep = i;
        }
        s.qr_inner_size = num(&d, "qr_inner_size")?;
        if let Some(p) = string(&d, "qr_position")? {
            s.qr_position = QrPosition::from_config(&p)?;
        }
        Ok(s)
    }
}

impl StaticStampStyle {
    /// `StaticStampStyle.from_config`.
    pub fn from_config(v: &Value) -> Result<Self> {
        let d = normalise("StaticStampStyle", v, BASE_KEYS)?;
        let mut s = Self::default();
        apply_base(&d, &mut s.base)?;
        Ok(s)
    }
}
