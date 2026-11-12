// Derived from pyHanko `stamp/` (`__init__.py`, `appearances.py`, `base.py`,
// `noop.py`, `static.py`, `text.py`, `qr.py`, `functions.py`) and
// `sign/signers/cms_embedder.py` (`SigAppearanceSetup`) (MIT, see
// LICENSE-pyHanko).

//! Stamps and visible signature appearances (`pyhanko.stamp`).

pub mod art;
pub mod config;
pub mod strftime;

use std::collections::BTreeMap;
use std::path::Path;

use lopdf::{Dictionary, Object, ObjectId, Stream};
use qrcode::types::EcLevel;
use sigis_pki_core::errors::Result;
use sigis_pki_core::time::Moment;

use crate::content::ops::{fmt_g, rd, text_string_literal, uuid4};
use crate::content::{
    add_stream_to_page, compressed, init_xobject_dictionary, AnnotAppearances, Content,
    ContentWriter, ImportedPdfPage, PdfContent, PdfResources, ResourceType,
};
use crate::layout::{
    layout_error, AxisAlignment, BoxConstraints, InnerScaling, Margins, Positioning,
    SimpleBoxLayoutRule,
};
use crate::pdf::writer::PdfUpdate;
use crate::qr::{make_qr, render_qr_stream, FancyQrImage};
use crate::text::{TextBox, TextBoxStyle, DEFAULT_BOX_LAYOUT};

pub use art::{stamp_art_content, STAMP_ART_DATA};

/// Positioning convention for stamps (`CoordinateSystem`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CoordinateSystem {
    /// The page's default coordinate system: existing content is wrapped
    /// in `q`/`Q` (the default since pyHanko 0.27.0).
    #[default]
    PageDefault,
    /// The ambient frame of reference set by the existing page content.
    Ambient,
}

/// Settings shared by all stamp styles (`BaseStampStyle`).
#[derive(Clone, Debug)]
pub struct BaseStampStyle {
    /// Border width of the stamp.
    pub border_width: f64,
    /// Border colour (RGB).
    pub border_color: Option<[f64; 3]>,
    /// Background content.
    pub background: Option<Content>,
    /// Layout of the background (if its size is known).
    pub background_layout: SimpleBoxLayoutRule,
    /// Background opacity.
    pub background_opacity: f64,
}

impl Default for BaseStampStyle {
    fn default() -> Self {
        Self {
            border_width: 3.0,
            border_color: None,
            background: None,
            background_layout: SimpleBoxLayoutRule::new(
                AxisAlignment::AlignMid,
                AxisAlignment::AlignMid,
            )
            .with_margins(Margins::uniform(5.0)),
            background_opacity: 0.6,
        }
    }
}

/// Text stamps (`TextStampStyle`).
#[derive(Clone, Debug)]
pub struct TextStampStyle {
    /// Common settings.
    pub base: BaseStampStyle,
    /// Style of the text box.
    pub text_box_style: TextBoxStyle,
    /// Position of the text box within the stamp.
    pub inner_content_layout: Option<SimpleBoxLayoutRule>,
    /// Text template with `%(name)s` parameters; `ts` is the time.
    pub stamp_text: String,
    /// `strftime` format of the time (rendered in UTC).
    pub timestamp_format: String,
}

impl Default for TextStampStyle {
    fn default() -> Self {
        Self {
            base: BaseStampStyle::default(),
            text_box_style: TextBoxStyle::default(),
            inner_content_layout: None,
            stamp_text: "%(ts)s".into(),
            timestamp_format: "%Y-%m-%d %H:%M:%S %Z".into(),
        }
    }
}

impl TextStampStyle {
    /// A style with the given template.
    pub fn with_text(text: impl Into<String>) -> Self {
        Self {
            stamp_text: text.into(),
            ..Self::default()
        }
    }
}

/// Position of a QR code relative to the text (`QRPosition`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QrPosition {
    /// Left of the text.
    #[default]
    LeftOfText,
    /// Right of the text.
    RightOfText,
    /// Above the text.
    AboveText,
    /// Below the text.
    BelowText,
}

impl QrPosition {
    /// All positions, in pyHanko's order.
    pub const ALL: [QrPosition; 4] = [
        Self::LeftOfText,
        Self::RightOfText,
        Self::AboveText,
        Self::BelowText,
    ];

    /// The default content layout rule of the position.
    pub fn layout_rule(self) -> SimpleBoxLayoutRule {
        use AxisAlignment::*;
        match self {
            Self::LeftOfText => SimpleBoxLayoutRule::new(AlignMin, AlignMid),
            Self::RightOfText => SimpleBoxLayoutRule::new(AlignMax, AlignMid),
            Self::AboveText => SimpleBoxLayoutRule::new(AlignMid, AlignMax),
            Self::BelowText => SimpleBoxLayoutRule::new(AlignMid, AlignMin),
        }
    }

    /// QR code and text side by side.
    pub fn horizontal_flow(self) -> bool {
        matches!(self, Self::LeftOfText | Self::RightOfText)
    }

    /// Parse `left`, `right`, `top` or `bottom`.
    pub fn from_config(s: &str) -> Result<Self> {
        Ok(match s.to_lowercase().as_str() {
            "left" => Self::LeftOfText,
            "right" => Self::RightOfText,
            "top" => Self::AboveText,
            "bottom" => Self::BelowText,
            _ => {
                return Err(config::config_error(format!(
                    "'{s}' is not a valid QR position setting; valid values are 'left', 'right', 'top', 'bottom'"
                )))
            }
        })
    }
}

/// Scale of QR codes without other size constraints (`DEFAULT_QR_SCALE`).
pub const DEFAULT_QR_SCALE: f64 = 0.2;

/// Text stamps with a QR code (`QRStampStyle`).
#[derive(Clone, Debug)]
pub struct QrStampStyle {
    /// The text part (template default: `Digital version available at\nthis
    /// url: %(url)s\nTimestamp: %(ts)s`).
    pub text: TextStampStyle,
    /// Inner separation.
    pub innsep: f64,
    /// Size of the QR code in the inner layout.
    pub qr_inner_size: Option<f64>,
    /// Position of the QR code.
    pub qr_position: QrPosition,
    /// Content drawn in the centre of the QR code (experimental).
    pub qr_inner_content: Option<Content>,
}

impl Default for QrStampStyle {
    fn default() -> Self {
        Self {
            text: TextStampStyle::with_text(
                "Digital version available at\nthis url: %(url)s\nTimestamp: %(ts)s",
            ),
            innsep: 3.0,
            qr_inner_size: None,
            qr_position: QrPosition::LeftOfText,
            qr_inner_content: None,
        }
    }
}

impl QrStampStyle {
    /// A style with the given template.
    pub fn with_text(text: impl Into<String>) -> Self {
        let mut s = Self::default();
        s.text.stamp_text = text.into();
        s
    }
}

/// Stamps that only render their background (`StaticStampStyle`).
#[derive(Clone, Debug)]
pub struct StaticStampStyle {
    /// Common settings (background opacity 1 by default).
    pub base: BaseStampStyle,
}

impl Default for StaticStampStyle {
    fn default() -> Self {
        Self {
            base: BaseStampStyle {
                background_opacity: 1.0,
                ..BaseStampStyle::default()
            },
        }
    }
}

impl StaticStampStyle {
    /// A page of a PDF file as the stamp (`from_pdf_file`).
    pub fn from_pdf_file(file_name: impl AsRef<Path>, page_ix: usize) -> Self {
        let mut s = Self::default();
        s.base.background = Some(Content::ImportedPage(ImportedPdfPage::new(
            file_name.as_ref(),
            page_ix,
        )));
        s
    }
}

/// A stamp style (`BaseStampStyle` and its subclasses).
#[derive(Clone, Debug)]
pub enum StampStyle {
    /// Text stamp (`TextStampStyle`).
    Text(TextStampStyle),
    /// Text and QR code (`QRStampStyle`).
    Qr(QrStampStyle),
    /// Background only (`StaticStampStyle`).
    Static(StaticStampStyle),
    /// No stamp: keep the existing appearance (`NoOpStampStyle`).
    NoOp,
}

/// The default stamp of visible signatures (`DEFAULT_SIGNING_STAMP_STYLE`).
pub fn default_signing_stamp_style() -> StampStyle {
    let mut s = TextStampStyle::with_text("Digitally signed by %(signer)s.\nTimestamp: %(ts)s.");
    s.base.background = Some(stamp_art_content());
    StampStyle::Text(s)
}

impl StampStyle {
    /// Create a stamp of size `bbox` (`create_stamp`); `None` for
    /// [`StampStyle::NoOp`]. QR styles take the URL from the `url` text
    /// parameter.
    pub fn create_stamp(
        &self,
        bbox: BoxConstraints,
        text_params: &BTreeMap<String, String>,
    ) -> Result<Option<Stamp>> {
        Ok(match self {
            Self::Text(s) => Some(Stamp::text(
                s.clone(),
                Some(bbox),
                Some(text_params.clone()),
            )),
            Self::Qr(s) => {
                let mut params = text_params.clone();
                let url = params.remove("url").ok_or_else(|| {
                    layout_error("Using a QR stamp style requires a 'url' text parameter.")
                })?;
                Some(Stamp::qr(s.clone(), url, Some(bbox), Some(params)))
            }
            Self::Static(s) => Some(Stamp::static_content(s.clone(), bbox)?),
            Self::NoOp => None,
        })
    }

    fn base(&self) -> Option<&BaseStampStyle> {
        match self {
            Self::Text(s) => Some(&s.base),
            Self::Qr(s) => Some(&s.text.base),
            Self::Static(s) => Some(&s.base),
            Self::NoOp => None,
        }
    }
}

/// Interpolate `%(name)s` parameters (Python's `template % params`).
pub fn interpolate(template: &str, params: &BTreeMap<String, String>) -> Result<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        if let Some(r) = after.strip_prefix('%') {
            out.push('%');
            rest = r;
            continue;
        }
        let Some(r) = after.strip_prefix('(') else {
            return Err(layout_error(
                "Stamp text contains an unsupported format specifier",
            ));
        };
        let close = r
            .find(')')
            .ok_or_else(|| layout_error("Stamp text contains an incomplete format key"))?;
        let key = &r[..close];
        let spec = &r[close + 1..];
        let Some(spec_rest) = spec.strip_prefix('s').or_else(|| spec.strip_prefix('r')) else {
            return Err(layout_error(
                "Stamp text contains an unsupported format specifier",
            ));
        };
        let v = params
            .get(key)
            .ok_or_else(|| layout_error(format!("Stamp text parameter '{key}' is missing")))?;
        if spec.starts_with('r') {
            out.push('\'');
            out.push_str(v);
            out.push('\'');
        } else {
            out.push_str(v);
        }
        rest = spec_rest;
    }
    out.push_str(rest);
    Ok(out)
}

/// Inner content operators and natural size.
type InnerLayout = (Vec<Vec<u8>>, (f64, f64));

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
enum StampKind {
    Text(TextStampStyle),
    Qr(QrStampStyle, String),
    Static(StaticStampStyle),
}

/// A stamp (`TextStamp`, `QRStamp`, `StaticContentStamp`).
#[derive(Debug)]
pub struct Stamp {
    kind: StampKind,
    text_params: Option<BTreeMap<String, String>>,
    bbox: BoxConstraints,
    resources: PdfResources,
    text_box: Option<TextBox>,
    xobj_ref: Option<ObjectId>,
    /// Time used for the default `ts` parameter (the current time if not
    /// set).
    pub time: Option<Moment>,
}

impl Stamp {
    fn new(
        kind: StampKind,
        bbox: Option<BoxConstraints>,
        text_params: Option<BTreeMap<String, String>>,
    ) -> Self {
        Self {
            kind,
            text_params,
            bbox: bbox.unwrap_or_default(),
            resources: PdfResources::default(),
            text_box: None,
            xobj_ref: None,
            time: None,
        }
    }

    /// A text stamp (`TextStamp`).
    pub fn text(
        style: TextStampStyle,
        bbox: Option<BoxConstraints>,
        text_params: Option<BTreeMap<String, String>>,
    ) -> Self {
        Self::new(StampKind::Text(style), bbox, text_params)
    }

    /// A QR stamp pointing to `url` (`QRStamp`).
    pub fn qr(
        style: QrStampStyle,
        url: impl Into<String>,
        bbox: Option<BoxConstraints>,
        text_params: Option<BTreeMap<String, String>>,
    ) -> Self {
        Self::new(StampKind::Qr(style, url.into()), bbox, text_params)
    }

    /// A static stamp (`StaticContentStamp`); the box must be fully
    /// determined.
    pub fn static_content(style: StaticStampStyle, bbox: BoxConstraints) -> Result<Self> {
        if !(bbox.width_defined() && bbox.height_defined()) {
            return Err(layout_error(
                "StaticContentStamp requires a predetermined bounding box.",
            ));
        }
        Ok(Self::new(StampKind::Static(style), Some(bbox), None))
    }

    /// The internal text box, once laid out.
    pub fn text_box(&self) -> Option<&TextBox> {
        self.text_box.as_ref()
    }

    fn base(&self) -> &BaseStampStyle {
        match &self.kind {
            StampKind::Text(s) => &s.base,
            StampKind::Qr(s, _) => &s.text.base,
            StampKind::Static(s) => &s.base,
        }
    }

    fn text_style(&self) -> Option<&TextStampStyle> {
        match &self.kind {
            StampKind::Text(s) => Some(s),
            StampKind::Qr(s, _) => Some(&s.text),
            StampKind::Static(_) => None,
        }
    }

    /// Default interpolation parameters (`get_default_text_params`): `ts`,
    /// and `url` for QR stamps.
    pub fn default_text_params(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        if let Some(s) = self.text_style() {
            let t = self.time.unwrap_or_else(Moment::now);
            m.insert("ts".into(), strftime::strftime(t, &s.timestamp_format));
        }
        if let StampKind::Qr(_, url) = &self.kind {
            m.insert("url".into(), url.clone());
        }
        m
    }

    fn text_layout(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        let style = self.text_style().cloned().unwrap_or_default();
        let mut tb = TextBox::new(style.text_box_style.clone(), w, None)?;
        let mut params = self.default_text_params();
        if let Some(p) = &self.text_params {
            params.extend(p.clone());
        }
        let text = interpolate(&style.stamp_text, &params)?;
        tb.set_content(w, &text)?;
        let out = tb.render_into(w, &mut self.resources)?;
        self.text_box = Some(tb);
        Ok(out)
    }

    fn text_natural(&mut self, w: &mut ContentWriter<'_>) -> Result<InnerLayout> {
        let cmds = self.text_layout(w)?;
        let b = self
            .text_box
            .as_ref()
            .map(|t| t.bbox().clone())
            .unwrap_or_default();
        Ok((vec![cmds], (b.width()?, b.height()?)))
    }

    fn qr_xobject(
        &mut self,
        w: &mut ContentWriter<'_>,
        style: &QrStampStyle,
        url: &str,
    ) -> Result<(ObjectId, f64)> {
        let fancy = style.qr_inner_content.is_some();
        let qr = make_qr(url, if fancy { EcLevel::H } else { EcLevel::M })?;
        let cmd = if fancy {
            let mut center = style.qr_inner_content.clone();
            FancyQrImage::new(&qr)
                .render_command_stream(center.as_mut().map(|c| c as &mut dyn PdfContent), w)?
        } else {
            render_qr_stream(&qr)
        };
        let size = ((qr.modules_count() as u32 + 2 * qr.border) * qr.box_size) as f64;
        let xobj = compressed(init_xobject_dictionary(cmd, size, size, None));
        Ok((w.add(Object::Stream(xobj)), size))
    }

    /// The inner content and its natural size (`_inner_layout_natural_size`).
    pub fn inner_layout_natural_size(&mut self, w: &mut ContentWriter<'_>) -> Result<InnerLayout> {
        let (style, url) = match &self.kind {
            StampKind::Qr(s, u) => (s.clone(), u.clone()),
            _ => return self.text_natural(w),
        };
        let (text_commands, (text_width, text_height)) = self.text_natural(w)?;
        let (qr_ref, natural_qr_size) = self.qr_xobject(w, &style, &url)?;
        self.resources
            .set(ResourceType::XObject, "QR", Object::Reference(qr_ref));
        let innsep = style.innsep;
        let stamp_box = &self.bbox;
        let qr_size = if let Some(s) = style.qr_inner_size {
            s
        } else if stamp_box.width_defined() && stamp_box.height_defined() {
            let min_dim = stamp_box
                .height()?
                .max(text_height)
                .min(stamp_box.width()?.max(text_width));
            min_dim - 2.0 * innsep
        } else {
            (DEFAULT_QR_SCALE * natural_qr_size).round_ties_even()
        };
        let qr_innunits_scale = qr_size / natural_qr_size;
        let qr_padded = qr_size + 2.0 * innsep;
        let (inn_width, inn_height) = if style.qr_position.horizontal_flow() {
            (qr_padded + text_width, qr_padded.max(text_height))
        } else {
            (qr_padded.max(text_width), qr_padded + text_height)
        };
        let default_layout = style.qr_position.layout_rule();
        let qr_layout_rule = SimpleBoxLayoutRule {
            x_align: default_layout.x_align,
            y_align: default_layout.y_align,
            margins: Margins::uniform(innsep),
            inner_content_scaling: InnerScaling::NoScaling,
        };
        let mut inner_box = BoxConstraints::fixed(inn_width, inn_height);
        let qr_inn_pos = qr_layout_rule.fit(&mut inner_box, qr_size, qr_size)?;
        let draw_qr = format!(
            "q {} 0 0 {} {} {} cm /QR Do Q",
            fmt_g(qr_inn_pos.x_scale * qr_innunits_scale),
            fmt_g(qr_inn_pos.y_scale * qr_innunits_scale),
            fmt_g(qr_inn_pos.x_pos),
            fmt_g(qr_inn_pos.y_pos)
        )
        .into_bytes();
        let mut tb_margins = Margins::default();
        match style.qr_position {
            QrPosition::LeftOfText => tb_margins.left = qr_padded,
            QrPosition::RightOfText => tb_margins.right = qr_padded,
            QrPosition::BelowText => tb_margins.bottom = qr_padded,
            QrPosition::AboveText => tb_margins.top = qr_padded,
        }
        let tb_layout_rule = SimpleBoxLayoutRule {
            x_align: default_layout.x_align.flipped(),
            y_align: default_layout.y_align.flipped(),
            margins: tb_margins,
            inner_content_scaling: InnerScaling::NoScaling,
        };
        let text_inn_pos = tb_layout_rule.fit(&mut inner_box, text_width, text_height)?;
        let mut commands = vec![draw_qr, b"q".to_vec(), text_inn_pos.as_cm()];
        commands.extend(text_commands);
        commands.push(b"Q".to_vec());
        Ok((commands, (inn_width, inn_height)))
    }

    fn inner_content_layout_rule(&self) -> SimpleBoxLayoutRule {
        match &self.kind {
            StampKind::Qr(s, _) => s
                .text
                .inner_content_layout
                .unwrap_or_else(|| s.qr_position.layout_rule()),
            StampKind::Text(s) => s.inner_content_layout.unwrap_or(DEFAULT_BOX_LAYOUT),
            StampKind::Static(_) => DEFAULT_BOX_LAYOUT,
        }
    }

    fn render_inner_content(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<Vec<u8>>> {
        if matches!(self.kind, StampKind::Static(_)) {
            return Ok(Vec::new());
        }
        let (inn_commands, (inn_width, inn_height)) = self.inner_layout_natural_size(w)?;
        let rule = self.inner_content_layout_rule();
        let pos = rule.fit(&mut self.bbox, inn_width, inn_height)?;
        let mut cs = vec![b"q".to_vec(), pos.as_cm()];
        cs.extend(inn_commands);
        cs.push(b"Q".to_vec());
        Ok(cs)
    }

    fn render_background(&mut self, w: &mut ContentWriter<'_>) -> Result<Option<Vec<u8>>> {
        let Some(mut bg) = self.base().background.clone() else {
            return Ok(None);
        };
        let layout = self.base().background_layout;
        let opacity = self.base().background_opacity;
        let bg_content = bg.render(w)?;
        let bg_box = bg.bbox().clone();
        let positioning = if bg_box.width_defined() && bg_box.height_defined() {
            layout.fit(&mut self.bbox, bg_box.width()?, bg_box.height()?)?
        } else {
            Positioning {
                x_scale: 1.0,
                y_scale: 1.0,
                x_pos: layout.margins.left,
                y_pos: layout.margins.bottom,
            }
        };
        let mut gs = Dictionary::new();
        gs.set("CA", Object::Real(opacity as f32));
        gs.set("ca", Object::Real(opacity as f32));
        self.resources.set(
            ResourceType::ExtGState,
            "BackgroundGS",
            Object::Dictionary(gs),
        );
        let mut cmd = b"q /BackgroundGS gs ".to_vec();
        cmd.extend(positioning.as_cm());
        cmd.push(b' ');
        cmd.extend(bg_content);
        cmd.extend_from_slice(b" Q");
        self.resources.merge(bg.resources())?;
        Ok(Some(cmd))
    }

    /// Register the stamp as a form XObject (cached) (`register`).
    pub fn register(&mut self, w: &mut ContentWriter<'_>) -> Result<ObjectId> {
        if let Some(r) = self.xobj_ref {
            return Ok(r);
        }
        let x = self.as_form_xobject(w)?;
        let r = w.add(Object::Stream(x));
        self.xobj_ref = Some(r);
        Ok(r)
    }

    /// The appearance dictionary (`as_appearances`).
    pub fn as_appearances(&mut self, w: &mut ContentWriter<'_>) -> Result<AnnotAppearances> {
        Ok(AnnotAppearances {
            normal: self.register(w)?,
            rollover: None,
            down: None,
        })
    }

    /// Use the stamp as the appearance of `annot` (`apply_appearance`).
    pub fn apply_appearance(&mut self, w: &mut ContentWriter<'_>, annot: ObjectId) -> Result<()> {
        let ap = self.as_appearances(w)?;
        let d = w.update().get_dict_mut(annot)?;
        d.set("AP", Object::Dictionary(ap.as_pdf_object()));
        d.remove(b"AS");
        Ok(())
    }

    /// Put the stamp on page `dest_page` with its lower left corner at
    /// `(x, y)` (`apply`); returns the page and the stamp's size. QR stamps
    /// also get a link annotation.
    pub fn apply(
        &mut self,
        w: &mut ContentWriter<'_>,
        dest_page: i64,
        x: f64,
        y: f64,
        coords: CoordinateSystem,
    ) -> Result<(ObjectId, (f64, f64))> {
        let stamp_ref = self.register(w)?;
        let resource_name = format!("Stamp{}", uuid4(false));
        let paint = format!(
            "q 1 0 0 1 {} {} cm /{resource_name} Do Q",
            fmt_g(rd(x)),
            fmt_g(rd(y))
        );
        let wrapper = w.add(Object::Stream(Stream::new(
            Dictionary::new(),
            paint.into_bytes(),
        )));
        let mut xobjs = Dictionary::new();
        xobjs.set(
            resource_name.as_bytes().to_vec(),
            Object::Reference(stamp_ref),
        );
        let mut resources = Dictionary::new();
        resources.set("XObject", Object::Dictionary(xobjs));
        if coords == CoordinateSystem::PageDefault {
            let q = w.add(Object::Stream(Stream::new(
                Dictionary::new(),
                b"q".to_vec(),
            )));
            add_stream_to_page(w.update(), dest_page, q, None, true)?;
            let qq = w.add(Object::Stream(Stream::new(
                Dictionary::new(),
                b"Q".to_vec(),
            )));
            add_stream_to_page(w.update(), dest_page, qq, None, false)?;
        }
        let page_ref = add_stream_to_page(w.update(), dest_page, wrapper, Some(resources), false)?;
        let dims = (self.bbox.width()?, self.bbox.height()?);
        if let StampKind::Qr(_, url) = &self.kind {
            let mut link = Dictionary::new();
            link.set("Type", Object::Name(b"Annot".to_vec()));
            link.set("Subtype", Object::Name(b"Link".to_vec()));
            link.set(
                "Rect",
                Object::Array(
                    [x, y, x + dims.0, y + dims.1]
                        .into_iter()
                        .map(|v| Object::Real(v as f32))
                        .collect(),
                ),
            );
            let mut action = Dictionary::new();
            action.set("S", Object::Name(b"URI".to_vec()));
            action.set("URI", crate::pdf::util::text_string(url));
            link.set("A", Object::Dictionary(action));
            let link_id = w.add(Object::Dictionary(link));
            w.update().register_annotation(page_ref, link_id)?;
        }
        Ok((page_ref, dims))
    }
}

impl PdfContent for Stamp {
    /// `BaseStamp.render`.
    fn render(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        let mut cs: Vec<Vec<u8>> = vec![b"q".to_vec()];
        let inner = self.render_inner_content(w)?;
        if let Some(bg) = self.render_background(w)? {
            cs.push(bg);
        }
        cs.extend(inner);
        let base = self.base().clone();
        if base.border_width != 0.0 {
            if let Some([r, g, b]) = base.border_color {
                cs.push(format!("{} {} {} RG", fmt_g(r), fmt_g(g), fmt_g(b)).into_bytes());
            }
            cs.push(
                format!(
                    "{} w 0 0 {} {} re S",
                    fmt_g(base.border_width),
                    fmt_g(self.bbox.width()?),
                    fmt_g(self.bbox.height()?)
                )
                .into_bytes(),
            );
        }
        cs.push(b"Q".to_vec());
        Ok(cs.join(&b" "[..]))
    }
    fn resources(&self) -> &PdfResources {
        &self.resources
    }
    fn resources_mut(&mut self) -> &mut PdfResources {
        &mut self.resources
    }
    fn bbox(&self) -> &BoxConstraints {
        &self.bbox
    }
    fn bbox_mut(&mut self) -> &mut BoxConstraints {
        &mut self.bbox
    }
}

/// Generate the appearance of a visible signature widget
/// (`SigAppearanceSetup.apply`). `style` defaults to
/// [`default_signing_stamp_style`]; `signer` becomes the `signer`
/// parameter and the time is rendered as `ts`.
#[allow(clippy::too_many_arguments)]
pub fn apply_signature_appearance(
    update: &mut PdfUpdate,
    annot: ObjectId,
    w: f64,
    h: f64,
    style: Option<&StampStyle>,
    signer_name: Option<&str>,
    timestamp: Moment,
    text_params: &BTreeMap<String, String>,
) -> Result<()> {
    if w == 0.0 || h == 0.0 {
        return Ok(());
    }
    let default_style;
    let style = match style {
        Some(s) => s,
        None => {
            default_style = default_signing_stamp_style();
            &default_style
        }
    };
    let mut params = BTreeMap::new();
    if let Some(n) = signer_name {
        params.insert("signer".to_owned(), n.to_owned());
    }
    params.extend(text_params.clone());
    let ts_format = match style {
        StampStyle::Text(s) => Some(&s.timestamp_format),
        StampStyle::Qr(s) => Some(&s.text.timestamp_format),
        _ => None,
    };
    if let Some(f) = ts_format {
        params.insert("ts".into(), strftime::strftime(timestamp, f));
    }
    let _ = style.base();
    let mut cw = ContentWriter::new(update);
    let bbox = BoxConstraints::new(Some(w), Some(h), None)?;
    if let Some(mut stamp) = style.create_stamp(bbox, &params)? {
        stamp.time = Some(timestamp);
        stamp.apply_appearance(&mut cw, annot)?;
    }
    cw.prepare_write()
}

fn stamp_file(
    input: &Path,
    output: &Path,
    mut stamp: Stamp,
    dest_page: i64,
    x: f64,
    y: f64,
) -> Result<()> {
    let data = std::fs::read(input)?;
    let mut update = PdfUpdate::new(&data)?;
    let mut w = ContentWriter::new(&mut update);
    stamp.apply(&mut w, dest_page, x, y, CoordinateSystem::PageDefault)?;
    let out = w.write()?;
    std::fs::write(output, out)?;
    Ok(())
}

/// Add a text stamp to a file (`text_stamp_file`).
pub fn text_stamp_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    style: &TextStampStyle,
    dest_page: i64,
    x: f64,
    y: f64,
    text_params: Option<BTreeMap<String, String>>,
) -> Result<()> {
    let stamp = Stamp::text(style.clone(), None, text_params);
    stamp_file(input.as_ref(), output.as_ref(), stamp, dest_page, x, y)
}

/// Add a QR stamp to a file (`qr_stamp_file`).
#[allow(clippy::too_many_arguments)]
pub fn qr_stamp_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    style: &QrStampStyle,
    dest_page: i64,
    x: f64,
    y: f64,
    url: &str,
    text_params: Option<BTreeMap<String, String>>,
) -> Result<()> {
    let stamp = Stamp::qr(style.clone(), url, None, text_params);
    stamp_file(input.as_ref(), output.as_ref(), stamp, dest_page, x, y)
}

/// The serialized form of a text string in content streams (re-exported
/// for callers that build their own operators).
pub fn pdf_text(s: &str) -> Vec<u8> {
    text_string_literal(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolation() {
        let mut p = BTreeMap::new();
        p.insert("ts".to_owned(), "now".to_owned());
        assert_eq!(
            interpolate("Hi, it's\n%(ts)s 100%%", &p).unwrap(),
            "Hi, it's\nnow 100%"
        );
        let e = interpolate("%(foo)s missing", &p).unwrap_err();
        assert!(e
            .to_string()
            .contains("Stamp text parameter 'foo' is missing"));
    }
}
