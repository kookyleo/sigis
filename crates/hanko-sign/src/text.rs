// Derived from pyHanko `pdf_utils/text.py` (MIT, see LICENSE-pyHanko).

//! Text rendering and layout (`pyhanko.pdf_utils.text`).

use hanko_core::errors::Result;

use crate::content::ops::fmt_g;
use crate::content::{ContentWriter, PdfContent, PdfResources, ResourceType};
use crate::font::{FontEngineFactory, FontHandle};
use crate::layout::{AxisAlignment, BoxConstraints, Margins, SimpleBoxLayoutRule};

/// Text styling (`TextStyle`) and text box settings (`TextBoxStyle`).
#[derive(Clone, Debug, PartialEq)]
pub struct TextBoxStyle {
    /// The font; Courier (non-embedded) by default.
    pub font: FontEngineFactory,
    /// Font size.
    pub font_size: f64,
    /// Leading; the font size if `None`.
    pub leading: Option<f64>,
    /// Border width.
    pub border_width: f64,
    /// Rule to nest the text within its box; the default is centered with
    /// margins of [`DEFAULT_TEXT_BOX_MARGIN`].
    pub box_layout_rule: Option<SimpleBoxLayoutRule>,
    /// Vertical instead of horizontal layout.
    pub vertical_text: bool,
    /// Text colour (RGB, components between 0 and 1).
    pub text_color: Option<[f64; 3]>,
}

impl Default for TextBoxStyle {
    fn default() -> Self {
        Self {
            font: FontEngineFactory::default(),
            font_size: 10.0,
            leading: None,
            border_width: 0.0,
            box_layout_rule: None,
            vertical_text: false,
            text_color: None,
        }
    }
}

/// Centered, shrink-to-fit (`DEFAULT_BOX_LAYOUT`).
pub const DEFAULT_BOX_LAYOUT: SimpleBoxLayoutRule =
    SimpleBoxLayoutRule::new(AxisAlignment::AlignMid, AxisAlignment::AlignMid);

/// Default margin of text boxes (`DEFAULT_TEXT_BOX_MARGIN`).
pub const DEFAULT_TEXT_BOX_MARGIN: f64 = 10.0;

/// A text box (`TextBox`). Text boxes do not wrap words.
#[derive(Debug)]
pub struct TextBox {
    /// The style.
    pub style: TextBoxStyle,
    /// Resource name of the font.
    pub font_name: String,
    font_engine: FontHandle,
    resources: PdfResources,
    bbox: BoxConstraints,
    content: Option<String>,
    wrapped_lines: Vec<Vec<u8>>,
    nat_text_width: f64,
    nat_text_height: f64,
}

impl TextBox {
    /// A text box with the given style and box (natural size if `None`);
    /// creates the font engine (`TextBox.__init__`).
    pub fn new(style: TextBoxStyle, w: &mut ContentWriter<'_>, bbox: Option<BoxConstraints>) -> Result<Self> {
        let font_engine = style.font.create_font_engine(w)?;
        // keep the engine's positioning in sync with the Tf operator
        w.font(font_engine)?.set_font_size(style.font_size);
        Ok(Self {
            style,
            font_name: "F1".into(),
            font_engine,
            resources: PdfResources::default(),
            bbox: bbox.unwrap_or_default(),
            content: None,
            wrapped_lines: Vec::new(),
            nat_text_width: 0.0,
            nat_text_height: 0.0,
        })
    }

    /// The font engine.
    pub fn font_engine(&self) -> FontHandle {
        self.font_engine
    }

    /// The effective leading.
    pub fn leading(&self) -> f64 {
        self.style.leading.unwrap_or(self.style.font_size)
    }

    fn put_string_line(&self, w: &mut ContentWriter<'_>, txt: &str) -> Result<(Vec<u8>, f64)> {
        let font_size = self.style.font_size;
        let engine = w.font(self.font_engine)?;
        let shaped = engine.shape(txt)?;
        let x_advance = shaped.x_advance * font_size;
        let y_advance = shaped.y_advance * font_size;
        let mut ops = shaped.graphics_ops;
        let extent;
        if engine.uses_complex_positioning() {
            let mut newline_x = -x_advance;
            let mut newline_y = -y_advance;
            let leading = self.leading();
            if self.style.vertical_text {
                newline_x -= leading;
                extent = y_advance.abs();
            } else {
                newline_y -= leading;
                extent = x_advance.abs();
            }
            ops.extend_from_slice(format!(" {} {} Td", fmt_g(newline_x), fmt_g(newline_y)).as_bytes());
        } else {
            ops.extend_from_slice(b" T*");
            extent = x_advance.abs();
        }
        Ok((ops, extent))
    }

    /// The text (`content`).
    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    /// The text, split into lines (`content_lines`).
    pub fn content_lines(&self) -> Vec<&str> {
        self.content.as_deref().map(|c| c.split('\n').collect()).unwrap_or_default()
    }

    /// Set the text; shapes every line and computes the natural size.
    pub fn set_content(&mut self, w: &mut ContentWriter<'_>, content: &str) -> Result<()> {
        let leading = self.leading();
        let (mut nat_w, mut nat_h) = (0.0f64, 0.0f64);
        let mut lines = Vec::new();
        for line in content.split('\n') {
            let (ops, extent) = self.put_string_line(w, line)?;
            let rounded = extent.round_ties_even();
            if self.style.vertical_text {
                nat_h = nat_h.max(rounded);
                nat_w += leading;
            } else {
                nat_w = nat_w.max(rounded);
                nat_h += leading;
            }
            lines.push(ops);
        }
        self.wrapped_lines = lines;
        self.content = Some(content.to_owned());
        self.nat_text_width = nat_w;
        self.nat_text_height = nat_h;
        Ok(())
    }

    /// The `/DA`-style font selection (`da_string`).
    pub fn da_string(&self) -> Vec<u8> {
        format!(
            "/{} {} Tf {} TL",
            self.font_name,
            self.style.font_size.trunc() as i64,
            self.leading().trunc() as i64
        )
        .into_bytes()
    }

    /// Render into `resources` instead of the box's own resources (used
    /// when the box is part of a stamp, whose resources it shares).
    pub fn render_into(&mut self, w: &mut ContentWriter<'_>, resources: &mut PdfResources) -> Result<Vec<u8>> {
        let font_res = w.font_resource(self.font_engine)?;
        resources.set(ResourceType::Font, &self.font_name, font_res);
        let style = &self.style;
        let leading = self.leading();
        let box_layout = style.box_layout_rule.unwrap_or_else(|| {
            DEFAULT_BOX_LAYOUT.substitute_margins(Margins::uniform(DEFAULT_TEXT_BOX_MARGIN))
        });
        let positioning = box_layout.fit(&mut self.bbox, self.nat_text_width, self.nat_text_height)?;
        let mut cs: Vec<Vec<u8>> = Vec::new();
        if style.border_width != 0.0 {
            cs.push(
                format!(
                    "q {} w 0 0 {} {} re S Q",
                    fmt_g(style.border_width),
                    fmt_g(self.bbox.width()?),
                    fmt_g(self.bbox.height()?)
                )
                .into_bytes(),
            );
        }
        cs.push(positioning.as_cm());
        if let Some([r, g, b]) = style.text_color {
            cs.push(format!("{} {} {} rg", fmt_g(r), fmt_g(g), fmt_g(b)).into_bytes());
        }
        let da = self.da_string();
        cs.push(b"/Tx BMC q".to_vec());
        cs.push(b"BT".to_vec());
        cs.push(da.clone());
        cs.push(da);
        let start = if style.vertical_text {
            format!(
                "{} {} Td",
                fmt_g(self.nat_text_width * positioning.x_scale - leading / 2.0),
                fmt_g(self.nat_text_height * positioning.y_scale)
            )
        } else {
            format!("0 {} Td", fmt_g(self.nat_text_height * positioning.y_scale - leading))
        };
        cs.push(start.into_bytes());
        cs.extend(self.wrapped_lines.iter().cloned());
        cs.push(b"ET Q EMC".to_vec());
        Ok(cs.join(&b" "[..]))
    }
}

impl PdfContent for TextBox {
    fn render(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        let mut res = std::mem::take(&mut self.resources);
        let out = self.render_into(w, &mut res);
        self.resources = res;
        out
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
