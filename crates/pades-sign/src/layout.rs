// Derived from pyHanko `pdf_utils/layout.py` (MIT, see LICENSE-pyHanko).

//! Layout utilities (`pyhanko.pdf_utils.layout`): boxes, alignment, margins
//! and scaling rules.

use sigis_pki_core::errors::{HankoError, Result};

use crate::content::ops::{fmt_g, py_num};

/// Prefix of the messages of layout errors (`LayoutError`).
pub const LAYOUT_ERROR_PREFIX: &str = "layout error: ";

/// A layout error (`LayoutError`), reported as [`HankoError::Layout`].
pub fn layout_error(msg: impl AsRef<str>) -> HankoError {
    HankoError::Layout(msg.as_ref().to_owned())
}

/// `true` if `e` is a layout error (`isinstance(e, LayoutError)`).
pub fn is_layout_error(e: &HankoError) -> bool {
    matches!(e, HankoError::Layout(_))
}

/// `BoxSpecificationError`.
pub fn box_specification_error() -> HankoError {
    layout_error("box constraint is over/underspecified")
}

/// A non-negative rational number (`fractions.Fraction`), for aspect ratios.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fraction {
    num: i64,
    den: i64,
}

fn gcd(a: i64, b: i64) -> i64 {
    let (mut a, mut b) = (a.abs(), b.abs());
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

impl Fraction {
    /// `num / den` in lowest terms; `None` if `den` is zero.
    pub fn new(num: i64, den: i64) -> Option<Self> {
        if den == 0 {
            return None;
        }
        let g = gcd(num, den).max(1);
        let sign = if den < 0 { -1 } else { 1 };
        Some(Self {
            num: sign * num / g,
            den: sign * den / g,
        })
    }

    /// Numerator.
    pub fn numerator(&self) -> i64 {
        self.num
    }

    /// Denominator.
    pub fn denominator(&self) -> i64 {
        self.den
    }

    /// The value as a float.
    pub fn as_f64(&self) -> f64 {
        self.num as f64 / self.den as f64
    }

    fn from_dims(w: f64, h: f64) -> Option<Self> {
        if w.fract() == 0.0 && h.fract() == 0.0 && w.abs() < 1e15 && h.abs() < 1e15 {
            Self::new(w as i64, h as i64)
        } else if h != 0.0 {
            // non-integral dimensions: approximate with a fixed denominator
            Self::new((w / h * 1e6).round() as i64, 1_000_000)
        } else {
            None
        }
    }
}

/// Python's `round()` of a rational: round half to even.
fn round_fraction(num: i128, den: i128) -> f64 {
    let q = num.div_euclid(den);
    let r = num.rem_euclid(den);
    let twice = 2 * r;
    let rounded = if twice > den || (twice == den && q % 2 != 0) {
        q + 1
    } else {
        q
    };
    rounded as f64
}

/// A box of potentially variable width and height (`BoxConstraints`).
///
/// Dimensions given at construction are truncated to integers, as in
/// pyHanko; dimensions filled in later by layout computations are not.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BoxConstraints {
    width: Option<f64>,
    height: Option<f64>,
    ar: Option<Fraction>,
    fully_specified: bool,
}

impl BoxConstraints {
    /// A box with the given (optional) dimensions and aspect ratio.
    /// Specifying all three is an error.
    pub fn new(
        width: Option<f64>,
        height: Option<f64>,
        aspect_ratio: Option<Fraction>,
    ) -> Result<Self> {
        let w = width.map(f64::trunc);
        let h = height.map(f64::trunc);
        let mut b = Self {
            width: w,
            height: h,
            ar: None,
            fully_specified: false,
        };
        match (w, h, aspect_ratio) {
            (None, None, None) => {}
            (Some(w), Some(h), ar) => {
                if ar.is_some() {
                    return Err(box_specification_error());
                }
                b.ar = Fraction::from_dims(w, h);
                b.fully_specified = true;
            }
            (w, h, Some(ar)) => {
                b.ar = Some(ar);
                if let Some(h) = h {
                    b.width = Some(round_fraction(h as i128 * ar.num as i128, ar.den as i128));
                } else if let Some(w) = w {
                    b.height = Some(round_fraction(w as i128 * ar.den as i128, ar.num as i128));
                }
            }
            _ => {}
        }
        Ok(b)
    }

    /// A box of `width` by `height`.
    pub fn fixed(width: f64, height: f64) -> Self {
        Self::new(Some(width), Some(height), None).unwrap_or_default()
    }

    /// A box with no constraints.
    pub fn unconstrained() -> Self {
        Self::default()
    }

    fn recalculate(&mut self) {
        match (self.width, self.height, self.ar) {
            (Some(w), Some(h), _) => {
                self.ar = Fraction::from_dims(w, h);
                self.fully_specified = true;
            }
            (None, Some(h), Some(ar)) => {
                self.width = Some((h * ar.as_f64()).trunc());
                self.fully_specified = true;
            }
            (Some(w), None, Some(ar)) => {
                self.height = Some((w / ar.as_f64()).trunc());
                self.fully_specified = true;
            }
            _ => {}
        }
    }

    /// The width; an error if it is not determined.
    pub fn width(&self) -> Result<f64> {
        self.width.ok_or_else(box_specification_error)
    }

    /// The height; an error if it is not determined.
    pub fn height(&self) -> Result<f64> {
        self.height.ok_or_else(box_specification_error)
    }

    /// Set the width; an error if it is already set.
    pub fn set_width(&mut self, w: f64) -> Result<()> {
        if self.width.is_some() {
            return Err(box_specification_error());
        }
        self.width = Some(w);
        self.recalculate();
        Ok(())
    }

    /// Set the height; an error if it is already set.
    pub fn set_height(&mut self, h: f64) -> Result<()> {
        if self.height.is_some() {
            return Err(box_specification_error());
        }
        self.height = Some(h);
        self.recalculate();
        Ok(())
    }

    /// The width is determined.
    pub fn width_defined(&self) -> bool {
        self.width.is_some()
    }

    /// The height is determined.
    pub fn height_defined(&self) -> bool {
        self.height.is_some()
    }

    /// The aspect ratio; an error if it is not determined.
    pub fn aspect_ratio(&self) -> Result<Fraction> {
        self.ar.ok_or_else(box_specification_error)
    }

    /// The aspect ratio is determined.
    pub fn aspect_ratio_defined(&self) -> bool {
        self.ar.is_some()
    }
}

/// Inner content scaling convention (`InnerScaling`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InnerScaling {
    /// Never scale content.
    NoScaling,
    /// Scale content to fill the entire container.
    StretchFill,
    /// Scale content, preserving the aspect ratio, until the maximal width
    /// or height is reached.
    StretchToFit,
    /// Scale content down (never up) to fit, preserving the aspect ratio.
    #[default]
    ShrinkToFit,
}

impl InnerScaling {
    /// Parse a configuration string: `none`, `stretch-fill`,
    /// `stretch-to-fit`, `shrink-to-fit`.
    pub fn from_config(s: &str) -> Result<Self> {
        Ok(match s.to_lowercase().as_str() {
            "none" => Self::NoScaling,
            "stretch-fill" => Self::StretchFill,
            "stretch-to-fit" => Self::StretchToFit,
            "shrink-to-fit" => Self::ShrinkToFit,
            _ => {
                return Err(crate::stamp::config::config_error(format!(
                    "'{s}' is not a valid inner scaling setting; valid values are 'none', 'stretch-fill', 'stretch-to-fit', 'shrink-to-fit'."
                )))
            }
        })
    }
}

/// One-dimensional alignment along an axis (`AxisAlignment`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AxisAlignment {
    /// Towards the negative end of the axis.
    AlignMin,
    /// Centered.
    AlignMid,
    /// Towards the positive end of the axis.
    AlignMax,
}

impl AxisAlignment {
    /// Parse a horizontal alignment: `left`, `mid` or `right`.
    pub fn from_x_align(s: &str) -> Result<Self> {
        Ok(match s.to_lowercase().as_str() {
            "left" => Self::AlignMin,
            "mid" => Self::AlignMid,
            "right" => Self::AlignMax,
            _ => {
                return Err(crate::stamp::config::config_error(format!(
                    "'{s}' is not a valid horizontal alignment; valid values are 'left', 'mid', 'right'."
                )))
            }
        })
    }

    /// Parse a vertical alignment: `bottom`, `mid` or `top`.
    pub fn from_y_align(s: &str) -> Result<Self> {
        Ok(match s.to_lowercase().as_str() {
            "bottom" => Self::AlignMin,
            "mid" => Self::AlignMid,
            "top" => Self::AlignMax,
            _ => {
                return Err(crate::stamp::config::config_error(format!(
                "'{s}' is not a valid vertical alignment; valid values are 'bottom', 'mid', 'top'."
            )))
            }
        })
    }

    /// The opposite alignment (`flipped`).
    pub fn flipped(self) -> Self {
        match self {
            Self::AlignMid => Self::AlignMid,
            Self::AlignMin => Self::AlignMax,
            Self::AlignMax => Self::AlignMin,
        }
    }

    /// Position of content of length `inner_len` in a container of length
    /// `container_len` with the given margins (`align`).
    pub fn align(
        self,
        container_len: f64,
        inner_len: f64,
        pre_margin: f64,
        post_margin: f64,
    ) -> Result<f64> {
        let effective_max_len =
            Margins::effective("length", container_len, pre_margin, post_margin)?;
        Ok(match self {
            Self::AlignMax => container_len - inner_len - post_margin,
            Self::AlignMin => pre_margin,
            Self::AlignMid if inner_len > effective_max_len => {
                // pyHanko logs a warning: post_margin is ignored
                pre_margin
            }
            Self::AlignMid => pre_margin + ((effective_max_len - inner_len) / 2.0).floor(),
        })
    }
}

/// Position and scaling of an object in a container (`Positioning`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Positioning {
    /// Horizontal coordinate.
    pub x_pos: f64,
    /// Vertical coordinate.
    pub y_pos: f64,
    /// Horizontal scaling.
    pub x_scale: f64,
    /// Vertical scaling.
    pub y_scale: f64,
}

impl Positioning {
    /// The `cm` operator for this positioning (`as_cm`).
    pub fn as_cm(&self) -> Vec<u8> {
        format!(
            "{} 0 0 {} {} {} cm",
            fmt_g(self.x_scale),
            fmt_g(self.y_scale),
            fmt_g(self.x_pos),
            fmt_g(self.y_pos)
        )
        .into_bytes()
    }
}

/// A set of margins (`Margins`).
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct Margins {
    /// Left margin.
    pub left: f64,
    /// Right margin.
    pub right: f64,
    /// Top margin.
    pub top: f64,
    /// Bottom margin.
    pub bottom: f64,
}

impl Margins {
    /// The same margin on all sides.
    pub fn uniform(n: f64) -> Self {
        Self {
            left: n,
            right: n,
            top: n,
            bottom: n,
        }
    }

    /// `container_len - pre - post`, an error if negative.
    pub fn effective(dim_name: &str, container_len: f64, pre: f64, post: f64) -> Result<f64> {
        let eff = container_len - pre - post;
        if eff < 0.0 {
            return Err(layout_error(format!(
                "Margins ({}, {}) too wide for container {dim_name} {}.",
                py_num(pre),
                py_num(post),
                py_num(container_len)
            )));
        }
        Ok(eff)
    }

    /// The width without the left and right margins.
    pub fn effective_width(&self, width: f64) -> Result<f64> {
        Self::effective("width", width, self.left, self.right)
    }

    /// The height without the top and bottom margins.
    pub fn effective_height(&self, height: f64) -> Result<f64> {
        Self::effective("height", height, self.bottom, self.top)
    }
}

fn aln(
    alignment: AxisAlignment,
    container_len: Option<f64>,
    inner_nat: f64,
    pre: f64,
    post: f64,
) -> Result<(f64, Option<f64>)> {
    match container_len {
        Some(len) => Ok((alignment.align(len, inner_nat, pre, post)?, None)),
        None => Ok((pre, Some(inner_nat + pre + post))),
    }
}

/// Alignment, scaling and margins of a box inside another box
/// (`SimpleBoxLayoutRule`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SimpleBoxLayoutRule {
    /// Horizontal alignment.
    pub x_align: AxisAlignment,
    /// Vertical alignment.
    pub y_align: AxisAlignment,
    /// Container (inner) margins.
    pub margins: Margins,
    /// Inner content scaling rule.
    pub inner_content_scaling: InnerScaling,
}

impl SimpleBoxLayoutRule {
    /// A rule with zero margins and shrink-to-fit scaling.
    pub const fn new(x_align: AxisAlignment, y_align: AxisAlignment) -> Self {
        Self {
            x_align,
            y_align,
            margins: Margins {
                left: 0.0,
                right: 0.0,
                top: 0.0,
                bottom: 0.0,
            },
            inner_content_scaling: InnerScaling::ShrinkToFit,
        }
    }

    /// The same rule with other margins (`substitute_margins`).
    pub fn substitute_margins(&self, margins: Margins) -> Self {
        Self { margins, ..*self }
    }

    /// The same rule with other margins.
    pub fn with_margins(self, margins: Margins) -> Self {
        self.substitute_margins(margins)
    }

    /// The same rule with another scaling convention.
    pub fn with_scaling(self, s: InnerScaling) -> Self {
        Self {
            inner_content_scaling: s,
            ..self
        }
    }

    /// Position (and possibly scale) a box of natural size
    /// `inner_nat_width` x `inner_nat_height` within `container`
    /// (`fit`). Undetermined container dimensions are set to fit the
    /// content.
    pub fn fit(
        &self,
        container: &mut BoxConstraints,
        inner_nat_width: f64,
        inner_nat_height: f64,
    ) -> Result<Positioning> {
        let margins = self.margins;
        let scaling = self.inner_content_scaling;
        let (mut x_scale, mut y_scale) = (1.0, 1.0);
        if scaling != InnerScaling::NoScaling
            && container.width_defined()
            && container.height_defined()
        {
            let eff_width = margins.effective_width(container.width()?)?;
            let eff_height = margins.effective_height(container.height()?)?;
            x_scale = if inner_nat_width != 0.0 {
                eff_width / inner_nat_width
            } else {
                1.0
            };
            y_scale = if inner_nat_height != 0.0 {
                eff_height / inner_nat_height
            } else {
                1.0
            };
            match scaling {
                InnerScaling::StretchToFit => {
                    let m = x_scale.min(y_scale);
                    x_scale = m;
                    y_scale = m;
                }
                InnerScaling::ShrinkToFit => {
                    let m = x_scale.min(y_scale).min(1.0);
                    x_scale = m;
                    y_scale = m;
                }
                _ => {}
            }
        }
        let (x_pos, new_w) = aln(
            self.x_align,
            container.width,
            inner_nat_width * x_scale,
            margins.left,
            margins.right,
        )?;
        if let Some(w) = new_w {
            container.set_width(w)?;
        }
        let (y_pos, new_h) = aln(
            self.y_align,
            container.height,
            inner_nat_height * y_scale,
            margins.bottom,
            margins.top,
        )?;
        if let Some(h) = new_h {
            container.set_height(h)?;
        }
        Ok(Positioning {
            x_pos,
            y_pos,
            x_scale,
            y_scale,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aspect_ratio_boxes() {
        let b = BoxConstraints::new(None, Some(50.0), Fraction::new(4, 1)).unwrap();
        assert_eq!(b.width().unwrap(), 200.0);
        assert!(BoxConstraints::new(Some(1.0), Some(1.0), Fraction::new(1, 1)).is_err());
        let mut b = BoxConstraints::new(None, None, Fraction::new(2, 1)).unwrap();
        b.set_height(10.0).unwrap();
        assert_eq!(b.width().unwrap(), 20.0);
    }

    #[test]
    fn fit_natural() {
        let rule = SimpleBoxLayoutRule::new(AxisAlignment::AlignMid, AxisAlignment::AlignMid)
            .with_margins(Margins::uniform(10.0));
        let mut b = BoxConstraints::default();
        let p = rule.fit(&mut b, 100.0, 20.0).unwrap();
        assert_eq!((p.x_pos, p.y_pos), (10.0, 10.0));
        assert_eq!((b.width().unwrap(), b.height().unwrap()), (120.0, 40.0));
        assert_eq!(p.as_cm(), b"1 0 0 1 10 10 cm".to_vec());
    }
}
