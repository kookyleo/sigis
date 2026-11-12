// Derived from pyHanko `pdf_utils/qr.py` (MIT, see LICENSE-pyHanko), with the
// QR symbol construction of python-qrcode (`qrcode.main.QRCode.make`,
// `qrcode.util.optimal_data_chunks`, `qrcode.util.lost_point`; BSD).

//! QR codes as PDF graphics operators (`pyhanko.pdf_utils.qr`).
//!
//! Encoding, error correction and module placement use the `qrcode` crate.
//! Segmentation, version selection and mask selection follow python-qrcode,
//! which pyHanko uses, so that the symbols are identical: python-qrcode
//! scores masks with the format information left blank.

use sigis_pki_core::errors::{HankoError, Result};
use qrcode::bits::Bits;
use qrcode::canvas::{Canvas, MaskPattern};
use qrcode::types::{Color, EcLevel, Version};

use crate::content::ops::{fmt_g, py_float, rd};
use crate::content::{ContentWriter, PdfContent};

fn qr_error(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(format!("QR code: {}", msg.into()))
}

/// A QR symbol: the module matrix plus python-qrcode's rendering
/// parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrMatrix {
    /// Symbol version (1 to 40).
    pub version: u8,
    /// Modules, `modules[row][col]`, `true` for dark.
    pub modules: Vec<Vec<bool>>,
    /// Quiet zone in modules (`border`).
    pub border: u32,
    /// Size of one module in canvas units (`box_size`).
    pub box_size: u32,
}

impl QrMatrix {
    /// Number of modules per side (`modules_count`).
    pub fn modules_count(&self) -> usize {
        self.modules.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Number,
    AlphaNum,
    Byte,
}

const ALPHA_NUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn is_alnum(b: u8) -> bool {
    ALPHA_NUM.contains(&b)
}

/// Leftmost run of at least `min` bytes satisfying `pred` (a greedy
/// `[class]{min,}` search).
fn find_run(data: &[u8], pred: fn(u8) -> bool, min: usize) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < data.len() {
        if pred(data[i]) {
            let start = i;
            while i < data.len() && pred(data[i]) {
                i += 1;
            }
            if i - start >= min {
                return Some((start, i));
            }
        } else {
            i += 1;
        }
    }
    None
}

/// `_optimal_split`.
fn optimal_split(data: &[u8], pred: fn(u8) -> bool, minimum: usize, short: bool) -> Vec<(bool, Vec<u8>)> {
    let mut out = Vec::new();
    let mut data = data;
    while !data.is_empty() {
        let m = if short {
            // `^class+$`: the whole remaining data
            (data.iter().all(|&b| pred(b))).then_some((0, data.len()))
        } else {
            find_run(data, pred, minimum)
        };
        let Some((start, end)) = m else { break };
        if start > 0 {
            out.push((false, data[..start].to_vec()));
        }
        out.push((true, data[start..end].to_vec()));
        data = &data[end..];
    }
    if !data.is_empty() {
        out.push((false, data.to_vec()));
    }
    out
}

/// `optimal_data_chunks(data, minimum=20)`.
fn optimal_data_chunks(data: &[u8], minimum: usize) -> Vec<(Mode, Vec<u8>)> {
    let short = data.len() <= minimum;
    let mut out = Vec::new();
    for (is_num, chunk) in optimal_split(data, |b| b.is_ascii_digit(), minimum, short) {
        if is_num {
            out.push((Mode::Number, chunk));
        } else {
            for (is_alpha, sub) in optimal_split(&chunk, is_alnum, minimum, short) {
                out.push((if is_alpha { Mode::AlphaNum } else { Mode::Byte }, sub));
            }
        }
    }
    out
}

fn length_bits(mode: Mode, version: i16) -> usize {
    let tier = if version < 10 {
        0
    } else if version < 27 {
        1
    } else {
        2
    };
    match mode {
        Mode::Number => [10, 12, 14][tier],
        Mode::AlphaNum => [9, 11, 13][tier],
        Mode::Byte => [8, 16, 16][tier],
    }
}

fn data_bits(mode: Mode, len: usize) -> usize {
    match mode {
        Mode::Number => 10 * (len / 3) + [0, 4, 7][len % 3],
        Mode::AlphaNum => 11 * (len / 2) + 6 * (len % 2),
        Mode::Byte => 8 * len,
    }
}

fn bit_limit(version: i16, ec: EcLevel) -> Result<usize> {
    Bits::new(Version::Normal(version))
        .max_len(ec)
        .map_err(|e| qr_error(format!("{e:?}")))
}

/// `QRCode.best_fit`.
fn best_fit(chunks: &[(Mode, Vec<u8>)], ec: EcLevel) -> Result<i16> {
    let mut start: i16 = 1;
    loop {
        let needed: usize = chunks
            .iter()
            .map(|(m, d)| 4 + length_bits(*m, start) + data_bits(*m, d.len()))
            .sum();
        let mut version = start;
        while version <= 40 && bit_limit(version, ec)? < needed {
            version += 1;
        }
        if version > 40 {
            return Err(qr_error("data overflow"));
        }
        let tier = |v: i16| (v >= 10) as u8 + (v >= 27) as u8;
        if tier(version) != tier(start) {
            start = version;
            continue;
        }
        return Ok(version);
    }
}

const MASKS: [MaskPattern; 8] = [
    MaskPattern::Checkerboard,
    MaskPattern::HorizontalLines,
    MaskPattern::VerticalLines,
    MaskPattern::DiagonalLines,
    MaskPattern::LargeCheckerboard,
    MaskPattern::Fields,
    MaskPattern::Diamonds,
    MaskPattern::Meadow,
];

fn canvas_modules(c: Canvas, width: usize) -> Vec<Vec<bool>> {
    let colors = c.into_colors();
    colors
        .chunks(width)
        .map(|row| row.iter().map(|c| *c == Color::Dark).collect())
        .collect()
}

/// Blank the format information, the dark module and the version
/// information, as python-qrcode does in its mask test runs.
fn blank_type_info(m: &mut [Vec<bool>], version: i16) {
    let n = m.len();
    for i in 0..15 {
        let row = if i < 6 {
            i
        } else if i < 8 {
            i + 1
        } else {
            n - 15 + i
        };
        m[row][8] = false;
        let col = if i < 8 {
            n - i - 1
        } else if i < 9 {
            15 - i
        } else {
            14 - i
        };
        m[8][col] = false;
    }
    m[n - 8][8] = false;
    if version >= 7 {
        for i in 0..18 {
            m[i / 3][i % 3 + n - 11] = false;
            m[i % 3 + n - 11][i / 3] = false;
        }
    }
}

fn lost_point_level1(m: &[Vec<bool>]) -> u64 {
    let n = m.len();
    let mut container = vec![0u64; n + 1];
    let mut runs = |cells: &mut dyn Iterator<Item = bool>| {
        let mut prev: Option<bool> = None;
        let mut length = 0usize;
        for c in cells {
            if Some(c) == prev {
                length += 1;
            } else {
                if length >= 5 {
                    container[length] += 1;
                }
                length = 1;
                prev = Some(c);
            }
        }
        if length >= 5 {
            container[length] += 1;
        }
    };
    for row in m {
        runs(&mut row.iter().copied());
    }
    for col in 0..n {
        runs(&mut m.iter().map(|r| r[col]));
    }
    (5..=n).map(|l| container[l] * (l as u64 - 2)).sum()
}

fn lost_point_level2(m: &[Vec<bool>]) -> u64 {
    let n = m.len();
    let mut lost = 0;
    for row in 0..n - 1 {
        let this_row = &m[row];
        let next_row = &m[row + 1];
        let mut col = 0;
        while col < n - 1 {
            let top_right = this_row[col + 1];
            if top_right != next_row[col + 1] {
                col += 1; // skip the next block
            } else if top_right == this_row[col] && top_right == next_row[col] {
                lost += 3;
            }
            col += 1;
        }
    }
    lost
}

fn finder_like(get: &dyn Fn(usize) -> bool) -> bool {
    !get(1)
        && get(4)
        && !get(5)
        && get(6)
        && !get(9)
        && ((get(0) && get(2) && get(3) && !get(7) && !get(8) && !get(10))
            || (!get(0) && !get(2) && !get(3) && get(7) && get(8) && get(10)))
}

fn lost_point_level3(m: &[Vec<bool>]) -> u64 {
    let n = m.len();
    let mut lost = 0;
    let short = n.saturating_sub(10);
    for this_row in m {
        let mut col = 0;
        while col < short {
            if finder_like(&|k| this_row[col + k]) {
                lost += 40;
            }
            if this_row[col + 10] {
                col += 1;
            }
            col += 1;
        }
    }
    for col in 0..n {
        let mut row = 0;
        while row < short {
            if finder_like(&|k| m[row + k][col]) {
                lost += 40;
            }
            if m[row + 10][col] {
                row += 1;
            }
            row += 1;
        }
    }
    lost
}

fn lost_point_level4(m: &[Vec<bool>]) -> u64 {
    let n = m.len();
    let dark: usize = m.iter().map(|r| r.iter().filter(|&&b| b).count()).sum();
    let percent = dark as f64 / (n * n) as f64;
    let rating = ((percent * 100.0 - 50.0).abs() / 5.0).trunc() as u64;
    rating * 10
}

/// `util.lost_point`.
fn lost_point(m: &[Vec<bool>]) -> u64 {
    lost_point_level1(m) + lost_point_level2(m) + lost_point_level3(m) + lost_point_level4(m)
}

/// Build a QR symbol for `data` as python-qrcode's
/// `QRCode(error_correction=ec); add_data(data); make()` does.
pub fn make_qr(data: &str, ec: EcLevel) -> Result<QrMatrix> {
    let chunks = optimal_data_chunks(data.as_bytes(), 20);
    let version = best_fit(&chunks, ec)?;
    let v = Version::Normal(version);
    let mut bits = Bits::new(v);
    for (mode, d) in &chunks {
        let r = match mode {
            Mode::Number => bits.push_numeric_data(d),
            Mode::AlphaNum => bits.push_alphanumeric_data(d),
            Mode::Byte => bits.push_byte_data(d),
        };
        r.map_err(|e| qr_error(format!("{e:?}")))?;
    }
    bits.push_terminator(ec).map_err(|e| qr_error(format!("{e:?}")))?;
    let (data_cw, ec_cw) =
        qrcode::ec::construct_codewords(&bits.into_bytes(), v, ec).map_err(|e| qr_error(format!("{e:?}")))?;
    let mut canvas = Canvas::new(v, ec);
    canvas.draw_all_functional_patterns();
    canvas.draw_data(&data_cw, &ec_cw);
    let width = usize::try_from(version).unwrap_or(1) * 4 + 17;
    let mut best: Option<(u64, MaskPattern)> = None;
    for mask in MASKS {
        let mut c = canvas.clone();
        c.apply_mask(mask);
        let mut m = canvas_modules(c, width);
        blank_type_info(&mut m, version);
        let lp = lost_point(&m);
        if best.is_none_or(|(b, _)| lp < b) {
            best = Some((lp, mask));
        }
    }
    let (_, mask) = best.ok_or_else(|| qr_error("no mask"))?;
    canvas.apply_mask(mask);
    Ok(QrMatrix {
        version: u8::try_from(version).unwrap_or(1),
        modules: canvas_modules(canvas, width),
        border: 4,
        box_size: 10,
    })
}

/// Alignment pattern centres per version (`PATTERN_POSITION_TABLE`).
const PATTERN_POSITION_TABLE: [&[usize]; 40] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
    &[6, 30, 54],
    &[6, 32, 58],
    &[6, 34, 62],
    &[6, 26, 46, 66],
    &[6, 26, 48, 70],
    &[6, 26, 50, 74],
    &[6, 30, 54, 78],
    &[6, 30, 56, 82],
    &[6, 30, 58, 86],
    &[6, 34, 62, 90],
    &[6, 28, 50, 72, 94],
    &[6, 26, 50, 74, 98],
    &[6, 30, 54, 78, 102],
    &[6, 28, 54, 80, 106],
    &[6, 32, 58, 84, 110],
    &[6, 30, 58, 86, 114],
    &[6, 34, 62, 90, 118],
    &[6, 26, 50, 74, 98, 122],
    &[6, 30, 54, 78, 102, 126],
    &[6, 26, 52, 78, 104, 130],
    &[6, 30, 56, 82, 108, 134],
    &[6, 34, 60, 86, 112, 138],
    &[6, 30, 58, 86, 114, 142],
    &[6, 34, 62, 90, 118, 146],
    &[6, 30, 54, 78, 102, 126, 150],
    &[6, 24, 50, 76, 102, 128, 154],
    &[6, 28, 54, 80, 106, 132, 158],
    &[6, 32, 58, 84, 110, 136, 162],
    &[6, 26, 54, 82, 110, 138, 166],
    &[6, 30, 58, 86, 114, 142, 170],
];

/// A number with Python's int/float distinction, for operators that
/// pyHanko formats with `str()`.
#[derive(Clone, Copy, Debug)]
struct PyN {
    v: f64,
    int: bool,
}

impl PyN {
    fn i(v: i64) -> Self {
        Self { v: v as f64, int: true }
    }
    fn f(v: f64) -> Self {
        Self { v, int: false }
    }
    fn add(self, o: PyN) -> Self {
        Self {
            v: self.v + o.v,
            int: self.int && o.int,
        }
    }
    fn sub(self, o: PyN) -> Self {
        Self {
            v: self.v - o.v,
            int: self.int && o.int,
        }
    }
    fn rd(self) -> Self {
        if self.int {
            self
        } else {
            Self::f(rd(self.v))
        }
    }
    fn fmt(self) -> String {
        if self.int {
            format!("{}", self.v as i64)
        } else {
            py_float(self.v)
        }
    }
}

/// `rounded_square`: a counterclockwise square subpath with rounded corners.
fn rounded_square(x_pos: PyN, y_pos: PyN, sz: PyN, rad: PyN) -> Vec<Vec<u8>> {
    let c_off = PyN::f((4.0 * (2f64.sqrt() - 1.0) / 3.0) * rad.v);
    let zero = PyN::i(0);
    let mut result: Vec<Vec<u8>> = Vec::new();
    let mut op = |pts: &[(PyN, PyN)], opc: &str| {
        for (x, y) in pts {
            let px = x_pos.add(*x).rd();
            let py = y_pos.add(*y).rd();
            result.push(format!("{} {} ", px.fmt(), py.fmt()).into_bytes());
        }
        result.push(opc.as_bytes().to_vec());
    };
    op(&[(rad, zero)], "m");
    op(&[(sz.sub(rad), zero)], "l");
    op(&[(sz.sub(c_off), zero), (sz, c_off), (sz, rad)], "c");
    op(&[(sz, sz.sub(rad))], "l");
    op(&[(sz, sz.sub(c_off)), (sz.sub(c_off), sz), (sz.sub(rad), sz)], "c");
    op(&[(rad, sz)], "l");
    op(&[(c_off, sz), (zero, sz.sub(c_off)), (zero, sz.sub(rad))], "c");
    op(&[(zero, rad)], "l");
    op(&[(zero, c_off), (c_off, zero), (rad, zero)], "c");
    result.push(b"h".to_vec());
    result
}

fn qr_color_and_cm(qr: &QrMatrix) -> Vec<u8> {
    let brd = i64::from(qr.border * qr.box_size);
    let ydiff = (qr.modules_count() as i64) * i64::from(qr.box_size);
    let bs = i64::from(qr.box_size);
    format!(
        "{0} {0} {0} rg\n{0} {0} {0} RG\n{bs} 0 0 {neg} {brd} {top} cm",
        fmt_g(0.0),
        neg = -bs,
        top = brd + ydiff
    )
    .into_bytes()
}

fn dark_modules(qr: &QrMatrix) -> impl Iterator<Item = (usize, usize)> + '_ {
    qr.modules
        .iter()
        .enumerate()
        .flat_map(|(r, row)| row.iter().enumerate().filter(|(_, d)| **d).map(move |(c, _)| (r, c)))
}

/// Plain rendering (`PdfStreamQRImage.render_command_stream`).
pub fn render_qr_stream(qr: &QrMatrix) -> Vec<u8> {
    let mut parts = vec![qr_color_and_cm(qr)];
    for (row, col) in dark_modules(qr) {
        parts.push(format!("{} {} 1 1 re", fmt_g(col as f64), fmt_g(row as f64)).into_bytes());
    }
    parts.push(b"f".to_vec());
    parts.join(&b"\n"[..])
}

/// Stylised rendering with an optional centerpiece (`PdfFancyQRImage`).
pub struct FancyQrImage<'q> {
    qr: &'q QrMatrix,
    alignment: Vec<(usize, usize)>,
}

const CENTERPIECE_CORNER_RADIUS: f64 = 0.2;

impl<'q> FancyQrImage<'q> {
    /// A fancy renderer for `qr`.
    pub fn new(qr: &'q QrMatrix) -> Self {
        let width = qr.modules_count();
        let major = |r: usize, c: usize| {
            (r < 7 && c < 7) || (r + 8 > width && c < 7) || (r < 7 && c + 8 > width)
        };
        let ptns = PATTERN_POSITION_TABLE
            .get(usize::from(qr.version).saturating_sub(1))
            .copied()
            .unwrap_or(&[]);
        let mut alignment = Vec::new();
        for &pr in ptns {
            for &pc in ptns {
                if !major(pr, pc) {
                    alignment.push((pr, pc));
                }
            }
        }
        Self { qr, alignment }
    }

    fn width(&self) -> usize {
        self.qr.modules_count()
    }

    fn is_major_position_pattern(&self, r: usize, c: usize) -> bool {
        let w = self.width();
        (r < 7 && c < 7) || (r + 8 > w && c < 7) || (r < 7 && c + 8 > w)
    }

    fn is_position_pattern(&self, r: usize, c: usize) -> bool {
        self.is_major_position_pattern(r, c)
            || self
                .alignment
                .iter()
                .any(|&(pr, pc)| r.abs_diff(pr) <= 2 && c.abs_diff(pc) <= 2)
    }

    fn measure_out_centerpiece(&self) -> (f64, f64, f64) {
        let w = self.width() as f64;
        let c_sz = 0.28 * w;
        let c_x = (w - c_sz) / 2.0;
        (rd(c_x), rd(c_x), rd(c_sz))
    }

    fn setup_drawing_area(&self, with_centerpiece: bool) -> Vec<u8> {
        let mut commands = vec![qr_color_and_cm(self.qr)];
        if with_centerpiece {
            let w = self.width();
            commands.push(b"q".to_vec());
            commands.push(b"0.2 w".to_vec());
            commands.push(format!("0 0 m 0 {w} l {w} {w} l {w} 0 l h").into_bytes());
            let (c_x, c_y, c_sz) = self.measure_out_centerpiece();
            commands.extend(rounded_square(
                PyN::f(c_x),
                PyN::f(c_y),
                PyN::f(c_sz),
                PyN::f(CENTERPIECE_CORNER_RADIUS * c_sz),
            ));
            commands.push(b"W n".to_vec());
        }
        commands.join(&b"\n"[..])
    }

    fn draw_position_patterns(&self) -> Vec<u8> {
        let sz = self.width() as i64;
        let i = PyN::i;
        let mut cs: Vec<Vec<u8>> = vec![b"q\n1 0 0 1 0.5 0.5 cm\n0.7 w".to_vec()];
        cs.extend(rounded_square(i(0), i(0), i(6), i(1)));
        cs.extend(rounded_square(i(0), i(sz - 7), i(6), i(1)));
        cs.extend(rounded_square(i(sz - 7), i(0), i(6), i(1)));
        for &(pr, pc) in &self.alignment {
            cs.extend(rounded_square(i(pr as i64 - 2), i(pc as i64 - 2), i(4), PyN::f(0.7)));
        }
        cs.push(b"S\nQ".to_vec());
        cs.extend(rounded_square(i(2), i(2), i(3), PyN::f(0.6)));
        cs.extend(rounded_square(i(2), i(sz - 7 + 2), i(3), PyN::f(0.6)));
        cs.extend(rounded_square(i(sz - 7 + 2), i(2), i(3), PyN::f(0.6)));
        for &(pr, pc) in &self.alignment {
            cs.extend(rounded_square(i(pr as i64), i(pc as i64), i(1), PyN::f(0.1)));
        }
        cs.push(b"f".to_vec());
        cs.join(&b"\n"[..])
    }

    fn draw_centerpiece(&self, center: &mut dyn PdfContent, w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        let (c_x, c_y, c_sz) = self.measure_out_centerpiece();
        let c_w = center.bbox().width()?;
        let c_h = center.bbox().height()?;
        let mut cs: Vec<Vec<u8>> = vec![b"q".to_vec(), b"0.2 w".to_vec()];
        cs.extend(rounded_square(
            PyN::f(c_x),
            PyN::f(c_y),
            PyN::f(c_sz),
            PyN::f(CENTERPIECE_CORNER_RADIUS * c_sz),
        ));
        cs.push(b"S\nQ\nq".to_vec());
        let x_scale = rd(c_sz / c_w);
        let y_scale = rd(c_sz / c_h);
        let shrink = 0.85;
        let x_shift = rd((1.0 - shrink) * c_w / 2.0);
        let y_shift = rd((1.0 - shrink) * c_h / 2.0);
        cs.push(
            format!(
                "{} 0 0 {} {} {} cm",
                py_float(x_scale * shrink),
                py_float(-y_scale * shrink),
                py_float(c_x + x_shift * x_scale),
                py_float(c_y + c_sz - y_shift * y_scale)
            )
            .into_bytes(),
        );
        // resource management is left to the caller, as in pyHanko
        cs.push(center.render(w)?);
        cs.push(b"Q".to_vec());
        Ok(cs.join(&b"\n"[..]))
    }

    /// `render_command_stream`.
    pub fn render_command_stream(
        &self,
        centerpiece: Option<&mut dyn PdfContent>,
        w: &mut ContentWriter<'_>,
    ) -> Result<Vec<u8>> {
        let mut first = vec![self.setup_drawing_area(centerpiece.is_some())];
        for (row, col) in dark_modules(self.qr) {
            if self.is_position_pattern(row, col) {
                continue;
            }
            first.extend(rounded_square(PyN::i(col as i64), PyN::i(row as i64), PyN::f(0.9), PyN::f(0.3)));
        }
        first.push(b"f".to_vec());
        let mut parts = vec![first.join(&b"\n"[..]), self.draw_position_patterns()];
        if let Some(c) = centerpiece {
            parts.push(b"Q".to_vec());
            parts.push(self.draw_centerpiece(c, w)?);
        }
        Ok(parts.join(&b"\n"[..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks() {
        let c = optimal_data_chunks(b"https://example.com", 20);
        assert_eq!(c, vec![(Mode::Byte, b"https://example.com".to_vec())]);
        let c = optimal_data_chunks(b"12345", 20);
        assert_eq!(c, vec![(Mode::Number, b"12345".to_vec())]);
    }

    #[test]
    fn example_version() {
        let qr = make_qr("https://example.com", EcLevel::M).unwrap();
        assert_eq!(qr.version, 2);
        assert_eq!(qr.modules_count(), 25);
    }
}
