// Derived from pyHanko `pdf_utils/barcodes.py` (MIT, see LICENSE-pyHanko), with
// the Code 128 encoder and module layout of python-barcode
// (`barcode.codex.Code128`, `barcode.writer.BaseWriter`; MIT).

//! Barcodes as PDF graphics operators (`pyhanko.pdf_utils.barcodes`).
//!
//! pyHanko delegates encoding to python-barcode. Its Code 128 encoder (with
//! automatic code set switching) and its module layout are ported here;
//! other symbologies are not supported.

use hanko_core::errors::{HankoError, Result};

use crate::content::ops::{fmt_g, rd};
use crate::content::{ContentWriter, PdfContent, PdfResources};
use crate::layout::BoxConstraints;

const COMMON: &str = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Charset {
    A,
    B,
    C,
}

/// A symbol of a Code 128 code set: a character or a control code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sym {
    Ch(char),
    ToA,
    ToB,
    ToC,
}

fn index_a(s: Sym) -> Option<u8> {
    match s {
        Sym::Ch(c) => {
            if let Some(i) = COMMON.chars().position(|x| x == c) {
                return u8::try_from(i).ok();
            }
            let cp = u32::from(c);
            if cp < 0x20 {
                return u8::try_from(64 + cp).ok();
            }
            match c {
                'ó' => Some(96),
                'ò' => Some(97),
                'ô' => Some(101),
                'ñ' => Some(102),
                _ => None,
            }
        }
        Sym::ToC => Some(99),
        Sym::ToB => Some(100),
        Sym::ToA => None,
    }
}

fn index_b(s: Sym) -> Option<u8> {
    match s {
        Sym::Ch(c) => {
            if let Some(i) = COMMON.chars().position(|x| x == c) {
                return u8::try_from(i).ok();
            }
            let cp = u32::from(c);
            if (0x60..=0x7f).contains(&cp) {
                return u8::try_from(cp).ok();
            }
            match c {
                'ó' => Some(96),
                'ò' => Some(97),
                'ô' => Some(100),
                'ñ' => Some(102),
                _ => None,
            }
        }
        Sym::ToC => Some(99),
        Sym::ToA => Some(101),
        Sym::ToB => None,
    }
}

fn index_c(s: Sym) -> Option<u8> {
    match s {
        Sym::ToB => Some(100),
        Sym::ToA => Some(101),
        Sym::Ch('ñ') => Some(102),
        _ => None,
    }
}

const CODES: [&str; 106] = [
    "11011001100", "11001101100", "11001100110", "10010011000", "10010001100", "10001001100",
    "10011001000", "10011000100", "10001100100", "11001001000", "11001000100", "11000100100",
    "10110011100", "10011011100", "10011001110", "10111001100", "10011101100", "10011100110",
    "11001110010", "11001011100", "11001001110", "11011100100", "11001110100", "11101101110",
    "11101001100", "11100101100", "11100100110", "11101100100", "11100110100", "11100110010",
    "11011011000", "11011000110", "11000110110", "10100011000", "10001011000", "10001000110",
    "10110001000", "10001101000", "10001100010", "11010001000", "11000101000", "11000100010",
    "10110111000", "10110001110", "10001101110", "10111011000", "10111000110", "10001110110",
    "11101110110", "11010001110", "11000101110", "11011101000", "11011100010", "11011101110",
    "11101011000", "11101000110", "11100010110", "11101101000", "11101100010", "11100011010",
    "11101111010", "11001000010", "11110001010", "10100110000", "10100001100", "10010110000",
    "10010000110", "10000101100", "10000100110", "10110010000", "10110000100", "10011010000",
    "10011000010", "10000110100", "10000110010", "11000010010", "11001010000", "11110111010",
    "11000010100", "10001111010", "10100111100", "10010111100", "10010011110", "10111100100",
    "10011110100", "10011110010", "11110100100", "11110010100", "11110010010", "11011011110",
    "11011110110", "11110110110", "10101111000", "10100011110", "10001011110", "10111101000",
    "10111100010", "11110101000", "11110100010", "10111011110", "10111101110", "11101011110",
    "11110101110", "11010000100", "11010010000", "11010011100",
];
const STOP: &str = "11000111010";

fn barcode_error(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(format!("barcode: {}", msg.into()))
}

/// The python-barcode Code 128 encoder state.
struct Code128 {
    code: Vec<char>,
    charset: Charset,
    buffer: String,
}

impl Code128 {
    fn convert_sym(&mut self, s: Sym) -> Result<Option<u8>> {
        match self.charset {
            Charset::A => index_a(s).map(Some),
            Charset::B => index_b(s).map(Some),
            Charset::C => {
                if let Some(v) = index_c(s) {
                    return Ok(Some(v));
                }
                if let Sym::Ch(c) = s {
                    if c.is_ascii_digit() {
                        self.buffer.push(c);
                        if self.buffer.len() == 2 {
                            let v: u8 = self.buffer.parse().map_err(|_| barcode_error("digits"))?;
                            self.buffer.clear();
                            return Ok(Some(v));
                        }
                        return Ok(None);
                    }
                }
                None
            }
        }
        .ok_or_else(|| barcode_error(format!("Character could not be converted in charset {:?}.", self.charset)))
    }

    fn new_charset(&mut self, which: Charset) -> Result<Vec<u8>> {
        let sym = match which {
            Charset::A => Sym::ToA,
            Charset::B => Sym::ToB,
            Charset::C => Sym::ToC,
        };
        let code = self.convert_sym(sym)?.ok_or_else(|| barcode_error("charset switch"))?;
        self.charset = which;
        Ok(vec![code])
    }

    fn maybe_switch_charset(&mut self, pos: usize) -> Result<Vec<u8>> {
        let ch = self.code[pos];
        let next: Vec<char> = self.code[pos..(pos + 10).min(self.code.len())].to_vec();
        let look_next = || next.iter().take_while(|c| c.is_ascii_digit()).count() > 3;
        let in_a = index_a(Sym::Ch(ch)).is_some();
        let in_b = index_b(Sym::Ch(ch)).is_some();
        let mut codes = Vec::new();
        match self.charset {
            Charset::C if !ch.is_ascii_digit() => {
                if in_b {
                    codes = self.new_charset(Charset::B)?;
                } else if in_a {
                    codes = self.new_charset(Charset::A)?;
                }
                if self.buffer.len() == 1 {
                    let b = self.buffer.chars().next().unwrap_or('0');
                    self.buffer.clear();
                    if let Some(c) = self.convert_sym(Sym::Ch(b))? {
                        codes.push(c);
                    }
                }
            }
            Charset::B => {
                if look_next() {
                    codes = self.new_charset(Charset::C)?;
                } else if !in_b && in_a {
                    codes = self.new_charset(Charset::A)?;
                }
            }
            Charset::A => {
                if look_next() {
                    codes = self.new_charset(Charset::C)?;
                } else if !in_a && in_b {
                    codes = self.new_charset(Charset::B)?;
                }
            }
            _ => {}
        }
        Ok(codes)
    }

    fn build(mut self) -> Result<String> {
        let mut encoded: Vec<u8> = vec![105]; // START C
        for i in 0..self.code.len() {
            let sw = self.maybe_switch_charset(i)?;
            encoded.extend(sw);
            if let Some(v) = self.convert_sym(Sym::Ch(self.code[i]))? {
                encoded.push(v);
            }
        }
        if self.buffer.len() == 1 {
            encoded.extend(self.new_charset(Charset::B)?);
            let b = self.buffer.chars().next().unwrap_or('0');
            self.buffer.clear();
            if let Some(v) = self.convert_sym(Sym::Ch(b))? {
                encoded.push(v);
            }
        }
        // _try_to_optimize
        if encoded.len() > 1 {
            let start = match encoded[1] {
                101 => Some(103),
                100 => Some(104),
                99 => Some(105),
                _ => None,
            };
            if let Some(s) = start {
                encoded.splice(..2, [s]);
            }
        }
        let mut cs: u64 = u64::from(encoded[0]);
        for (i, c) in encoded.iter().enumerate().skip(1) {
            cs += i as u64 * u64::from(*c);
        }
        encoded.push(u8::try_from(cs % 103).unwrap_or(0));
        let mut out = String::new();
        for c in encoded {
            out.push_str(CODES.get(usize::from(c)).ok_or_else(|| barcode_error("code"))?);
        }
        out.push_str(STOP);
        out.push_str("11");
        Ok(out)
    }
}

/// Encode `code` as Code 128 modules (`1` dark, `0` light), as
/// python-barcode does.
pub fn code128_modules(code: &str) -> Result<String> {
    for c in code.chars() {
        if index_a(Sym::Ch(c)).is_none() && index_b(Sym::Ch(c)).is_none() {
            return Err(barcode_error(format!("Code 128 cannot encode {c:?}")));
        }
    }
    Code128 {
        code: code.chars().collect(),
        charset: Charset::C,
        buffer: String::new(),
    }
    .build()
}

const PDF_UUPI: f64 = 72.0;

fn mm2uu(mm: f64) -> f64 {
    rd((mm / 25.4) * PDF_UUPI)
}

fn mm2px(mm: f64, dpi: f64) -> f64 {
    (mm * dpi) / 25.4
}

/// A barcode as content (`BarcodeBox`).
#[derive(Clone, Debug, PartialEq)]
pub struct BarcodeBox {
    /// The symbology (only `code128`).
    pub barcode_type: String,
    /// The encoded text.
    pub code: String,
    commands: Vec<u8>,
    resources: PdfResources,
    bbox: BoxConstraints,
}

impl BarcodeBox {
    /// Render `code` with python-barcode's default options (module width
    /// 0.2 mm, height 15 mm, quiet zone 2.54 mm; the human-readable text is
    /// not drawn but counts towards the height).
    pub fn new(barcode_type: &str, code: &str) -> Result<Self> {
        if barcode_type.to_lowercase() != "code128" {
            return Err(HankoError::Unsupported(format!("barcode type {barcode_type}")));
        }
        let modules = code128_modules(code)?;
        let module_width = 0.2;
        let base_height = 15.0;
        let quiet_zone = 2.54;
        let font_size = 10.0;
        let text_distance = 5.0;
        let margin_top = 1.0;
        let margin_bottom = 1.0;
        let guard_height_factor = 1.1;
        // calculate_size (with text)
        let width = 2.0 * quiet_zone + modules.len() as f64 * module_width;
        let pt2mm = |pt: f64| pt * 0.352777778;
        let height = margin_bottom + margin_top + base_height + pt2mm(font_size) / 2.0 + text_distance;
        let size = (mm2px(width, PDF_UUPI).trunc(), mm2px(height, PDF_UUPI).trunc());
        let mut cs: Vec<Vec<u8>> = vec![b"q".to_vec()];
        let ypos = margin_top;
        let mut xpos = quiet_zone;
        // `packed`: runs of equal modules
        let bytes = modules.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let mut j = i;
            while j < bytes.len() && bytes[j] == bytes[i] {
                j += 1;
            }
            let run = (j - i) as f64;
            let dark = bytes[i] == b'1';
            let module_height = if dark { base_height } else { base_height * guard_height_factor };
            let colour = if dark { "0 0 0" } else { "1 1 1" };
            let w = module_width * run;
            cs.push(
                format!(
                    "{colour} rg {} {} {} {} re f",
                    fmt_g(mm2uu(xpos)),
                    fmt_g(mm2uu(ypos)),
                    fmt_g(mm2uu(w)),
                    fmt_g(mm2uu(module_height))
                )
                .into_bytes(),
            );
            xpos += w;
            i = j;
        }
        cs.push(b"Q".to_vec());
        Ok(Self {
            barcode_type: barcode_type.to_owned(),
            code: code.to_owned(),
            commands: cs.join(&b"\n"[..]),
            resources: PdfResources::default(),
            bbox: BoxConstraints::fixed(size.0, size.1),
        })
    }
}

impl PdfContent for BarcodeBox {
    fn render(&mut self, _w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        Ok(self.commands.clone())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_use_code_c() {
        // "123456": start C, 12 34 56, checksum, stop
        let m = code128_modules("123456").unwrap();
        assert!(m.starts_with(CODES[105]));
    }
}
