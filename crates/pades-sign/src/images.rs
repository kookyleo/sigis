// Derived from pyHanko `pdf_utils/images.py` (MIT, see LICENSE-pyHanko).

//! Bitmap images as image XObjects (`pyhanko.pdf_utils.images`).
//!
//! pyHanko decodes images with Pillow; the port decodes PNG with the `png`
//! crate and JPEG with `zune-jpeg`, into the same pixel modes Pillow uses:
//! `L`, `LA`, `RGB`, `RGBA` and palette images (`P`), which keep their
//! palette as an `/Indexed` colour space.

use std::path::Path;
use std::sync::Arc;

use lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};
use sigis_pki_core::errors::{HankoError, Result};

use crate::content::ops::{fmt_g, uuid4};
use crate::content::{compressed, ContentWriter, PdfContent, PdfResources, ResourceType};
use crate::layout::BoxConstraints;
use crate::pdf::writer::PdfUpdate;

fn image_error(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(format!("image: {}", msg.into()))
}

/// Pixel layout of a decoded image (Pillow's image modes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageMode {
    /// 8-bit grayscale.
    L,
    /// 8-bit grayscale with alpha.
    La,
    /// 8-bit RGB.
    Rgb,
    /// 8-bit RGB with alpha.
    Rgba,
    /// 8-bit palette indices; the palette holds RGB triples.
    P(Vec<u8>),
}

impl ImageMode {
    fn channels(&self) -> usize {
        match self {
            Self::L | Self::P(_) => 1,
            Self::La => 2,
            Self::Rgb => 3,
            Self::Rgba => 4,
        }
    }
}

/// A decoded bitmap image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Pixel layout.
    pub mode: ImageMode,
    /// Pixels, row by row, one byte per channel.
    pub data: Vec<u8>,
}

fn expand_bits(row: &[u8], bits: u8, width: usize, scale: bool) -> Vec<u8> {
    let per_byte = usize::from(8 / bits);
    let mask = (1u16 << bits) - 1;
    let max = mask as u8;
    (0..width)
        .map(|i| {
            let byte = row.get(i / per_byte).copied().unwrap_or(0);
            let shift = 8 - bits as usize * (i % per_byte + 1);
            let v = (byte >> shift) & max;
            if scale {
                // Pillow scales low bit depth grayscale to 0..255
                (u16::from(v) * 255 / mask) as u8
            } else {
                v
            }
        })
        .collect()
}

impl Image {
    /// Decode a PNG or JPEG image.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.starts_with(b"\x89PNG") {
            Self::decode_png(data)
        } else if data.starts_with(&[0xff, 0xd8]) {
            Self::decode_jpeg(data)
        } else {
            Err(HankoError::Unsupported(
                "image format (only PNG and JPEG are supported)".into(),
            ))
        }
    }

    /// Read and decode an image file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::decode(&std::fs::read(path)?)
    }

    fn decode_png(data: &[u8]) -> Result<Self> {
        let mut decoder = png::Decoder::new(std::io::Cursor::new(data));
        decoder.set_transformations(png::Transformations::IDENTITY);
        let mut reader = decoder
            .read_info()
            .map_err(|e| image_error(e.to_string()))?;
        // Pillow exposes these grayscale PNGs as modes `1` and `I;16`,
        // which pyHanko's pil_image rejects. Indexed 1-bit and RGB(A)
        // 16-bit PNGs decode to supported Pillow modes and remain allowed.
        let header = reader.info();
        if header.color_type == png::ColorType::Grayscale
            && matches!(
                header.bit_depth,
                png::BitDepth::One | png::BitDepth::Sixteen
            )
        {
            return Err(HankoError::Unsupported(
                "image mode (1-bit and 16-bit grayscale PNGs are unsupported)".into(),
            ));
        }
        let size = reader
            .output_buffer_size()
            .ok_or_else(|| image_error("image too large"))?;
        let mut buf = vec![0u8; size];
        let info = reader
            .next_frame(&mut buf)
            .map_err(|e| image_error(e.to_string()))?;
        let (w, h) = (info.width as usize, info.height as usize);
        let line = info.line_size;
        let bits = info.bit_depth as u8;
        let ct = info.color_type;
        let palette = reader.info().palette.as_ref().map(|p| p.to_vec());
        let mode = match ct {
            png::ColorType::Grayscale => ImageMode::L,
            png::ColorType::GrayscaleAlpha => ImageMode::La,
            png::ColorType::Rgb => ImageMode::Rgb,
            png::ColorType::Rgba => ImageMode::Rgba,
            png::ColorType::Indexed => {
                ImageMode::P(palette.ok_or_else(|| image_error("palette missing"))?)
            }
        };
        let channels = mode.channels();
        let mut out = Vec::with_capacity(w * h * channels);
        for y in 0..h {
            let row = buf
                .get(y * line..(y + 1) * line)
                .ok_or_else(|| image_error("short image data"))?;
            match bits {
                1 | 2 | 4 => {
                    let scale = !matches!(mode, ImageMode::P(_));
                    out.extend(expand_bits(row, bits, w, scale));
                }
                8 => out.extend_from_slice(&row[..w * channels]),
                16 => out.extend(row.chunks(2).take(w * channels).map(|c| c[0])),
                _ => return Err(image_error("unsupported bit depth")),
            }
        }
        Ok(Self {
            width: info.width,
            height: info.height,
            mode,
            data: out,
        })
    }

    fn decode_jpeg(data: &[u8]) -> Result<Self> {
        use zune_jpeg::zune_core::colorspace::ColorSpace;
        use zune_jpeg::zune_core::options::DecoderOptions;
        let mut dec = zune_jpeg::JpegDecoder::new_with_options(
            data,
            DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGB),
        );
        dec.decode_headers()
            .map_err(|e| image_error(e.to_string()))?;
        let gray = matches!(dec.get_input_colorspace(), Some(ColorSpace::Luma));
        if gray {
            dec = zune_jpeg::JpegDecoder::new_with_options(
                data,
                DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::Luma),
            );
        }
        let pixels = dec.decode().map_err(|e| image_error(e.to_string()))?;
        let info = dec.info().ok_or_else(|| image_error("no JPEG header"))?;
        Ok(Self {
            width: u32::from(info.width),
            height: u32::from(info.height),
            mode: if gray { ImageMode::L } else { ImageMode::Rgb },
            data: pixels,
        })
    }

    /// The alpha channel as an `L` image, and the image without alpha
    /// (`img.split()[-1]`, `img.convert(...)`).
    fn split_alpha(&self) -> Option<(Image, Image)> {
        let (channels, base_mode) = match self.mode {
            ImageMode::La => (2, ImageMode::L),
            ImageMode::Rgba => (4, ImageMode::Rgb),
            _ => return None,
        };
        let alpha: Vec<u8> = self
            .data
            .chunks(channels)
            .map(|c| c[channels - 1])
            .collect();
        let base: Vec<u8> = self
            .data
            .chunks(channels)
            .flat_map(|c| c[..channels - 1].to_vec())
            .collect();
        Some((
            Image {
                width: self.width,
                height: self.height,
                mode: ImageMode::L,
                data: alpha,
            },
            Image {
                width: self.width,
                height: self.height,
                mode: base_mode,
                data: base,
            },
        ))
    }
}

/// Write `img` as an image XObject (`pil_image`); alpha channels become a
/// soft mask.
pub fn pil_image(img: &Image, update: &mut PdfUpdate) -> Result<ObjectId> {
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"XObject".to_vec()));
    d.set("Subtype", Object::Name(b"Image".to_vec()));
    d.set("Width", Object::Integer(i64::from(img.width)));
    d.set("Height", Object::Integer(i64::from(img.height)));
    let (smask, img) = match img.split_alpha() {
        Some((alpha, base)) => (
            Some(pil_image(&alpha, update)?),
            std::borrow::Cow::Owned(base),
        ),
        None => (None, std::borrow::Cow::Borrowed(img)),
    };
    let clr_space = match &img.mode {
        ImageMode::L => Object::Name(b"DeviceGray".to_vec()),
        ImageMode::P(palette) => {
            let size = palette.len() / 3;
            Object::Array(vec![
                Object::Name(b"Indexed".to_vec()),
                Object::Name(b"DeviceRGB".to_vec()),
                Object::Integer(i64::try_from(size).unwrap_or(1) - 1),
                Object::String(palette.clone(), StringFormat::Hexadecimal),
            ])
        }
        _ => Object::Name(b"DeviceRGB".to_vec()),
    };
    if let Some(s) = smask {
        d.set("SMask", Object::Reference(s));
    }
    d.set("ColorSpace", clr_space);
    d.set("BitsPerComponent", Object::Integer(8));
    Ok(update.add(Object::Stream(compressed(Stream::new(d, img.data.clone())))))
}

/// An image as content (`PdfImage`).
#[derive(Clone, Debug)]
pub struct PdfImage {
    /// The image.
    pub image: Arc<Image>,
    /// Resource name suffix.
    pub name: String,
    /// Fill opacity.
    pub opacity: Option<f64>,
    resources: PdfResources,
    bbox: BoxConstraints,
}

impl PdfImage {
    /// Wrap an image; the box defaults to the pixel size.
    pub fn new(
        image: Image,
        name: Option<String>,
        opacity: Option<f64>,
        bbox: Option<BoxConstraints>,
    ) -> Self {
        let bbox = bbox.unwrap_or_else(|| {
            BoxConstraints::fixed(f64::from(image.width), f64::from(image.height))
        });
        Self {
            image: Arc::new(image),
            name: name.unwrap_or_else(|| uuid4(true)),
            opacity,
            resources: PdfResources::default(),
            bbox,
        }
    }

    /// Open an image file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::new(Image::open(path)?, None, None, None))
    }
}

impl PdfContent for PdfImage {
    fn render(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        let img_ref_name = format!("Img{}", self.name);
        let image_ref = pil_image(&self.image, w.update())?;
        self.resources.set(
            ResourceType::XObject,
            &img_ref_name,
            Object::Reference(image_ref),
        );
        let mut opacity = String::new();
        if let Some(o) = self.opacity {
            let gs_name = format!("GS{}", uuid4(true));
            let mut gs = Dictionary::new();
            gs.set("ca", Object::Real(o as f32));
            self.resources
                .set(ResourceType::ExtGState, &gs_name, Object::Dictionary(gs));
            opacity = format!("/{gs_name} gs");
        }
        if !self.bbox.height_defined() {
            self.bbox.set_height(f64::from(self.image.height))?;
        }
        if !self.bbox.width_defined() {
            self.bbox.set_width(f64::from(self.image.width))?;
        }
        Ok(format!(
            "q {opacity} {} 0 0 {} 0 0 cm /{img_ref_name} Do Q",
            fmt_g(self.bbox.width()?),
            fmt_g(self.bbox.height()?)
        )
        .into_bytes())
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
