// Derived from pyHanko `pdf_utils/generic.py` (`StreamObject`)
// (MIT, see LICENSE-pyHanko).

//! Stream filter chains (`StreamObject._filters`, `read_data`,
//! `encoded_data`, `apply_filter`).

use lopdf::{Dictionary, Object, Stream};

use crate::decode_limits::{DecodeContext, DecodePurpose};
use crate::error::{PdfError, PdfResult};
use crate::filters::{get_generic_decoder, Deref};

/// Decrypts data for an explicit `/Crypt` filter (`CryptFilterDecoder`).
pub trait CryptFilterDecode {
    /// Decode `data` with the crypt filter named `name` (with slash).
    fn crypt_decode(&self, name: &[u8], params: &Dictionary, data: &[u8]) -> PdfResult<Vec<u8>>;
    /// Encode `data` with the crypt filter named `name`.
    fn crypt_encode(&self, name: &[u8], params: &Dictionary, data: &[u8]) -> PdfResult<Vec<u8>>;
}

/// One filter of a stream with its parameters.
#[derive(Clone, Debug, PartialEq)]
pub struct FilterSpec {
    /// Filter name without slash (as found; may be an arbitrary object for
    /// malformed files, in which case decoding fails).
    pub name: Object,
    /// Decode parameters, `None` for `null` or absent.
    pub params: Option<Dictionary>,
}

impl FilterSpec {
    fn is_crypt(&self) -> bool {
        matches!(&self.name, Object::Name(n) if n == b"Crypt")
    }
}

/// The filters of a stream dictionary (`_filters`).
pub fn stream_filters(dict: &Dictionary, deref: Deref<'_>) -> PdfResult<Vec<FilterSpec>> {
    let filter_arr = match dict.get(b"Filter") {
        Err(_) => return Ok(Vec::new()),
        Ok(f) => deref(f)?,
    };
    let names: Vec<Object> = match filter_arr {
        Object::Null => return Ok(Vec::new()),
        Object::Name(_) => vec![filter_arr],
        Object::Array(a) => a,
        _ => {
            return Err(PdfError::stream(
                "/Filter should be a name object or an array of names.",
            ))
        }
    };
    let params: Vec<Object> = match dict.get(b"DecodeParms") {
        Err(_) => vec![Object::Null; names.len()],
        Ok(p) => match deref(p)? {
            Object::Null => vec![Object::Null; names.len()],
            Object::Dictionary(d) => {
                let mut v = vec![Object::Dictionary(d)];
                v.resize(names.len().max(1), Object::Null);
                v
            }
            Object::Array(mut a) => {
                if a.len() < names.len() {
                    a.resize(names.len(), Object::Null);
                }
                a
            }
            _ => return Err(PdfError::stream("/DecodeParms must be a dictionary or an array")),
        },
    };
    names
        .into_iter()
        .zip(params)
        .map(|(name, p)| {
            let p = deref(&p)?;
            let params = match p {
                Object::Null => None,
                Object::Dictionary(d) => Some(d),
                _ => return Err(PdfError::stream("Decode parameters must be dictionaries")),
            };
            Ok(FilterSpec { name, params })
        })
        .collect()
}

/// `true` if the stream has a `/Crypt` filter (`_has_crypt_filter`).
pub fn has_crypt_filter(dict: &Dictionary, deref: Deref<'_>) -> PdfResult<bool> {
    Ok(stream_filters(dict, deref)?.iter().any(FilterSpec::is_crypt))
}

/// Decode stream data, applying the limits of `ctx` (`read_data`).
pub fn decode_stream_data(
    dict: &Dictionary,
    encoded: &[u8],
    ctx: &mut DecodeContext,
    purpose: DecodePurpose,
    expected_size: Option<i64>,
    deref: Deref<'_>,
    crypt: Option<&dyn CryptFilterDecode>,
) -> PdfResult<Vec<u8>> {
    let stream_cap = ctx.stream_output_cap(encoded.len() as u64, purpose, expected_size);
    let mut data: Option<Vec<u8>> = None;
    for spec in stream_filters(dict, deref)? {
        let empty = Dictionary::new();
        let params = spec.params.as_ref().unwrap_or(&empty);
        let input: &[u8] = data.as_deref().unwrap_or(encoded);
        let out = if spec.is_crypt() {
            let cf_name = match params.get(b"Name") {
                Ok(Object::Name(n)) => n.clone(),
                _ => b"Identity".to_vec(),
            };
            if cf_name == b"Identity" {
                continue;
            }
            let Some(c) = crypt else {
                return Err(PdfError::stream(
                    "PDF streams require a security handler to use explicit /Crypt filters.",
                ));
            };
            let mut slashed = b"/".to_vec();
            slashed.extend_from_slice(&cf_name);
            let out = c.crypt_decode(&slashed, params, input)?;
            crate::decode_limits::check_output_size(out.len(), ctx.stage_output_cap(stream_cap))?;
            out
        } else {
            let decoder = match &spec.name {
                Object::Name(n) => get_generic_decoder(n)?,
                other => {
                    return Err(PdfError::NotImplemented(format!(
                        "Filters of type {other:?} are not supported."
                    )))
                }
            };
            decoder.decode_bounded(input, spec.params.as_ref(), ctx.stage_output_cap(stream_cap), deref)?
        };
        ctx.record_output(out.len());
        data = Some(out);
    }
    Ok(data.unwrap_or_else(|| encoded.to_vec()))
}

/// Encode data through the filters declared in `dict` (`encoded_data`).
pub fn encode_stream_data(
    dict: &Dictionary,
    data: &[u8],
    deref: Deref<'_>,
    crypt: Option<&dyn CryptFilterDecode>,
) -> PdfResult<Vec<u8>> {
    let mut out = data.to_vec();
    for spec in stream_filters(dict, deref)?.into_iter().rev() {
        let empty = Dictionary::new();
        let params = spec.params.as_ref().unwrap_or(&empty);
        if spec.is_crypt() {
            let cf_name = match params.get(b"Name") {
                Ok(Object::Name(n)) => n.clone(),
                _ => b"Identity".to_vec(),
            };
            if cf_name == b"Identity" {
                continue;
            }
            let Some(c) = crypt else {
                return Err(PdfError::stream(
                    "PDF streams require a security handler to use explicit /Crypt filters.",
                ));
            };
            let mut slashed = b"/".to_vec();
            slashed.extend_from_slice(&cf_name);
            out = c.crypt_encode(&slashed, params, &out)?;
        } else {
            let decoder = match &spec.name {
                Object::Name(n) => get_generic_decoder(n)?,
                other => {
                    return Err(PdfError::NotImplemented(format!(
                        "Filters of type {other:?} are not supported."
                    )))
                }
            };
            out = decoder.encode(&out)?;
        }
    }
    Ok(out)
}

/// Deref function that refuses indirect references (for streams not tied to
/// a document).
pub fn no_deref(o: &Object) -> PdfResult<Object> {
    match o {
        Object::Reference(id) => Err(PdfError::read(format!(
            "Cannot resolve reference {} {} R without a PDF handler",
            id.0, id.1
        ))),
        other => Ok(other.clone()),
    }
}

/// How to treat a filter that is already present (`allow_duplicates`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicateFilter {
    /// Allow duplicates (`True`).
    Allow,
    /// Silently ignore the request (`None`).
    Ignore,
    /// Raise `PdfWriteError` (`False`).
    Error,
}

/// A stream under construction with decoded data (the writer-side view of
/// `StreamObject`): filters are applied on [`DecodedStream::to_stream`].
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedStream {
    /// Stream dictionary (without `/Length`).
    pub dict: Dictionary,
    /// Decoded data.
    pub data: Vec<u8>,
}

impl DecodedStream {
    /// A stream with the given dictionary and decoded data.
    pub fn new(dict: Dictionary, data: Vec<u8>) -> Self {
        Self { dict, data }
    }

    /// Prepend a filter (`apply_filter`).
    pub fn apply_filter(
        &mut self,
        filter_name: &str,
        params: Option<Dictionary>,
        allow_duplicates: DuplicateFilter,
    ) -> PdfResult<()> {
        let name = filter_name.strip_prefix('/').unwrap_or(filter_name).as_bytes().to_vec();
        let cur = stream_filters(&self.dict, &no_deref)?;
        if cur.is_empty() {
            self.dict.set("Filter", Object::Name(name));
            if let Some(p) = params.filter(|p| !p.is_empty()) {
                self.dict.set("DecodeParms", Object::Dictionary(p));
            }
            return Ok(());
        }
        if allow_duplicates != DuplicateFilter::Allow
            && cur.iter().any(|s| matches!(&s.name, Object::Name(n) if *n == name))
        {
            if allow_duplicates == DuplicateFilter::Error {
                return Err(PdfError::write(format!(
                    "Filter /{} has already been applied to this stream.",
                    String::from_utf8_lossy(&name)
                )));
            }
            return Ok(());
        }
        let mut names = vec![Object::Name(name)];
        names.extend(cur.iter().map(|s| s.name.clone()));
        self.dict.set("Filter", Object::Array(names));
        let params_nonempty = params.as_ref().is_some_and(|p| !p.is_empty());
        if params_nonempty || cur.iter().any(|s| s.params.as_ref().is_some_and(|p| !p.is_empty())) {
            let mut arr = vec![params.map_or(Object::Null, |p| {
                if p.is_empty() {
                    Object::Null
                } else {
                    Object::Dictionary(p)
                }
            })];
            arr.extend(cur.into_iter().map(|s| match s.params {
                Some(p) if !p.is_empty() => Object::Dictionary(p),
                _ => Object::Null,
            }));
            self.dict.set("DecodeParms", Object::Array(arr));
        }
        Ok(())
    }

    /// Add `/FlateDecode` unless present (`compress`).
    pub fn compress(&mut self) -> PdfResult<()> {
        self.apply_filter("FlateDecode", None, DuplicateFilter::Ignore)
    }

    /// Remove all filters (`strip_filters`).
    pub fn strip_filters(&mut self) {
        self.dict.remove(b"Filter");
        self.dict.remove(b"DecodeParms");
    }

    /// Encode into a [`Stream`] with encoded content.
    pub fn to_stream(&self) -> PdfResult<Stream> {
        let content = encode_stream_data(&self.dict, &self.data, &no_deref, None)?;
        Ok(Stream {
            dict: self.dict.clone(),
            content,
            allows_compression: false,
            start_position: None,
        })
    }

    /// Decode an existing (encoded) stream without limits.
    pub fn from_stream(s: &Stream) -> PdfResult<Self> {
        let mut ctx = DecodeContext::new(crate::decode_limits::DecodeLimits::for_trusted_input(), None);
        let data = decode_stream_data(&s.dict, &s.content, &mut ctx, DecodePurpose::Generic, None, &no_deref, None)?;
        Ok(Self {
            dict: s.dict.clone(),
            data,
        })
    }
}

/// A stream object with encoded content (`StreamObject(d, encoded_data=..)`).
pub fn encoded_stream(dict: Dictionary, content: Vec<u8>) -> Object {
    Object::Stream(Stream {
        dict,
        content,
        allows_compression: false,
        start_position: None,
    })
}
