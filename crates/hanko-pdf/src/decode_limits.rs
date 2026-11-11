// Derived from pyHanko `pdf_utils/decode_limits.py` (MIT, see LICENSE-pyHanko).

//! Limits on the amount of data produced when decoding PDF streams
//! (`pyhanko.pdf_utils.decode_limits`).

use std::collections::BTreeMap;

use crate::error::{PdfError, PdfResult};

const MIB: u64 = 1024 * 1024;

/// Limits that apply to decoding a single stream (`StreamDecodeLimits`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StreamDecodeLimits {
    /// Maximal ratio of decoded to encoded size (above `ratio_floor`).
    pub max_ratio: Option<f64>,
    /// Decoded size below which `max_ratio` is not enforced.
    pub ratio_floor: u64,
    /// Absolute upper bound on the decoded size of a single stream.
    pub max_output_size: Option<u64>,
}

impl Default for StreamDecodeLimits {
    fn default() -> Self {
        Self {
            max_ratio: Some(1100.0),
            ratio_floor: MIB,
            max_output_size: Some(256 * MIB),
        }
    }
}

impl StreamDecodeLimits {
    /// Maximal number of decoded bytes for a stream of the given encoded size.
    pub fn output_cap(&self, encoded_size: u64) -> Option<u64> {
        let mut caps = Vec::new();
        if let Some(r) = self.max_ratio {
            caps.push(self.ratio_floor.max((r * encoded_size as f64) as u64));
        }
        if let Some(m) = self.max_output_size {
            caps.push(m);
        }
        caps.into_iter().min()
    }
}

/// The reason why a stream is decoded (`DecodePurpose`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecodePurpose {
    /// No particular purpose.
    Generic,
    /// An object stream.
    ObjectStream,
    /// A cross-reference stream.
    XrefStream,
    /// An XMP metadata stream.
    XmpMetadata,
    /// A DER-encoded certificate.
    Certificate,
    /// A DER-encoded OCSP response.
    OcspResponse,
    /// A DER-encoded CRL.
    Crl,
}

/// Default purpose-specific limits (`DEFAULT_PURPOSE_LIMITS`).
pub fn default_purpose_limits() -> BTreeMap<DecodePurpose, StreamDecodeLimits> {
    BTreeMap::from([
        (
            DecodePurpose::ObjectStream,
            StreamDecodeLimits {
                max_ratio: Some(100.0),
                ratio_floor: 4 * MIB,
                max_output_size: Some(64 * MIB),
            },
        ),
        (
            DecodePurpose::XmpMetadata,
            StreamDecodeLimits {
                max_ratio: Some(100.0),
                ratio_floor: 4 * MIB,
                max_output_size: Some(32 * MIB),
            },
        ),
        (
            DecodePurpose::Certificate,
            StreamDecodeLimits {
                max_ratio: None,
                ratio_floor: MIB,
                max_output_size: Some(MIB),
            },
        ),
        (
            DecodePurpose::OcspResponse,
            StreamDecodeLimits {
                max_ratio: None,
                ratio_floor: MIB,
                max_output_size: Some(4 * MIB),
            },
        ),
        (
            DecodePurpose::Crl,
            StreamDecodeLimits {
                max_ratio: Some(50.0),
                ratio_floor: 4 * MIB,
                max_output_size: None,
            },
        ),
    ])
}

/// Bound on the total decoded bytes per document (`DocumentDecodeBudget`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DocumentDecodeBudget {
    /// Bytes that may always be decoded.
    pub base_allowance: u64,
    /// Maximal ratio of decoded bytes to input size.
    pub max_ratio: f64,
}

impl Default for DocumentDecodeBudget {
    fn default() -> Self {
        Self {
            base_allowance: 256 * MIB,
            max_ratio: 100.0,
        }
    }
}

impl DocumentDecodeBudget {
    /// The total budget for an input of the given size.
    pub fn total(&self, input_size: u64) -> u64 {
        self.base_allowance
            .max((self.max_ratio * input_size as f64) as u64)
    }
}

/// Decoding limits for a document (`DecodeLimits`).
#[derive(Clone, Debug, PartialEq)]
pub struct DecodeLimits {
    /// Limits for every stream.
    pub per_stream: StreamDecodeLimits,
    /// Additional purpose-specific limits.
    pub per_purpose: BTreeMap<DecodePurpose, StreamDecodeLimits>,
    /// Slack over the expected decoded size, if enforced.
    pub expected_size_slack: Option<u64>,
    /// Document-wide budget, if any.
    pub document_budget: Option<DocumentDecodeBudget>,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            per_stream: StreamDecodeLimits::default(),
            per_purpose: default_purpose_limits(),
            expected_size_slack: Some(4096),
            document_budget: Some(DocumentDecodeBudget::default()),
        }
    }
}

impl DecodeLimits {
    /// Limits for untrusted input (the default).
    pub fn for_untrusted_input() -> Self {
        Self::default()
    }

    /// No limits at all.
    pub fn for_trusted_input() -> Self {
        Self {
            per_stream: StreamDecodeLimits {
                max_ratio: None,
                ratio_floor: MIB,
                max_output_size: None,
            },
            per_purpose: BTreeMap::new(),
            expected_size_slack: None,
            document_budget: None,
        }
    }
}

fn min_cap(caps: &[Option<u64>]) -> Option<u64> {
    caps.iter().flatten().copied().min()
}

/// Applies [`DecodeLimits`] to the streams of a document (`DecodeContext`).
#[derive(Clone, Debug, PartialEq)]
pub struct DecodeContext {
    /// The limits.
    pub limits: DecodeLimits,
    /// Size of the input file, if known.
    pub input_size: Option<u64>,
    remaining_budget: Option<i64>,
}

impl Default for DecodeContext {
    /// `DEFAULT_DECODE_CONTEXT`: default limits, no document budget.
    fn default() -> Self {
        Self::new(DecodeLimits::default(), None)
    }
}

impl DecodeContext {
    /// A context for a document of `input_size` bytes.
    pub fn new(limits: DecodeLimits, input_size: Option<u64>) -> Self {
        let remaining_budget = match (&limits.document_budget, input_size) {
            (Some(b), Some(sz)) => Some(i64::try_from(b.total(sz)).unwrap_or(i64::MAX)),
            _ => None,
        };
        Self {
            limits,
            input_size,
            remaining_budget,
        }
    }

    /// Remaining document budget.
    pub fn remaining_budget(&self) -> Option<i64> {
        self.remaining_budget
    }

    /// Same limits, full budget (`fresh`).
    pub fn fresh(&self) -> Self {
        Self::new(self.limits.clone(), self.input_size)
    }

    /// Output cap of a single filter stage (`stage_output_cap`).
    pub fn stage_output_cap(&self, stream_cap: Option<u64>) -> Option<u64> {
        let budget = self.remaining_budget.map(|b| u64::try_from(b).unwrap_or(0));
        min_cap(&[stream_cap, budget])
    }

    /// Charge produced bytes to the budget (`record_output`).
    pub fn record_output(&mut self, size: usize) {
        if let Some(b) = self.remaining_budget.as_mut() {
            *b = b.saturating_sub(i64::try_from(size).unwrap_or(i64::MAX));
        }
    }

    /// Maximal decoded size of a stream (`stream_output_cap`).
    pub fn stream_output_cap(
        &self,
        encoded_size: u64,
        purpose: DecodePurpose,
        expected_size: Option<i64>,
    ) -> Option<u64> {
        let l = &self.limits;
        let purpose_cap = l
            .per_purpose
            .get(&purpose)
            .and_then(|p| p.output_cap(encoded_size));
        let expected_cap = match (expected_size, l.expected_size_slack) {
            (Some(e), Some(slack)) => {
                Some(u64::try_from(e.max(0)).unwrap_or(0).saturating_add(slack))
            }
            _ => None,
        };
        min_cap(&[
            l.per_stream.output_cap(encoded_size),
            purpose_cap,
            expected_cap,
        ])
    }
}

/// Raise if `size` exceeds `cap` (`check_output_size`).
pub fn check_output_size(size: usize, cap: Option<u64>) -> PdfResult<()> {
    if let Some(c) = cap {
        if size as u64 > c {
            return Err(PdfError::DecodeLimit(format!(
                "Decoded stream data exceeds the limit of {c} bytes."
            )));
        }
    }
    Ok(())
}
