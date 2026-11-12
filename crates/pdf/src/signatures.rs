// Derived from pyHanko `pdf_utils/form_tools.py` (`enumerate_fields_in`),
// `sign/fields.py` (`enumerate_sig_fields`, `SigSeedSubFilter`),
// `sign/validation/pdf_embedded.py` (`collect_embedded_signatures`,
// `extract_contents`, `EmbeddedPdfSignature.__init__`) and
// `sign/validation/dss.py` (`DocumentSecurityStore.read_dss`)
// (MIT, see LICENSE-pyHanko).

//! Signature field enumeration, embedded signature discovery and DSS reading.

use std::collections::{BTreeMap, BTreeSet};

use lopdf::{Dictionary, Object, ObjectId};

use crate::decode_limits::DecodePurpose;
use crate::error::{PdfError, PdfResult};
use crate::generic::{decode_text, is_name, PdfString};
use crate::reader::PdfFile;
use crate::rw_common::{PdfHandler, PdfHandlerExt};

/// A form field found by [`enumerate_fields_in`].
#[derive(Clone, Debug, PartialEq)]
pub struct FieldInfo {
    /// Fully qualified name.
    pub fq_name: String,
    /// Raw `/V` value (not dereferenced), if any.
    pub value: Option<Object>,
    /// Reference to the field dictionary.
    pub field_ref: ObjectId,
}

fn field_name_text(o: &Object) -> String {
    match o {
        Object::String(s, _) => match crate::generic::pdf_string(s) {
            PdfString::Text(t, _) => t,
            PdfString::Bytes(b) => crate::generic::py_bytes_repr(&b),
        },
        Object::Name(n) => crate::generic::name_str(n),
        other => format!("{other:?}"),
    }
}

/// `bool(value)` for a raw PDF value.
fn py_truthy(o: &Object) -> bool {
    match o {
        Object::Null => false,
        Object::Boolean(b) => *b,
        Object::Integer(i) => *i != 0,
        Object::Real(r) => *r != 0.0,
        Object::Name(_) => true,
        Object::String(s, _) => !s.is_empty(),
        Object::Array(a) => !a.is_empty(),
        Object::Dictionary(d) => !d.is_empty(),
        Object::Stream(_) => true,
        Object::Reference(_) => true,
    }
}

/// Enumerate the fields of type `target_field_type` (e.g. `"Sig"`) in a
/// field list (`enumerate_fields_in`).
pub fn enumerate_fields_in(
    handler: &dyn PdfHandler,
    field_list: &Object,
    filled_status: Option<bool>,
    with_name: Option<&str>,
    target_field_type: &str,
) -> PdfResult<Vec<FieldInfo>> {
    let mut out = Vec::new();
    enumerate_rec(
        handler,
        field_list,
        filled_status,
        with_name,
        "",
        &[],
        &BTreeSet::new(),
        target_field_type,
        &mut out,
    )?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn enumerate_rec(
    handler: &dyn PdfHandler,
    field_list: &Object,
    filled_status: Option<bool>,
    with_name: Option<&str>,
    parent_name: &str,
    parents: &[Dictionary],
    refs_seen: &BTreeSet<ObjectId>,
    target: &str,
    out: &mut Vec<FieldInfo>,
) -> PdfResult<()> {
    let Object::Array(fields) = field_list else {
        log::warn!("Field lists must be array objects -- skipping.");
        return Ok(());
    };
    for field_ref in fields {
        let Object::Reference(fref) = field_ref else {
            log::warn!("Entries in field list must be indirect references -- skipping.");
            continue;
        };
        if refs_seen.contains(fref) {
            return Err(PdfError::read("Circular reference in form tree"));
        }
        let field = match handler.resolve(field_ref)? {
            Object::Dictionary(d) => d,
            _ => {
                log::warn!("Entries in field list must be dictionary objects -- skipping.");
                continue;
            }
        };
        let Some(name_obj) = handler.get(&field, b"T")? else {
            continue;
        };
        let field_name = field_name_text(&name_obj);
        let fq_name = if parent_name.is_empty() {
            field_name
        } else {
            format!("{parent_name}.{field_name}")
        };
        let explicitly_requested = with_name == Some(fq_name.as_str());
        let child_requested =
            explicitly_requested || with_name.is_some_and(|w| w.starts_with(fq_name.as_str()));
        let mut current_path = vec![field.clone()];
        current_path.extend_from_slice(parents);
        let mut field_type = None;
        for p in &current_path {
            if let Some(ft) = handler.get(p, b"FT")? {
                field_type = Some(ft);
                break;
            }
        }
        if field_type.as_ref().is_some_and(|ft| is_name(ft, target)) {
            let value = field.get(b"V").ok().cloned();
            let filled = value.as_ref().is_some_and(py_truthy);
            let status_check = filled_status.is_none_or(|s| s == filled);
            let name_check = with_name.is_none() || explicitly_requested;
            if status_check && name_check {
                out.push(FieldInfo {
                    fq_name: fq_name.clone(),
                    value,
                    field_ref: *fref,
                });
            }
        } else if explicitly_requested {
            return Err(PdfError::FormFilling(format!(
                "Field with name {fq_name} exists but is not a /{target} field"
            )));
        }
        if with_name.is_none() || (child_requested && !explicitly_requested) {
            if let Some(kids) = handler.get(&field, b"Kids")? {
                let mut seen = refs_seen.clone();
                seen.insert(*fref);
                enumerate_rec(
                    handler,
                    &kids,
                    filled_status,
                    with_name,
                    &fq_name,
                    &current_path,
                    &seen,
                    target,
                    out,
                )?;
            }
        }
    }
    Ok(())
}

/// Enumerate signature fields (`enumerate_sig_fields`).
pub fn enumerate_sig_fields(
    handler: &dyn PdfHandler,
    filled_status: Option<bool>,
    with_name: Option<&str>,
) -> PdfResult<Vec<FieldInfo>> {
    let root = handler.root()?;
    let Some(Object::Dictionary(acroform)) = handler.get(&root, b"AcroForm")? else {
        return Ok(Vec::new());
    };
    let Some(fields) = handler.get(&acroform, b"Fields")? else {
        return Ok(Vec::new());
    };
    enumerate_fields_in(handler, &fields, filled_status, with_name, "Sig")
}

/// `/SubFilter` values pyHanko recognises (`SigSeedSubFilter`).
pub const KNOWN_SUBFILTERS: [&str; 4] = [
    "adbe.pkcs7.detached",
    "ETSI.CAdES.detached",
    "ETSI.RFC3161",
    "PBAD.PAdES",
];

/// Kind of an embedded signature dictionary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureKind {
    /// `/Type /Sig` (also the default).
    Signature,
    /// `/Type /DocTimeStamp`.
    DocTimeStamp,
}

/// A signature embedded in a PDF (`EmbeddedPdfSignature`, structural part).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedSignature {
    /// Fully qualified field name.
    pub field_name: String,
    /// Signature dictionary object.
    pub sig_object: ObjectId,
    /// Signature or document timestamp.
    pub kind: SignatureKind,
    /// `/SubFilter`.
    pub sub_filter: Option<String>,
    /// `/ByteRange` as flattened offset-length pairs.
    pub byte_range: Vec<u64>,
    /// `/Contents` with trailing padding removed (DER CMS).
    pub contents: Vec<u8>,
    /// Revision in which the signature was added.
    pub signed_revision: usize,
    /// The signature field dictionary holding the signature.
    pub field_object: ObjectId,
}

/// Length of the outer DER TLV of `b`, if well-formed.
pub fn der_outer_length(b: &[u8]) -> Option<usize> {
    let first_len = *b.get(1)?;
    let (len, hdr) = if first_len < 0x80 {
        (usize::from(first_len), 2)
    } else {
        let n = usize::from(first_len & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | usize::from(*b.get(2 + i)?);
        }
        (l, 2 + n)
    };
    let total = hdr.checked_add(len)?;
    (total <= b.len()).then_some(total)
}

/// Extract the signature bytes (`extract_contents`): the raw (never
/// decrypted) `/Contents`.
pub fn extract_contents(sig_object: &Dictionary) -> PdfResult<Vec<u8>> {
    match sig_object.get(b"Contents") {
        Err(_) => Err(PdfError::read(
            "Could not read /Contents entry in signature",
        )),
        Ok(Object::String(s, _)) => Ok(s.clone()),
        Ok(_) => Err(PdfError::read("/Contents must be string-like")),
    }
}

impl EmbeddedSignature {
    /// The bytes covered by the byte range (`/ByteRange` of `file`).
    pub fn signed_data(&self, file: &PdfFile) -> sigis_pki_core::errors::Result<Vec<u8>> {
        Ok(byte_range_data(file.bytes(), &self.byte_range)?)
    }
}

/// The data covered by complete `(offset, length)` pairs, in their given order.
///
/// Every range must fit within `bytes`. The concatenated output is limited to
/// the input length, including repeated or overlapping ranges, to prevent
/// attacker-controlled ranges from amplifying the allocation. This is a
/// stricter resource bound than pyHanko's streaming digest helper.
pub fn byte_range_data(bytes: &[u8], br: &[u64]) -> PdfResult<Vec<u8>> {
    let (pairs, remainder) = br.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(PdfError::read(
            "Byte range must contain complete offset-length pairs",
        ));
    }
    let input_len = u64::try_from(bytes.len())
        .map_err(|_| PdfError::read("Input length exceeds byte range representation"))?;
    let mut total_len = 0usize;
    // Validate every pair and the complete output size before allocating or
    // copying any data. In particular, a bad later pair cannot be ignored.
    for pair in pairs {
        let end = pair[0]
            .checked_add(pair[1])
            .ok_or_else(|| PdfError::read("Byte range overflows"))?;
        if end > input_len {
            return Err(PdfError::read(
                "Byte range extends beyond the end of the file",
            ));
        }
        let length =
            usize::try_from(pair[1]).map_err(|_| PdfError::read("Byte range overflows"))?;
        total_len = total_len
            .checked_add(length)
            .ok_or_else(|| PdfError::read("Total byte range length overflows"))?;
        if total_len > bytes.len() {
            return Err(PdfError::read(
                "Total byte range length exceeds input file length",
            ));
        }
    }
    let mut out = Vec::new();
    out.try_reserve_exact(total_len)
        .map_err(|_| PdfError::read("Could not allocate byte range buffer"))?;
    for pair in pairs {
        // The preflight proves these conversions and the slice bounds fit.
        let start = pair[0] as usize;
        let end = (pair[0] + pair[1]) as usize;
        out.extend_from_slice(&bytes[start..end]);
    }
    Ok(out)
}

fn parse_byte_range(o: &Object) -> PdfResult<Vec<u64>> {
    let Object::Array(a) = o else {
        return Err(PdfError::read("/ByteRange must be an array"));
    };
    if !a.len().is_multiple_of(2) {
        return Err(PdfError::read(
            "/ByteRange must contain complete offset-length pairs",
        ));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(a.len())
        .map_err(|_| PdfError::read("Could not allocate /ByteRange entries"))?;
    for value in a {
        match value {
            Object::Integer(i) if *i >= 0 => out.push(*i as u64),
            _ => {
                return Err(PdfError::read(
                    "/ByteRange entries must be nonnegative integers",
                ))
            }
        }
    }
    Ok(out)
}

impl PdfFile {
    /// Signatures with a value, in signing order (`embedded_signatures`).
    /// Signatures with an unrecognised `/SubFilter` are skipped, as in
    /// pyHanko.
    pub fn embedded_signatures(&self) -> sigis_pki_core::errors::Result<Vec<EmbeddedSignature>> {
        Ok(self.embedded_signatures_pdf()?)
    }

    /// [`Self::embedded_signatures`] with a [`PdfError`].
    pub fn embedded_signatures_pdf(&self) -> PdfResult<Vec<EmbeddedSignature>> {
        if let Some(s) = self.inner.embedded_signatures.get() {
            return Ok(s.clone());
        }
        let fields = enumerate_sig_fields(self, Some(true), None)?;
        let mut out = Vec::new();
        for f in fields {
            let Some(v) = f.value else { continue };
            let sig_obj = match self.resolve(&v)? {
                Object::Dictionary(d) => d,
                _ => return Err(PdfError::read("Signature value must be a dictionary")),
            };
            let sub_filter = match sig_obj.get(b"SubFilter") {
                Ok(Object::Name(n)) => Some(String::from_utf8_lossy(n).into_owned()),
                _ => None,
            };
            if !sub_filter
                .as_deref()
                .is_some_and(|s| KNOWN_SUBFILTERS.contains(&s))
            {
                log::warn!(
                    "Encountered signature with unsupported SubFilter type {sub_filter:?}; ignoring"
                );
                continue;
            }
            let Object::Reference(sig_ref) = v else {
                return Err(PdfError::IndirectObjectExpected(
                    "Signature value must be an indirect object".into(),
                ));
            };
            // the signature dictionary is fetched without decryption, so
            // /Contents and /ByteRange are as in the file
            let raw = match self.get_object_raw(sig_ref, None)? {
                Object::Dictionary(d) => d,
                _ => return Err(PdfError::read("Signature value must be a dictionary")),
            };
            let br = raw
                .get(b"ByteRange")
                .map_err(|_| PdfError::read("Could not read /ByteRange entry in signature"))?;
            let byte_range = parse_byte_range(&self.resolve(br)?)?;
            let mut contents = extract_contents(&raw)?;
            if let Some(l) = der_outer_length(&contents) {
                contents.truncate(l);
            }
            check_cms_content_info(&contents)?;
            let kind = match sig_obj.get(b"Type") {
                Ok(t) if is_name(t, "DocTimeStamp") => SignatureKind::DocTimeStamp,
                _ => SignatureKind::Signature,
            };
            let signed_revision = self
                .xrefs()
                .get_last_change(sig_ref)
                .ok_or_else(|| PdfError::Value("KeyError: signature object".into()))?;
            out.push(EmbeddedSignature {
                field_name: f.fq_name,
                sig_object: sig_ref,
                kind,
                sub_filter,
                byte_range,
                contents,
                signed_revision,
                field_object: f.field_ref,
            });
        }
        out.sort_by_key(|s| s.signed_revision);
        let _ = self.inner.embedded_signatures.set(out.clone());
        Ok(out)
    }

    /// The Document Security Store of the latest revision, if any.
    pub fn dss(&self) -> sigis_pki_core::errors::Result<Option<DocumentSecurityStore>> {
        Ok(read_dss(self)?)
    }
}

fn check_cms_content_info(contents: &[u8]) -> PdfResult<()> {
    use der::Decode;
    cms::content_info::ContentInfo::from_der(contents)
        .map(|_| ())
        .map_err(|e| PdfError::Value(format!("Failed to parse CMS ContentInfo: {e}")))
}

/// Validation-related information of a DSS `/VRI` entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VriEntry {
    /// Certificates (DER).
    pub certs: Vec<Vec<u8>>,
    /// OCSP responses (DER).
    pub ocsps: Vec<Vec<u8>>,
    /// CRLs (DER).
    pub crls: Vec<Vec<u8>>,
}

/// The Document Security Store (`DocumentSecurityStore`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DocumentSecurityStore {
    /// `/Certs`, `/OCSPs` and `/CRLs` of the DSS.
    pub material: VriEntry,
    /// `/VRI`, keyed by the upper-case hex SHA-1 of the signature contents.
    pub vri: BTreeMap<String, VriEntry>,
}

fn read_stream_list(
    handler: &dyn PdfHandler,
    dict: &Dictionary,
    key: &[u8],
    purpose: DecodePurpose,
) -> PdfResult<Vec<Vec<u8>>> {
    let Some(list) = handler.get(dict, key)? else {
        return Ok(Vec::new());
    };
    let Object::Array(items) = list else {
        return Err(PdfError::read(format!(
            "DSS entry /{} must be an array",
            String::from_utf8_lossy(key)
        )));
    };
    items
        .iter()
        .map(|item| match handler.resolve(item)? {
            Object::Stream(s) => handler.decode_stream(&s, purpose),
            _ => Err(PdfError::read("DSS entries must be streams")),
        })
        .collect()
}

/// Read the DSS of any handler (`DocumentSecurityStore.read_dss`); `None`
/// if the catalog has no `/DSS` (`NoDSSFoundError`).
pub fn read_dss(handler: &dyn PdfHandler) -> PdfResult<Option<DocumentSecurityStore>> {
    let root = handler.root()?;
    let Some(dss) = handler.get(&root, b"DSS")? else {
        return Ok(None);
    };
    let Object::Dictionary(dss) = dss else {
        return Err(PdfError::read("/DSS must be a dictionary"));
    };
    let material = VriEntry {
        certs: read_stream_list(handler, &dss, b"Certs", DecodePurpose::Certificate)?,
        ocsps: read_stream_list(handler, &dss, b"OCSPs", DecodePurpose::OcspResponse)?,
        crls: read_stream_list(handler, &dss, b"CRLs", DecodePurpose::Crl)?,
    };
    let mut vri = BTreeMap::new();
    if let Some(Object::Dictionary(vd)) = handler.get(&dss, b"VRI")? {
        for (k, v) in vd.iter() {
            let Object::Dictionary(entry) = handler.resolve(v)? else {
                continue;
            };
            vri.insert(
                String::from_utf8_lossy(k).into_owned(),
                VriEntry {
                    certs: read_stream_list(handler, &entry, b"Cert", DecodePurpose::Certificate)?,
                    ocsps: read_stream_list(handler, &entry, b"OCSP", DecodePurpose::OcspResponse)?,
                    crls: read_stream_list(handler, &entry, b"CRL", DecodePurpose::Crl)?,
                },
            );
        }
    }
    Ok(Some(DocumentSecurityStore { material, vri }))
}

/// VRI key of a signature (`sig_content_identifier`): upper-case hex SHA-1
/// of the signature contents.
pub fn sig_content_identifier(contents: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let d = Sha1::digest(contents);
    d.iter().map(|b| format!("{b:02X}")).collect()
}

/// Text of a field name object (helper for consumers).
pub fn text_of(o: &Object) -> Option<String> {
    match o {
        Object::String(s, _) => decode_text(s),
        _ => None,
    }
}

// Supplemental structural regressions for the approved variable ByteRange API.
// No coverage or trusted-validation verdict follows from extracting these bytes.
#[cfg(test)]
mod byte_range_regressions {
    use super::*;

    fn range_object(values: &[i64]) -> Object {
        Object::Array(values.iter().copied().map(Object::Integer).collect())
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        sigis_pki_core::algorithms::DigestAlgorithm::Sha256
            .digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn assert_read_error<T: std::fmt::Debug>(result: PdfResult<T>, message: &str) {
        let error = result.expect_err("malformed byte range must reject");
        assert!(matches!(error, PdfError::Read(_)), "{error:?}");
        assert!(error.message().contains(message), "{error:?}");
    }

    #[test]
    fn variable_byte_range_parser_retains_every_complete_pair() {
        for expected in [
            vec![],
            vec![0, 3],
            vec![0, 2, 4, 2],
            vec![6, 2, 2, 2, 0, 1],
            vec![i64::MAX, 0],
        ] {
            let actual = parse_byte_range(&range_object(&expected)).unwrap();
            assert_eq!(
                actual.to_vec(),
                expected
                    .iter()
                    .map(|value| *value as u64)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn variable_byte_range_data_preserves_pair_order_overlap_and_zero_lengths() {
        let bytes = b"abcdefghijkl";
        let cases: &[(&[u64], &[u8])] = &[
            (&[], b""),
            (&[0, 3], b"abc"),
            (&[0, 2, 4, 2], b"abef"),
            (&[6, 2, 2, 2, 0, 1], b"ghcda"),
            (&[0, 2, 0, 2], b"abab"),
            (&[12, 0, 0, 1], b"a"),
            (&[0, 0, 12, 0], b""),
        ];
        for (range, expected) in cases {
            assert_eq!(byte_range_data(bytes, range).unwrap(), *expected);
        }
    }

    #[test]
    fn variable_byte_range_rejects_incomplete_pairs_before_returning_data() {
        for range in [&[0][..], &[0, 1, 4][..], &[0, 1, 4, 1, 6][..]] {
            assert_read_error(
                byte_range_data(b"abcdefghijkl", range),
                "complete offset-length pairs",
            );
            let object = range_object(&range.iter().map(|value| *value as i64).collect::<Vec<_>>());
            assert_read_error(parse_byte_range(&object), "complete offset-length pairs");
        }
    }

    #[test]
    fn variable_byte_range_parser_rejects_noninteger_and_negative_entries() {
        assert_read_error(
            parse_byte_range(&Object::Integer(0)),
            "/ByteRange must be an array",
        );
        for invalid in [
            Object::Integer(-1),
            Object::Real(1.0),
            Object::Boolean(false),
            Object::Null,
            Object::Name(b"Offset".to_vec()),
            Object::String(b"1".to_vec(), lopdf::StringFormat::Literal),
            Object::Reference((1, 0)),
        ] {
            for position in [0, 1, 3, 5] {
                let mut values = vec![Object::Integer(0); 6];
                values[position] = invalid.clone();
                assert_read_error(
                    parse_byte_range(&Object::Array(values)),
                    "entries must be nonnegative integers",
                );
            }
        }
    }

    #[test]
    fn variable_byte_range_checks_all_bounds_and_integer_overflow() {
        let bytes = b"abcdefghijkl";
        for range in [
            &[0, 13][..],
            &[12, 1][..],
            &[13, 0][..],
            &[0, 1, 13, 0][..],
            &[0, 1, 1, 1, 12, 1][..],
            &[u64::MAX, 0][..],
        ] {
            assert_read_error(
                byte_range_data(bytes, range),
                "extends beyond the end of the file",
            );
        }
        for range in [
            &[u64::MAX, 1][..],
            &[1, u64::MAX][..],
            &[0, 1, u64::MAX, 1][..],
        ] {
            assert_read_error(byte_range_data(bytes, range), "Byte range overflows");
        }
    }

    #[test]
    fn variable_byte_range_bounds_total_allocation_for_repeated_ranges() {
        let bytes = [0x5a; 32];
        let at_limit = [0, 1].repeat(bytes.len());
        assert_eq!(byte_range_data(&bytes, &at_limit).unwrap(), bytes);
        for range in [vec![0, 32, 0, 32], [0, 1].repeat(bytes.len() + 1)] {
            assert_read_error(
                byte_range_data(&bytes, &range),
                "Total byte range length exceeds input file length",
            );
        }
    }

    #[test]
    fn variable_byte_range_preserves_real_nonstandard_fixture_cardinality() {
        let cases: &[(&[u8], &[u64])] = &[
            (
                include_bytes!(
                    "../../testdata/data/pyhanko/pdf/coverage-anomalies/one-byterange.pdf"
                ),
                &[0, 690],
            ),
            (
                include_bytes!(
                    "../../testdata/data/pyhanko/pdf/coverage-anomalies/weird-byterange.pdf"
                ),
                &[0, 10, 20, 30],
            ),
        ];
        for (bytes, expected) in cases {
            let file = PdfFile::parse(bytes).unwrap();
            let signatures = file.embedded_signatures_pdf().unwrap();
            assert_eq!(signatures.len(), 1);
            let signature = &signatures[0];
            assert_eq!(signature.byte_range.as_slice(), *expected);
            let signed = signature.signed_data(&file).unwrap();
            let exact_data: Vec<u8> = expected
                .as_chunks::<2>()
                .0
                .iter()
                .flat_map(|pair| {
                    bytes[pair[0] as usize..(pair[0] + pair[1]) as usize]
                        .iter()
                        .copied()
                })
                .collect();
            assert_eq!(signed, exact_data);
            eprintln!(
                "BYTE_RANGE_FIXTURE input_sha256={} signed_sha256={} signed_len={} range={:?}",
                sha256_hex(bytes),
                sha256_hex(&signed),
                signed.len(),
                signature.byte_range
            );
        }
    }
}
