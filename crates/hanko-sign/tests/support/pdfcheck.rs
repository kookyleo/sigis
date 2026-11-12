//! Test-side inspection of signed PDFs: signature discovery with `lopdf`,
//! Rust-side integrity checks, and pyHanko's verdict through the oracle.
//!
//! This stands in for `sigis-pdf` / `sigis-pades` (lanes B and E) until
//! they land; the oracle provides the authoritative verdict.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use der::Encode;
use sigis_pki_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::cert::Cert;
use lopdf::{Dictionary, Object, ObjectId};

use super::{oracle, path_str, temp_file, Pki};

/// A signature found in a PDF.
#[derive(Debug, Clone)]
pub struct FoundSig {
    pub field_name: String,
    pub field: Dictionary,
    pub field_id: ObjectId,
    pub sig: Dictionary,
    pub sig_id: Option<ObjectId>,
    pub byte_range: Vec<i64>,
    pub contents: Vec<u8>,
}

impl FoundSig {
    pub fn sig_type(&self) -> String {
        name_of(self.sig.get(b"Type").ok())
    }
    pub fn subfilter(&self) -> String {
        name_of(self.sig.get(b"SubFilter").ok())
    }
}

pub fn name_of(o: Option<&Object>) -> String {
    match o {
        Some(Object::Name(n)) => String::from_utf8_lossy(n).into_owned(),
        _ => String::new(),
    }
}

pub fn load(pdf: &[u8]) -> lopdf::Document {
    lopdf::Document::load_mem(pdf).expect("parse output PDF")
}

pub fn resolve<'a>(doc: &'a lopdf::Document, o: &'a Object) -> &'a Object {
    match o {
        Object::Reference(id) => doc.get_object(*id).expect("dangling reference"),
        o => o,
    }
}

pub fn dict_get<'a>(doc: &'a lopdf::Document, d: &'a Dictionary, k: &[u8]) -> Option<&'a Object> {
    d.get(k).ok().map(|o| resolve(doc, o))
}

/// Catalog of the document.
pub fn root(doc: &lopdf::Document) -> &Dictionary {
    let id = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_dictionary(id).unwrap()
}

fn text(o: Option<&Object>) -> String {
    match o {
        Some(Object::String(s, _)) => sigis_pades_sign::pdf::util::decode_text_string(s),
        _ => String::new(),
    }
}

/// All filled signature fields, in field order (`embedded_signatures`).
pub fn embedded_signatures(pdf: &[u8]) -> Vec<FoundSig> {
    let doc = load(pdf);
    let mut out = Vec::new();
    let r = root(&doc);
    let Some(Object::Dictionary(form)) = dict_get(&doc, r, b"AcroForm") else {
        return out;
    };
    let Some(Object::Array(fields)) = dict_get(&doc, form, b"Fields") else {
        return out;
    };
    fn walk(doc: &lopdf::Document, arr: &[Object], prefix: &str, ft_inh: Option<Vec<u8>>, out: &mut Vec<FoundSig>, seen: &mut Vec<ObjectId>) {
        for f in arr {
            let Object::Reference(fid) = f else { continue };
            if seen.contains(fid) {
                panic!("Circular reference in form tree");
            }
            seen.push(*fid);
            let Ok(field) = doc.get_dictionary(*fid) else { continue };
            let partial = text(dict_get(doc, field, b"T"));
            let fq = if prefix.is_empty() { partial.clone() } else { format!("{prefix}.{partial}") };
            let ft = match dict_get(doc, field, b"FT") {
                Some(Object::Name(n)) => Some(n.clone()),
                _ => ft_inh.clone(),
            };
            if ft.as_deref() == Some(b"Sig") {
                if let Ok(v) = field.get(b"V") {
                    let sig_id = v.as_reference().ok();
                    if let Object::Dictionary(sig) = resolve(doc, v) {
                        let br = match dict_get(doc, sig, b"ByteRange") {
                            Some(Object::Array(a)) => a.iter().map(|x| x.as_i64().unwrap()).collect(),
                            _ => Vec::new(),
                        };
                        let contents = match dict_get(doc, sig, b"Contents") {
                            Some(Object::String(s, _)) => s.clone(),
                            _ => Vec::new(),
                        };
                        out.push(FoundSig {
                            field_name: fq.clone(),
                            field: field.clone(),
                            field_id: *fid,
                            sig: sig.clone(),
                            sig_id,
                            byte_range: br,
                            contents,
                        });
                    }
                }
            }
            if let Some(Object::Array(kids)) = dict_get(doc, field, b"Kids") {
                if !partial.is_empty() {
                    walk(doc, kids, &fq, ft.clone(), out, seen);
                }
            }
        }
    }
    let fields = fields.clone();
    walk(&doc, &fields, "", None, &mut out, &mut Vec::new());
    // pyHanko orders signatures by the revision they cover
    out.sort_by_key(|s| s.byte_range.get(2).zip(s.byte_range.get(3)).map(|(a, b)| a + b).unwrap_or(0));
    out
}

/// Strip trailing zero padding from `/Contents` by DER length.
pub fn cms_bytes(sig: &FoundSig) -> Vec<u8> {
    let c = &sig.contents;
    let len = der_len(c).unwrap_or(c.len());
    c[..len.min(c.len())].to_vec()
}

/// Total length of the first DER TLV in `c`.
pub fn der_len(c: &[u8]) -> Option<usize> {
    let l0 = *c.get(1)? as usize;
    if l0 < 0x80 {
        return Some(2 + l0);
    }
    let n = l0 & 0x7f;
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | *c.get(2 + i)? as usize;
    }
    Some(2 + n + len)
}

/// Rust-side integrity check: byte range shape, digest, signature.
/// Returns the signer certificate.
pub fn check_integrity(pdf: &[u8], sig: &FoundSig) -> Cert {
    let br = &sig.byte_range;
    assert_eq!(br.len(), 4, "ByteRange");
    assert_eq!(br[0], 0);
    let (a, b, c, d) = (br[1] as usize, br[2] as usize, br[3] as usize, 0);
    let _ = d;
    assert!(a < b && b + c <= pdf.len());
    assert_eq!(pdf[a], b'<');
    assert_eq!(pdf[b - 1], b'>');
    let mut data = pdf[..a].to_vec();
    data.extend_from_slice(&pdf[b..b + c]);
    let cms = cms_bytes(sig);
    let sd = sigis_pades_sign::cms::decode_signed_data(&cms).unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap();
    let md = DigestAlgorithm::from_oid(&si.digest_alg.oid).unwrap();
    let certs: Vec<Cert> = sd
        .certificates
        .as_ref()
        .map(|cs| {
            cs.0.iter()
                .filter_map(|c| match c {
                    cms::cert::CertificateChoices::Certificate(c) => {
                        Some(Cert::from_der(&c.to_der().unwrap()).unwrap())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(isn) = &si.sid else {
        panic!("sid")
    };
    let signer = certs
        .iter()
        .find(|c| c.issuer() == &isn.issuer && c.serial_bytes() == isn.serial_number.as_bytes())
        .expect("signer cert embedded")
        .clone();
    let attrs = si.signed_attrs.as_ref().unwrap();
    let digest = attrs
        .iter()
        .find(|a| a.oid == oids::MESSAGE_DIGEST)
        .unwrap()
        .values
        .iter()
        .next()
        .unwrap()
        .decode_as::<der::asn1::OctetString>()
        .unwrap();
    if sig.sig_type() != "DocTimeStamp" {
        assert_eq!(digest.as_bytes(), md.digest(&data), "document digest");
    }
    match validate_signature(
        si.signature.as_bytes(),
        &attrs.to_der().unwrap(),
        &signer.public_key(),
        &si.signature_algorithm,
        &SignatureValidationContext {
            contextual_digest: Some(md),
            prehashed: false,
        },
    ) {
        Ok(()) => {}
        // e.g. ML-DSA: lane A's verifier does not support it yet; the
        // oracle still checks the signature
        Err(sigis_pki_core::errors::SignatureError::AlgorithmNotSupported(a)) => {
            eprintln!("Rust-side signature check skipped: {a}");
        }
        Err(e) => panic!("signature verifies: {e:?}"),
    }
    signer
}

/// pyHanko's verdicts for every signature, or `None` without oracle.
pub fn oracle_verdicts(pdf: &[u8], trust: &[&std::path::Path], time: &str, extra: &[&str]) -> Option<Vec<serde_json::Value>> {
    let p = temp_file("out.pdf", pdf);
    let mut args: Vec<String> = vec!["--pdf".into(), path_str(&p).into(), "--time".into(), time.into()];
    if trust.is_empty() {
        args.push("--no-trust".into());
    }
    for t in trust {
        args.push("--trust".into());
        args.push(path_str(t).into());
    }
    for e in extra {
        args.push((*e).into());
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    oracle("validate_pdf.py", &argv).map(|v| v.as_array().unwrap().clone())
}

/// `val_trusted` (`signing_commons.py`): checks signature `ix` of `pdf`.
/// `extd`: the signature is followed by later revisions.
pub fn val_trusted(pdf: &[u8], ix: usize, pki: &Pki, time: &str, extd: bool) -> Option<serde_json::Value> {
    let sigs = embedded_signatures(pdf);
    check_integrity(pdf, &sigs[ix]);
    let root = pki.cert_path("root");
    let v = oracle_verdicts(pdf, &[&root], time, if extd { &["--extd"] } else { &[] })?;
    let s = v[ix].clone();
    assert!(s.get("error").is_none(), "{s}");
    assert_eq!(s["intact"], true, "{s}");
    assert_eq!(s["valid"], true, "{s}");
    assert_eq!(s["trusted"], true, "{s}");
    let summ = s["summary"].as_str().unwrap_or_default();
    assert!(summ.contains("INTACT") && summ.contains("TRUSTED"), "{s}");
    if extd {
        assert_eq!(s["coverage"], "ENTIRE_REVISION", "{s}");
        let ml = s["modification_level"].as_str().unwrap_or("");
        assert!(matches!(ml, "NONE" | "LTA_UPDATES" | "FORM_FILLING"), "{s}");
    } else {
        assert_eq!(s["coverage"], "ENTIRE_FILE", "{s}");
        assert_eq!(s["modification_level"], "NONE", "{s}");
    }
    assert_eq!(s["bottom_line"], true, "{s}");
    Some(s)
}

/// `val_untrusted`: intact and valid without trust roots.
pub fn val_untrusted(pdf: &[u8], ix: usize, time: &str, extd: bool) -> Option<serde_json::Value> {
    let sigs = embedded_signatures(pdf);
    check_integrity(pdf, &sigs[ix]);
    let v = oracle_verdicts(pdf, &[], time, if extd { &["--extd"] } else { &[] })?;
    let s = v[ix].clone();
    assert!(s.get("error").is_none(), "{s}");
    assert_eq!(s["intact"], true, "{s}");
    assert_eq!(s["valid"], true, "{s}");
    if extd {
        assert_eq!(s["coverage"], "ENTIRE_REVISION", "{s}");
    } else {
        assert_eq!(s["coverage"], "ENTIRE_FILE", "{s}");
        assert_eq!(s["modification_level"], "NONE", "{s}");
    }
    assert!(s["summary"].as_str().unwrap_or_default().contains("INTACT"), "{s}");
    Some(s)
}

/// Counts of the DSS entries (`DocumentSecurityStore.read_dss`):
/// `(certs, ocsps, crls, vri entries)`.
pub fn dss_counts(pdf: &[u8]) -> Option<(usize, usize, usize, usize)> {
    let doc = load(pdf);
    let r = root(&doc);
    let Some(Object::Dictionary(dss)) = dict_get(&doc, r, b"DSS") else {
        return None;
    };
    let len = |k: &[u8]| match dict_get(&doc, dss, k) {
        Some(Object::Array(a)) => a.len(),
        _ => 0,
    };
    let vri = match dict_get(&doc, dss, b"VRI") {
        Some(Object::Dictionary(d)) => d.len(),
        _ => 0,
    };
    Some((len(b"Certs"), len(b"OCSPs"), len(b"CRLs"), vri))
}

/// pyHanko's `ades_lta_validation` verdicts (`_simple_pades_check`).
pub fn ades_lta(pdf: &[u8], trust: &[&std::path::Path], time: &str, norev: bool) -> Option<Vec<serde_json::Value>> {
    ades_lta_live(pdf, trust, time, norev, &["testing-ca"])
}

/// [`ades_lta`] with Certomancer's live services for `live` archs.
pub fn ades_lta_live(pdf: &[u8], trust: &[&std::path::Path], time: &str, norev: bool, live: &[&str]) -> Option<Vec<serde_json::Value>> {
    let mut extra = vec!["--ades-lta"];
    for l in live {
        extra.push("--live");
        extra.push(l);
    }
    if norev {
        extra.push("--norev");
    }
    oracle_verdicts(pdf, trust, time, &extra)
}

/// Number of signatures (`/Sig`) and document timestamps.
pub fn sig_kinds(pdf: &[u8]) -> (usize, usize) {
    let s = embedded_signatures(pdf);
    let ts = s.iter().filter(|x| x.sig_type() == "DocTimeStamp").count();
    (s.len() - ts, ts)
}

/// pyHanko's structural view of a PDF (`oracle/inspect_pdf.py`).
pub fn inspect(pdf: &[u8]) -> Option<serde_json::Value> {
    let p = temp_file("inspect.pdf", pdf);
    oracle("inspect_pdf.py", &[path_str(&p)])
}

/// Number of revisions (incremental sections), counted from `startxref`
/// keywords.
pub fn revision_count(pdf: &[u8]) -> usize {
    pdf.windows(9).filter(|w| *w == b"startxref").count()
}
