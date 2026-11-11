// Derived from the writing parts of pyHanko `sign/validation/dss.py`
// (`DocumentSecurityStore.register_vri`, `as_pdf_object`,
// `supply_dss_in_writer`, `add_dss`, `async_add_validation_info`) (MIT, see
// LICENSE-pyHanko).

//! Document Security Store updates (`/DSS`).

use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::cert::Cert;
use hanko_core::errors::Result;
use lopdf::{Dictionary, Object, ObjectId, Stream};

use crate::ltv::ocsp_certs;
use crate::pdf::util::name;
use crate::pdf::writer::PdfUpdate;

/// The VRI key of a signature (`sig_content_identifier`): upper-case hex
/// SHA-1 of `contents`.
pub fn sig_content_identifier(contents: &[u8]) -> String {
    DigestAlgorithm::Sha1
        .digest(contents)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// What to put into the DSS.
#[derive(Clone, Debug, Default)]
pub struct DssContent<'a> {
    /// Signature contents for the VRI entry (`None`: no VRI entry).
    pub sig_contents: Option<&'a [u8]>,
    /// Certificates.
    pub certs: Vec<Cert>,
    /// Validation paths (leaf first, anchor last).
    pub paths: Vec<Vec<Cert>>,
    /// OCSP responses (DER).
    pub ocsps: Vec<Vec<u8>>,
    /// CRLs (DER).
    pub crls: Vec<Vec<u8>>,
    /// Embed the trust anchors of `paths`.
    pub embed_roots: bool,
}

struct Dss {
    holder: Option<ObjectId>,
    dict: Dictionary,
    certs: Vec<(Vec<u8>, Object)>,
    ocsps: Vec<(Vec<u8>, Object)>,
    crls: Vec<(Vec<u8>, Object)>,
    modified: bool,
}

fn read_streams(update: &PdfUpdate, d: &Dictionary, key: &[u8]) -> Result<Vec<(Vec<u8>, Object)>> {
    let mut out = Vec::new();
    if let Some(Object::Array(a)) = update.dict_get(d, key)? {
        for r in a {
            if let Object::Stream(s) = update.resolve(r)? {
                let data = s
                    .decompressed_content()
                    .unwrap_or_else(|_| s.content.clone());
                out.push((data, r.clone()));
            }
        }
    }
    Ok(out)
}

/// Add or update the DSS (`supply_dss_in_writer`). Returns `true` if the
/// DSS changed.
pub fn supply_dss_in_writer(update: &mut PdfUpdate, content: &DssContent<'_>) -> Result<bool> {
    let root = update.root()?;
    let (holder, dict) = match root.get(b"DSS") {
        Ok(Object::Reference(id)) => (Some(*id), update.get_dict(*id)?.clone()),
        Ok(Object::Dictionary(d)) => (None, d.clone()),
        _ => (None, Dictionary::new()),
    };
    let created = root.get(b"DSS").is_err();
    let mut dss = Dss {
        certs: read_streams(update, &dict, b"Certs")?,
        ocsps: read_streams(update, &dict, b"OCSPs")?,
        crls: read_streams(update, &dict, b"CRLs")?,
        holder,
        dict,
        modified: false,
    };
    // certificates are deduplicated by issuer and serial number
    let key_of = |der: &[u8]| -> Vec<u8> {
        Cert::from_der(der)
            .map(|c| {
                let mut k = der::Encode::to_der(c.issuer()).unwrap_or_default();
                k.extend_from_slice(c.serial_bytes());
                k
            })
            .unwrap_or_else(|_| der.to_vec())
    };
    let embed_cert = |dss: &mut Dss, update: &mut PdfUpdate, c: &Cert| -> Object {
        let k = key_of(c.der());
        if let Some((_, r)) = dss.certs.iter().find(|(d, _)| key_of(d) == k) {
            return r.clone();
        }
        let id = update.add(Object::Stream(Stream::new(Dictionary::new(), c.der().to_vec())));
        dss.modified = true;
        dss.certs.push((c.der().to_vec(), Object::Reference(id)));
        Object::Reference(id)
    };
    let embed_blob = |list: &mut Vec<(Vec<u8>, Object)>, modified: &mut bool, update: &mut PdfUpdate, d: &[u8]| -> Object {
        if let Some((_, r)) = list.iter().find(|(x, _)| x == d) {
            return r.clone();
        }
        let id = update.add(Object::Stream(Stream::new(Dictionary::new(), d.to_vec())));
        *modified = true;
        list.push((d.to_vec(), Object::Reference(id)));
        Object::Reference(id)
    };
    let mut cert_refs = Vec::new();
    let mut all_certs: Vec<Cert> = content.certs.clone();
    for p in &content.paths {
        // pyHanko iterates paths root first; skipping the root when
        // `embed_roots` is false
        let mut certs: Vec<Cert> = p.iter().rev().cloned().collect();
        if !content.embed_roots && !certs.is_empty() {
            certs.remove(0);
        }
        all_certs.extend(certs);
    }
    for c in &all_certs {
        let r = embed_cert(&mut dss, update, c);
        if !cert_refs.contains(&r) {
            cert_refs.push(r);
        }
    }
    let mut ocsp_refs = Vec::new();
    for o in &content.ocsps {
        let r = embed_blob(&mut dss.ocsps, &mut dss.modified, update, o);
        if !ocsp_refs.contains(&r) {
            ocsp_refs.push(r);
        }
    }
    let mut crl_refs = Vec::new();
    for c in &content.crls {
        let r = embed_blob(&mut dss.crls, &mut dss.modified, update, c);
        if !crl_refs.contains(&r) {
            crl_refs.push(r);
        }
    }
    for o in &content.ocsps {
        for c in ocsp_certs(o) {
            let r = embed_cert(&mut dss, update, &c);
            if !cert_refs.contains(&r) {
                cert_refs.push(r);
            }
        }
    }
    if let Some(sc) = content.sig_contents {
        let mut vri = Dictionary::new();
        vri.set("Type", name("VRI"));
        if !ocsp_refs.is_empty() {
            vri.set("OCSP", Object::Array(ocsp_refs));
        }
        if !crl_refs.is_empty() {
            vri.set("CRL", Object::Array(crl_refs));
        }
        vri.set("Cert", Object::Array(cert_refs));
        let vri_id = update.add(Object::Dictionary(vri));
        let mut vri_dict = match update.dict_get(&dss.dict, b"VRI")? {
            Some(Object::Dictionary(d)) => d.clone(),
            _ => Dictionary::new(),
        };
        vri_dict.set(sig_content_identifier(sc).into_bytes(), Object::Reference(vri_id));
        dss.dict.set("VRI", Object::Dictionary(vri_dict));
        dss.modified = true;
    }
    if !dss.modified && !created {
        return Ok(false);
    }
    dss.dict.set(
        "Certs",
        Object::Array(dss.certs.iter().map(|(_, r)| r.clone()).collect()),
    );
    if !dss.ocsps.is_empty() {
        dss.dict.set("OCSPs", Object::Array(dss.ocsps.iter().map(|(_, r)| r.clone()).collect()));
    }
    if !dss.crls.is_empty() {
        dss.dict.set("CRLs", Object::Array(dss.crls.iter().map(|(_, r)| r.clone()).collect()));
    }
    match dss.holder {
        Some(id) => update.update(id, Object::Dictionary(dss.dict)),
        None if created => {
            let id = update.add(Object::Dictionary(dss.dict));
            update.root_mut()?.set("DSS", Object::Reference(id));
        }
        None => {
            update.root_mut()?.set("DSS", Object::Dictionary(dss.dict));
        }
    }
    Ok(true)
}

/// Apply [`supply_dss_in_writer`] as an incremental update of `pdf`
/// (`DocumentSecurityStore.add_dss`). Returns the input unchanged if the
/// DSS did not change and `force_write` is false.
pub fn add_dss(pdf: &[u8], content: &DssContent<'_>, force_write: bool) -> Result<Vec<u8>> {
    let mut update = PdfUpdate::new(pdf)?;
    let modified = supply_dss_in_writer(&mut update, content)?;
    if modified || force_write {
        Ok(update.write()?.0)
    } else {
        Ok(pdf.to_vec())
    }
}
