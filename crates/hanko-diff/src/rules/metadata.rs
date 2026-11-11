// Derived from pyHanko `sign/diff_analysis/rules/metadata_rules.py` (MIT, see
// LICENSE-pyHanko).

//! Rules for the document information dictionary and XMP metadata.

use lopdf::{Dictionary, Object, ObjectId};
use quick_xml::events::Event;
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::NsReader;

use crate::commons::safe_whitelist;
use crate::context::{Context, ReferenceUpdate};
use crate::error::{read_error, suspicious, DiffError, DiffResultT};
use crate::history::Revision;
use crate::object::as_dict;
use crate::path::RawPdfPath;
use crate::rules::WhitelistRule;

/// Upper bound for decoded XMP metadata (pyHanko's decode limits play this
/// role there).
pub const MAX_XMP_SIZE: usize = 16 * 1024 * 1024;

/// `get_value_as_reference(key, optional=True)`: `Ok(None)` if absent,
/// `Err(())` if present but direct.
fn value_as_reference(d: &Dictionary, key: &[u8]) -> Result<Option<ObjectId>, ()> {
    match d.get(key) {
        Ok(Object::Reference(id)) => Ok(Some(*id)),
        Ok(_) => Err(()),
        Err(_) => Ok(None),
    }
}

/// Allows the trailer's `/Info` dictionary to be updated (`DocInfoRule`).
#[derive(Clone, Debug, Default)]
pub struct DocInfoRule;

impl WhitelistRule for DocInfoRule {
    fn apply(&self, old: &Revision<'_>, new: &Revision<'_>) -> DiffResultT<Vec<ReferenceUpdate>> {
        let Some(new_info) = value_as_reference(new.trailer(), b"Info")
            .map_err(|_| DiffError::Read("indirect object expected".into()))?
        else {
            return Ok(Vec::new());
        };
        let old_info = value_as_reference(old.trailer(), b"Info")
            .map_err(|_| DiffError::Read("indirect object expected".into()))?;
        let ctx = Context::absolute(RawPdfPath::of(["/Info"]));
        Ok(safe_whitelist(old, new, old_info, new_info)?
            .into_iter()
            .map(|r| ReferenceUpdate::with_context(r, ctx.clone()))
            .collect())
    }
}

/// Adjudicates updates to the XMP metadata stream (`MetadataUpdateRule`).
///
/// The metadata must be well-formed XML without entity references, with an
/// `x:xmpmeta` root element; its content is not validated further.
#[derive(Clone, Debug)]
pub struct MetadataUpdateRule {
    /// Check that old and new metadata are well-formed XMP (default `true`).
    pub check_xml_syntax: bool,
    /// Refuse to overwrite a metadata stream that existed in the signed
    /// revision, even if it is well-formed (default `false`).
    pub always_refuse_stream_override: bool,
}

impl Default for MetadataUpdateRule {
    fn default() -> Self {
        Self {
            check_xml_syntax: true,
            always_refuse_stream_override: false,
        }
    }
}

impl MetadataUpdateRule {
    /// `is_well_formed_xml`: check that `metadata_ref` (resolved in `rev`)
    /// is a stream holding well-formed XMP.
    pub fn is_well_formed_xml(rev: &Revision<'_>, metadata_ref: ObjectId) -> DiffResultT<()> {
        let obj = rev.get(metadata_ref)?;
        let Object::Stream(stream) = &*obj else {
            return suspicious("/Metadata should be a reference to a stream object");
        };
        let data = if stream.dict.get(b"Filter").is_ok() {
            match stream.decompressed_content_with_limit(MAX_XMP_SIZE) {
                Ok(d) => d,
                Err(_) => return suspicious("/Metadata XML syntax could not be validated"),
            }
        } else {
            stream.content.clone()
        };
        check_xmp(&data)
    }

    fn grab_metadata(root: &Object) -> DiffResultT<Option<ObjectId>> {
        let Some(d) = as_dict(root) else {
            return read_error("Document catalog is not a dictionary");
        };
        value_as_reference(d, b"Metadata")
            .or_else(|_| suspicious("/Metadata should be an indirect reference"))
    }
}

impl WhitelistRule for MetadataUpdateRule {
    fn apply(&self, old: &Revision<'_>, new: &Revision<'_>) -> DiffResultT<Vec<ReferenceUpdate>> {
        let Some(new_ref) = Self::grab_metadata(&*new.root()?)? else {
            return Ok(Vec::new());
        };
        if self.check_xml_syntax {
            Self::is_well_formed_xml(new, new_ref)?;
        }
        let old_ref = Self::grab_metadata(&*old.root()?)?;
        if self.check_xml_syntax {
            if let Some(r) = old_ref {
                Self::is_well_formed_xml(old, r)?;
            }
        }
        let same_ref_ok = old_ref == Some(new_ref) && !self.always_refuse_stream_override;
        if same_ref_ok || old.is_ref_unassignable(new_ref) {
            return Ok(vec![ReferenceUpdate::with_context(
                new_ref,
                Context::absolute(RawPdfPath::of(["/Root", "/Metadata"])),
            )]);
        }
        Ok(Vec::new())
    }
}

const PREDEFINED_ENTITIES: &[&[u8]] = &[b"lt", b"gt", b"amp", b"apos", b"quot"];

fn bad_syntax<T>() -> DiffResultT<T> {
    suspicious("/Metadata XML syntax could not be validated")
}

/// Whether `text` holds only references to predefined entities and valid
/// character references.
fn refs_ok(text: &[u8]) -> Result<bool, ()> {
    let mut rest = text;
    while let Some(amp) = rest.iter().position(|c| *c == b'&') {
        let after = &rest[amp + 1..];
        let end = after.iter().position(|c| *c == b';').ok_or(())?;
        let name = &after[..end];
        if !ref_name_ok(name)? {
            return Ok(false);
        }
        rest = &after[end + 1..];
    }
    Ok(true)
}

/// `Ok(true)` for a predefined entity or valid character reference,
/// `Ok(false)` for a general entity, `Err` for a syntax error.
fn ref_name_ok(name: &[u8]) -> Result<bool, ()> {
    if let Some(num) = name.strip_prefix(b"#") {
        let s = std::str::from_utf8(num).map_err(|_| ())?;
        let cp = match s.strip_prefix('x') {
            Some(hex) => u32::from_str_radix(hex, 16),
            None => s.parse::<u32>(),
        }
        .map_err(|_| ())?;
        return if xml_char_ok(cp) { Ok(true) } else { Err(()) };
    }
    if name.is_empty() {
        return Err(());
    }
    Ok(PREDEFINED_ENTITIES.contains(&name))
}

fn xml_char_ok(cp: u32) -> bool {
    matches!(cp, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

/// The XML checks of `is_well_formed_xml`: well-formed (UTF-8), no entity
/// references other than the predefined ones, root `{adobe:ns:meta/}xmpmeta`.
pub(crate) fn check_xmp(data: &[u8]) -> DiffResultT<()> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return bad_syntax(),
    };
    if text.chars().any(|c| !xml_char_ok(u32::from(c))) {
        return bad_syntax();
    }
    let mut reader = NsReader::from_str(text);
    reader.config_mut().check_comments = true;
    let mut depth: usize = 0;
    let mut root_seen = false;
    let mut root_ok = false;
    let mut entities = false;
    loop {
        let (ns, ev) = match reader.read_resolved_event() {
            Ok(x) => x,
            Err(_) => return bad_syntax(),
        };
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                if depth == 0 {
                    if root_seen {
                        return bad_syntax();
                    }
                    root_seen = true;
                    root_ok = matches!(ns, ResolveResult::Bound(Namespace(b"adobe:ns:meta/")))
                        && e.local_name().as_ref() == b"xmpmeta";
                }
                for a in e.attributes().with_checks(true) {
                    let Ok(a) = a else { return bad_syntax() };
                    match refs_ok(&a.value) {
                        Ok(true) => {}
                        Ok(false) => entities = true,
                        Err(()) => return bad_syntax(),
                    }
                }
                if matches!(ev, Event::Start(_)) {
                    depth += 1;
                }
            }
            Event::End(_) => {
                if depth == 0 {
                    return bad_syntax();
                }
                depth -= 1;
            }
            Event::Text(ref t) => {
                if depth == 0 && !t.iter().all(u8::is_ascii_whitespace) {
                    return bad_syntax();
                }
            }
            Event::CData(_) => {
                if depth == 0 {
                    return bad_syntax();
                }
            }
            Event::GeneralRef(ref r) => {
                if depth == 0 {
                    return bad_syntax();
                }
                match ref_name_ok(r) {
                    Ok(true) => {}
                    Ok(false) => entities = true,
                    Err(()) => return bad_syntax(),
                }
            }
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::DocType(_) => {
                if root_seen {
                    return bad_syntax();
                }
            }
            Event::Eof => break,
        }
    }
    if depth != 0 || !root_seen {
        return bad_syntax();
    }
    if entities {
        return suspicious("XML entities found in XMP metadata");
    }
    if !root_ok {
        return suspicious("Metadata does not look like XMP");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const XMP: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:format>a &amp; b &#65;</dc:format></rdf:Description>
</rdf:RDF></x:xmpmeta>
<?xpacket end="w"?>"#;

    #[test]
    fn accepts_xmp() {
        check_xmp(XMP.as_bytes()).unwrap();
    }

    #[test]
    fn rejects_bad_xml() {
        for bad in [
            "This is bogus data, yay!",
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">",
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"></y>",
            "<root/>",
            "<x:xmpmeta xmlns:x=\"other\"/>",
            "<!DOCTYPE a [<!ENTITY e \"x\">]><x:xmpmeta xmlns:x=\"adobe:ns:meta/\">&e;</x:xmpmeta>",
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
        ] {
            assert!(check_xmp(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_bad_xml_corpus() {
        let dir = hanko_testdata::pyhanko(&["xml", "bad-xml"]);
        let mut n = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().is_some_and(|e| e == "xml") {
                let data = std::fs::read(&p).unwrap();
                assert!(check_xmp(&data).is_err(), "{}", p.display());
                n += 1;
            }
        }
        assert_eq!(n, 10);
    }
}
