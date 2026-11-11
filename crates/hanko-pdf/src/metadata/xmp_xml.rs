// Derived from pyHanko `pdf_utils/metadata/xmp_xml.py` (MIT, see
// LICENSE-pyHanko).

//! XMP metadata parsing and serialisation (`pyhanko.pdf_utils.metadata.xmp_xml`).
//!
//! Parsing uses `quick-xml` (namespace-aware reader) into a minimal tree;
//! documents with a DTD or non-predefined entities are rejected (pyHanko
//! rejects XML entities as well).

use lopdf::{Dictionary, Object, Stream};

use super::model::{
    self, dc_creator, dc_description, dc_title, not_property_attributes, pdf_keywords,
    pdf_producer, rdf_about, rdf_alt, rdf_bag, rdf_description, rdf_li, rdf_parse_type,
    rdf_rdf, rdf_resource, rdf_seq, rdf_value, x_xmpmeta, xml_lang, xmp_createdate,
    xmp_creatortool, xmp_moddate, DocumentMetadata, ExpandedName, MetaDate, MetaString,
    Qualifiers, XmpArray, XmpStructure, XmpUri, XmpValue, XmpValueKind, VENDOR,
};
use crate::decode_limits::DecodePurpose;
use crate::error::{PdfError, PdfResult};
use crate::generic::PdfDate;
use crate::rw_common::PdfHandler;
use crate::stream::DecodedStream;

/// Error while processing XMP (`XmpXmlProcessingError`, a `ValueError`).
pub fn xmp_error(msg: impl Into<String>) -> PdfError {
    PdfError::Value(format!("XmpXmlProcessingError: {}", msg.into()))
}

/// A minimal element tree (what pyHanko uses of lxml's).
#[derive(Debug, Default)]
struct XNode {
    /// Element name; `None` for processing instructions and names without
    /// a namespace (lxml's `_name` returns `None` for those).
    name: Option<ExpandedName>,
    /// Attributes with a namespace (others are not properties).
    attrs: Vec<(ExpandedName, String)>,
    has_any_attr: bool,
    /// lxml's `.text`: text before the first child.
    text: String,
    children: Vec<XNode>,
}

fn parse_dom(text: &str) -> PdfResult<XNode> {
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;
    let fail = |m: String| xmp_error(format!("Failed to parse XMP XML: {m}"));
    let mut reader = quick_xml::reader::NsReader::from_str(text);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<XNode> = Vec::new();
    let mut root: Option<XNode> = None;
    let resolve_ns = |r: ResolveResult<'_>| -> PdfResult<Option<String>> {
        match r {
            ResolveResult::Bound(ns) => Ok(Some(String::from_utf8_lossy(ns.0).into_owned())),
            ResolveResult::Unbound => Ok(None),
            ResolveResult::Unknown(p) => Err(fail(format!(
                "unknown namespace prefix '{}'",
                String::from_utf8_lossy(&p)
            ))),
        }
    };
    fn push_text(stack: &mut [XNode], root_done: bool, t: &str) -> Result<(), String> {
        match stack.last_mut() {
            Some(n) => {
                if n.children.is_empty() {
                    n.text.push_str(t);
                }
                Ok(())
            }
            None => {
                if t.chars().all(char::is_whitespace) {
                    Ok(())
                } else {
                    let _ = root_done;
                    Err("text outside of the root element".into())
                }
            }
        }
    }
    loop {
        let (ns_res, ev) = reader.read_resolved_event().map_err(|e| fail(e.to_string()))?;
        let ns = resolve_ns(ns_res)?;
        match ev {
            Event::Start(e) => {
                let node = open_node(&reader, &e, ns, &resolve_ns)?;
                stack.push(node);
            }
            Event::Empty(e) => {
                let node = open_node(&reader, &e, ns, &resolve_ns)?;
                close(&mut stack, &mut root, node).map_err(fail)?;
            }
            Event::End(_) => {
                let Some(node) = stack.pop() else {
                    return Err(fail("unbalanced end tag".into()));
                };
                close(&mut stack, &mut root, node).map_err(fail)?;
            }
            Event::Text(t) => {
                let s = t.decode().map_err(|e| fail(e.to_string()))?;
                push_text(&mut stack, root.is_some(), &s).map_err(fail)?;
            }
            Event::CData(t) => {
                let s = t.decode().map_err(|e| fail(e.to_string()))?;
                push_text(&mut stack, root.is_some(), &s).map_err(fail)?;
            }
            Event::GeneralRef(r) => {
                let name = r.decode().map_err(|e| fail(e.to_string()))?;
                let resolved = match &*name {
                    "amp" => "&".to_owned(),
                    "lt" => "<".to_owned(),
                    "gt" => ">".to_owned(),
                    "apos" => "'".to_owned(),
                    "quot" => "\"".to_owned(),
                    other => {
                        let ch = other
                            .strip_prefix("#x")
                            .and_then(|h| u32::from_str_radix(h, 16).ok())
                            .or_else(|| other.strip_prefix('#').and_then(|d| d.parse().ok()))
                            .and_then(char::from_u32);
                        match ch {
                            Some(c) => c.to_string(),
                            None => return Err(xmp_error("XML entities not supported")),
                        }
                    }
                };
                push_text(&mut stack, root.is_some(), &resolved).map_err(fail)?;
            }
            Event::PI(_) => {
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XNode::default());
                }
            }
            Event::DocType(_) => return Err(xmp_error("XML entities not supported")),
            Event::Comment(_) | Event::Decl(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(fail("unclosed element".into()));
    }
    root.ok_or_else(|| fail("no root element".into()))
}

fn open_node(
    reader: &quick_xml::reader::NsReader<&[u8]>,
    e: &quick_xml::events::BytesStart<'_>,
    ns: Option<String>,
    resolve_ns: &dyn Fn(quick_xml::name::ResolveResult<'_>) -> PdfResult<Option<String>>,
) -> PdfResult<XNode> {
    let fail = |m: String| xmp_error(format!("Failed to parse XMP XML: {m}"));
    let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
    let mut node = XNode {
        name: ns.map(|n| ExpandedName::new(&n, &local)),
        ..XNode::default()
    };
    for a in e.attributes() {
        let a = a.map_err(|err| fail(err.to_string()))?;
        let key = a.key;
        if key.as_namespace_binding().is_some() {
            continue;
        }
        node.has_any_attr = true;
        let (r, aloc) = reader.resolver().resolve_attribute(key);
        let ans = resolve_ns(r)?;
        // attribute-value normalisation (XML 1.0 §3.3.3)
        let raw = String::from_utf8_lossy(&a.value).replace(['\n', '\r', '\t'], " ");
        let value = quick_xml::escape::unescape(&raw)
            .map_err(|err| fail(err.to_string()))?
            .into_owned();
        if let Some(ans) = ans {
            node.attrs.push((ExpandedName::new(&ans, &String::from_utf8_lossy(aloc.as_ref())), value));
        }
    }
    Ok(node)
}

fn close(stack: &mut [XNode], root: &mut Option<XNode>, node: XNode) -> Result<(), String> {
    match stack.last_mut() {
        Some(parent) => {
            parent.children.push(node);
            Ok(())
        }
        None => {
            if root.is_some() {
                return Err("multiple root elements".into());
            }
            *root = Some(node);
            Ok(())
        }
    }
}

fn name_of(node: &XNode) -> Option<ExpandedName> {
    node.name.clone()
}

fn element_children(node: &XNode) -> Vec<&XNode> {
    node.children.iter().collect()
}

fn attr(node: &XNode, name: &ExpandedName) -> Option<String> {
    node.attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
}

fn check_lang(node: &XNode) -> Option<String> {
    attr(node, &xml_lang())
}

fn is_http_uri(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn proc_struct(node: &XNode, lang: Option<&str>) -> PdfResult<XmpStructure> {
    let mut s = XmpStructure::default();
    for child in element_children(node) {
        if let Some(name) = name_of(child) {
            if s.get(&name).is_some() {
                return Err(xmp_error(format!("Duplicate field {name} in XMP structure value")));
            }
            s.set(name, proc_value(child, lang)?);
        }
    }
    let skip = not_property_attributes();
    for (name, v) in &node.attrs {
        if skip.contains(name) {
            continue;
        }
        let value = if is_http_uri(v) {
            XmpValueKind::Uri(XmpUri(v.clone()))
        } else {
            XmpValueKind::Str(v.clone())
        };
        s.set(name.clone(), XmpValue::new(value));
    }
    Ok(s)
}

fn proc_arr(node: &XNode, lang: Option<&str>) -> PdfResult<XmpArray> {
    let name = name_of(node).ok_or_else(|| xmp_error("Invalid array"))?;
    let mut entries = Vec::new();
    for li in element_children(node) {
        if name_of(li) == Some(rdf_li()) {
            entries.push(proc_value(li, lang)?);
        }
    }
    Ok(if name == rdf_seq() {
        XmpArray::ordered(entries)
    } else if name == rdf_bag() {
        XmpArray::unordered(entries)
    } else {
        XmpArray::alternative(entries)
    })
}

fn extract_qualifiers(node: &XNode, lang: Option<&str>) -> PdfResult<Qualifiers> {
    let mut pairs = Vec::new();
    if let Some(l) = lang.filter(|l| !l.is_empty()) {
        pairs.push((xml_lang(), XmpValue::text(l)));
    }
    for q in element_children(node) {
        let q_name = name_of(q);
        if q_name != Some(rdf_value()) {
            let Some(n) = q_name else {
                return Err(xmp_error("Invalid qualifier"));
            };
            pairs.push((n, proc_value(q, lang)?));
        }
    }
    Ok(Qualifiers::of(pairs))
}

fn unwrap_resource(node: &XNode, lang: Option<&str>) -> PdfResult<(XmpValueKind, Qualifiers)> {
    let rdf_val = element_children(node).into_iter().find(|c| name_of(c) == Some(rdf_value()));
    match rdf_val {
        Some(v) => Ok((proc_value(v, lang)?.value, extract_qualifiers(node, lang)?)),
        None => Ok((
            XmpValueKind::Structure(proc_struct(node, lang)?),
            Qualifiers::lang_as_qual(lang),
        )),
    }
}

fn proc_value(node: &XNode, lang: Option<&str>) -> PdfResult<XmpValue> {
    let own_lang = check_lang(node);
    let lang = own_lang.as_deref().or(lang);
    if let Some(pt) = attr(node, &rdf_parse_type()) {
        if pt == "Resource" {
            let (inner, quals) = unwrap_resource(node, lang)?;
            return Ok(XmpValue::with_quals(inner, quals));
        }
        return Err(xmp_error(format!("Parse type '{pt}' is not supported")));
    }
    let children = element_children(node);
    match children.len() {
        0 => {
            if let Some(uri) = attr(node, &rdf_resource()) {
                return Ok(XmpValue::new(XmpValueKind::Uri(XmpUri(uri))));
            }
            let text = node.text.clone();
            if !text.is_empty() {
                if is_http_uri(&text) {
                    return Ok(XmpValue::new(XmpValueKind::Uri(XmpUri(text))));
                }
                return Ok(XmpValue::with_quals(XmpValueKind::Str(text), Qualifiers::lang_as_qual(lang)));
            }
            if node.has_any_attr {
                return Ok(XmpValue::new(XmpValueKind::Structure(proc_struct(node, lang)?)));
            }
            Ok(XmpValue::with_quals(XmpValueKind::Str(String::new()), Qualifiers::lang_as_qual(lang)))
        }
        1 => {
            let child = children[0];
            let name = name_of(child);
            if name == Some(rdf_seq()) || name == Some(rdf_alt()) || name == Some(rdf_bag()) {
                let arr = proc_arr(child, lang)?;
                Ok(XmpValue::with_quals(XmpValueKind::Array(arr), Qualifiers::lang_as_qual(lang)))
            } else if name == Some(rdf_description()) {
                let (inner, quals) = unwrap_resource(child, lang)?;
                Ok(XmpValue::with_quals(inner, quals))
            } else {
                Err(xmp_error(format!(
                    "Cannot process tag with name {} as an XMP value form",
                    name.map_or_else(|| "None".to_owned(), |n| n.to_string())
                )))
            }
        }
        _ => Err(xmp_error(format!(
            "Tag with name {} has more than one child.",
            own_lang.as_deref().unwrap_or("None")
        ))),
    }
}

/// `XMP_HEADER_PATTERN`: `\s*<\?\s?xpacket begin="(...?)" id="W5M0MpCehiHzreSzNTczkc9d"\s?\?>`.
fn match_header(header: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut i = 0;
    let ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    while i < header.len() && ws(header[i]) {
        i += 1;
    }
    let rest = &header[i..];
    let rest = rest.strip_prefix(b"<?")?;
    let (rest, skipped) = match rest.first() {
        Some(&b) if ws(b) => (&rest[1..], 1),
        _ => (rest, 0),
    };
    let rest = rest.strip_prefix(b"xpacket begin=\"")?;
    // (...?): 2 or 3 bytes, then '"'
    let (bom, rest) = if rest.len() >= 3 && rest.get(2) == Some(&b'"') {
        (rest[..2].to_vec(), &rest[3..])
    } else if rest.len() >= 4 && rest.get(3) == Some(&b'"') {
        (rest[..3].to_vec(), &rest[4..])
    } else {
        return None;
    };
    let rest = rest.strip_prefix(b" id=\"W5M0MpCehiHzreSzNTczkc9d\"")?;
    let (rest, sk2) = match rest.first() {
        Some(&b) if ws(b) => (&rest[1..], 1),
        _ => (rest, 0),
    };
    rest.strip_prefix(b"?>")?;
    let consumed = i + 2 + skipped + 15 + bom.len() + 1 + 30 + sk2 + 2;
    Some((bom, consumed))
}

fn decode_with(enc: &str, data: &[u8]) -> PdfResult<String> {
    let bad = || xmp_error("Failed to decode XMP data");
    match enc {
        "utf-16be" | "utf-16le" => {
            if !data.len().is_multiple_of(2) {
                return Err(bad());
            }
            let le = enc == "utf-16le";
            let units: Vec<u16> = data
                .as_chunks::<2>().0.iter()
                .map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
                .collect();
            String::from_utf16(&units).map_err(|_| bad())
        }
        _ => String::from_utf8(data.to_vec()).map_err(|_| bad()),
    }
}

/// Parse XMP data into its `rdf:Description` structures (`parse_xmp`).
pub fn parse_xmp(data: &[u8]) -> PdfResult<Vec<XmpStructure>> {
    let header = &data[..data.len().min(128)];
    let (encoding, start) = match match_header(header) {
        None => ("utf-8", 0),
        Some((bom, len)) => {
            let enc = match bom.as_slice() {
                [0xef, 0xbb, 0xbf] => "utf-8",
                [0xfe, 0xff] => "utf-16be",
                [0xff, 0xfe] => "utf-16le",
                _ => "utf-8",
            };
            (enc, len)
        }
    };
    let text = decode_with(encoding, &data[start.min(data.len())..])?;
    // lxml refuses str input with an encoding declaration
    let trimmed = text.trim_start();
    if trimmed.starts_with("<?xml") {
        let decl_end = trimmed.find("?>").unwrap_or(trimmed.len());
        if trimmed[..decl_end].contains("encoding") {
            return Err(xmp_error("Failed to parse XMP XML: encoding declaration in decoded text"));
        }
    }
    let root = parse_dom(&text)?;
    let root_name = name_of(&root);
    let rdf_root = if root_name == Some(rdf_rdf()) {
        &root
    } else if root_name == Some(x_xmpmeta()) {
        element_children(&root)
            .into_iter()
            .find(|c| name_of(c) == Some(rdf_rdf()))
            .ok_or_else(|| xmp_error("No rdf:RDF node in x:xmpmeta"))?
    } else {
        return Err(xmp_error("XMP root must be rdf:RDF or x:xmpmeta"));
    };
    element_children(rdf_root)
        .into_iter()
        .filter(|n| name_of(n) == Some(rdf_description()))
        .map(|n| proc_struct(n, None))
        .collect()
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

struct NsMap(Vec<(String, String)>);

impl NsMap {
    fn prefix(&mut self, uri: &str) -> String {
        if let Some((p, _)) = self.0.iter().find(|(_, u)| u == uri) {
            return p.clone();
        }
        let p = model::NS
            .iter()
            .find(|(_, u)| *u == uri)
            .map(|(p, _)| (*p).to_owned())
            .unwrap_or_else(|| format!("ns{}", self.0.iter().filter(|(p, _)| p.starts_with("ns")).count()));
        self.0.push((p.clone(), uri.to_owned()));
        p
    }
}

fn esc(s: &str, attr: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attr => out.push_str("&quot;"),
            '\n' if attr => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' if attr => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
    out
}

/// A tiny element tree used for serialisation.
struct Elem {
    name: ExpandedName,
    attrs: Vec<(ExpandedName, String)>,
    text: Option<String>,
    children: Vec<Elem>,
}

impl Elem {
    fn new(name: ExpandedName) -> Self {
        Self {
            name,
            attrs: Vec::new(),
            text: None,
            children: Vec::new(),
        }
    }

    fn set(&mut self, name: ExpandedName, value: String) {
        if let Some(slot) = self.attrs.iter_mut().find(|(n, _)| *n == name) {
            slot.1 = value;
        } else {
            self.attrs.push((name, value));
        }
    }

    fn sub(&mut self, name: ExpandedName) -> &mut Elem {
        self.children.push(Elem::new(name));
        let last = self.children.len() - 1;
        &mut self.children[last]
    }

    fn collect_ns(&self, ns: &mut NsMap) {
        if self.name.ns != model::ns("xml") {
            ns.prefix(&self.name.ns);
        }
        for (a, _) in &self.attrs {
            if a.ns != model::ns("xml") {
                ns.prefix(&a.ns);
            }
        }
        for c in &self.children {
            c.collect_ns(ns);
        }
    }

    fn qname(n: &ExpandedName, ns: &mut NsMap) -> String {
        if n.ns == model::ns("xml") {
            return format!("xml:{}", n.local_name);
        }
        format!("{}:{}", ns.prefix(&n.ns), n.local_name)
    }

    fn write(&self, out: &mut String, ns: &mut NsMap, root: bool) {
        out.push('<');
        out.push_str(&Self::qname(&self.name, ns));
        if root {
            let decls: Vec<(String, String)> = ns.0.clone();
            for (p, u) in decls {
                out.push_str(&format!(" xmlns:{p}=\"{}\"", esc(&u, true)));
            }
        }
        for (a, v) in &self.attrs {
            out.push(' ');
            out.push_str(&Self::qname(a, ns));
            out.push_str("=\"");
            out.push_str(&esc(v, true));
            out.push('"');
        }
        if self.text.is_none() && self.children.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        if let Some(t) = &self.text {
            out.push_str(&esc(t, false));
        }
        for c in &self.children {
            c.write(out, ns, false);
        }
        out.push_str("</");
        out.push_str(&Self::qname(&self.name, ns));
        out.push('>');
    }
}

fn struct_to_xml(description: &mut Elem, value: &XmpStructure) {
    for (k, v) in value.iter() {
        match &v.value {
            XmpValueKind::Str(s) if v.qualifiers.is_empty() => description.set(k.clone(), s.clone()),
            _ => add_xmp_value(description.sub(k.clone()), v),
        }
    }
}

fn add_inner_value(container: &mut Elem, value: &XmpValueKind) {
    match value {
        XmpValueKind::Str(s) => container.text = Some(s.clone()),
        XmpValueKind::Uri(u) => container.set(rdf_resource(), u.0.clone()),
        XmpValueKind::Structure(st) => struct_to_xml(container.sub(rdf_description()), st),
        XmpValueKind::Array(arr) => {
            let a = container.sub(arr.array_type.as_rdf());
            for v in &arr.entries {
                add_xmp_value(a.sub(rdf_li()), v);
            }
        }
    }
}

fn add_xmp_value(container: &mut Elem, value: &XmpValue) {
    let quals = &value.qualifiers;
    if quals.has_non_lang_quals() {
        let d = container.sub(rdf_description());
        for (k, v) in quals.iter_quals(false) {
            add_xmp_value(d.sub(k), &v);
        }
        add_inner_value(d.sub(rdf_value()), &value.value);
    } else {
        add_inner_value(container, &value.value);
    }
    if let Some(l) = quals.lang() {
        container.set(xml_lang(), l.to_owned());
    }
}

/// Serialise XMP structures into an XMP packet (`serialise_xmp`).
pub fn serialise_xmp(roots: &[XmpStructure]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n");
    out.push_str(&format!(
        "<x:xmpmeta xmlns:x=\"{}\" x:xmptk=\"{}\">\n",
        model::ns("x"),
        esc(VENDOR, true)
    ));
    out.push_str(&format!("<rdf:RDF xmlns:rdf=\"{}\">\n", model::ns("rdf")));
    for root in roots {
        let mut d = Elem::new(rdf_description());
        struct_to_xml(&mut d, root);
        d.set(rdf_about(), String::new());
        let mut ns = NsMap(Vec::new());
        d.collect_ns(&mut ns);
        d.write(&mut out, &mut ns, true);
    }
    out.push_str("\n</rdf:RDF>");
    out.push_str("\n</x:xmpmeta>");
    out.push_str("\n<?xpacket end=\"r\"?>");
    out.into_bytes()
}

// ---------------------------------------------------------------------------
// Metadata mapping
// ---------------------------------------------------------------------------

fn lang_x_default() -> Qualifiers {
    Qualifiers::of(vec![(xml_lang(), XmpValue::text("x-default"))])
}

fn meta_string_as_value(m: Option<&MetaString>, lang_xdefault: bool) -> Option<XmpValue> {
    let m = m?;
    let quals = match m.lang_code.as_deref() {
        None => {
            if lang_xdefault {
                lang_x_default()
            } else {
                Qualifiers::default()
            }
        }
        Some("DEFAULT") => {
            if lang_xdefault {
                lang_x_default()
            } else {
                Qualifiers::default()
            }
        }
        Some(lc) => {
            let cc = m.country_code.as_deref().map(|c| format!("-{c}")).unwrap_or_default();
            Qualifiers::of(vec![(xml_lang(), XmpValue::text(&format!("{lc}{cc}")))])
        }
    };
    Some(XmpValue::with_quals(XmpValueKind::Str(m.value.clone()), quals))
}

/// ISO 8601 format of a date (`datetime.isoformat()` without microseconds).
pub fn iso_format(d: &PdfDate) -> String {
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        d.year, d.month, d.day, d.hour, d.minute, d.second
    );
    match d.utc_offset_minutes {
        None => base,
        Some(o) => {
            let sign = if o < 0 { '-' } else { '+' };
            format!("{base}{sign}{:02}:{:02}", o.abs() / 60, o.abs() % 60)
        }
    }
}

/// Parse an ISO 8601 date-time (`misc.isoparse`, as `dateutil.isoparse`);
/// naive values are taken as UTC.
pub fn isoparse(s: &str) -> Option<PdfDate> {
    let b = s.as_bytes();
    let digits = |i: usize, n: usize| -> Option<u32> {
        let slice = b.get(i..i + n)?;
        if !slice.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(slice).ok()?.parse().ok()
    };
    let year = digits(0, 4)? as i32;
    let mut i = 4;
    let (mut month, mut day) = (1u32, 1u32);
    let extended = b.get(i) == Some(&b'-');
    if i < b.len() && b[i] != b'T' {
        if extended {
            month = digits(i + 1, 2)?;
            i += 3;
            if b.get(i) == Some(&b'-') {
                day = digits(i + 1, 2)?;
                i += 3;
            }
        } else {
            month = digits(i, 2)?;
            day = digits(i + 2, 2)?;
            i += 4;
        }
    }
    let (mut hour, mut minute, mut second) = (0u32, 0u32, 0u32);
    let mut offset: Option<i32> = None;
    if i < b.len() {
        if b[i] != b'T' && b[i] != b' ' {
            return None;
        }
        i += 1;
        hour = digits(i, 2)?;
        i += 2;
        if b.get(i) == Some(&b':') {
            minute = digits(i + 1, 2)?;
            i += 3;
            if b.get(i) == Some(&b':') {
                second = digits(i + 1, 2)?;
                i += 3;
            }
        } else if let Some(m) = digits(i, 2) {
            minute = m;
            i += 2;
            if let Some(sec) = digits(i, 2) {
                second = sec;
                i += 2;
            }
        }
        if matches!(b.get(i), Some(b'.') | Some(b',')) {
            i += 1;
            let st = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == st {
                return None;
            }
        }
        match b.get(i) {
            None => {}
            Some(b'Z') => {
                offset = Some(0);
                i += 1;
            }
            Some(&sgn @ (b'+' | b'-')) => {
                let h = digits(i + 1, 2)? as i32;
                i += 3;
                let mut m = 0i32;
                if b.get(i) == Some(&b':') {
                    m = digits(i + 1, 2)? as i32;
                    i += 3;
                } else if let Some(mm) = digits(i, 2) {
                    m = mm as i32;
                    i += 2;
                }
                let total = h * 60 + m;
                offset = Some(if sgn == b'-' { -total } else { total });
            }
            Some(_) => return None,
        }
    }
    if i != b.len() {
        return None;
    }
    let d = PdfDate {
        year,
        month: u8::try_from(month).ok()?,
        day: u8::try_from(day).ok()?,
        hour: u8::try_from(hour).ok()?,
        minute: u8::try_from(minute).ok()?,
        second: u8::try_from(second).ok()?,
        utc_offset_minutes: Some(offset.unwrap_or(0)),
    };
    // validate through the PDF date parser's checks
    crate::generic::parse_pdf_date(&crate::generic::pdf_date(&d), true).ok()
}

/// Update XMP structures with document metadata (`update_xmp_with_meta`).
pub fn update_xmp_with_meta(meta: &DocumentMetadata, roots: &[XmpStructure], now: PdfDate) -> Vec<XmpStructure> {
    let mut fields = XmpStructure::default();
    for root in roots {
        for (k, v) in root.iter() {
            fields.set(k.clone(), v.clone());
        }
    }
    populate_xmp_with_meta(meta, fields, now)
}

fn write_meta_date(fields: &mut XmpStructure, key: ExpandedName, d: Option<MetaDate>, now: PdfDate) {
    let v = match d {
        Some(MetaDate::At(v)) => v,
        Some(MetaDate::Now) => now,
        None => return,
    };
    fields.set(key, XmpValue::text(&iso_format(&v)));
}

fn populate_xmp_with_meta(meta: &DocumentMetadata, mut fields: XmpStructure, now: PdfDate) -> Vec<XmpStructure> {
    write_meta_date(&mut fields, xmp_moddate(), meta.last_modified, now);
    fields.set(pdf_producer(), XmpValue::text(VENDOR));
    if !meta.xmp_unmanaged {
        write_meta_date(&mut fields, xmp_createdate(), meta.created, now);
        if let Some(v) = meta_string_as_value(meta.title.as_ref(), true) {
            fields.set(dc_title(), XmpValue::new(XmpValueKind::Array(XmpArray::alternative(vec![v]))));
        }
        if let Some(v) = meta_string_as_value(meta.author.as_ref(), false) {
            fields.set(dc_creator(), XmpValue::new(XmpValueKind::Array(XmpArray::ordered(vec![v]))));
        }
        if let Some(v) = meta_string_as_value(meta.subject.as_ref(), true) {
            fields.set(dc_description(), XmpValue::new(XmpValueKind::Array(XmpArray::alternative(vec![v]))));
        }
        if let Some(v) = meta_string_as_value(meta.creator.as_ref(), false) {
            fields.set(xmp_creatortool(), v);
        }
        if !meta.keywords.is_empty() {
            fields.set(pdf_keywords(), XmpValue::text(&meta.keywords.join(",")));
        }
    }
    let mut out = vec![fields];
    out.extend(meta.xmp_extra.iter().cloned());
    out
}

fn parse_dt(v: &XmpValue) -> PdfResult<PdfDate> {
    let XmpValueKind::Str(s) = &v.value else {
        return Err(xmp_error("Wrong type for XMP date"));
    };
    isoparse(s).ok_or_else(|| xmp_error(format!("Failed to parse '{s}' as a date")))
}

fn simplify_meta_str(v: &XmpValue) -> Option<MetaString> {
    let focus = match &v.value {
        XmpValueKind::Array(a) if !a.entries.is_empty() => &a.entries[0],
        _ => v,
    };
    let XmpValueKind::Str(s) = &focus.value else {
        return None;
    };
    Some(match focus.qualifiers.lang() {
        None | Some("") => MetaString::plain(s.clone()),
        Some("x-default") => MetaString::with_lang(s.clone(), "DEFAULT", None),
        Some(l) => {
            let mut parts = l.splitn(2, '-');
            let lc = parts.next().unwrap_or("");
            MetaString::with_lang(s.clone(), lc, parts.next())
        }
    })
}

/// Document metadata from XMP structures (`meta_from_xmp`).
pub fn meta_from_xmp(roots: &[XmpStructure]) -> PdfResult<DocumentMetadata> {
    let mut all = XmpStructure::default();
    for root in roots {
        for (k, v) in root.iter() {
            all.set(k.clone(), v.clone());
        }
    }
    let mut meta = DocumentMetadata::default();
    if let Some(v) = all.get(&xmp_moddate()) {
        meta.last_modified = Some(MetaDate::At(parse_dt(v)?));
    }
    if let Some(v) = all.get(&xmp_createdate()) {
        meta.created = Some(MetaDate::At(parse_dt(v)?));
    }
    meta.title = all.get(&dc_title()).and_then(simplify_meta_str);
    meta.author = all.get(&dc_creator()).and_then(simplify_meta_str);
    meta.subject = all.get(&dc_description()).and_then(simplify_meta_str);
    if let Some(s) = all.get(&pdf_keywords()).and_then(XmpValue::as_str) {
        meta.keywords = s.split(',').map(str::to_owned).collect();
    }
    if let Some(s) = all.get(&xmp_creatortool()).and_then(XmpValue::as_str) {
        meta.creator = Some(MetaString::plain(s));
    }
    Ok(meta)
}

/// The XMP structures of a metadata stream (`MetadataStream.xmp`).
pub fn stream_xmp(handler: &dyn PdfHandler, stream: &Stream) -> PdfResult<Vec<XmpStructure>> {
    parse_xmp(&handler.decode_stream(stream, DecodePurpose::XmpMetadata)?)
}

/// A new metadata stream (`MetadataStream.from_xmp`), uncompressed.
pub fn metadata_stream_from_xmp(xmp: &[XmpStructure]) -> DecodedStream {
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"Metadata".to_vec()));
    d.set("Subtype", Object::Name(b"XML".to_vec()));
    DecodedStream::new(d, serialise_xmp(xmp))
}

/// Update an existing metadata stream (`update_xmp_with_meta` on a
/// `MetadataStream`): the XMP is re-serialised and re-encoded with the
/// stream's filters; `/Type` and `/Subtype` are set.
pub fn update_metadata_stream(
    handler: &dyn PdfHandler,
    stream: &Stream,
    meta: &DocumentMetadata,
    now: PdfDate,
) -> PdfResult<DecodedStream> {
    let xmp = stream_xmp(handler, stream)?;
    let updated = update_xmp_with_meta(meta, &xmp, now);
    let mut d = stream.dict.clone();
    d.set("Type", Object::Name(b"Metadata".to_vec()));
    d.set("Subtype", Object::Name(b"XML".to_vec()));
    d.remove(b"Length");
    Ok(DecodedStream::new(d, serialise_xmp(&updated)))
}
