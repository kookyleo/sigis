//! XML helpers on top of `roxmltree`: parsing with safe options, prefix
//! recovery for canonicalization, and small tree navigation utilities.

pub mod c14n;
pub mod dsig;

use roxmltree::{Document, Node, ParsingOptions};

/// XML namespace of the `xml:` prefix.
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
/// XMLDSig namespace.
pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// XAdES 1.3.2 namespace.
pub const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// ETSI TS 119 612 namespace.
pub const TSL_NS: &str = "http://uri.etsi.org/02231/v2#";
/// ETSI TS 119 612 additional types namespace.
pub const TSL_ADDTYPES_NS: &str = "http://uri.etsi.org/02231/v2/additionaltypes#";
/// ETSI TS 119 612 service information extension namespace.
pub const TSL_SIE_NS: &str =
    "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#";

/// Error parsing or interpreting XML.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct XmlError(pub String);

/// Parse an XML document. DTDs are rejected, so no entity expansion or
/// external resource loading can happen.
pub fn parse(xml: &str) -> Result<Document<'_>, XmlError> {
    let opts = ParsingOptions {
        allow_dtd: false,
        ..ParsingOptions::default()
    };
    Document::parse_with_options(xml, opts).map_err(|e| XmlError(format!("XML parse error: {e}")))
}

/// The prefix of an element's tag as written in the source (`None` for an
/// unprefixed tag).
pub fn element_prefix<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    let text = node.document().input_text();
    let start = node.range().start;
    let rest = text.get(start + 1..)?;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .unwrap_or(rest.len());
    let qname = &rest[..end];
    qname.split_once(':').map(|(p, _)| p)
}

/// The prefix of an attribute as written in the source.
pub fn attribute_prefix<'a>(
    doc: &'a Document<'_>,
    attr: &roxmltree::Attribute<'_, '_>,
) -> Option<&'a str> {
    let qname = doc.input_text().get(attr.range_qname())?;
    qname.split_once(':').map(|(p, _)| p)
}

/// `true` if `node` is the element `{ns}name`.
pub fn is(node: Node<'_, '_>, ns: &str, name: &str) -> bool {
    node.is_element() && node.tag_name().name() == name && node.tag_name().namespace() == Some(ns)
}

/// Child elements of `node` named `{ns}name`.
pub fn children<'a, 'i: 'a>(
    node: Node<'a, 'i>,
    ns: &'a str,
    name: &'a str,
) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    node.children().filter(move |c| is(*c, ns, name))
}

/// First child element named `{ns}name`.
pub fn child<'a, 'i>(node: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    node.children().find(|c| is(*c, ns, name))
}

/// Element children of `node`.
pub fn element_children<'a, 'i: 'a>(node: Node<'a, 'i>) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    node.children().filter(|c| c.is_element())
}

/// Concatenated text content of `node` (descendant text nodes).
pub fn text_content(node: Node<'_, '_>) -> String {
    node.descendants()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .collect()
}

/// Text content with XML Schema whitespace collapsing applied (as for
/// `xsd:token`, `xsd:anyURI` and `xsd:dateTime` values).
pub fn collapsed_text(node: Node<'_, '_>) -> String {
    text_content(node)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
