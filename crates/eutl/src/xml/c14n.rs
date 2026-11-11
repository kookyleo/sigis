//! Canonical XML 1.0 / 1.1 and Exclusive XML Canonicalization 1.0
//! (W3C recommendations), for document subsets of the form "a subtree,
//! optionally minus one excluded subtree", which is what XMLDSig
//! same-document references with the enveloped-signature transform produce.
//!
//! Original code (no Python counterpart: pyHanko relies on lxml / signxml).

use std::collections::BTreeMap;

use roxmltree::{Document, Node, NodeId, NodeType};

use super::{attribute_prefix, element_prefix, XmlError, XML_NS};

/// Canonicalization algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum C14nMethod {
    /// Canonical XML 1.0.
    Inclusive10,
    /// Canonical XML 1.1.
    Inclusive11,
    /// Exclusive XML Canonicalization 1.0.
    Exclusive10,
}

/// Canonicalization parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C14nParams {
    /// Algorithm.
    pub method: C14nMethod,
    /// Keep comments.
    pub with_comments: bool,
    /// Exclusive C14N `InclusiveNamespaces PrefixList` (`#default` for the
    /// default namespace).
    pub inclusive_prefixes: Vec<String>,
}

impl C14nParams {
    /// Parameters from an algorithm URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let (method, with_comments) = match uri {
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => (C14nMethod::Inclusive10, false),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                (C14nMethod::Inclusive10, true)
            }
            "http://www.w3.org/2006/12/xml-c14n11" => (C14nMethod::Inclusive11, false),
            "http://www.w3.org/2006/12/xml-c14n11#WithComments" => (C14nMethod::Inclusive11, true),
            "http://www.w3.org/2001/10/xml-exc-c14n#" => (C14nMethod::Exclusive10, false),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                (C14nMethod::Exclusive10, true)
            }
            _ => return None,
        };
        Some(Self {
            method,
            with_comments,
            inclusive_prefixes: Vec::new(),
        })
    }
}

/// Canonicalize the subtree rooted at `apex` (the whole document if `apex`
/// is the root node), leaving out the subtree rooted at `exclude`.
pub fn canonicalize(
    doc: &Document<'_>,
    apex: Node<'_, '_>,
    exclude: Option<NodeId>,
    params: &C14nParams,
) -> Result<Vec<u8>, XmlError> {
    let mut c = Canon {
        doc,
        params,
        exclude,
        out: String::new(),
    };
    if apex.node_type() == NodeType::Root {
        let mut seen_root = false;
        for child in apex.children() {
            if Some(child.id()) == exclude {
                continue;
            }
            match child.node_type() {
                NodeType::Element => {
                    c.element(child, &BTreeMap::new(), true)?;
                    seen_root = true;
                }
                NodeType::Comment | NodeType::PI => {
                    if child.is_comment() && !params.with_comments {
                        continue;
                    }
                    if seen_root {
                        c.out.push('\n');
                    }
                    c.leaf(child);
                    if !seen_root {
                        c.out.push('\n');
                    }
                }
                _ => {}
            }
        }
    } else if apex.is_element() {
        c.element(apex, &BTreeMap::new(), true)?;
    } else {
        c.leaf(apex);
    }
    Ok(c.out.into_bytes())
}

struct Canon<'d, 'a, 'i> {
    doc: &'d Document<'i>,
    params: &'a C14nParams,
    exclude: Option<NodeId>,
    out: String,
}

/// Namespace declarations in effect in the output (prefix "" = default).
type Rendered = BTreeMap<String, String>;

impl Canon<'_, '_, '_> {
    fn leaf(&mut self, node: Node<'_, '_>) {
        match node.node_type() {
            NodeType::Text => escape_text(node.text().unwrap_or(""), &mut self.out),
            NodeType::Comment => {
                if self.params.with_comments {
                    self.out.push_str("<!--");
                    self.out.push_str(node.text().unwrap_or(""));
                    self.out.push_str("-->");
                }
            }
            NodeType::PI => {
                if let Some(pi) = node.pi() {
                    self.out.push_str("<?");
                    self.out.push_str(pi.target);
                    if let Some(v) = pi.value {
                        if !v.is_empty() {
                            self.out.push(' ');
                            self.out.push_str(v);
                        }
                    }
                    self.out.push_str("?>");
                }
            }
            _ => {}
        }
    }

    fn element(
        &mut self,
        node: Node<'_, '_>,
        rendered: &Rendered,
        is_apex: bool,
    ) -> Result<(), XmlError> {
        let prefix = element_prefix(node);
        let local = node.tag_name().name();

        // In-scope namespaces (prefix "" = default).
        let mut in_scope: BTreeMap<String, String> = BTreeMap::new();
        for ns in node.namespaces() {
            let p = ns.name().unwrap_or("");
            if p == "xml" || (p.is_empty() && ns.uri().is_empty()) {
                continue;
            }
            in_scope.insert(p.to_owned(), ns.uri().to_owned());
        }

        // Attributes with their prefixes.
        let mut attrs: Vec<(String, String, String, String)> = Vec::new(); // (ns, local, qname, value)
        for a in node.attributes() {
            let ns = a.namespace().unwrap_or("").to_owned();
            let qname = match attribute_prefix(self.doc, &a) {
                Some(p) => format!("{p}:{}", a.name()),
                None => a.name().to_owned(),
            };
            attrs.push((ns, a.name().to_owned(), qname, a.value().to_owned()));
        }

        // Namespace declarations to emit.
        let mut emit: BTreeMap<String, String> = BTreeMap::new();
        match self.params.method {
            C14nMethod::Inclusive10 | C14nMethod::Inclusive11 => {
                for (p, uri) in &in_scope {
                    if rendered.get(p) != Some(uri) {
                        emit.insert(p.clone(), uri.clone());
                    }
                }
                if !in_scope.contains_key("") && rendered.get("").is_some_and(|u| !u.is_empty()) {
                    emit.insert(String::new(), String::new());
                }
                if is_apex {
                    self.inherit_xml_attrs(node, &mut attrs);
                }
            }
            C14nMethod::Exclusive10 => {
                let mut used: Vec<String> = vec![prefix.unwrap_or("").to_owned()];
                for a in node.attributes() {
                    if let Some(p) = attribute_prefix(self.doc, &a) {
                        if p != "xml" {
                            used.push(p.to_owned());
                        }
                    }
                }
                for p in &self.params.inclusive_prefixes {
                    let p = if p == "#default" { "" } else { p.as_str() };
                    if in_scope.contains_key(p) {
                        used.push(p.to_owned());
                    }
                }
                for p in used {
                    let uri = in_scope.get(&p).cloned().unwrap_or_default();
                    let current = rendered.get(&p).cloned().unwrap_or_default();
                    if uri != current {
                        emit.insert(p, uri);
                    }
                }
            }
        }

        let qname = match prefix {
            Some(p) => format!("{p}:{local}"),
            None => local.to_owned(),
        };
        self.out.push('<');
        self.out.push_str(&qname);
        // BTreeMap order: "" (default) first, then prefixes in order.
        for (p, uri) in &emit {
            if p.is_empty() {
                self.out.push_str(" xmlns=\"");
            } else {
                self.out.push_str(" xmlns:");
                self.out.push_str(p);
                self.out.push_str("=\"");
            }
            escape_attr(uri, &mut self.out);
            self.out.push('"');
        }
        attrs.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        for (_, _, qname, value) in &attrs {
            self.out.push(' ');
            self.out.push_str(qname);
            self.out.push_str("=\"");
            escape_attr(value, &mut self.out);
            self.out.push('"');
        }
        self.out.push('>');

        let mut child_rendered = rendered.clone();
        for (p, uri) in emit {
            child_rendered.insert(p, uri);
        }
        for child in node.children() {
            if Some(child.id()) == self.exclude {
                continue;
            }
            if child.is_element() {
                self.element(child, &child_rendered, false)?;
            } else {
                self.leaf(child);
            }
        }
        self.out.push_str("</");
        self.out.push_str(&qname);
        self.out.push('>');
        Ok(())
    }

    /// Inclusive canonicalization of a document subset imports `xml:lang`,
    /// `xml:space` (and, for 1.0, `xml:base`) from ancestors of the apex.
    fn inherit_xml_attrs(
        &self,
        node: Node<'_, '_>,
        attrs: &mut Vec<(String, String, String, String)>,
    ) {
        let names: &[&str] = match self.params.method {
            C14nMethod::Inclusive10 => &["lang", "space", "base"],
            _ => &["lang", "space"],
        };
        for name in names {
            if attrs.iter().any(|a| a.0 == XML_NS && a.1 == *name) {
                continue;
            }
            for anc in node.ancestors().skip(1).filter(|a| a.is_element()) {
                if let Some(v) = anc.attribute((XML_NS, *name)) {
                    attrs.push((
                        XML_NS.to_owned(),
                        (*name).to_owned(),
                        format!("xml:{name}"),
                        v.to_owned(),
                    ));
                    break;
                }
            }
        }
    }
}

fn escape_text(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse;

    fn c14n(xml: &str, method: C14nMethod, apex_name: Option<&str>) -> String {
        let doc = parse(xml).unwrap();
        let apex = match apex_name {
            Some(n) => doc
                .descendants()
                .find(|n2| n2.is_element() && n2.tag_name().name() == n)
                .unwrap(),
            None => doc.root(),
        };
        let p = C14nParams {
            method,
            with_comments: false,
            inclusive_prefixes: vec![],
        };
        String::from_utf8(canonicalize(&doc, apex, None, &p).unwrap()).unwrap()
    }

    // W3C C14N 1.0 spec, example 3.3 (start and end tags).
    #[test]
    fn spec_example_3_3() {
        let input = r#"<doc>
   <e1   />
   <e2   ></e2>
   <e3   name = "elem3"   id="elem3"   />
   <e4   name="elem4"   id="elem4"   ></e4>
   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
   <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="" xmlns:a="http://www.w3.org">
            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
         </e8>
      </e7>
   </e6>
</doc>"#;
        let expected = r#"<doc>
   <e1></e1>
   <e2></e2>
   <e3 id="elem3" name="elem3"></e3>
   <e4 id="elem4" name="elem4"></e4>
   <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
   <e6 xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="">
            <e9 xmlns:a="http://www.ietf.org"></e9>
         </e8>
      </e7>
   </e6>
</doc>"#;
        assert_eq!(c14n(input, C14nMethod::Inclusive10, None), expected);
    }

    // W3C C14N 1.0 spec, example 3.4 (character modifications).
    #[test]
    fn spec_example_3_4_subset() {
        let input = "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>";
        let expected = "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>";
        assert_eq!(c14n(input, C14nMethod::Inclusive10, None), expected);
    }

    #[test]
    fn exclusive_omits_unused_namespaces() {
        let input = r#"<a:root xmlns:a="urn:a" xmlns:b="urn:b" xmlns="urn:d"><a:child b:x="1"><c/></a:child></a:root>"#;
        assert_eq!(
            c14n(input, C14nMethod::Exclusive10, Some("child")),
            r#"<a:child xmlns:a="urn:a" xmlns:b="urn:b" b:x="1"><c xmlns="urn:d"></c></a:child>"#
        );
        assert_eq!(
            c14n(input, C14nMethod::Inclusive10, Some("child")),
            r#"<a:child xmlns="urn:d" xmlns:a="urn:a" xmlns:b="urn:b" b:x="1"><c></c></a:child>"#
        );
    }

    #[test]
    fn inclusive_imports_xml_attrs() {
        let input = r#"<r xml:lang="en"><s xml:space="preserve"><t/></s></r>"#;
        assert_eq!(
            c14n(input, C14nMethod::Inclusive10, Some("t")),
            r#"<t xml:lang="en" xml:space="preserve"></t>"#
        );
        assert_eq!(c14n(input, C14nMethod::Exclusive10, Some("t")), "<t></t>");
    }

    #[test]
    fn pis_and_comments_outside_root() {
        let input = "<?xml version=\"1.0\"?>\n<?pi data?>\n<!-- c -->\n<r/>\n<!-- d -->";
        let doc = parse(input).unwrap();
        let p = C14nParams {
            method: C14nMethod::Inclusive10,
            with_comments: true,
            inclusive_prefixes: vec![],
        };
        let out = String::from_utf8(canonicalize(&doc, doc.root(), None, &p).unwrap()).unwrap();
        assert_eq!(out, "<?pi data?>\n<!-- c -->\n<r></r>\n<!-- d -->");
    }
}
