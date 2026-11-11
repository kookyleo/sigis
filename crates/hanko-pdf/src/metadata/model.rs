// Derived from pyHanko `pdf_utils/metadata/model.py` (MIT, see LICENSE-pyHanko).

//! Metadata model (`pyhanko.pdf_utils.metadata.model`).

use crate::generic::PdfDate;

/// Producer string written by this library (`VENDOR`).
pub const VENDOR: &str = concat!("sigis-hanko ", env!("CARGO_PKG_VERSION"));

/// A string with an optional language (`StringWithLanguage` / `MetaString`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaString {
    /// The value.
    pub value: String,
    /// Language code.
    pub lang_code: Option<String>,
    /// Country code.
    pub country_code: Option<String>,
}

impl MetaString {
    /// A plain string.
    pub fn plain(s: impl Into<String>) -> Self {
        Self {
            value: s.into(),
            lang_code: None,
            country_code: None,
        }
    }

    /// A string with a language (`StringWithLanguage`); `lang_code`
    /// `"DEFAULT"` stands for `x-default`.
    pub fn with_lang(s: impl Into<String>, lang_code: &str, country_code: Option<&str>) -> Self {
        Self {
            value: s.into(),
            lang_code: Some(lang_code.to_owned()),
            country_code: country_code.map(str::to_owned),
        }
    }
}

impl From<&str> for MetaString {
    fn from(s: &str) -> Self {
        Self::plain(s)
    }
}

/// A metadata date: the current time, or a fixed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaDate {
    /// `'now'`.
    Now,
    /// A fixed date.
    At(PdfDate),
}

/// Document metadata (`DocumentMetadata`).
#[derive(Clone, Debug, PartialEq)]
pub struct DocumentMetadata {
    /// Title.
    pub title: Option<MetaString>,
    /// Author.
    pub author: Option<MetaString>,
    /// Subject.
    pub subject: Option<MetaString>,
    /// Keywords.
    pub keywords: Vec<String>,
    /// Creator application.
    pub creator: Option<MetaString>,
    /// Creation date.
    pub created: Option<MetaDate>,
    /// Modification date (default: now).
    pub last_modified: Option<MetaDate>,
    /// Extra XMP metadata (`xmp_extra`).
    pub xmp_extra: Vec<XmpStructure>,
    /// XMP-only metadata (`xmp_unmanaged`).
    pub xmp_unmanaged: bool,
}

impl Default for DocumentMetadata {
    fn default() -> Self {
        Self {
            title: None,
            author: None,
            subject: None,
            keywords: Vec::new(),
            creator: None,
            created: None,
            last_modified: Some(MetaDate::Now),
            xmp_extra: Vec::new(),
            xmp_unmanaged: false,
        }
    }
}

impl DocumentMetadata {
    /// Overlay `self` over `base` (`view_over`).
    pub fn view_over(&self, base: &DocumentMetadata) -> DocumentMetadata {
        let or = |a: &Option<MetaString>, b: &Option<MetaString>| {
            a.clone().filter(|s| !s.value.is_empty()).or_else(|| b.clone())
        };
        DocumentMetadata {
            title: or(&self.title, &base.title),
            author: or(&self.author, &base.author),
            subject: or(&self.subject, &base.subject),
            keywords: if self.keywords.is_empty() {
                base.keywords.clone()
            } else {
                self.keywords.clone()
            },
            creator: or(&self.creator, &base.creator),
            created: self.created.or(base.created),
            last_modified: self.last_modified,
            xmp_extra: Vec::new(),
            xmp_unmanaged: false,
        }
    }
}

// ---------------------------------------------------------------------------
// XMP data model
// ---------------------------------------------------------------------------

/// An expanded XML name (`ExpandedName`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExpandedName {
    /// Namespace URI.
    pub ns: String,
    /// Local name.
    pub local_name: String,
}

impl ExpandedName {
    /// A name in namespace `ns`.
    pub fn new(ns: &str, local_name: &str) -> Self {
        Self {
            ns: ns.to_owned(),
            local_name: local_name.to_owned(),
        }
    }
}

impl std::fmt::Display for ExpandedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sep = if self.ns.ends_with('/') || self.ns.ends_with('#') { "" } else { "/" };
        write!(f, "{}{sep}{}", self.ns, self.local_name)
    }
}

/// Known namespaces and their customary prefixes (`NS`).
pub const NS: [(&str, &str); 11] = [
    ("xml", "http://www.w3.org/XML/1998/namespace"),
    ("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
    ("xmp", "http://ns.adobe.com/xap/1.0/"),
    ("dc", "http://purl.org/dc/elements/1.1/"),
    ("pdf", "http://ns.adobe.com/pdf/1.3/"),
    ("pdfaid", "http://www.aiim.org/pdfa/ns/id/"),
    ("pdfuaid", "http://www.aiim.org/pdfua/ns/id/"),
    ("pdfaSchema", "http://www.aiim.org/pdfa/ns/schema#"),
    ("pdfaExtension", "http://www.aiim.org/pdfa/ns/extension/"),
    ("pdfaProperty", "http://www.aiim.org/pdfa/ns/property#"),
    ("x", "adobe:ns:meta/"),
];

/// The URI of a known namespace prefix.
pub fn ns(prefix: &str) -> &'static str {
    NS.iter().find(|(p, _)| *p == prefix).map(|(_, u)| *u).unwrap_or("")
}

fn rdf(local: &str) -> ExpandedName {
    ExpandedName::new(ns("rdf"), local)
}

macro_rules! names {
    ($($(#[$m:meta])* $fn_name:ident => ($prefix:literal, $local:literal);)*) => {
        $(
            $(#[$m])*
            pub fn $fn_name() -> ExpandedName {
                ExpandedName::new(ns($prefix), $local)
            }
        )*
    };
}

names! {
    /// `xml:lang`.
    xml_lang => ("xml", "lang");
    /// `rdf:RDF`.
    rdf_rdf => ("rdf", "RDF");
    /// `rdf:Seq`.
    rdf_seq => ("rdf", "Seq");
    /// `rdf:Bag`.
    rdf_bag => ("rdf", "Bag");
    /// `rdf:Alt`.
    rdf_alt => ("rdf", "Alt");
    /// `rdf:li`.
    rdf_li => ("rdf", "li");
    /// `rdf:value`.
    rdf_value => ("rdf", "value");
    /// `rdf:resource`.
    rdf_resource => ("rdf", "resource");
    /// `rdf:about`.
    rdf_about => ("rdf", "about");
    /// `rdf:parseType`.
    rdf_parse_type => ("rdf", "parseType");
    /// `rdf:Description`.
    rdf_description => ("rdf", "Description");
    /// `x:xmpmeta`.
    x_xmpmeta => ("x", "xmpmeta");
    /// `dc:title`.
    dc_title => ("dc", "title");
    /// `dc:creator`.
    dc_creator => ("dc", "creator");
    /// `dc:description`.
    dc_description => ("dc", "description");
    /// `pdf:Keywords`... (`pdf:keywords` in pyHanko).
    pdf_keywords => ("pdf", "keywords");
    /// `pdf:Producer`.
    pdf_producer => ("pdf", "Producer");
    /// `xmp:CreatorTool`.
    xmp_creatortool => ("xmp", "CreatorTool");
    /// `xmp:CreateDate`.
    xmp_createdate => ("xmp", "CreateDate");
    /// `xmp:ModifyDate`.
    xmp_moddate => ("xmp", "ModifyDate");
}

/// Attributes that are not properties (`NOT_PROPERTY_ATTRIBUTES`).
pub fn not_property_attributes() -> Vec<ExpandedName> {
    vec![
        xml_lang(),
        rdf("parseType"),
        rdf("ID"),
        rdf("nodeID"),
        rdf("Description"),
        rdf("li"),
        rdf("aboutEach"),
        rdf("aboutEachPrefix"),
        rdf("bagID"),
    ]
}

/// XMP qualifiers (`Qualifiers`); `xml:lang` is kept separately.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Qualifiers {
    quals: indexmap::IndexMap<ExpandedName, XmpValue>,
    lang: Option<String>,
}

impl Qualifiers {
    /// Build from name-value pairs (`Qualifiers.of`); an `xml:lang` entry
    /// becomes the language.
    pub fn of(pairs: Vec<(ExpandedName, XmpValue)>) -> Self {
        let mut quals: indexmap::IndexMap<ExpandedName, XmpValue> = pairs.into_iter().collect();
        let lang = quals.shift_remove(&xml_lang()).and_then(|v| match v.value {
            XmpValueKind::Str(s) => Some(s),
            _ => None,
        });
        Self { quals, lang }
    }

    /// Only a language qualifier (`lang_as_qual`).
    pub fn lang_as_qual(lang: Option<&str>) -> Self {
        Self {
            quals: indexmap::IndexMap::new(),
            lang: lang.filter(|l| !l.is_empty()).map(str::to_owned),
        }
    }

    /// A qualifier by name (`__getitem__`).
    pub fn get(&self, name: &ExpandedName) -> Option<&XmpValue> {
        self.quals.get(name)
    }

    /// All qualifiers (`iter_quals`).
    pub fn iter_quals(&self, with_lang: bool) -> Vec<(ExpandedName, XmpValue)> {
        let mut out: Vec<_> = self.quals.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        if with_lang {
            if let Some(l) = &self.lang {
                out.push((xml_lang(), XmpValue::text(l)));
            }
        }
        out
    }

    /// The language (`lang`).
    pub fn lang(&self) -> Option<&str> {
        self.lang.as_deref()
    }

    /// `true` if there are qualifiers other than the language.
    pub fn has_non_lang_quals(&self) -> bool {
        !self.quals.is_empty()
    }

    /// `bool(qualifiers)`.
    pub fn is_empty(&self) -> bool {
        self.quals.is_empty() && self.lang.is_none()
    }
}

/// An XMP URI (`XmpUri`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct XmpUri(pub String);

/// The value part of an [`XmpValue`].
#[derive(Clone, Debug, PartialEq)]
pub enum XmpValueKind {
    /// A structure.
    Structure(XmpStructure),
    /// An array.
    Array(XmpArray),
    /// A URI.
    Uri(XmpUri),
    /// A string.
    Str(String),
}

/// An XMP value with qualifiers (`XmpValue`).
#[derive(Clone, Debug, PartialEq)]
pub struct XmpValue {
    /// The value.
    pub value: XmpValueKind,
    /// Qualifiers.
    pub qualifiers: Qualifiers,
}

impl XmpValue {
    /// A plain value.
    pub fn new(value: XmpValueKind) -> Self {
        Self {
            value,
            qualifiers: Qualifiers::default(),
        }
    }

    /// A plain string value.
    pub fn text(s: &str) -> Self {
        Self::new(XmpValueKind::Str(s.to_owned()))
    }

    /// A value with qualifiers.
    pub fn with_quals(value: XmpValueKind, qualifiers: Qualifiers) -> Self {
        Self { value, qualifiers }
    }

    /// The string value, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            XmpValueKind::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// An XMP structure (`XmpStructure`); equality ignores field order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct XmpStructure {
    fields: indexmap::IndexMap<ExpandedName, XmpValue>,
}

impl XmpStructure {
    /// Build from name-value pairs (`XmpStructure.of`).
    pub fn of(pairs: Vec<(ExpandedName, XmpValue)>) -> Self {
        Self {
            fields: pairs.into_iter().collect(),
        }
    }

    /// A field (`__getitem__`).
    pub fn get(&self, name: &ExpandedName) -> Option<&XmpValue> {
        self.fields.get(name)
    }

    /// Set a field.
    pub fn set(&mut self, name: ExpandedName, value: XmpValue) {
        self.fields.insert(name, value);
    }

    /// Fields in order.
    pub fn iter(&self) -> impl Iterator<Item = (&ExpandedName, &XmpValue)> {
        self.fields.iter()
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// `true` if there are no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// XMP array types (`XmpArrayType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XmpArrayType {
    /// `rdf:Seq`.
    Ordered,
    /// `rdf:Bag`.
    Unordered,
    /// `rdf:Alt`.
    Alternative,
}

impl XmpArrayType {
    /// The RDF element name (`as_rdf`).
    pub fn as_rdf(self) -> ExpandedName {
        match self {
            Self::Ordered => rdf_seq(),
            Self::Unordered => rdf_bag(),
            Self::Alternative => rdf_alt(),
        }
    }
}

/// An XMP array (`XmpArray`); unordered arrays compare as sets.
#[derive(Clone, Debug)]
pub struct XmpArray {
    /// The array type.
    pub array_type: XmpArrayType,
    /// Entries.
    pub entries: Vec<XmpValue>,
}

impl XmpArray {
    /// An ordered array.
    pub fn ordered(entries: Vec<XmpValue>) -> Self {
        Self {
            array_type: XmpArrayType::Ordered,
            entries,
        }
    }

    /// An unordered array.
    pub fn unordered(entries: Vec<XmpValue>) -> Self {
        Self {
            array_type: XmpArrayType::Unordered,
            entries,
        }
    }

    /// An alternative array.
    pub fn alternative(entries: Vec<XmpValue>) -> Self {
        Self {
            array_type: XmpArrayType::Alternative,
            entries,
        }
    }
}

impl PartialEq for XmpArray {
    fn eq(&self, other: &Self) -> bool {
        if self.array_type != other.array_type {
            return false;
        }
        if self.array_type == XmpArrayType::Unordered {
            other.entries.iter().all(|e| self.entries.contains(e))
                && self.entries.iter().all(|e| other.entries.contains(e))
        } else {
            self.entries == other.entries
        }
    }
}
