// Derived from pyHanko `pdf_utils/extensions.py` (MIT, see LICENSE-pyHanko).

//! Developer extensions (`pyhanko.pdf_utils.extensions`).

use lopdf::{Dictionary, Object};

use crate::generic::text_string;

/// How an extension behaves with ISO 32000-2 multivalued extensions
/// (`DevExtensionMultivalued`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum DevExtensionMultivalued {
    /// Always serialise as multivalued.
    Always,
    /// Never serialise as multivalued.
    Never,
    /// Single-valued when possible.
    #[default]
    Maybe,
}

/// A developer extension designation (`DeveloperExtension`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeveloperExtension {
    /// Registered prefix (name without slash).
    pub prefix_name: Vec<u8>,
    /// Base version (name without slash, e.g. `1.7`).
    pub base_version: Vec<u8>,
    /// Extension level.
    pub extension_level: i64,
    /// Documentation URL.
    pub url: Option<String>,
    /// Extra revision information.
    pub extension_revision: Option<String>,
    /// Compare by level number.
    pub compare_by_level: bool,
    /// Levels that subsume this one.
    pub subsumed_by: Vec<i64>,
    /// Levels this one subsumes.
    pub subsumes: Vec<i64>,
    /// Multivalued behaviour.
    pub multivalued: DevExtensionMultivalued,
}

impl DeveloperExtension {
    /// An extension with default settings.
    pub fn new(prefix_name: &str, base_version: &str, extension_level: i64) -> Self {
        Self {
            prefix_name: prefix_name.trim_start_matches('/').as_bytes().to_vec(),
            base_version: base_version.trim_start_matches('/').as_bytes().to_vec(),
            extension_level,
            url: None,
            extension_revision: None,
            compare_by_level: false,
            subsumed_by: Vec::new(),
            subsumes: Vec::new(),
            multivalued: DevExtensionMultivalued::Maybe,
        }
    }

    /// The extension dictionary (`as_pdf_object`).
    pub fn as_pdf_object(&self) -> Dictionary {
        let mut d = Dictionary::new();
        d.set("Type", Object::Name(b"DeveloperExtensions".to_vec()));
        d.set("BaseVersion", Object::Name(self.base_version.clone()));
        d.set("ExtensionLevel", Object::Integer(self.extension_level));
        if let Some(u) = &self.url {
            d.set("URL", text_string(u));
        }
        if let Some(r) = &self.extension_revision {
            d.set("ExtensionRevision", text_string(r));
        }
        d
    }
}
