// Derived from pyHanko `pdf_utils/embed.py` (MIT, see LICENSE-pyHanko).

//! Embedded files (`pyhanko.pdf_utils.embed`).

use lopdf::{Dictionary, Object, ObjectId};

use crate::error::{PdfError, PdfResult};
use crate::generic::{byte_string, pdf_date, text_string, PdfDate};
use crate::rw_common::{PdfHandler, PdfHandlerExt};
use crate::stream::DecodedStream;
use crate::writer::PdfWriter;

/// Parameters of an embedded file (`EmbeddedFileParams`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedFileParams {
    /// Record the size.
    pub embed_size: bool,
    /// Record an MD5 checksum.
    pub embed_checksum: bool,
    /// Creation date.
    pub creation_date: Option<PdfDate>,
    /// Modification date.
    pub modification_date: Option<PdfDate>,
}

impl Default for EmbeddedFileParams {
    fn default() -> Self {
        Self {
            embed_size: true,
            embed_checksum: true,
            creation_date: None,
            modification_date: None,
        }
    }
}

/// Add an embedded file stream to a writer (`EmbeddedFileObject.from_file_data`).
///
/// The `/Params` dictionary is computed from the (unencoded) data. If the
/// writer encrypts embedded files with a filter other than the stream
/// filter, a `/Crypt` filter is added, as pyHanko does on output.
pub fn embedded_file_object(
    w: &mut PdfWriter,
    data: &[u8],
    compress: bool,
    params: Option<&EmbeddedFileParams>,
    mime_type: Option<&str>,
) -> PdfResult<ObjectId> {
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"EmbeddedFile".to_vec()));
    if let Some(m) = mime_type {
        d.set("Subtype", Object::Name(m.as_bytes().to_vec()));
    }
    if let Some(p) = params {
        let mut pd = Dictionary::new();
        if p.embed_size {
            pd.set("Size", Object::Integer(data.len() as i64));
        }
        if p.embed_checksum {
            use md5::{Digest, Md5};
            pd.set("CheckSum", byte_string(Md5::digest(data).to_vec()));
        }
        if let Some(c) = &p.creation_date {
            pd.set("CreationDate", text_string(&pdf_date(c)));
        }
        if let Some(m) = &p.modification_date {
            pd.set("ModDate", text_string(&pdf_date(m)));
        }
        d.set("Params", Object::Dictionary(pd));
    }
    let mut s = DecodedStream::new(d, data.to_vec());
    if compress {
        s.compress()?;
    }
    if let Some(ef) = w.embedded_file_crypt_filter() {
        let mut params = Dictionary::new();
        params.set("Type", Object::Name(b"CryptFilterDecodeParms".to_vec()));
        params.set("Name", Object::Name(ef));
        s.apply_filter("Crypt", Some(params), crate::stream::DuplicateFilter::Allow)?;
    }
    let stream = w.encode_with_crypt_filters(&s)?;
    w.add_object(Object::Stream(stream))
}

/// A related file (`RelatedFileSpec`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelatedFileSpec {
    /// Name of the related file.
    pub name: String,
    /// Its embedded file stream.
    pub embedded_data: ObjectId,
}

impl RelatedFileSpec {
    fn fmt_related_files(lst: &[RelatedFileSpec]) -> Object {
        Object::Array(
            lst.iter()
                .flat_map(|r| [text_string(&r.name), Object::Reference(r.embedded_data)])
                .collect(),
        )
    }
}

/// An embedded file description (`FileSpec`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileSpec {
    /// File specification string (`/F`).
    pub file_spec_string: String,
    /// Unicode file name (`/UF`).
    pub file_name: Option<String>,
    /// The embedded file stream.
    pub embedded_data: Option<ObjectId>,
    /// Description (`/Desc`).
    pub description: Option<String>,
    /// Associated file relationship (name without slash).
    pub af_relationship: Option<String>,
    /// Related files with PDFDocEncoded names.
    pub f_related_files: Vec<RelatedFileSpec>,
    /// Related files with Unicode names.
    pub uf_related_files: Vec<RelatedFileSpec>,
}

impl FileSpec {
    /// The file specification dictionary (`as_pdf_object`).
    pub fn as_pdf_object(&self) -> Dictionary {
        let mut r = Dictionary::new();
        r.set("Type", Object::Name(b"Filespec".to_vec()));
        r.set("F", text_string(&self.file_spec_string));
        if let Some(n) = &self.file_name {
            r.set("UF", text_string(n));
        }
        if let Some(ef) = self.embedded_data {
            let mut efd = Dictionary::new();
            efd.set("F", Object::Reference(ef));
            if self.file_name.is_some() {
                efd.set("UF", Object::Reference(ef));
            }
            r.set("EF", Object::Dictionary(efd));
        }
        if let Some(d) = &self.description {
            r.set("Desc", text_string(d));
        }
        if let Some(a) = &self.af_relationship {
            r.set("AFRelationship", Object::Name(a.as_bytes().to_vec()));
        }
        if !self.f_related_files.is_empty() || !self.uf_related_files.is_empty() {
            let mut rf = Dictionary::new();
            if !self.f_related_files.is_empty() {
                rf.set(
                    "F",
                    RelatedFileSpec::fmt_related_files(&self.f_related_files),
                );
            }
            if !self.uf_related_files.is_empty() && self.file_name.is_some() {
                rf.set(
                    "UF",
                    RelatedFileSpec::fmt_related_files(&self.uf_related_files),
                );
            }
            r.set("RF", Object::Dictionary(rf));
        }
        r
    }
}

/// Where a dictionary lives: as its own object, or directly inside a parent.
enum Loc {
    Indirect(ObjectId),
    InRoot,
    InParent,
}

fn get_or_create_dict(
    w: &mut PdfWriter,
    parent: &mut Dictionary,
    key: &[u8],
) -> PdfResult<(Dictionary, Loc, bool)> {
    match parent.get(key).cloned() {
        Ok(Object::Reference(r)) => match w.resolve(&Object::Reference(r))? {
            Object::Dictionary(d) => Ok((d, Loc::Indirect(r), false)),
            Object::Null => {
                let id = w.add_object(Object::Dictionary(Dictionary::new()))?;
                parent.set(key.to_vec(), Object::Reference(id));
                Ok((Dictionary::new(), Loc::Indirect(id), true))
            }
            _ => Err(PdfError::read("Expected a dictionary")),
        },
        Ok(Object::Dictionary(d)) => Ok((d, Loc::InParent, false)),
        Ok(Object::Null) | Err(_) => {
            let id = w.add_object(Object::Dictionary(Dictionary::new()))?;
            parent.set(key.to_vec(), Object::Reference(id));
            Ok((Dictionary::new(), Loc::Indirect(id), true))
        }
        Ok(_) => Err(PdfError::read("Expected a dictionary")),
    }
}

/// Register an embedded file in the document's `/EmbeddedFiles` name tree
/// (`embed_file`).
pub fn embed_file(w: &mut PdfWriter, spec: &FileSpec) -> PdfResult<()> {
    if spec.embedded_data.is_none() {
        return Err(PdfError::write(
            "File spec does not have an embedded file stream",
        ));
    }
    let spec_obj = spec.as_pdf_object();
    let mut root = w.root()?;
    let orig_root = root.clone();
    let (mut names, names_loc, created_names) = get_or_create_dict(w, &mut root, b"Names")?;
    let names_loc = match names_loc {
        Loc::InParent => Loc::InRoot,
        other => other,
    };
    let (mut ef_tree, ef_loc, _) = get_or_create_dict(w, &mut names, b"EmbeddedFiles")?;
    if ef_tree.has(b"Kids") {
        return Err(PdfError::NotImplemented(
            "Only flat name trees are supported right now".into(),
        ));
    }
    let spec_ref = w.add_object(Object::Dictionary(spec_obj))?;
    let new_entries = [
        text_string(&spec.file_spec_string),
        Object::Reference(spec_ref),
    ];
    match ef_tree.get(b"Names").cloned() {
        Ok(Object::Reference(r)) => {
            let mut arr = match w.resolve(&Object::Reference(r))? {
                Object::Array(a) => a,
                Object::Null => Vec::new(),
                _ => return Err(PdfError::read("/Names must be an array")),
            };
            arr.extend(new_entries);
            w.update_object(r, Object::Array(arr));
        }
        Ok(Object::Array(mut a)) => {
            a.extend(new_entries);
            ef_tree.set("Names", Object::Array(a));
        }
        _ => {
            let id = w.add_object(Object::Array(new_entries.to_vec()))?;
            ef_tree.set("Names", Object::Reference(id));
        }
    }
    // write back the name tree and the names dictionary
    match ef_loc {
        Loc::Indirect(r) => w.update_object(r, Object::Dictionary(ef_tree)),
        _ => names.set("EmbeddedFiles", Object::Dictionary(ef_tree)),
    }
    match names_loc {
        Loc::Indirect(r) => w.update_object(r, Object::Dictionary(names)),
        _ => root.set("Names", Object::Dictionary(names)),
    }
    let _ = created_names;
    if spec.af_relationship.is_some() {
        match root.get(b"AF").cloned() {
            Ok(Object::Reference(r)) => {
                let mut a = match w.resolve(&Object::Reference(r))? {
                    Object::Array(a) => a,
                    _ => Vec::new(),
                };
                a.push(Object::Reference(spec_ref));
                w.update_object(r, Object::Array(a));
            }
            Ok(Object::Array(mut a)) => {
                a.push(Object::Reference(spec_ref));
                root.set("AF", Object::Array(a));
            }
            _ => {
                let id = w.add_object(Object::Array(vec![Object::Reference(spec_ref)]))?;
                root.set("AF", Object::Reference(id));
            }
        }
        w.set_root(root);
        w.ensure_output_version((2, 0))?;
    } else {
        if root != orig_root {
            w.set_root(root);
        }
        w.ensure_output_version((1, 7))?;
    }
    Ok(())
}

/// The embedded file stream of a file specification, if any.
pub fn embedded_file_stream(h: &dyn PdfHandler, spec: &Dictionary) -> PdfResult<Option<Object>> {
    let Some(Object::Dictionary(ef)) = h.get(spec, b"EF")? else {
        return Ok(None);
    };
    h.get(&ef, b"F")
}

/// How to encrypt the attachment of [`wrap_encrypted_payload`].
#[derive(Clone, Debug)]
pub enum WrapEncryption {
    /// A password (standard handler, AES-256).
    Password(String),
    /// Public-key encryption for the given DER certificates.
    Certs(Vec<Vec<u8>>),
    /// An explicit security handler.
    Handler(crate::crypt::SecurityHandler),
}

/// Wrap a PDF as an encrypted attachment of an unencrypted wrapper document
/// (`wrap_encrypted_payload`). Only the embedded file is encrypted.
///
/// pyHanko's `ValueError` for passing both or neither of `password` and
/// `certs` cannot occur: [`WrapEncryption`] holds exactly one.
#[allow(clippy::too_many_arguments)]
pub fn wrap_encrypted_payload(
    plaintext_payload: &[u8],
    encryption: WrapEncryption,
    file_spec_string: &str,
    params: Option<EmbeddedFileParams>,
    file_name: Option<&str>,
    description: &str,
    include_explanation_page: bool,
) -> PdfResult<crate::writer::PdfFileWriter> {
    use crate::crypt::{
        CryptFilter, CryptFilterConfiguration, PubKeyAdbeSubFilter, PubKeyCfData,
        PubKeyPermissions, RecipientEncryptionPolicy, SecurityHandler, SecurityHandlerVersion,
        StandardEncryptOptions, DEF_EMBEDDED_FILE, STD_CF,
    };
    let mut w = crate::writer::PdfFileWriter::new(true, true)?;
    let sh = match encryption {
        WrapEncryption::Handler(sh) => sh,
        WrapEncryption::Certs(certs) => {
            let mut cf = CryptFilter::pubkey_aes(32, PubKeyCfData::new(None, false, false))?;
            cf.set_embedded_only();
            let cfc = CryptFilterConfiguration::new(
                vec![(DEF_EMBEDDED_FILE, cf)],
                "Identity",
                "Identity",
                Some(DEF_EMBEDDED_FILE),
            )?;
            let sh = SecurityHandler::new_pubkey(
                SecurityHandlerVersion::Aes256,
                PubKeyAdbeSubFilter::S5,
                32,
                false,
                Some(cfc),
                None,
                true,
                None,
            )?;
            sh.add_recipients(
                &certs,
                PubKeyPermissions::allow_everything(),
                RecipientEncryptionPolicy::default(),
            )?;
            sh
        }
        WrapEncryption::Password(pw) => {
            let mut cf = CryptFilter::standard_aes(32)?;
            cf.set_embedded_only();
            let cfc = CryptFilterConfiguration::new(
                vec![(STD_CF, cf)],
                "Identity",
                "Identity",
                Some(STD_CF),
            )?;
            SecurityHandler::build_from_pw(
                pw.as_str(),
                None,
                StandardEncryptOptions {
                    encrypt_metadata: false,
                    crypt_filter_config: Some(cfc),
                    ..StandardEncryptOptions::default()
                },
            )?
        }
    };
    w.assign_security_handler(&sh)?;
    let mut root = w.root()?;
    let mut collection = Dictionary::new();
    collection.set("Type", Object::Name(b"Collection".to_vec()));
    collection.set("D", text_string(file_spec_string));
    collection.set("View", Object::Name(b"H".to_vec()));
    root.set("Collection", Object::Dictionary(collection));
    w.set_root(root);
    let ef = embedded_file_object(
        &mut w,
        plaintext_payload,
        true,
        Some(&params.unwrap_or_default()),
        Some("application/pdf"),
    )?;
    let spec = FileSpec {
        file_spec_string: file_spec_string.to_owned(),
        file_name: file_name.map(str::to_owned),
        embedded_data: Some(ef),
        description: Some(description.to_owned()),
        ..FileSpec::default()
    };
    embed_file(&mut w, &spec)?;
    if include_explanation_page {
        let mut font = Dictionary::new();
        font.set("Type", Object::Name(b"Font".to_vec()));
        font.set("BaseFont", Object::Name(b"Courier".to_vec()));
        font.set("Subtype", Object::Name(b"Type1".to_vec()));
        font.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
        let mut fonts = Dictionary::new();
        fonts.set("F1", Object::Dictionary(font));
        let mut resources = Dictionary::new();
        resources.set("Font", Object::Dictionary(fonts));
        let content = "
        BT
            /F1 10 Tf 10 830 Td 12 TL
            (This document is a wrapper for an encrypted attachment.) '
            (Your viewer should prompt for a password and ) '
            (open the attached file automatically.) Tj
            (If not, navigate to the attached document manually.) ' T*
            (In addition, your viewer must support encryption ) '
            (scoped to embedded files.) Tj
        ET
        ";
        let stream =
            DecodedStream::new(Dictionary::new(), content.as_bytes().to_vec()).to_stream()?;
        let contents = w.add_object(Object::Stream(stream))?;
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set(
            "MediaBox",
            Object::Array(vec![
                0.into(),
                0.into(),
                Object::Real(595.28),
                Object::Real(841.89),
            ]),
        );
        page.set("Resources", Object::Dictionary(resources));
        page.set("Contents", Object::Reference(contents));
        w.insert_page(page, None)?;
    }
    Ok(w)
}
