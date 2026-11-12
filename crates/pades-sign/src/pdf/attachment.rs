// Derived from pyHanko `sign/signers/functions.py`
// (`embed_payload_with_cms`) (MIT, see LICENSE-pyHanko).

//! Bundle a payload attachment with its CMS signature as related files.

use lopdf::ObjectId;
use sigis_pdf::embed::{
    embed_file, embedded_file_object, EmbeddedFileParams, FileSpec, RelatedFileSpec,
};
use sigis_pdf::generic::PdfDate;
use sigis_pdf::{PdfError, PdfResult, PdfWriter};
use sigis_pki_core::time::Moment;

/// File names and metadata for [`embed_payload_with_cms`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAttachmentOptions {
    /// Extension replacing the payload file's final extension; defaults to `.sig`.
    pub extension: String,
    /// Unicode payload file name (`/UF`), if any.
    pub file_name: Option<String>,
    /// Description of the payload file specification (`/Desc`).
    pub description: Option<String>,
    /// Description of the CMS file specification (`/Desc`).
    pub cms_description: Option<String>,
    /// Payload associated-file relationship (PDF name without a slash).
    pub af_relationship: Option<String>,
    /// CMS associated-file relationship (PDF name without a slash).
    pub cms_af_relationship: Option<String>,
}

impl Default for SignedAttachmentOptions {
    fn default() -> Self {
        Self {
            extension: ".sig".into(),
            file_name: None,
            description: None,
            cms_description: None,
            af_relationship: None,
            cms_af_relationship: None,
        }
    }
}

fn replace_extension(file_name: &str, extension: &str) -> String {
    let stem = file_name
        .rsplit_once('.')
        .map_or(file_name, |(stem, _)| stem);
    format!("{stem}{extension}")
}

/// Embed `payload` and its DER-encoded CMS object as two attachments.
///
/// The payload must already be an embedded file stream in `pdf_writer`,
/// for example one returned by [`embedded_file_object`]. Its file
/// specification is inserted first, followed by the CMS specification.
/// The payload's `/RF/F` and optional `/RF/UF` point to the same CMS stream
/// as the standalone CMS attachment's `/EF` entries.
///
/// The CMS stream is uncompressed, has MIME type `application/pkcs7-mime`,
/// and records its size, checksum and current creation/modification time,
/// matching pyHanko's `embed_payload_with_cms`. Payload stream metadata is
/// supplied when the caller creates `payload`.
pub fn embed_payload_with_cms(
    pdf_writer: &mut PdfWriter,
    file_spec_string: &str,
    payload: ObjectId,
    cms_der: &[u8],
    options: &SignedAttachmentOptions,
) -> PdfResult<()> {
    let now = Moment::now().to_der_datetime().ok_or_else(|| {
        PdfError::Value("Current time cannot be represented as a PDF date".into())
    })?;
    let now = PdfDate {
        year: i32::from(now.year()),
        month: now.month(),
        day: now.day(),
        hour: now.hour(),
        minute: now.minutes(),
        second: now.seconds(),
        utc_offset_minutes: Some(0),
    };
    let cms_stream = embedded_file_object(
        pdf_writer,
        cms_der,
        false,
        Some(&EmbeddedFileParams {
            creation_date: Some(now),
            modification_date: Some(now),
            ..Default::default()
        }),
        Some("application/pkcs7-mime"),
    )?;
    let cms_file_name = replace_extension(file_spec_string, &options.extension);
    let cms_unicode_name = options
        .file_name
        .as_deref()
        .map(|name| replace_extension(name, &options.extension));
    let related = |name| RelatedFileSpec {
        name,
        embedded_data: cms_stream,
    };
    let payload_spec = FileSpec {
        file_spec_string: file_spec_string.into(),
        file_name: options.file_name.clone(),
        embedded_data: Some(payload),
        description: options.description.clone(),
        af_relationship: options.af_relationship.clone(),
        f_related_files: vec![related(cms_file_name.clone())],
        uf_related_files: cms_unicode_name.iter().cloned().map(related).collect(),
    };
    embed_file(pdf_writer, &payload_spec)?;
    let cms_spec = FileSpec {
        file_spec_string: cms_file_name,
        file_name: cms_unicode_name,
        embedded_data: Some(cms_stream),
        description: options.cms_description.clone(),
        af_relationship: options.cms_af_relationship.clone(),
        ..Default::default()
    };
    embed_file(pdf_writer, &cms_spec)
}
