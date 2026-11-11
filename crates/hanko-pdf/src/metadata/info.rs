// Derived from pyHanko `pdf_utils/metadata/info.py` (MIT, see LICENSE-pyHanko).

//! Info dictionary mapping (`pyhanko.pdf_utils.metadata.info`).

use lopdf::{Dictionary, Object};

use super::model::{DocumentMetadata, MetaDate, MetaString, VENDOR};
use crate::error::PdfResult;
use crate::generic::{self, parse_pdf_date, pdf_date, text_string, PdfDate, PdfString};
use crate::rw_common::{PdfHandler, PdfHandlerExt};

/// The current time as a UTC PDF date.
pub fn now_utc() -> PdfDate {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    date_from_unix(secs)
}

/// A UTC PDF date from a Unix timestamp.
pub fn date_from_unix(secs: i64) -> PdfDate {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil_from_days
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    PdfDate {
        year: y as i32,
        month: m as u8,
        day: d as u8,
        hour: (rem / 3600) as u8,
        minute: (rem % 3600 / 60) as u8,
        second: (rem % 60) as u8,
        utc_offset_minutes: Some(0),
    }
}

fn text_of(o: &Object) -> Option<String> {
    match o {
        Object::String(s, _) => match generic::pdf_string(s) {
            PdfString::Text(t, _) => Some(t),
            PdfString::Bytes(_) => None,
        },
        _ => None,
    }
}

fn write_meta_string(
    handler: &dyn PdfHandler,
    d: &mut Dictionary,
    key: &[u8],
    s: Option<&MetaString>,
    existing_only: bool,
) -> PdfResult<bool> {
    let Some(s) = s else { return Ok(false) };
    let new = text_string(&s.value);
    let modified = match handler.get(d, key)? {
        Some(old) => text_of(&old).as_deref() != Some(s.value.as_str()),
        None => !existing_only,
    };
    if modified {
        d.set(key.to_vec(), new);
    }
    Ok(modified)
}

fn write_meta_date(
    d: &mut Dictionary,
    key: &[u8],
    date: Option<MetaDate>,
    existing_only: bool,
    now: PdfDate,
) -> bool {
    let value = match date {
        Some(MetaDate::At(v)) => v,
        Some(MetaDate::Now) => now,
        None => return false,
    };
    if !existing_only || d.has(key) {
        d.set(key.to_vec(), text_string(&pdf_date(&value)));
        true
    } else {
        false
    }
}

/// Update an Info dictionary (`update_info_dict`); returns `true` if it
/// was modified.
pub fn update_info_dict(
    handler: &dyn PdfHandler,
    meta: &DocumentMetadata,
    info: &mut Dictionary,
    only_update_existing: bool,
    now: PdfDate,
) -> PdfResult<bool> {
    let mut modified = write_meta_date(info, b"ModDate", meta.last_modified, only_update_existing, now);
    let producer_string = match handler.get(info, b"Producer")? {
        Some(p) => match &p {
            Object::String(s, _) => match generic::pdf_string(s) {
                PdfString::Text(t, _) => {
                    if t.contains(VENDOR) {
                        p.clone()
                    } else {
                        modified = true;
                        text_string(&format!("{t}; {VENDOR}"))
                    }
                }
                PdfString::Bytes(_) => {
                    modified = true;
                    text_string(VENDOR)
                }
            },
            Object::Name(n) => {
                let t = generic::name_str(n);
                if t.contains(VENDOR) {
                    p.clone()
                } else {
                    modified = true;
                    text_string(&format!("{t}; {VENDOR}"))
                }
            }
            _ => {
                modified = true;
                text_string(VENDOR)
            }
        },
        None => {
            modified = true;
            text_string(VENDOR)
        }
    };
    info.set("Producer", producer_string);
    if meta.xmp_unmanaged {
        return Ok(modified);
    }
    modified |= write_meta_string(handler, info, b"Title", meta.title.as_ref(), only_update_existing)?;
    modified |= write_meta_string(handler, info, b"Author", meta.author.as_ref(), only_update_existing)?;
    modified |= write_meta_string(handler, info, b"Subject", meta.subject.as_ref(), only_update_existing)?;
    modified |= write_meta_string(handler, info, b"Creator", meta.creator.as_ref(), only_update_existing)?;
    modified |= write_meta_date(info, b"CreationDate", meta.created, only_update_existing, now);
    if !meta.keywords.is_empty() {
        info.set("Keywords", text_string(&meta.keywords.join(",")));
        modified = true;
    }
    Ok(modified)
}

fn read_date(handler: &dyn PdfHandler, info: &Dictionary, key: &[u8], strict: bool) -> Option<PdfDate> {
    let v = handler.get(info, key).ok()??;
    if let Some(t) = text_of(&v) {
        if let Ok(d) = parse_pdf_date(&t, strict) {
            return Some(d);
        }
    }
    log::warn!(
        "Key /{} in info dict has a value that is not a valid date string",
        String::from_utf8_lossy(key)
    );
    None
}

/// Read metadata from an Info dictionary (`view_from_info_dict`).
pub fn view_from_info_dict(handler: &dyn PdfHandler, info: &Dictionary, strict: bool) -> DocumentMetadata {
    let s = |k: &[u8]| {
        handler
            .get(info, k)
            .ok()
            .flatten()
            .map(|v| MetaString::plain(py_str(&v)))
    };
    let mut meta = DocumentMetadata {
        title: s(b"Title"),
        author: s(b"Author"),
        subject: s(b"Subject"),
        creator: s(b"Creator"),
        last_modified: None,
        ..DocumentMetadata::default()
    };
    if let Some(d) = read_date(handler, info, b"CreationDate", strict) {
        meta.created = Some(MetaDate::At(d));
    }
    meta.last_modified = Some(match read_date(handler, info, b"ModDate", strict) {
        Some(d) => MetaDate::At(d),
        None => MetaDate::Now,
    });
    if let Ok(Some(k)) = handler.get(info, b"Keywords") {
        meta.keywords = py_str(&k).split(',').map(str::to_owned).collect();
    }
    meta
}

/// Python `str()` of a PDF value (text strings decode, names keep the slash).
pub fn py_str(o: &Object) -> String {
    match o {
        Object::String(s, _) => match generic::pdf_string(s) {
            PdfString::Text(t, _) => t,
            PdfString::Bytes(b) => generic::py_bytes_repr(&b),
        },
        Object::Name(n) => generic::name_str(n),
        Object::Integer(i) => i.to_string(),
        Object::Real(r) => generic::format_real(*r),
        Object::Boolean(b) => if *b { "True".into() } else { "False".into() },
        other => format!("{other:?}"),
    }
}
