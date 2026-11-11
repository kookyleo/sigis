// Partly derived from asn1crypto `x509.py` (`Name.human_friendly`,
// `NameTypeAndValue._ldap_string_prep`; MIT) as used by pyhanko-certvalidator.

//! Distinguished names: display as pyHanko shows them, and the string
//! preparation checks that make asn1crypto reject a name.

use der::asn1::{BmpString, Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
use der::{Decode, Tag, Tagged};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::Name;

/// The asn1crypto `NameType.human_friendly` label of an attribute type.
pub fn attribute_label(oid: &const_oid::ObjectIdentifier) -> String {
    let label = match oid.to_string().as_str() {
        "2.5.4.3" => "Common Name",
        "2.5.4.4" => "Surname",
        "2.5.4.5" => "Serial Number",
        "2.5.4.6" => "Country",
        "2.5.4.7" => "Locality",
        "2.5.4.8" => "State/Province",
        "2.5.4.9" => "Street Address",
        "2.5.4.10" => "Organization",
        "2.5.4.11" => "Organizational Unit",
        "2.5.4.12" => "Title",
        "2.5.4.15" => "Business Category",
        "2.5.4.17" => "Postal Code",
        "2.5.4.20" => "Telephone Number",
        "2.5.4.41" => "Name",
        "2.5.4.42" => "Given Name",
        "2.5.4.43" => "Initials",
        "2.5.4.44" => "Generation Qualifier",
        "2.5.4.45" => "Unique Identifier",
        "2.5.4.46" => "DN Qualifier",
        "2.5.4.65" => "Pseudonym",
        "2.5.4.97" => "Organization Identifier",
        "2.23.133.2.1" => "TPM Manufacturer",
        "2.23.133.2.2" => "TPM Model",
        "2.23.133.2.3" => "TPM Version",
        "2.23.133.2.4" => "Platform Manufacturer",
        "2.23.133.2.5" => "Platform Model",
        "2.23.133.2.6" => "Platform Version",
        "1.2.840.113549.1.9.1" => "Email Address",
        "1.3.6.1.4.1.311.60.2.1.1" => "Incorporation Locality",
        "1.3.6.1.4.1.311.60.2.1.2" => "Incorporation State/Province",
        "1.3.6.1.4.1.311.60.2.1.3" => "Incorporation Country",
        "0.9.2342.19200300.100.1.1" => "User ID",
        "0.9.2342.19200300.100.1.25" => "Domain Component",
        "0.2.262.1.10.7.20" => "Name Distinguisher",
        other => return other.to_owned(),
    };
    label.to_owned()
}

/// The string value of an attribute, decoding the common string types.
/// Returns `None` for values that are not character strings.
pub fn attribute_string(atv: &AttributeTypeAndValue) -> Option<String> {
    let v = &atv.value;
    let bytes = v.value();
    Some(match v.tag() {
        Tag::Utf8String => Utf8StringRef::new(bytes).ok()?.as_str().to_owned(),
        Tag::PrintableString => PrintableStringRef::new(bytes).ok()?.as_str().to_owned(),
        Tag::Ia5String => Ia5StringRef::new(bytes).ok()?.as_str().to_owned(),
        Tag::TeletexString => TeletexStringRef::new(bytes).ok()?.as_str().to_owned(),
        Tag::VisibleString => core::str::from_utf8(bytes).ok()?.to_owned(),
        Tag::NumericString => core::str::from_utf8(bytes).ok()?.to_owned(),
        Tag::BmpString => BmpString::from_ucs2(bytes).ok()?.to_string(),
        t if t.number().value() == 28 && t.class() == der::Class::Universal => {
            if !bytes.len().is_multiple_of(4) {
                return None;
            }
            bytes
                .chunks(4)
                .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
                .collect::<Option<String>>()?
        }
        _ => return None,
    })
}

fn display_value(atv: &AttributeTypeAndValue) -> String {
    attribute_string(atv).unwrap_or_else(|| {
        atv.value
            .value()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    })
}

enum Humanized {
    One(String),
    Many(Vec<Humanized>),
}

impl Humanized {
    fn render(&self) -> String {
        match self {
            Self::One(s) => s.clone(),
            Self::Many(v) => v
                .iter()
                .rev()
                .map(Humanized::render)
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}

/// `Name.human_friendly` of asn1crypto, e.g. `Common Name: Alice,
/// Organization: Example Inc, Country: BE`.
pub fn human_friendly(name: &Name) -> String {
    let mut data: Vec<(String, Humanized)> = Vec::new();
    let mut last_field = None;
    for rdn in name.as_ref().iter() {
        for atv in rdn.as_ref().iter() {
            let field = attribute_label(&atv.oid);
            let value = display_value(atv);
            last_field = Some(field.clone());
            match data.iter_mut().find(|(k, _)| *k == field) {
                Some((_, existing)) => {
                    let prev = core::mem::replace(existing, Humanized::One(String::new()));
                    *existing = match prev {
                        Humanized::Many(mut v) if v.len() > 1 => {
                            // asn1crypto wraps the existing list again:
                            // `data[f] = [data[f]]` then appends.
                            let inner = Humanized::Many(core::mem::take(&mut v));
                            Humanized::Many(vec![inner, Humanized::One(value)])
                        }
                        other => Humanized::Many(vec![other, Humanized::One(value)]),
                    };
                }
                None => data.push((field, Humanized::One(value))),
            }
        }
    }
    if last_field.as_deref() == Some("Country") {
        data.reverse();
    }
    let parts: Vec<String> = data
        .iter()
        .map(|(k, v)| format!("{k}: {}", v.render()))
        .collect();
    let separator = if parts.iter().any(|p| p.contains(',')) {
        "; "
    } else {
        ", "
    };
    parts.into_iter().rev().collect::<Vec<_>>().join(separator)
}

/// Decode a DER `Name` and render it with [`human_friendly`].
pub fn human_friendly_der(der: &[u8]) -> Option<String> {
    Name::from_der(der).ok().map(|n| human_friendly(&n))
}

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    let cp = u32::from(c);
    table
        .binary_search_by(|(lo, hi)| {
            if cp < *lo {
                core::cmp::Ordering::Greater
            } else if cp > *hi {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn in_ranges(c: char, ranges: &[(u32, u32)]) -> bool {
    let cp = u32::from(c);
    ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&cp))
}

/// RFC 4518 string preparation as asn1crypto implements it
/// (`NameTypeAndValue._ldap_string_prep`), up to the point where it may
/// fail. Returns asn1crypto's error message for values it rejects.
///
/// Known simplification: the case-folding map (RFC 3454 table B.2) is not
/// applied before the prohibition checks, and normalization uses the
/// current Unicode version; neither changes which values are rejected for
/// practical inputs.
pub fn ldap_string_prep_check(value: &str) -> Result<(), &'static str> {
    use crate::stringprep_tables as t;
    use unicode_normalization::UnicodeNormalization;
    const REMOVE_1: &[(u32, u32)] = &[
        (0x00AD, 0x00AD),
        (0x1806, 0x1806),
        (0x034F, 0x034F),
        (0x180B, 0x180D),
        (0xFE0F, 0xFF00),
        (0xFFFC, 0xFFFC),
    ];
    const REMOVE_2: &[(u32, u32)] = &[(0x1D173, 0x1D17A), (0xE0020, 0xE007F), (0xE0001, 0xE0001)];
    const REMOVE_3: &[(u32, u32)] = &[
        (0x0000, 0x0008),
        (0x000E, 0x001F),
        (0x007F, 0x0084),
        (0x0086, 0x009F),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x180E, 0x180E),
        (0x200C, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2063),
        (0x206A, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x200B, 0x200B),
    ];
    let mapped: String = value
        .chars()
        .filter(|c| !in_ranges(*c, REMOVE_1))
        .map(|c| if "\t\n\u{b}\u{c}\r\u{85}".contains(c) { ' ' } else { c })
        .filter(|c| !in_ranges(*c, REMOVE_2) && !in_ranges(*c, REMOVE_3))
        .collect();
    let normalized: String = mapped.nfkc().collect();
    for c in normalized.chars() {
        if in_table(t::A1, c) {
            return Err("X.509 Name objects may not contain unassigned code points");
        }
        if in_table(t::C8, c) {
            return Err("X.509 Name objects may not contain change display or zzzzdeprecated characters");
        }
        if in_table(t::C3, c) {
            return Err("X.509 Name objects may not contain private use characters");
        }
        if in_table(t::C4, c) {
            return Err("X.509 Name objects may not contain non-character code points");
        }
        if in_table(t::C5, c) {
            return Err("X.509 Name objects may not contain surrogate code points");
        }
        if c == '\u{fffd}' {
            return Err("X.509 Name objects may not contain the replacement character");
        }
    }
    let has_r_al = normalized.chars().any(|c| in_table(t::D1, c));
    let has_l = normalized
        .chars()
        .any(|c| !in_table(t::D1, c) && in_table(t::D2, c));
    if has_r_al {
        let first = normalized.chars().next().is_some_and(|c| in_table(t::D1, c));
        let last = normalized.chars().last().is_some_and(|c| in_table(t::D1, c));
        if has_l || !first || !last {
            return Err("X.509 Name object contains a malformed bidirectional sequence");
        }
    }
    Ok(())
}

/// Check every string value of `name` with [`ldap_string_prep_check`]:
/// asn1crypto cannot compare or hash a name that fails, so
/// pyhanko-certvalidator cannot use certificates carrying one.
pub fn check_name(name: &Name) -> Result<(), String> {
    for rdn in name.as_ref().iter() {
        for atv in rdn.as_ref().iter() {
            if let Some(s) = attribute_string(atv) {
                ldap_string_prep_check(&s).map_err(str::to_owned)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mixed_bidi() {
        assert!(ldap_string_prep_check("Alice").is_ok());
        assert!(ldap_string_prep_check("\u{5d0}\u{5d1}").is_ok());
        assert_eq!(
            ldap_string_prep_check("Invalid\u{5d0}"),
            Err("X.509 Name object contains a malformed bidirectional sequence")
        );
        assert!(ldap_string_prep_check("a\u{e000}").is_err());
        assert!(ldap_string_prep_check("\u{fffd}").is_err());
    }
}
