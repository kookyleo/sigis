// Derived from pyHanko `sign/validation/pdf_embedded.py`
// (`EmbeddedPdfSignature.evaluate_signature_coverage`) and
// `pdf_utils/reader.py` (`read_next_end_line`, `process_data_at_eof`)
// (MIT, see LICENSE-pyHanko).

//! Signature coverage evaluation.

use crate::SignatureCoverageLevel;

/// Cross-reference data of one revision needed for the coverage check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XrefMeta {
    /// The `startxref` value of the revision.
    pub startxref: u64,
    /// Offset just past the revision's xref table or stream.
    pub xref_end: u64,
}

/// Error reading the end of a revision (`PdfReadError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EofError(pub &'static str);

/// Read one line backwards from the cursor `pos` (`read_next_end_line`).
/// Returns the line and the new cursor. `pos` behaves like the position of
/// a Python stream: reads consume the byte at `pos`.
fn read_next_end_line(data: &[u8], pos: usize) -> Result<(Vec<u8>, usize), EofError> {
    fn read1(data: &[u8], pos: &mut usize) -> Option<u8> {
        let b = *data.get(*pos)?;
        *pos += 1;
        Some(b)
    }
    fn back(pos: &mut usize, n: usize) -> Result<(), EofError> {
        *pos = pos.checked_sub(n).ok_or(EofError("negative seek"))?;
        Ok(())
    }
    let mut pos = pos;
    let mut rev: Vec<u8> = Vec::new();
    let mut x;
    loop {
        if pos == 0 {
            return Err(EofError("Could not read malformed PDF file"));
        }
        x = read1(data, &mut pos);
        let Some(b) = x.filter(|_| pos >= 2) else {
            return Err(EofError("EOL marker not found"));
        };
        back(&mut pos, 2)?;
        if b == b'\n' || b == b'\r' {
            break;
        }
        rev.push(b);
    }
    let mut crlf = false;
    while matches!(x, Some(b'\n' | b'\r')) {
        x = read1(data, &mut pos);
        if matches!(x, Some(b'\n' | b'\r')) {
            back(&mut pos, 1)?;
            crlf = true;
        }
        back(&mut pos, 2)?;
    }
    pos += if crlf { 2 } else { 1 };
    rev.reverse();
    Ok((rev, pos))
}

/// Find `%%EOF` and the `startxref` value reading backwards from `pos`
/// (`process_data_at_eof`).
pub fn process_data_at_eof(data: &[u8], pos: usize) -> Result<u64, EofError> {
    let last_1k = (pos + 1).saturating_sub(1024);
    let mut pos = pos;
    let mut line: Vec<u8> = Vec::new();
    while !line.starts_with(b"%%EOF") {
        if pos < last_1k {
            return Err(EofError("EOF marker not found"));
        }
        let (l, p) = read_next_end_line(data, pos)?;
        line = l;
        pos = p;
    }
    let (line, pos) = read_next_end_line(data, pos)?;
    let text = String::from_utf8_lossy(&line);
    match text.trim().parse::<u64>() {
        Ok(v) => {
            let (line, _) = read_next_end_line(data, pos)?;
            if !line.starts_with(b"startxref") {
                return Err(EofError("startxref not found"));
            }
            Ok(v)
        }
        Err(_) => {
            if !line.starts_with(b"startxref") {
                return Err(EofError("startxref not found"));
            }
            String::from_utf8_lossy(&line[9..])
                .trim()
                .parse::<u64>()
                .map_err(|_| EofError("startxref not found"))
        }
    }
}

/// Evaluate how much of the file a signature covers
/// (`evaluate_signature_coverage`).
///
/// `contents_len` is the length of the decoded `/Contents` string (with its
/// padding); `xrefs[i]` describes revision `i`.
pub fn evaluate_signature_coverage(
    file: &[u8],
    byte_range: &[u64],
    contents_len: usize,
    signed_revision: usize,
    xrefs: &[XrefMeta],
) -> SignatureCoverageLevel {
    if byte_range.len() != 4 || byte_range[0] != 0 {
        return SignatureCoverageLevel::Unclear;
    }
    let (len1, start2, len2) = (byte_range[1], byte_range[2], byte_range[3]);
    let embedded = (contents_len as u64) * 2 + 2;
    let Some(signed_zone_len) = len1.checked_add(len2).and_then(|v| v.checked_add(embedded)) else {
        return SignatureCoverageLevel::Unclear;
    };
    if file.len() as u64 == signed_zone_len {
        return SignatureCoverageLevel::EntireFile;
    }
    if start2 != len1 + embedded {
        return SignatureCoverageLevel::Unclear;
    }
    let Ok(zone) = usize::try_from(signed_zone_len) else {
        return SignatureCoverageLevel::Unclear;
    };
    let Some(expected) = xrefs.get(signed_revision) else {
        return SignatureCoverageLevel::ContiguousBlockFromStart;
    };
    match process_data_at_eof(file, zone) {
        Ok(startxref) if startxref == expected.startxref => {}
        _ => return SignatureCoverageLevel::ContiguousBlockFromStart,
    }
    if xrefs[..=signed_revision]
        .iter()
        .any(|x| x.xref_end > signed_zone_len)
    {
        return SignatureCoverageLevel::ContiguousBlockFromStart;
    }
    SignatureCoverageLevel::EntireRevision
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eof_scan() {
        let data = b"%PDF-1.7\nxref\ntrailer<<>>\nstartxref\n1234\n%%EOF\n";
        assert_eq!(process_data_at_eof(data, data.len() - 1), Ok(1234));
        let crlf = b"%PDF-1.7\r\nstartxref\r\n99\r\n%%EOF\r\n";
        assert_eq!(process_data_at_eof(crlf, crlf.len() - 1), Ok(99));
        let same_line = b"%PDF\nstartxref 77\n%%EOF\n";
        assert_eq!(process_data_at_eof(same_line, same_line.len() - 1), Ok(77));
        assert!(process_data_at_eof(b"%PDF\nnothing\n", 12).is_err());
    }

    #[test]
    fn nonstandard_cardinality_cannot_gain_coverage() {
        for range in [
            vec![],
            vec![0],
            vec![0, 690],
            vec![0, 0, 0],
            vec![0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(
                evaluate_signature_coverage(&[], &range, 0, 0, &[]),
                SignatureCoverageLevel::Unclear,
                "{range:?}"
            );
        }
    }

    #[test]
    fn oversized_contents_length_cannot_panic_or_gain_coverage() {
        // Numeric-domain calls to the public helper, without allocating a
        // giant PDF or claiming any corresponding CMS/trust validation.
        for length in [usize::MAX / 2, usize::MAX / 2 + 1, usize::MAX] {
            assert_eq!(
                evaluate_signature_coverage(&[], &[0, 0, 0, 0], length, 0, &[]),
                SignatureCoverageLevel::Unclear,
                "{length}"
            );
        }
    }

    #[test]
    fn coverage_levels() {
        // file: [0..10) + <hex of 3 bytes = 8 chars> + [18..28)
        let mut file = vec![b'a'; 10];
        file.extend_from_slice(b"<000000>");
        file.extend_from_slice(b"startxref\n");
        assert_eq!(file.len(), 28);
        let br = [0, 10, 18, 10];
        assert_eq!(
            evaluate_signature_coverage(&file, &br, 3, 0, &[]),
            SignatureCoverageLevel::EntireFile
        );
        assert_eq!(
            evaluate_signature_coverage(&file, &[1, 10, 18, 10], 3, 0, &[]),
            SignatureCoverageLevel::Unclear
        );
        let mut longer = file.clone();
        longer.extend_from_slice(b"more");
        assert_eq!(
            evaluate_signature_coverage(&longer, &[0, 10, 19, 10], 3, 0, &[]),
            SignatureCoverageLevel::Unclear
        );
        assert_eq!(
            evaluate_signature_coverage(
                &longer,
                &br,
                3,
                0,
                &[XrefMeta {
                    startxref: 5,
                    xref_end: 9
                }]
            ),
            SignatureCoverageLevel::ContiguousBlockFromStart
        );
    }

    #[test]
    fn entire_revision() {
        let rev1 = b"%PDF-1.7\nxref\n0 1\ntrailer<<>>\nstartxref\n9\n%%EOF\n";
        // Signed region = everything of revision 1 except the contents hole.
        let mut file = Vec::new();
        file.extend_from_slice(b"<0000>");
        file.extend_from_slice(rev1);
        let br = [0u64, 0, 6, rev1.len() as u64];
        let zone = file.len() as u64;
        file.extend_from_slice(b"appended update\n%%EOF\n");
        let xrefs = [XrefMeta {
            startxref: 9,
            xref_end: zone - 10,
        }];
        assert_eq!(
            evaluate_signature_coverage(&file, &br, 2, 0, &xrefs),
            SignatureCoverageLevel::EntireRevision
        );
        let bad = [XrefMeta {
            startxref: 9,
            xref_end: zone + 1,
        }];
        assert_eq!(
            evaluate_signature_coverage(&file, &br, 2, 0, &bad),
            SignatureCoverageLevel::ContiguousBlockFromStart
        );
    }
}
