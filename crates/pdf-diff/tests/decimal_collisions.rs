//! Production-path regressions for source decimals that collapse to one f32.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pdf::{PdfFile, PdfHandler, ReaderOptions};
use sigis_pdf_diff::{DiffOutcome, DiffPolicy, StandardDiffPolicy};

fn pdf(base: &str, updated: &str) -> Vec<u8> {
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] >> /Probe 4 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>".to_owned(),
        format!("<< /N {base} >>"),
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    let update = out.len();
    out.extend_from_slice(format!("4 0 obj\n<< /N {updated} >>\nendobj\n").as_bytes());
    let new_xref = out.len();
    out.extend_from_slice(format!("xref\n4 1\n{update:010} 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R /Prev {xref} >>\nstartxref\n{new_xref}\n%%EOF\n").as_bytes());
    out
}

#[test]
fn rounded_cache_does_not_hide_decimal_changes() {
    let dir = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for (original, changed) in [
        ("1.0", "1.00000001"),
        ("0.1", ".1000000001"),
        ("595.28", "595.28000001"),
    ] {
        for strict in [true, false] {
            let bytes = pdf(original, changed);
            let file = PdfFile::parse_with(
                &bytes,
                ReaderOptions {
                    strict,
                    ..Default::default()
                },
            )
            .unwrap();
            // Populate the permissive reader's caches before the review.
            assert_eq!(
                file.object_in_revision((4, 0), 0).unwrap(),
                file.object_in_revision((4, 0), 1).unwrap()
            );
            assert!(file.get_object((4, 0)).is_ok());
            let result = StandardDiffPolicy.review_file(&file, 0, None, None);
            assert!(
                !matches!(result, Ok(DiffOutcome::Reviewed(_))),
                "accepted decimal collision {original} -> {changed}: {result:?}"
            );
        }
        let path = dir.path().join(format!("{}.pdf", paths.len()));
        std::fs::write(&path, pdf(original, changed)).unwrap();
        paths.push(path);
    }
    let script = sigis_testdata::manifest_dir().join("oracle/decimal_verdicts.py");
    let args: Vec<_> = paths.iter().map(|path| path.to_str().unwrap()).collect();
    if let Some(verdicts) = sigis_testdata::oracle::run_json(&script, &args) {
        for verdict in verdicts.as_array().unwrap() {
            assert_eq!(verdict["accepted"], false, "{verdict}");
        }
    }
}

#[test]
fn equal_decimal_spellings_still_review_as_identical() {
    let bytes = pdf("0.1", "+.1000");
    let file = PdfFile::parse(&bytes).unwrap();
    assert!(matches!(
        StandardDiffPolicy
            .review_file(&file, 0, None, None)
            .unwrap(),
        DiffOutcome::Reviewed(_)
    ));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("equal.pdf");
    std::fs::write(&path, bytes).unwrap();
    let script = sigis_testdata::manifest_dir().join("oracle/decimal_verdicts.py");
    if let Some(verdicts) = sigis_testdata::oracle::run_json(&script, &[path.to_str().unwrap()]) {
        assert_eq!(verdicts[0]["accepted"], true, "{verdicts}");
    }
}
