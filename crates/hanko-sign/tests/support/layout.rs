//! Port of `pyhanko_testing_commons/test_utils/layout_test_utils.py`:
//! render the first page of the output and of the expected file with
//! `pdftoppm` and compare them with ImageMagick's `compare -metric ae`.

use std::path::{Path, PathBuf};
use std::process::Command;

use sigis_pades_sign::content::ContentWriter;
use sigis_pades_sign::pdf::writer::PdfUpdate;
use lopdf::{dictionary, Document, Object, Stream};

fn tool(env: &str, default: &str) -> Option<PathBuf> {
    let p = std::env::var_os(env).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(default));
    p.exists().then_some(p)
}

/// The tools, or `None` (after a note) if one is missing
/// (`with_layout_comparison`).
pub fn layout_tools() -> Option<(PathBuf, PathBuf)> {
    match (tool("PDFTOPPM_PATH", "/usr/bin/pdftoppm"), tool("IM_COMPARE_PATH", "/usr/bin/compare")) {
        (Some(a), Some(b)) => Some((a, b)),
        _ => {
            eprintln!("Skipping layout test --- pdftoppm or compare tool path not specified");
            None
        }
    }
}

fn render(pdftoppm: &Path, pdf: &Path, prefix: &Path) -> PathBuf {
    let st = Command::new(pdftoppm)
        .args(["-singlefile", "-png"])
        .arg(pdf)
        .arg(prefix)
        .status()
        .expect("run pdftoppm");
    assert!(st.success(), "Failed to convert {} with pdftoppm", pdf.display());
    prefix.with_extension("png")
}

/// The expected outputs (`EXPECTED_OUTPUT_DIR`).
pub fn expected(name: &str) -> PathBuf {
    super::data_path(&["pyhanko", "pdf", "layout-tests", name])
}

/// Compare `output` with the expected file; panics with the absolute error
/// otherwise (files are kept under `target/failed_layout_tests`).
pub fn compare_output(output: &[u8], expected_name: &str) {
    let Some((pdftoppm, compare)) = layout_tools() else {
        return;
    };
    let dir = super::temp_file(&format!("layout-{expected_name}.d"), b"").with_extension("dir");
    std::fs::create_dir_all(&dir).unwrap();
    let out_pdf = dir.join("output.pdf");
    std::fs::write(&out_pdf, output).unwrap();
    let exp_png = render(&pdftoppm, &expected(expected_name), &dir.join("expected"));
    let act_png = render(&pdftoppm, &out_pdf, &dir.join("actual"));
    let res = Command::new(compare)
        .args(["-metric", "ae"])
        .arg(&exp_png)
        .arg(&act_png)
        .arg(dir.join("diff.png"))
        .output()
        .expect("run compare");
    let err = String::from_utf8_lossy(&res.stderr).trim().to_owned();
    if err != "0" && err != "0 (0)" {
        panic!(
            "Output compare test failed --- absolute error: {err}; Output saved in {}.",
            dir.display()
        );
    }
}

/// `empty_page()`: a new document with one empty A4 page; with
/// `stream_xrefs`, the file uses an xref stream (so updates do too).
pub fn empty_page(stream_xrefs: bool) -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let content = doc.add_object(Stream::new(dictionary! {}, Vec::new()));
    let page = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content,
        "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page.into()],
            "Count" => 1,
        }),
    );
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    let opts = lopdf::SaveOptions::builder().use_xref_streams(stream_xrefs).build();
    doc.save_with_options(&mut out, opts).unwrap();
    out
}

/// Run `f` with a writer over `pdf` and return the written update.
pub fn with_writer(pdf: &[u8], f: impl FnOnce(&mut ContentWriter<'_>)) -> Vec<u8> {
    let mut update = PdfUpdate::new(pdf).unwrap();
    let mut w = ContentWriter::new(&mut update);
    f(&mut w);
    w.write().unwrap()
}
