// Differential mutation tests against pyHanko 0.38.1 (MIT, see
// LICENSE-pyHanko).
//
// `oracle/mutate.py` appended one seeded random incremental update to each
// recorded input file and recorded pyHanko's DEFAULT_DIFF_POLICY verdict on
// it (`crates/hanko-testdata/data/lanes/c/mutations.json`). The port must
// agree on accepted updates (level and changed fields) and must reject
// every update pyHanko rejects, both with pyHanko's cross-reference model
// and through the `PdfFile`-style derivation (`DerivedSource`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::rc::Rc;

use hanko_core::errors::Result;
use hanko_diff::{DerivedSource, DiffOutcome, FieldMdpAction, MdpPerm, StandardDiffPolicy};
use serde_json::Value;
use support::{lane_dir, OracleFile, OraclePrimitives, OracleSource};

/// Directory with `mutations.json` and `mutations/`: the committed corpus,
/// or `$HANKO_DIFF_MUTATIONS` (for larger local runs of `oracle/mutate.py`
/// with other seeds; the base files always come from the lane directory).
fn corpus_dir() -> std::path::PathBuf {
    std::env::var_os("HANKO_DIFF_MUTATIONS").map_or_else(lane_dir, Into::into)
}

fn corpus() -> Value {
    serde_json::from_slice(&std::fs::read(corpus_dir().join("mutations.json")).unwrap()).unwrap()
}

#[derive(Default)]
struct Tally {
    agree: usize,
    accepted: usize,
    problems: Vec<String>,
    kind_differences: Vec<String>,
    /// Stricter verdicts and rejection-kind differences on files with
    /// hybrid-reference sections.
    hybrid_stricter: Vec<String>,
}

/// The three recorded verdicts: plain, under DocMDP P=2, all fields locked.
const VARIANTS: [(&str, Option<MdpPerm>, bool); 3] = [
    ("verdict", None, false),
    ("verdict_certify", Some(MdpPerm::FillForms), false),
    ("verdict_locked", None, true),
];

type Review =
    dyn Fn(&Rc<OracleFile>, usize, Option<&FieldMdpAction>, Option<MdpPerm>) -> Result<DiffOutcome>;

fn run(review: &Review) -> Tally {
    let data = corpus();
    let mut t = Tally::default();
    let lock_all = FieldMdpAction::All;
    for (id, case) in data["cases"].as_object().unwrap() {
        let base = case["base"].as_str().unwrap();
        let mut bytes = std::fs::read(lane_dir().join("pdf").join(format!("{base}.pdf"))).unwrap();
        bytes.extend(
            std::fs::read(corpus_dir().join("mutations").join(format!("{id}.bin"))).unwrap(),
        );
        let file = Rc::new(OracleFile::from_parts(id, bytes, &case["model"]));
        let base_rev = usize::try_from(case["base_revision"].as_u64().unwrap()).unwrap();
        for (key, doc_mdp, locked) in VARIANTS {
            let expected = &case[key];
            let actual = review(&file, base_rev, locked.then_some(&lock_all), doc_mdp);
            let what = format!(
                "{id} {key} ({}): pyHanko {expected} vs port {actual:?}",
                case["mutation"]
            );
            classify(&mut t, &file, expected, &actual, what);
        }
    }
    t
}

fn classify(
    t: &mut Tally,
    file: &OracleFile,
    expected: &Value,
    actual: &Result<DiffOutcome>,
    what: String,
) {
    match (&actual, expected.get("level")) {
        (Ok(DiffOutcome::Reviewed(r)), Some(level)) => {
            t.accepted += 1;
            let fields: Vec<&str> = expected["changed_form_fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap())
                .collect();
            let ours: Vec<&str> = r.changed_form_fields.iter().map(String::as_str).collect();
            if level.as_u64().unwrap() as usize == r.modification_level as usize && fields == ours {
                t.agree += 1;
            } else {
                t.problems.push(what);
            }
        }
        (Ok(DiffOutcome::Reviewed(_)), None) => t.problems.push(format!("FAIL-OPEN {what}")),
        (_, Some(_)) if file.has_hybrid() => t.hybrid_stricter.push(what),
        (_, Some(_)) => t.problems.push(what),
        (Ok(DiffOutcome::Suspicious(_)), None) if expected.get("suspicious").is_some() => {
            t.agree += 1
        }
        (Err(_), None) if expected.get("error").is_some() => t.agree += 1,
        (_, None) if file.has_hybrid() => t.hybrid_stricter.push(what),
        (_, None) => t.kind_differences.push(what),
    }
}

#[test]
fn mutations_agree_with_pyhanko() {
    let t = run(&|file, base, field_mdp, doc_mdp| {
        let src = OracleSource {
            file: file.clone(),
            strict: true,
        };
        StandardDiffPolicy.review_source(&src, base, field_mdp, doc_mdp)
    });
    assert!(
        t.problems.is_empty(),
        "{} problems:\n{}",
        t.problems.len(),
        t.problems.join("\n")
    );
    assert!(
        t.kind_differences.is_empty(),
        "{}",
        t.kind_differences.join("\n")
    );
    report_hybrid(&t);
    eprintln!(
        "{} mutations agree, {} accepted by both",
        t.agree, t.accepted
    );
    assert!(
        t.agree >= 1200 && t.accepted >= 300,
        "{} agree, {} accepted",
        t.agree,
        t.accepted
    );
}

#[test]
fn mutations_derived_source_never_more_lenient() {
    let t = run(&|file, base, field_mdp, doc_mdp| {
        let prims = OraclePrimitives { file, strict: true };
        let src = DerivedSource::new(&prims).unwrap();
        StandardDiffPolicy.review_source(&src, base, field_mdp, doc_mdp)
    });
    assert!(
        t.problems.is_empty(),
        "{} problems:\n{}",
        t.problems.len(),
        t.problems.join("\n")
    );
    assert!(
        t.kind_differences.is_empty(),
        "{}",
        t.kind_differences.join("\n")
    );
    report_hybrid(&t);
}

/// The input of `test_sign_with_hybrid_sneaky_edit` has a deliberately
/// broken hybrid entry that points at another object. pyHanko never reads
/// it; the derived source reads every object a revision writes (PORTING.md
/// divergence 8), and lopdf (test harness) can let the bogus entry replace
/// the object it points at. Both only make the port stricter: these cases
/// are reported, never fail-open (fail-open cases are `problems`).
fn report_hybrid(t: &Tally) {
    for h in &t.hybrid_stricter {
        eprintln!("stricter on hybrid-reference file: {h}");
    }
}
