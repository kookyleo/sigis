// Differential sweep against pyHanko 0.38.1 (MIT, see LICENSE-pyHanko).
//
// `oracle/sweep.py` ran pyHanko's DEFAULT_DIFF_POLICY on every recorded input
// file, for every base revision, in strict and lenient reading mode
// (`crates/hanko-testdata/data/lanes/c/sweep.json`). This test replays all of
// them with `StandardDiffPolicy`: accepted reviews must agree on the level and
// the changed fields, and every rejection by pyHanko must be a rejection here
// ("never accept what pyHanko rejects"). With the oracle installed,
// `sweep_matches_live_oracle` re-runs pyHanko to check that sweep.json is
// current.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;
use std::rc::Rc;

use hanko_diff::{DerivedSource, DiffOutcome, StandardDiffPolicy};
use serde_json::Value;
use support::{lane_dir, OracleFile, OraclePrimitives, OracleSource};

fn sweep() -> Value {
    serde_json::from_slice(&std::fs::read(lane_dir().join("sweep.json")).unwrap()).unwrap()
}

#[derive(Debug, Default)]
struct Tally {
    agree: usize,
    class_mismatch: Vec<String>,
    problems: Vec<String>,
}

fn replay_sweep(
    data: &Value,
    review: impl Fn(&Rc<OracleFile>, bool, usize) -> hanko_core::errors::Result<DiffOutcome>,
) -> Tally {
    let mut t = Tally::default();
    for (sha, entry) in data.as_object().unwrap() {
        let file = OracleFile::load(sha);
        for (mode, strict) in [("strict", true), ("lenient", false)] {
            for (base, expected) in entry[mode].as_array().unwrap().iter().enumerate() {
                let actual = review(&file, strict, base);
                let id = format!("{sha} {mode} base {base}");
                let theirs_accept = expected.get("level").is_some();
                match (&actual, theirs_accept) {
                    (Ok(DiffOutcome::Reviewed(r)), true) => {
                        let fields: Vec<&str> = expected["changed_form_fields"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|f| f.as_str().unwrap())
                            .collect();
                        let ours: Vec<&str> =
                            r.changed_form_fields.iter().map(String::as_str).collect();
                        if expected["level"].as_u64().unwrap() as usize
                            != r.modification_level as usize
                            || fields != ours
                        {
                            t.problems
                                .push(format!("{id}: pyHanko {expected} vs port {r:?}"));
                        } else {
                            t.agree += 1;
                        }
                    }
                    (Ok(DiffOutcome::Reviewed(r)), false) => {
                        t.problems
                            .push(format!("FAIL-OPEN {id}: pyHanko {expected} vs port {r:?}"));
                    }
                    (_, true) => {
                        t.problems
                            .push(format!("{id}: pyHanko {expected} vs port {actual:?}"));
                    }
                    (Ok(DiffOutcome::Suspicious(_)), false)
                        if expected.get("suspicious").is_some() =>
                    {
                        t.agree += 1
                    }
                    (Err(_), false) if expected.get("error").is_some() => t.agree += 1,
                    (_, false) => t
                        .class_mismatch
                        .push(format!("{id}: pyHanko {expected} vs port {actual:?}")),
                }
            }
        }
    }
    t
}

fn exact_review(
    file: &Rc<OracleFile>,
    strict: bool,
    base: usize,
) -> hanko_core::errors::Result<DiffOutcome> {
    let src = OracleSource {
        file: file.clone(),
        strict,
    };
    StandardDiffPolicy.review_source(&src, base, None, None)
}

#[test]
fn sweep_agrees_with_pyhanko() {
    let t = replay_sweep(&sweep(), exact_review);
    assert!(
        t.problems.is_empty(),
        "{} problems:\n{}",
        t.problems.len(),
        t.problems.join("\n")
    );
    // rejections where pyHanko and the port disagree on the kind of
    // rejection (suspicious modification vs. read error): none so far
    assert!(
        t.class_mismatch.is_empty(),
        "{} class mismatches:\n{}",
        t.class_mismatch.len(),
        t.class_mismatch.join("\n")
    );
    assert!(t.agree > 700, "only {} agreeing reviews", t.agree);
}

/// Whether the oracle interpreter has pyHanko 0.38.1 installed.
fn oracle_ready() -> bool {
    let Some(py) = hanko_testdata::oracle::python() else {
        return false;
    };
    let ok = std::process::Command::new(py)
        .args([
            "-c",
            "from importlib.metadata import version; assert version('pyhanko') == '0.38.1'",
        ])
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("pyHanko oracle not usable; skipping differential check");
    }
    ok
}

/// Re-run pyHanko on every sweep input (skips without the oracle).
#[test]
fn sweep_matches_live_oracle() {
    if !oracle_ready() {
        return;
    }
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("oracle/sweep.py");
    let recorded = sweep();
    let shas: Vec<&String> = recorded.as_object().unwrap().keys().collect();
    let lane = lane_dir();
    let mut args: Vec<&str> = vec![lane.to_str().unwrap()];
    args.extend(shas.iter().map(|s| s.as_str()));
    let Some(live) = hanko_testdata::oracle::run_json(&script, &args) else {
        return;
    };
    // messages may list Python sets in any order; compare the verdicts
    fn norm(v: &Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, x)| match k.as_str() {
                        "suspicious" | "message" => (k.clone(), Value::Null),
                        _ => (k.clone(), norm(x)),
                    })
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
            other => other.clone(),
        }
    }
    let mut diffs = BTreeMap::new();
    for sha in shas {
        if norm(&live[sha.as_str()]) != norm(&recorded[sha.as_str()]) {
            diffs.insert(
                sha.clone(),
                (live[sha.as_str()].clone(), recorded[sha.as_str()].clone()),
            );
        }
    }
    assert!(diffs.is_empty(), "sweep.json is stale: {diffs:?}");
}

/// The production path: `PdfFileSource` derives the cross-reference details
/// from `PdfFile`'s four revision primitives (see request C1). Run the
/// sweep through that derivation on pyHanko's model of each file: it must
/// never accept what pyHanko rejects.
#[test]
fn sweep_derived_source_never_more_lenient() {
    let t = replay_sweep(&sweep(), |file, strict, base| {
        let prims = OraclePrimitives { file, strict };
        let src = DerivedSource::new(&prims).unwrap();
        StandardDiffPolicy.review_source(&src, base, None, None)
    });
    let fail_open: Vec<&String> = t
        .problems
        .iter()
        .filter(|p| p.starts_with("FAIL-OPEN"))
        .collect();
    assert!(
        fail_open.is_empty(),
        "{}",
        fail_open
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "derived source: {} agree, {} differ (stricter), {} rejection-kind differences",
        t.agree,
        t.problems.len(),
        t.class_mismatch.len()
    );
    for p in t.problems.iter().chain(&t.class_mismatch).take(20) {
        eprintln!("  {p}");
    }
    assert!(t.problems.is_empty(), "{}", t.problems.join("\n"));
    assert_eq!(
        t.class_mismatch.len(),
        DERIVED_SOURCE_KIND_DIFFERENCES,
        "{}",
        t.class_mismatch.join("\n")
    );
}

/// Rejections of a different kind with the derived source: to find freed
/// references and stream types, it reads every object a revision writes,
/// including the deliberately broken hybrid entry of
/// `test_sign_with_hybrid_sneaky_edit` that pyHanko never reads (read error
/// instead of suspicious modification, both reject; PORTING.md divergence 8).
const DERIVED_SOURCE_KIND_DIFFERENCES: usize = 2;
