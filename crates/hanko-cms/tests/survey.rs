//! Prints every divergence between hanko-cms and the recorded pyHanko
//! outcomes (`cargo test -p hanko-cms --test survey -- --ignored --nocapture`).

mod common;

#[test]
#[ignore = "diagnostic survey"]
fn survey_all() {
    for module in ["test_cms"] {
        let h = common::Harvest::load(module);
        let mut n = 0;
        for call in &h.calls {
            let got = common::replay(h, call).to_json();
            let d = common::diff(call, &got);
            let f = common::fail_open(call, &got);
            if !d.is_empty() || f.is_some() {
                n += 1;
                println!(
                    "{}#{} [{}]: {}{}",
                    call["test"].as_str().unwrap(),
                    call["index"],
                    call["fn"].as_str().unwrap(),
                    d.join("; "),
                    f.map(|f| format!(" FAIL-OPEN: {f}")).unwrap_or_default()
                );
            }
        }
        println!("{module}: {n} of {} calls diverge", h.calls.len());
    }
}
