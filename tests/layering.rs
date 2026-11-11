//! Enforces the crate layering of `docs/crates.md` (layer map in
//! `tools/layers.json`): normal and build dependencies between workspace
//! packages must point to a strictly lower layer, or to an allowed package of
//! the same layer; test-support packages may only be dev-dependencies; every
//! workspace package must have a layer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn root() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
}

#[test]
fn workspace_respects_layers() {
    let root = root();
    let config: Value = serde_json::from_slice(
        &std::fs::read(root.join("tools/layers.json")).expect("read tools/layers.json"),
    )
    .expect("parse tools/layers.json");
    let layers: BTreeMap<String, u64> = config["layers"]
        .as_object()
        .expect("layers")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_u64().expect("layer number")))
        .collect();
    let allowed: BTreeSet<(String, String)> = config["same_layer_allowed"]
        .as_array()
        .expect("same_layer_allowed")
        .iter()
        .map(|p| {
            (
                p[0].as_str().expect("from").to_owned(),
                p[1].as_str().expect("to").to_owned(),
            )
        })
        .collect();
    let dev_only: BTreeSet<String> = config["dev_only"]
        .as_array()
        .expect("dev_only")
        .iter()
        .map(|v| v.as_str().expect("name").to_owned())
        .collect();

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .current_dir(&root)
        .output()
        .expect("run cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout).expect("metadata JSON");

    let workspace: BTreeSet<String> = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .map(|p| p["name"].as_str().expect("name").to_owned())
        .collect();
    let mut violations = Vec::new();
    for package in meta["packages"].as_array().expect("packages") {
        let name = package["name"].as_str().expect("name");
        let Some(&layer) = layers.get(name) else {
            if !dev_only.contains(name) {
                violations.push(format!("{name}: no layer in tools/layers.json"));
            }
            continue;
        };
        for dep in package["dependencies"].as_array().expect("dependencies") {
            let dep_name = dep["name"].as_str().expect("dependency name");
            if !workspace.contains(dep_name) || dep["kind"].as_str() == Some("dev") {
                continue;
            }
            if dev_only.contains(dep_name) {
                violations.push(format!(
                    "{name} -> {dep_name}: test support may only be a dev-dependency"
                ));
                continue;
            }
            let Some(&dep_layer) = layers.get(dep_name) else {
                continue; // reported for the package itself
            };
            let ok = dep_layer < layer
                || (dep_layer == layer
                    && allowed.contains(&(name.to_owned(), dep_name.to_owned())));
            if !ok {
                violations.push(format!(
                    "{name} (L{layer}) -> {dep_name} (L{dep_layer}): {}",
                    if dep_layer > layer {
                        "upward dependency"
                    } else {
                        "same-layer dependency not allowed"
                    }
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "layering violations (docs/crates.md):\n{}",
        violations.join("\n")
    );
}
