//! Read and hash the frozen exported PKI inputs selected by these root callers.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pki_core::algorithms::DigestAlgorithm;
use std::path::Path;

pub fn read(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    let hash = DigestAlgorithm::Sha256
        .digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    eprintln!(
        "S_PDF_PKI_INPUT {}",
        serde_json::json!({
            "path":std::fs::canonicalize(path).unwrap(),"sha256":hash,"length":bytes.len(),
            "host":std::fs::read_to_string("/etc/hostname").unwrap().trim(),
            "runtime_slot":std::env::var("RUST_SLOTS_HELD").ok(),
        })
    );
    bytes
}

pub fn trace_pki(architecture: &str) {
    let base = sigis_testdata::path(&["lanes", "d", "pki", architecture]);
    let manifest: serde_json::Value =
        serde_json::from_slice(&read(&base.join("manifest.json"))).unwrap();
    for label in ["root", "interm", "signer1", "tsa"] {
        let entry = &manifest["certs"][label];
        let bytes = read(&base.join(entry["file"].as_str().unwrap()));
        let cert = sigis_pki_core::cert::Cert::from_der(&bytes).unwrap();
        assert!(!cert.der().is_empty());
        if label == "signer1" || label == "tsa" {
            let key = &manifest["keys"][entry["subject_key"].as_str().unwrap()];
            let path = sigis_testdata::path(&["pyhanko", "crypto", key["path"].as_str().unwrap()]);
            assert!(!read(&path).is_empty());
        }
    }
}
