//! Shared helpers for the ported pyHanko signing tests: the exported
//! Certomancer PKI (`data/lanes/d/pki`, see `oracle/export_pki.py`), signers,
//! a local TSA, and the pyHanko oracle.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod layout;
pub mod pdfcheck;
pub mod services;
pub mod softhsm;
pub mod csc_server;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use hanko_core::cert::Cert;
use hanko_core::time::Moment;
use hanko_sign::keys::{load_private_key_from_pemder_data, PrivateKey};
use hanko_sign::{DummyTimeStamper, SimpleSigner};

/// The fixture root `crates/hanko-testdata/data` of this checkout
/// (resolved at run time by `hanko_testdata`).
pub fn data_dir() -> PathBuf {
    hanko_testdata::data_dir()
}

pub fn data_path(parts: &[&str]) -> PathBuf {
    let mut p = data_dir();
    p.extend(parts);
    p
}

/// One Certomancer PKI architecture exported to `data/lanes/d/pki/<arch>`.
pub struct Pki {
    pub arch: String,
    dir: PathBuf,
    manifest: serde_json::Value,
}

pub fn pki(arch: &str) -> Pki {
    let dir = data_path(&["lanes", "d", "pki", arch]);
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).expect("manifest"))
            .expect("manifest JSON");
    Pki {
        arch: arch.to_owned(),
        dir,
        manifest,
    }
}

impl Pki {
    pub fn cert(&self, label: &str) -> Cert {
        let file = self.manifest["certs"][label]["file"]
            .as_str()
            .unwrap_or_else(|| panic!("no cert {label} in {}", self.arch));
        Cert::from_der(&std::fs::read(self.dir.join(file)).unwrap()).unwrap()
    }

    pub fn labels(&self) -> Vec<String> {
        self.manifest["certs"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    pub fn key_label_of(&self, cert_label: &str) -> String {
        self.manifest["certs"][cert_label]["subject_key"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    pub fn key(&self, key_label: &str) -> PrivateKey {
        let entry = &self.manifest["keys"][key_label];
        let path = entry["path"]
            .as_str()
            .unwrap_or_else(|| panic!("no key {key_label} in {}", self.arch));
        let pass = entry["password"].as_str().map(str::as_bytes);
        let data = std::fs::read(data_path(&["pyhanko", "crypto", path])).unwrap();
        load_private_key_from_pemder_data(&data, pass)
            .unwrap_or_else(|e| panic!("key {key_label}: {e}"))
    }

    /// A signer for `label` with root and intermediate in its registry
    /// (`FROM_CA` and friends in `signing_commons.py`).
    pub fn signer(&self, label: &str) -> SimpleSigner {
        let key = self.key(&self.key_label_of(label));
        SimpleSigner::new(key, self.cert(label), vec![self.cert("root"), self.cert("interm")])
            .unwrap()
    }

    /// A local TSA for `label` (`DUMMY_TS`) at `at`.
    pub fn tsa(&self, label: &str, at: Moment) -> DummyTimeStamper {
        let key = self.key(&self.key_label_of(label));
        let embed: Vec<Cert> = ["root", "interm"]
            .iter()
            .filter(|l| self.manifest["certs"].get(**l).is_some())
            .map(|l| self.cert(l))
            .collect();
        DummyTimeStamper::new(self.cert(label), key, embed).with_fixed_time(at)
    }

    pub fn cert_path(&self, label: &str) -> PathBuf {
        self.dir.join(self.manifest["certs"][label]["file"].as_str().unwrap())
    }

    pub fn revocation(&self, label: &str) -> Option<(Moment, String)> {
        let r = &self.manifest["certs"][label]["revocation"];
        if r.is_null() {
            return None;
        }
        Some((
            Moment::parse_rfc3339(r["revoked_since"].as_str().unwrap()).unwrap(),
            r["reason"].as_str().unwrap().to_owned(),
        ))
    }
}

pub fn at(s: &str) -> Moment {
    Moment::parse_rfc3339(s).unwrap_or_else(|| panic!("bad time {s}"))
}

pub fn pyhanko_data(parts: &[&str]) -> Vec<u8> {
    let mut all = vec!["pyhanko"];
    all.extend_from_slice(parts);
    std::fs::read(data_path(&all)).unwrap()
}

pub fn pdf(name: &str) -> Vec<u8> {
    pyhanko_data(&["pdf", name])
}

/// The pyHanko oracle's Python, if it is installed and imports pyHanko.
pub fn oracle_python() -> Option<PathBuf> {
    static PY: OnceLock<Option<PathBuf>> = OnceLock::new();
    PY.get_or_init(|| {
        let candidates = [
            std::env::var_os("HANKO_ORACLE").map(PathBuf::from),
            Some(PathBuf::from("/tmp/pyhanko-oracle/venv/bin/python")),
            Some(PathBuf::from("/tmp/hanko-lane-d/venv/bin/python")),
        ];
        candidates.into_iter().flatten().find(|p| {
            p.exists()
                && Command::new(p)
                    .args(["-I", "-c", "import pyhanko.sign, certomancer"])
                    .output()
                    .is_ok_and(|o| o.status.success())
        })
    })
    .clone()
}

pub fn oracle_dir() -> PathBuf {
    data_dir().join("../../hanko-sign/oracle")
}

/// Run `oracle/<script>` with `args`; returns its JSON output, or `None`
/// (after printing a note) when the oracle is not installed.
pub fn oracle(script: &str, args: &[&str]) -> Option<serde_json::Value> {
    let Some(py) = oracle_python() else {
        eprintln!("pyHanko oracle not installed; skipping differential check ({script})");
        return None;
    };
    let out = Command::new(py)
        .arg("-I")
        .arg(oracle_dir().join(script))
        .args(args)
        .env("HANKO_TESTDATA", data_dir())
        .output()
        .expect("run oracle");
    if !out.status.success() {
        panic!(
            "oracle {script} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Some(serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "oracle JSON: {e}: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    }))
}

/// Write `data` to a fresh temporary file and return its path.
pub fn temp_file(name: &str, data: &[u8]) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("hanko-sign-tests-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let p = dir.join(format!("{n}-{name}"));
    std::fs::write(&p, data).unwrap();
    p
}

pub fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}
