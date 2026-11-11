//! A SoftHSM2 token set-up for the PKCS#11 tests, following pyHanko's
//! `pkcs11-setup-certomancer.sh`: one token per algorithm (`testrsa`,
//! `testecdsa`, `tested25519`, user PIN `1234`), each holding `signer1`'s
//! key and certificate plus the `root` and `interm` certificates, with label
//! and id equal to the Certomancer certificate label (Certomancer's
//! `Alchemist`).
//!
//! The tokens live in a fresh temporary directory; `SOFTHSM2_CONF` is set
//! for this process before the module is first initialised.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use der::{Decode, Encode};
use hanko_core::asn1::oids;
use hanko_core::cert::Cert;
use hanko_sign::keys::PrivateKey;
use hanko_sign::pkcs11::cryptoki::object::{
    Attribute, CertificateType, KeyType, ObjectClass,
};
use hanko_sign::pkcs11::cryptoki::session::UserType;
use hanko_sign::pkcs11::cryptoki::types::AuthPin;
use hanko_sign::pkcs11::load_module;

use super::{pki, Pki};

pub const USER_PIN: &str = "1234";
pub const SO_PIN: &str = "5678";

/// One algorithm's token (`P11TestConfig`).
#[derive(Clone, Debug)]
pub struct P11Config {
    pub algo: &'static str,
    pub arch: &'static str,
    pub token_label: String,
    pub module: String,
    pub user_pin: String,
    pub cert_label: String,
    pub key_label: Option<String>,
    pub cert_chain_labels: Vec<String>,
}

impl P11Config {
    pub fn pki(&self) -> Pki {
        pki(self.arch)
    }
    /// Root first, then intermediates (`cert_chain`).
    pub fn cert_chain(&self) -> Vec<Cert> {
        let p = self.pki();
        self.cert_chain_labels.iter().map(|l| p.cert(l)).collect()
    }
}

/// Algorithms of pyHanko's `DEFAULT_SUPPORTED_ALGOS`, with the reason when
/// the port cannot run them.
pub const ALL_ALGOS: &[(&str, &str, Option<&str>)] = &[
    ("rsa", "testing-ca", None),
    ("ecdsa", "testing-ca-ecdsa", None),
    ("ed25519", "testing-ca-ed25519", None),
    (
        "dsa",
        "testing-ca-dsa",
        Some("cryptoki 0.12 cannot invoke CKM_DSA* mechanisms (no MechanismType for them)"),
    ),
    (
        "ed448",
        "testing-ca-ed448",
        Some("hanko-core has no SHAKE256 digest (Ed448 CMS signing unsupported)"),
    ),
    ("mldsa", "testing-ca-mldsa", Some("SoftHSM 2.6.1 has no ML-DSA support")),
];

pub struct SoftHsm {
    pub module: String,
    pub dir: PathBuf,
}

/// Serialises the tests that use the token: login state is shared by all
/// sessions of a process, and some tests depend on not being logged in.
pub fn lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The SoftHSM set-up, or `None` (with a printed reason) if SoftHSM is
/// unusable here.
pub fn softhsm() -> Option<&'static SoftHsm> {
    static HSM: OnceLock<Result<SoftHsm, String>> = OnceLock::new();
    match HSM.get_or_init(setup) {
        Ok(h) => Some(h),
        Err(reason) => {
            eprintln!("skipping PKCS#11 test: {reason}");
            None
        }
    }
}

/// The configuration for `algo`, or `None` (with a printed reason).
pub fn p11_config(algo: &str) -> Option<P11Config> {
    let (_, arch, reason) = ALL_ALGOS.iter().find(|(a, _, _)| *a == algo)?;
    if let Some(r) = reason {
        eprintln!("skipping PKCS#11 test for '{algo}': {r}");
        return None;
    }
    let hsm = softhsm()?;
    Some(P11Config {
        algo: ALL_ALGOS.iter().find(|(a, _, _)| *a == algo)?.0,
        arch,
        token_label: format!("test{algo}"),
        module: hsm.module.clone(),
        user_pin: USER_PIN.into(),
        cert_label: "signer1".into(),
        key_label: None,
        cert_chain_labels: vec!["root".into(), "interm".into()],
    })
}

fn setup() -> Result<SoftHsm, String> {
    let module = std::env::var("PKCS11_TEST_MODULE")
        .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".into());
    if !std::path::Path::new(&module).exists() {
        return Err(format!("PKCS#11 module {module} not found"));
    }
    let dir = std::env::temp_dir().join(format!("hanko-softhsm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let tokens = dir.join("tokens");
    std::fs::create_dir_all(&tokens).map_err(|e| e.to_string())?;
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
            tokens.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    // Before the module is initialised in this process; SoftHSM reads the
    // variable in C_Initialize.
    std::env::set_var("SOFTHSM2_CONF", &conf);
    let usable: Vec<_> = ALL_ALGOS.iter().filter(|(_, _, r)| r.is_none()).collect();
    for (algo, _, _) in &usable {
        let out = Command::new("softhsm2-util")
            .env("SOFTHSM2_CONF", &conf)
            .args([
                "--init-token",
                "--free",
                "--label",
                &format!("test{algo}"),
                "--pin",
                USER_PIN,
                "--so-pin",
                SO_PIN,
            ])
            .output()
            .map_err(|e| format!("cannot run softhsm2-util: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "softhsm2-util --init-token failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    let ctx = load_module(&module).map_err(|e| format!("cannot load {module}: {e}"))?;
    let slots = ctx.get_slots_with_token().map_err(|e| e.to_string())?;
    for (algo, arch, _) in &usable {
        let label = format!("test{algo}");
        let slot = slots
            .iter()
            .copied()
            .find(|s| {
                ctx.get_token_info(*s)
                    .is_ok_and(|i| i.label().trim_end() == label)
            })
            .ok_or_else(|| format!("token {label} not found after init"))?;
        let session = ctx.open_rw_session(slot).map_err(|e| e.to_string())?;
        session
            .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
            .map_err(|e| e.to_string())?;
        let p = pki(arch);
        for cert_label in ["root", "interm"] {
            session
                .create_object(&cert_template(&p.cert(cert_label), cert_label))
                .map_err(|e| format!("{label}: importing {cert_label}: {e}"))?;
        }
        session
            .create_object(&cert_template(&p.cert("signer1"), "signer1"))
            .map_err(|e| format!("{label}: importing signer1 cert: {e}"))?;
        let key = p.key(&p.key_label_of("signer1"));
        import_key(&session, &key, "signer1").map_err(|e| format!("{label}: importing key: {e}"))?;
        session.logout().ok();
        session.close().ok();
    }
    Ok(SoftHsm { module, dir })
}

fn cert_template(cert: &Cert, label: &str) -> Vec<Attribute> {
    let parsed = x509_cert::Certificate::from_der(cert.der()).unwrap();
    let tbs = parsed.tbs_certificate();
    vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(label.as_bytes().to_vec()),
        Attribute::Subject(tbs.subject().to_der().unwrap()),
        Attribute::Issuer(tbs.issuer().to_der().unwrap()),
        Attribute::SerialNumber(tbs.serial_number().to_der().unwrap()),
        Attribute::Value(cert.der().to_vec()),
    ]
}

fn key_base(label: &str, key_type: KeyType) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(key_type),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(label.as_bytes().to_vec()),
    ]
}

fn import_key(
    session: &hanko_sign::pkcs11::cryptoki::session::Session,
    key: &PrivateKey,
    label: &str,
) -> Result<(), String> {
    let ec = |curve: der::asn1::ObjectIdentifier, value: Vec<u8>| {
        let mut t = key_base(label, KeyType::EC);
        t.push(Attribute::EcParams(curve.to_der().unwrap()));
        t.push(Attribute::Value(value));
        t
    };
    match key {
        PrivateKey::Rsa(k) => {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            let doc = k.to_pkcs1_der().map_err(|e| e.to_string())?;
            let r: rsa::pkcs1::RsaPrivateKey<der::asn1::UintRef<'_>> = rsa::pkcs1::RsaPrivateKey::from_der(doc.as_bytes()).map_err(|e| e.to_string())?;
            let mut t = key_base(label, KeyType::RSA);
            t.extend([
                Attribute::Modulus(r.modulus.as_bytes().to_vec()),
                Attribute::PublicExponent(r.public_exponent.as_bytes().to_vec()),
                Attribute::PrivateExponent(r.private_exponent.as_bytes().to_vec()),
                Attribute::Prime1(r.prime1.as_bytes().to_vec()),
                Attribute::Prime2(r.prime2.as_bytes().to_vec()),
                Attribute::Exponent1(r.exponent1.as_bytes().to_vec()),
                Attribute::Exponent2(r.exponent2.as_bytes().to_vec()),
                Attribute::Coefficient(r.coefficient.as_bytes().to_vec()),
            ]);
            session.create_object(&t).map_err(|e| e.to_string())?;
        }
        PrivateKey::P256(k) => {
            session
                .create_object(&ec(oids::SECP256R1, k.to_bytes().to_vec()))
                .map_err(|e| e.to_string())?;
        }
        PrivateKey::P384(k) => {
            session
                .create_object(&ec(oids::SECP384R1, k.to_bytes().to_vec()))
                .map_err(|e| e.to_string())?;
        }
        PrivateKey::P521(k) => {
            session
                .create_object(&ec(oids::SECP521R1, k.to_bytes().to_vec()))
                .map_err(|e| e.to_string())?;
        }
        PrivateKey::Ed448(_) => {
            return Err("Ed448 keys are not imported into SoftHSM 2.6".into());
        }
        PrivateKey::MlDsa44(_) | PrivateKey::MlDsa65(_) | PrivateKey::MlDsa87(_) => {
            return Err("SoftHSM 2.6 does not support ML-DSA keys".into());
        }
        PrivateKey::Ed25519(k) => {
            // SoftHSM 2.6 identifies Edwards curves by OID; PKCS#11 3.0
            // also allows the curve name as a PrintableString (Certomancer's
            // choice). Try both.
            let by_oid = oids::ED25519.to_der().unwrap();
            let by_name = der::asn1::PrintableStringRef::new("edwards25519")
                .unwrap()
                .to_der()
                .unwrap();
            let mut last = String::new();
            for params in [by_oid, by_name] {
                let mut t = key_base(label, KeyType::EC_EDWARDS);
                t.push(Attribute::EcParams(params));
                t.push(Attribute::Value(k.to_bytes().to_vec()));
                match session.create_object(&t) {
                    Ok(_) => return Ok(()),
                    Err(e) => last = e.to_string(),
                }
            }
            return Err(last);
        }
    }
    Ok(())
}
