//! A SoftHSM2 token set-up for the PKCS#11 tests, following pyHanko's
//! `pkcs11-setup-certomancer.sh`: one token per algorithm (`testrsa`,
//! `testecdsa`, `tested25519`, `tested448`, user PIN `1234`), each holding `signer1`'s
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
use sigis_pades_sign::keys::PrivateKey;
use sigis_pades_sign::pkcs11::cryptoki::object::{
    Attribute, CertificateType, KeyType, ObjectClass,
};
use sigis_pades_sign::pkcs11::cryptoki::session::UserType;
use sigis_pades_sign::pkcs11::cryptoki::types::AuthPin;
use sigis_pades_sign::pkcs11::load_module;
use sigis_pki_core::asn1::oids;
use sigis_pki_core::cert::Cert;

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
        Some("the general DSA token fixture and full original trusted-PDF/oracle proof are not enabled"),
    ),
    ("ed448", "testing-ca-ed448", None),
    (
        "mldsa",
        "testing-ca-mldsa",
        Some("SoftHSM 2.6.1 has no ML-DSA support"),
    ),
];

pub struct SoftHsm {
    pub module: String,
    pub dir: PathBuf,
    raw_dsa_enabled: bool,
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

/// Explicit acceptance-only DSA fixture; generic ALL_ALGOS stays excluded.
/// Select before this test binary first initializes its native fixture.
pub fn raw_dsa_config() -> Result<P11Config, String> {
    if std::env::var("PKCS11_TEST_RAW_DSA").as_deref() != Ok("1") {
        return Err(
            "raw DSA acceptance requires PKCS11_TEST_RAW_DSA=1 before initialization".into(),
        );
    }
    let hsm = softhsm().ok_or("mandatory raw DSA native fixture setup failed")?;
    if !hsm.raw_dsa_enabled {
        return Err("raw DSA opt-in must precede the first native fixture initialization".into());
    }
    Ok(P11Config {
        algo: "dsa",
        arch: "testing-ca-dsa",
        token_label: "testdsa".into(),
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
    let mut usable: Vec<_> = ALL_ALGOS.iter().filter(|(_, _, r)| r.is_none()).collect();
    let raw_dsa_enabled = std::env::var("PKCS11_TEST_RAW_DSA").as_deref() == Ok("1");
    if raw_dsa_enabled {
        // Only the dedicated complete acceptance test opts in. General
        // parametrized tests still exclude DSA through ALL_ALGOS.
        usable.push(
            ALL_ALGOS
                .iter()
                .find(|(algo, _, _)| *algo == "dsa")
                .unwrap(),
        );
    }
    for (algo, _, _) in &usable {
        let utility =
            std::env::var_os("PKCS11_TEST_SOFTHSM_UTIL").unwrap_or_else(|| "softhsm2-util".into());
        let out = Command::new(utility)
            .args(["--module", &module])
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
        if *algo == "dsa" {
            let key_path = sigis_testdata::pyhanko(&["crypto", "keys-dsa", "signer.key.pem"]);
            let pem = std::fs::read(&key_path)
                .map_err(|e| format!("read {}: {e}", key_path.display()))?;
            let blocks = sigis_pades_sign::keys::parse_pem(&pem)
                .map_err(|e| format!("decode original DSA fixture PEM: {e}"))?;
            if blocks.len() != 1 || blocks[0].label != "PRIVATE KEY" {
                return Err("original DSA fixture must contain one unencrypted PKCS#8 key".into());
            }
            import_dsa_pkcs8(&session, &blocks[0].der, "signer1")
                .map_err(|e| format!("{label}: importing DSA key: {e}"))?;
        } else {
            let key = p.key(&p.key_label_of("signer1"));
            import_key(&session, &key, "signer1")
                .map_err(|e| format!("{label}: importing key: {e}"))?;
        }
        session.logout().ok();
        session.close().ok();
    }
    Ok(SoftHsm {
        module,
        dir,
        raw_dsa_enabled,
    })
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

/// Standard finite-field DSA parameters from PKCS#8 or SubjectPublicKeyInfo.
#[derive(Debug, der::Sequence)]
pub struct DsaParameters<'a> {
    pub prime: der::asn1::UintRef<'a>,
    pub subprime: der::asn1::UintRef<'a>,
    pub base: der::asn1::UintRef<'a>,
}

/// Import a fixture's DSA private key without a software DSA signing fallback.
/// Metadata is decoded and checked before the sole native create_object call.
pub fn import_dsa_pkcs8(
    session: &sigis_pades_sign::pkcs11::cryptoki::session::Session,
    pkcs8_der: &[u8],
    label: &str,
) -> Result<sigis_pades_sign::pkcs11::cryptoki::object::ObjectHandle, String> {
    use sigis_pades_sign::pkcs11::cryptoki::object::AttributeType;

    let key = pkcs8::PrivateKeyInfoRef::from_der(pkcs8_der).map_err(|e| e.to_string())?;
    if key.algorithm.oid != oids::DSA {
        return Err("expected a DSA private key".into());
    }
    let params: DsaParameters<'_> = key
        .algorithm
        .parameters
        .as_ref()
        .ok_or("missing DSA parameters")?
        .decode_as::<DsaParameters<'_>>()
        .map_err(|e| e.to_string())?;
    let private =
        der::asn1::UintRef::from_der(key.private_key.as_bytes()).map_err(|e| e.to_string())?;
    if [params.prime, params.subprime, params.base, private]
        .iter()
        .any(|value| value.as_bytes().iter().all(|byte| *byte == 0))
    {
        return Err("DSA parameters and private value must be positive".into());
    }
    let mut template = key_base(label, KeyType::DSA);
    template.extend([
        Attribute::Prime(params.prime.as_bytes().to_vec()),
        // cryptoki's safe generic attribute variant carries the standard
        // CKA_SUBPRIME number absent from its named attribute variants.
        Attribute::VendorDefined((
            AttributeType::VendorDefined(0x131),
            params.subprime.as_bytes().to_vec(),
        )),
        // In cryptoki 0.12.1 the named Base variant reports length one.
        // The safe generic attribute preserves the full standard CKA_BASE.
        Attribute::VendorDefined((AttributeType::Base, params.base.as_bytes().to_vec())),
        Attribute::Value(private.as_bytes().to_vec()),
    ]);
    session.create_object(&template).map_err(|e| e.to_string())
}

fn import_key(
    session: &sigis_pades_sign::pkcs11::cryptoki::session::Session,
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
            let r: rsa::pkcs1::RsaPrivateKey<der::asn1::UintRef<'_>> =
                rsa::pkcs1::RsaPrivateKey::from_der(doc.as_bytes()).map_err(|e| e.to_string())?;
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
        PrivateKey::Ed448(k) => {
            // SoftHSM 2.6.1 accepts either Edwards curve encoding and the
            // 57-byte RFC 8032 seed, just as for Ed25519 below.
            let by_oid = oids::ED448.to_der().unwrap();
            let by_name = der::asn1::PrintableStringRef::new("edwards448")
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
