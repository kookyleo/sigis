//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_pkcs11.py`, against a
//! SoftHSM2 token set up per test process (`support::softhsm`).
//!
//! pyHanko's `p11_config.session` / `PKCS11Signer(sess, ...)` map to
//! [`open_pkcs11_session`] / [`Pkcs11Signer::new`]. pyHanko loads the key
//! and certificates on the first signature; the port loads them in
//! `Pkcs11Signer::new`, so lookup errors that pyHanko raises from `sign_pdf`
//! surface there. The `async` tests use the same blocking API.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::type_complexity
)]

mod support;

use std::sync::Arc;

use der::{Any, Decode, Encode};
use sigis_pades_sign::pkcs11::{
    self, criteria_satisfied_by, find_token, open_pkcs11_session, ObjectSelectors, PinEntryMode,
    Pkcs11Config, Pkcs11Error, Pkcs11Mechanism, Pkcs11Session, Pkcs11Signer, Pkcs11SignerOptions,
    SlotView, TokenCriteria, TokenView, UserPin,
};
use sigis_pades_sign::signer::digest_algorithm_id;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner};
use sigis_pki_core::algorithms::{DigestAlgorithm, RsaPssParams};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::HankoError;
use sigis_pki_core::sign::KeySigner;
use spki::AlgorithmIdentifierOwned;
use support::pdfcheck::*;
use support::softhsm::{self, P11Config, ALL_ALGOS};
use support::*;

/// pyHanko's SoftHSM configuration freezes time at 2020-11-01.
const T: &str = "2020-11-01T00:00:00+00:00";

fn session(cfg: &P11Config) -> Arc<Pkcs11Session> {
    Arc::new(
        open_pkcs11_session(
            &cfg.module,
            None,
            Some(&TokenCriteria::label(&cfg.token_label)),
            &UserPin::Pin(cfg.user_pin.clone()),
        )
        .unwrap(),
    )
}

/// Skip unless the token supports `mech` (`required_mechanism`).
fn has_mechanism(sess: &Pkcs11Session, mech: Pkcs11Mechanism) -> bool {
    let ok = sess.mechanisms().unwrap().contains(&mech.mechanism_type());
    if !ok {
        eprintln!("skipping: required mechanism {mech:?} is not available on token");
    }
    ok
}

/// The mechanism `required_mechanism` demands for an algorithm.
fn default_mechanism(algo: &str) -> Pkcs11Mechanism {
    match algo {
        "rsa" => Pkcs11Mechanism::ShaRsaPkcs(DigestAlgorithm::Sha256),
        "ecdsa" => Pkcs11Mechanism::EcdsaSha(DigestAlgorithm::Sha256),
        "ed25519" => Pkcs11Mechanism::Eddsa,
        "ed448" => Pkcs11Mechanism::EddsaEd448,
        other => panic!("no default mechanism for {other}"),
    }
}

/// Set-up shared by the token tests: the lock, the config for `algo`, and
/// the mechanism check. `None`: skip.
fn p11(
    algo: &str,
    mech: Option<Pkcs11Mechanism>,
) -> Option<(std::sync::MutexGuard<'static, ()>, P11Config)> {
    let guard = softhsm::lock();
    let cfg = softhsm::p11_config(algo)?;
    let mech = mech.unwrap_or_else(|| default_mechanism(algo));
    let sess = session(&cfg);
    if !has_mechanism(&sess, mech) {
        return None;
    }
    Some((guard, cfg))
}

fn opts(cfg: &P11Config) -> Pkcs11SignerOptions {
    Pkcs11SignerOptions {
        cert_label: Some(cfg.cert_label.clone()),
        key_label: cfg.key_label.clone(),
        ..Default::default()
    }
}

fn meta() -> PdfSignatureMetadata {
    PdfSignatureMetadata::pyhanko_defaults("Sig1")
}

fn sign_with(
    signer: Arc<dyn KeySigner>,
    meta: PdfSignatureMetadata,
) -> sigis_pki_core::errors::Result<Vec<u8>> {
    PdfSigner::new(meta, signer)
        .at(at(T))
        .sign_pdf(&pdf("minimal.pdf"))
}

/// `val_trusted(emb, vc=p11_config.validation_context)` on the only
/// signature; returns the signer certificate.
fn check_signed(out: &[u8], cfg: &P11Config) -> Cert {
    let sigs = embedded_signatures(out);
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "Sig1");
    let signer = check_integrity(out, &sigs[0]);
    val_trusted(out, 0, &cfg.pki(), T, false);
    signer
}

fn signer_info_algorithm(out: &[u8]) -> AlgorithmIdentifierOwned {
    let sigs = embedded_signatures(out);
    let sd = sigis_pades_sign::cms::decode_signed_data(&cms_bytes(&sigs[0])).unwrap();
    sd.signer_infos
        .0
        .iter()
        .next()
        .unwrap()
        .signature_algorithm
        .clone()
}

fn signing_err(r: sigis_pki_core::errors::Result<impl std::fmt::Debug>) -> String {
    match r {
        Err(HankoError::Signing(m)) => m,
        Err(HankoError::Unsupported(m)) => format!("NotImplementedError: {m}"),
        other => panic!("expected a signing error, got {other:?}"),
    }
}

/// Algorithms of the `any_algo` fixture that the port runs.
fn any_algo() -> Vec<&'static str> {
    ALL_ALGOS
        .iter()
        .filter_map(|(a, _, reason)| match reason {
            Some(r) => {
                eprintln!("skipping algorithm '{a}': {r}");
                None
            }
            None => Some(*a),
        })
        .collect()
}

#[test]
fn test_simple_sign() {
    for algo in any_algo() {
        for bulk_fetch in [true, false] {
            let Some((_g, cfg)) = p11(algo, None) else {
                continue;
            };
            let signer = Pkcs11Signer::new(
                session(&cfg),
                Pkcs11SignerOptions {
                    other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
                    bulk_fetch,
                    ..opts(&cfg)
                },
            )
            .unwrap();
            let out = sign_with(Arc::new(signer), meta()).unwrap();
            check_signed(&out, &cfg);
        }
    }
}

#[test]
fn test_simple_sign_raw_ecdsa() {
    let Some((_g, cfg)) = p11("ecdsa", Some(Pkcs11Mechanism::Ecdsa)) else {
        return;
    };
    let signer = Pkcs11Signer::new(
        session(&cfg),
        Pkcs11SignerOptions {
            other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
            use_raw_mechanism: true,
            ..opts(&cfg)
        },
    )
    .unwrap();
    let out = sign_with(Arc::new(signer), meta()).unwrap();
    check_signed(&out, &cfg);
}

fn pss_mech() -> Pkcs11Mechanism {
    Pkcs11Mechanism::ShaRsaPkcsPss {
        digest: DigestAlgorithm::Sha256,
        mgf_digest: DigestAlgorithm::Sha256,
        salt_len: 32,
    }
}

#[test]
fn test_simple_sign_with_rsassa_pss() {
    let Some((_g, cfg)) = p11("rsa", Some(pss_mech())) else {
        return;
    };
    let signer = Pkcs11Signer::new(
        session(&cfg),
        Pkcs11SignerOptions {
            other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
            prefer_pss: true,
            ..opts(&cfg)
        },
    )
    .unwrap();
    let out = sign_with(Arc::new(signer), meta()).unwrap();
    assert_eq!(signer_info_algorithm(&out).oid, oids::RSASSA_PSS);
    check_signed(&out, &cfg);
}

#[test]
fn test_simple_sign_with_rsassa_pss_custom_parameters() {
    let Some((_g, cfg)) = p11("rsa", Some(pss_mech())) else {
        return;
    };
    let md = digest_algorithm_id(DigestAlgorithm::Sha256);
    let pss_params = RsaPssParams {
        hash_algorithm: Some(md.clone()),
        mask_gen_algorithm: Some(AlgorithmIdentifierOwned {
            oid: oids::MGF1,
            parameters: Some(Any::encode_from(&md).unwrap()),
        }),
        salt_length: Some(32),
        trailer_field: None,
    };
    let pss_der = pss_params.to_der().unwrap();
    // asn1crypto's encoding of the same parameters
    assert_eq!(
        hex(&pss_der),
        "3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120"
    );
    let signer = Pkcs11Signer::new(
        session(&cfg),
        Pkcs11SignerOptions {
            other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
            prefer_pss: true,
            signature_mechanism: Some(AlgorithmIdentifierOwned {
                oid: oids::RSASSA_PSS,
                parameters: Some(Any::from_der(&pss_der).unwrap()),
            }),
            ..opts(&cfg)
        },
    )
    .unwrap();
    let out = sign_with(Arc::new(signer), meta()).unwrap();
    let alg = signer_info_algorithm(&out);
    assert_eq!(alg.oid, oids::RSASSA_PSS);
    assert_eq!(alg.parameters.unwrap().to_der().unwrap(), pss_der);
    check_signed(&out, &cfg);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn test_sign_external_certs() {
    // Unnecessary fetches for intermediate certs are skipped.
    for bulk_fetch in [true, false] {
        let Some((_g, cfg)) = p11("rsa", None) else {
            return;
        };
        let chain = cfg.cert_chain();
        let signer = Pkcs11Signer::new(
            session(&cfg),
            Pkcs11SignerOptions {
                ca_chain: vec![chain[1].clone()],
                bulk_fetch,
                ..opts(&cfg)
            },
        )
        .unwrap();
        assert_eq!(signer.cert_registry().len(), 1);
        let out = sign_with(Arc::new(signer), meta()).unwrap();
        check_signed(&out, &cfg);
    }
}

#[test]
fn test_sign_multiple_cert_sources() {
    for bulk_fetch in [true, false] {
        let Some((_g, cfg)) = p11("rsa", None) else {
            return;
        };
        let chain = cfg.cert_chain();
        let signer = Pkcs11Signer::new(
            session(&cfg),
            Pkcs11SignerOptions {
                other_certs_to_pull: Some(vec![cfg.cert_chain_labels[0].clone()]),
                ca_chain: vec![chain[1].clone()],
                bulk_fetch,
                ..opts(&cfg)
            },
        )
        .unwrap();
        assert_eq!(signer.cert_registry().len(), 2);
        let out = sign_with(Arc::new(signer), meta()).unwrap();
        check_signed(&out, &cfg);
    }
}

#[test]
fn test_wrong_key_label() {
    for bulk_fetch in [true, false] {
        let Some((_g, cfg)) = p11("rsa", None) else {
            return;
        };
        let r = Pkcs11Signer::new(
            session(&cfg),
            Pkcs11SignerOptions {
                other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
                bulk_fetch,
                key_label: Some("NoSuchKeyExists".into()),
                ..opts(&cfg)
            },
        );
        let e = signing_err(r);
        assert!(
            e.starts_with("[PKCS11Error]") && e.contains("Could not find private key"),
            "{e}"
        );
    }
}

#[test]
fn test_wrong_key_id() {
    for bulk_fetch in [true, false] {
        let Some((_g, cfg)) = p11("rsa", None) else {
            return;
        };
        let r = Pkcs11Signer::new(
            session(&cfg),
            Pkcs11SignerOptions {
                other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
                bulk_fetch,
                key_id: Some(vec![0xde, 0xad, 0xbe, 0xef]),
                ..opts(&cfg)
            },
        );
        let e = signing_err(r);
        assert!(
            e.starts_with("[PKCS11Error]") && e.contains("Could not find private key"),
            "{e}"
        );
    }
}

#[test]
fn test_wrong_cert() {
    for bulk_fetch in [true, false] {
        let Some((_g, cfg)) = p11("rsa", None) else {
            return;
        };
        let r = Pkcs11Signer::new(
            session(&cfg),
            Pkcs11SignerOptions {
                key_label: Some(cfg.cert_label.clone()),
                other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
                bulk_fetch,
                cert_id: Some(vec![0xde, 0xad, 0xbe, 0xef]),
                ..Default::default()
            },
        );
        let e = signing_err(r);
        assert!(
            e.starts_with("[PKCS11Error]") && e.contains("Could not find cert"),
            "{e}"
        );
    }
}

#[test]
fn test_provided_certs() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let signer_cert = pki("testing-ca").cert("signer1");
    let signer = Pkcs11Signer::new(
        session(&cfg),
        Pkcs11SignerOptions {
            signing_cert: Some(signer_cert.clone()),
            ca_chain: cfg.cert_chain(),
            ..opts(&cfg)
        },
    )
    .unwrap();
    let out = sign_with(Arc::new(signer), meta()).unwrap();
    // this will fail if the intermediate cert is not present
    assert_eq!(check_signed(&out, &cfg), signer_cert);
}

#[test]
fn test_signer_provided_others_pulled() {
    // pyHanko parametrises this test over `bulk_fetch` without using it.
    for _bulk_fetch in [true, false] {
        let Some((_g, cfg)) = p11("rsa", None) else {
            return;
        };
        let signer = Pkcs11Signer::new(
            session(&cfg),
            Pkcs11SignerOptions {
                ca_chain: cfg.cert_chain(),
                ..opts(&cfg)
            },
        )
        .unwrap();
        let out = sign_with(Arc::new(signer), meta()).unwrap();
        check_signed(&out, &cfg);
    }
}

#[test]
fn test_signer_pulled_others_provided() {
    for bulk_fetch in [true, false] {
        let Some((_g, cfg)) = p11("rsa", None) else {
            return;
        };
        let signer_cert = pki("testing-ca").cert("signer1");
        let signer = Pkcs11Signer::new(
            session(&cfg),
            Pkcs11SignerOptions {
                key_label: Some(cfg.cert_label.clone()),
                other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
                signing_cert: Some(signer_cert.clone()),
                bulk_fetch,
                ..Default::default()
            },
        )
        .unwrap();
        let out = sign_with(Arc::new(signer), meta()).unwrap();
        assert_eq!(check_signed(&out, &cfg), signer_cert);
    }
}

#[test]
fn test_unclear_key_label_and_cert() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let r = Pkcs11Signer::new(session(&cfg), Pkcs11SignerOptions::default());
    let e = signing_err(r);
    assert!(e.contains("Found more than one"), "{e}");
}

#[test]
fn test_auto_use_only_key_if_cert_is_known() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let signer_cert = pki("testing-ca").cert("signer1");
    let signer = Pkcs11Signer::new(
        session(&cfg),
        Pkcs11SignerOptions {
            signing_cert: Some(signer_cert),
            other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let out = sign_with(Arc::new(signer), meta()).unwrap();
    check_signed(&out, &cfg);
}

fn config(cfg: &P11Config) -> Pkcs11Config {
    Pkcs11Config {
        module_path: cfg.module.clone(),
        token_criteria: Some(TokenCriteria::label(&cfg.token_label)),
        cert_label: Some(cfg.cert_label.clone()),
        key_label: cfg.key_label.clone(),
        user_pin: Some(cfg.user_pin.clone()),
        ..Default::default()
    }
}

#[test]
fn test_simple_sign_from_config() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let config = Pkcs11Config {
        other_certs_to_pull: None,
        only_resident_certs: true,
        ..config(&cfg)
    };
    let signer = pkcs11::open(&config, None).unwrap();
    let out = sign_with(signer, meta()).unwrap();
    check_signed(&out, &cfg);
}

#[test]
#[ignore = "Provider exclusion: upstream requires hsm(platform='safenet'); no SafeNet provider is configured"]
fn test_simple_sign_from_config_with_signing_pin() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let config = Pkcs11Config {
        signing_pin_mode: pkcs11::SigningPinEntryMode::Reauthenticate,
        signing_pin: Some(cfg.user_pin.clone()),
        other_certs_to_pull: None,
        only_resident_certs: true,
        ..config(&cfg)
    };
    let signer = pkcs11::open(&config, None).unwrap();
    let out = sign_with(signer, meta()).unwrap();
    check_signed(&out, &cfg);
}

#[test]
fn test_config_init_failure_signing_error() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let config = Pkcs11Config {
        module_path: ".".into(),
        other_certs_to_pull: None,
        ..config(&cfg)
    };
    let e = signing_err(pkcs11::open(&config, None));
    assert!(e.contains("error while opening session"), "{e}");
}

#[test]
fn test_sign_skip_login_fail() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let config = Pkcs11Config {
        user_pin: None,
        prompt_pin: PinEntryMode::Skip,
        ..config(&cfg)
    };
    // no key will be found, since we didn't bother logging in
    let e = signing_err(pkcs11::open(&config, None));
    assert!(
        e.starts_with("[PKCS11Error]") && e.contains("Could not find private key"),
        "{e}"
    );
}

#[test]
fn test_sign_deferred_auth() {
    // relies on SoftHSM not supporting the PROTECTED_AUTHENTICATION_PATH flag
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let config = Pkcs11Config {
        user_pin: None,
        prompt_pin: PinEntryMode::Defer,
        ..config(&cfg)
    };
    let e = signing_err(pkcs11::open(&config, None));
    assert!(
        e.contains("Protected auth") && e.contains("not supported by loaded module"),
        "{e}"
    );
    assert!(e.contains("error while opening session"), "{e}");
}

#[test]
fn test_simple_sign_with_raw_rsa() {
    let Some((_g, cfg)) = p11("rsa", Some(Pkcs11Mechanism::RsaPkcs)) else {
        return;
    };
    let config = Pkcs11Config {
        other_certs_to_pull: None,
        raw_mechanism: true,
        ..config(&cfg)
    };
    let signer = pkcs11::open(&config, None).unwrap();
    let out = sign_with(signer, meta()).unwrap();
    check_signed(&out, &cfg);
}

#[test]
#[ignore = "Implementation gap: cryptoki 0.12.1 cannot construct standard CKM_DSA through its safe API; native DSA token import is not enabled"]
fn test_simple_sign_with_raw_dsa() {
    let Some((_g, cfg)) = p11("dsa", Some(Pkcs11Mechanism::Dsa)) else {
        return;
    };
    let signer = Pkcs11Signer::new(
        session(&cfg),
        Pkcs11SignerOptions {
            other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
            use_raw_mechanism: true,
            ..opts(&cfg)
        },
    )
    .unwrap();
    let meta = PdfSignatureMetadata {
        md_algorithm: Some(DigestAlgorithm::Sha256),
        ..meta()
    };
    let out = sign_with(Arc::new(signer), meta).unwrap();
    check_signed(&out, &cfg);
}

#[test]
fn test_no_raw_pss() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let signer = Pkcs11Signer::new(
        session(&cfg),
        Pkcs11SignerOptions {
            other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
            use_raw_mechanism: true,
            prefer_pss: true,
            ..opts(&cfg)
        },
    )
    .unwrap();
    let meta = PdfSignatureMetadata {
        md_algorithm: Some(DigestAlgorithm::Sha256),
        ..meta()
    };
    let e = signing_err(sign_with(Arc::new(signer), meta));
    assert!(
        e.starts_with("NotImplementedError") && e.contains("PSS not available"),
        "{e}"
    );
}

fn alg(oid: &str) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: der::asn1::ObjectIdentifier::new(oid).unwrap(),
        parameters: None,
    }
}

/// pyHanko uses the OID `2.999`, which `const-oid` cannot represent (it
/// limits the second arc under `2`); any unknown OID exercises the same path.
const UNKNOWN_OID: &str = "1.3.6.1.4.1.99999.2.999";

#[test]
fn test_unsupported_algo() {
    let r = pkcs11::select_pkcs11_signing_params(
        &alg(UNKNOWN_OID),
        DigestAlgorithm::Sha256,
        false,
        None,
    );
    let e = signing_err(r);
    assert!(
        e.starts_with("NotImplementedError") && e.contains(UNKNOWN_OID),
        "{e}"
    );
}

#[test]
fn test_unsupported_algo_mech_specified_in_kwargs() {
    // this should be allowed
    let result = pkcs11::select_pkcs11_signing_params(
        &alg(UNKNOWN_OID),
        DigestAlgorithm::Sha256,
        false,
        Some(Pkcs11Mechanism::Other(0xDEADBEEF)),
    )
    .unwrap();
    assert_eq!(result.mechanism.mechanism_type(), 0xDEADBEEF);
}

#[test]
fn test_select_ecdsa_mech() {
    // can't do a round-trip test since softhsm doesn't support these, but
    // we can at least verify that the selection works
    for (md, oid, ckm) in [
        (DigestAlgorithm::Sha256, oids::ECDSA_WITH_SHA256, 0x1044u64),
        (DigestAlgorithm::Sha384, oids::ECDSA_WITH_SHA384, 0x1045u64),
    ] {
        let result = pkcs11::select_pkcs11_signing_params(
            &AlgorithmIdentifierOwned {
                oid,
                parameters: None,
            },
            md,
            false,
            None,
        )
        .unwrap();
        assert_eq!(result.mechanism, Pkcs11Mechanism::EcdsaSha(md));
        assert_eq!(result.mechanism.mechanism_type(), ckm);
    }
}

#[test]
fn test_select_sign_kwargs_priority() {
    let result = pkcs11::select_pkcs11_signing_params(
        &AlgorithmIdentifierOwned {
            oid: oids::ECDSA_WITH_SHA256,
            parameters: None,
        },
        DigestAlgorithm::Sha256,
        false,
        Some(Pkcs11Mechanism::Other(0xDEADBEEF)),
    )
    .unwrap();
    assert_eq!(result.mechanism.mechanism_type(), 0xDEADBEEF);
}

#[test]
fn test_pull_err_fmt() {
    let cases: [(Option<&str>, Option<&[u8]>, bool, &str); 4] = [
        (
            Some("foo"),
            Some(b"foo"),
            true,
            "Could not find cert with label 'foo', ID '666f6f'.",
        ),
        (
            Some("foo"),
            None,
            true,
            "Could not find cert with label 'foo'.",
        ),
        (
            None,
            Some(b"foo"),
            true,
            "Could not find cert with ID '666f6f'.",
        ),
        (
            Some("foo"),
            None,
            false,
            "Found more than one cert with label 'foo'.",
        ),
    ];
    for (label, cert_id, no_results, exp_err) in cases {
        assert_eq!(
            pkcs11::format_pull_err_msg("cert", no_results, label, cert_id),
            exp_err
        );
    }
}

fn config_async_case(
    algo: &str,
    mech: Option<Pkcs11Mechanism>,
    f: impl FnOnce(Pkcs11Config) -> Pkcs11Config,
) {
    let Some((_g, cfg)) = p11(algo, mech) else {
        return;
    };
    let config = f(Pkcs11Config {
        other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
        ..config(&cfg)
    });
    let signer = pkcs11::open(&config, None).unwrap();
    let out = sign_with(signer, meta()).unwrap();
    check_signed(&out, &cfg);
}

#[test]
fn test_simple_sign_from_config_async() {
    for algo in any_algo() {
        config_async_case(algo, None, |c| c);
    }
}

#[test]
fn test_simple_sign_from_config_async_raw_ecdsa() {
    config_async_case("ecdsa", Some(Pkcs11Mechanism::Ecdsa), |c| Pkcs11Config {
        raw_mechanism: true,
        ..c
    });
}

#[test]
fn test_simple_sign_from_config_async_pss() {
    config_async_case("rsa", Some(pss_mech()), |c| Pkcs11Config {
        prefer_pss: true,
        ..c
    });
}

#[test]
fn test_token_does_not_exist() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let e = open_pkcs11_session(
        &cfg.module,
        None,
        Some(&TokenCriteria::label("aintnosuchtoken")),
        &UserPin::Pin(cfg.user_pin.clone()),
    )
    .unwrap_err();
    assert!(e.message.contains("No token matching criteria"), "{e}");
}

#[test]
fn test_token_unclear() {
    let Some((_g, cfg)) = p11("rsa", None) else {
        return;
    };
    let e = open_pkcs11_session(&cfg.module, None, None, &UserPin::Pin(cfg.user_pin.clone()))
        .unwrap_err();
    assert!(e.message.contains("more than 1"), "{e}");
}

// --- find_token with dummy slots ---

struct DummyToken {
    label: String,
    serial: Vec<u8>,
}

impl TokenView for DummyToken {
    fn label(&self) -> &str {
        &self.label
    }
    fn serial(&self) -> &[u8] {
        &self.serial
    }
}

struct DummySlot(Option<&'static str>);

impl SlotView for DummySlot {
    type Token = DummyToken;
    fn get_token(&self) -> Result<DummyToken, Pkcs11Error> {
        match self.0 {
            Some(lbl) => {
                let mut serial = lbl.as_bytes().to_vec();
                serial.extend_from_slice(b"-\xde\xad\xbe\xef");
                Ok(DummyToken {
                    label: lbl.into(),
                    serial,
                })
            }
            None => Err(Pkcs11Error::new("No token in slot")),
        }
    }
}

fn slots(list: &[Option<&'static str>]) -> Vec<DummySlot> {
    list.iter().map(|l| DummySlot(*l)).collect()
}

fn crit(label: Option<&str>, serial: Option<&[u8]>) -> TokenCriteria {
    TokenCriteria {
        label: label.map(str::to_owned),
        serial: serial.map(<[u8]>::to_vec),
    }
}

#[test]
fn test_find_token() {
    let foo_serial: &[u8] = b"foo-\xde\xad\xbe\xef";
    let bar_serial: &[u8] = b"bar-\xde\xad\xbe\xef";
    let cases: Vec<(
        Vec<Option<&'static str>>,
        Option<usize>,
        Option<TokenCriteria>,
    )> = vec![
        (vec![Some("foo")], None, None),
        (
            vec![Some("foo"), Some("bar")],
            Some(0),
            Some(crit(Some("foo"), None)),
        ),
        (
            vec![Some("foo"), None, Some("bar")],
            Some(0),
            Some(crit(Some("foo"), None)),
        ),
        (
            vec![Some("foo"), None, Some("bar")],
            None,
            Some(crit(Some("foo"), None)),
        ),
        (
            vec![Some("foo"), None, Some("bar")],
            None,
            Some(crit(Some("foo"), Some(foo_serial))),
        ),
        (
            vec![Some("foo"), None, Some("bar")],
            None,
            Some(crit(None, Some(foo_serial))),
        ),
        (
            vec![Some("foo"), None, Some("bar")],
            None,
            Some(crit(None, Some(bar_serial))),
        ),
        // skip over empty slots when doing this scan
        (
            vec![None, Some("foo"), None, Some("bar")],
            None,
            Some(crit(Some("foo"), None)),
        ),
        (vec![None, Some("foo"), None], Some(1), None),
    ];
    for (slot_list, slot_no, criteria) in cases {
        let tok = find_token(&slots(&slot_list), slot_no, criteria.as_ref()).unwrap();
        let tok = tok.expect("token found");
        assert!(criteria_satisfied_by(criteria.as_ref(), &tok));
    }
}

#[test]
fn test_find_token_error() {
    let foo_serial: &[u8] = b"foo-\xde\xad\xbe\xef";
    let cases: Vec<(
        Vec<Option<&'static str>>,
        Option<usize>,
        Option<TokenCriteria>,
        &str,
    )> = vec![
        (
            vec![Some("foo"), Some("bar")],
            Some(2),
            Some(crit(Some("foo"), None)),
            "too large",
        ),
        (
            vec![Some("foo"), Some("bar")],
            Some(1),
            Some(crit(Some("foo"), None)),
            "label is not 'foo'",
        ),
        (
            vec![Some("foo"), Some("bar")],
            Some(1),
            Some(crit(None, Some(foo_serial))),
            "serial is not '666f6f2ddeadbeef'",
        ),
        // when querying by slot, we want the error to be passed on
        (vec![None, Some("bar")], Some(0), None, "No token in"),
        (vec![Some("foo"), Some("bar")], None, None, "more than 1"),
        // right now, we don't care about the status of the slot in any way
        (vec![Some("foo"), None], None, None, "more than 1"),
    ];
    for (slot_list, slot_no, criteria, err) in cases {
        let e = find_token(&slots(&slot_list), slot_no, criteria.as_ref())
            .map(|t| t.map(|t| t.label))
            .unwrap_err();
        assert!(e.message.contains(err), "{e} !~ {err}");
    }
}

#[test]
fn test_token_not_found() {
    let cases: Vec<(Vec<Option<&'static str>>, &str)> = vec![
        (vec![None, Some("bar")], "foo"),
        (vec![Some("foo"), Some("bar")], "baz"),
        (vec![None, None], "foo"),
        (vec![], "foo"),
    ];
    for (slot_list, lbl) in cases {
        let tok = find_token(&slots(&slot_list), None, Some(&TokenCriteria::label(lbl))).unwrap();
        assert!(tok.is_none());
    }
}

#[test]
fn test_config_fallbacks() {
    type Pair = (Option<&'static str>, Option<&'static [u8]>);
    let base: [(Pair, Pair, Pair, Pair); 5] = [
        ((None, None), (None, None), (None, None), (None, None)),
        (
            (Some("a"), Some(b"a")),
            (None, None),
            (Some("a"), Some(b"a")),
            (Some("a"), Some(b"a")),
        ),
        (
            (Some("a"), None),
            (None, None),
            (Some("a"), None),
            (Some("a"), None),
        ),
        (
            (None, Some(b"a")),
            (None, None),
            (None, Some(b"a")),
            (None, Some(b"a")),
        ),
        (
            (Some("a"), None),
            (None, Some(b"a")),
            (Some("a"), None),
            (None, Some(b"a")),
        ),
    ];
    // `_mirror`: each case, and the case with key and cert swapped
    let mut cases = Vec::new();
    for c in base {
        let m = (c.1, c.0, c.3, c.2);
        cases.push(c);
        if m != c {
            cases.push(m);
        }
    }
    assert_eq!(cases.len(), 9);
    let own = |p: Pair| (p.0.map(str::to_owned), p.1.map(<[u8]>::to_vec));
    for (key_in, cert_in, key_prop, cert_prop) in cases {
        let (kl, ki) = own(key_in);
        let (cl, ci) = own(cert_in);
        let s = ObjectSelectors::resolve(cl, ci, kl, ki);
        assert_eq!(
            ((s.key_label, s.key_id), (s.cert_label, s.cert_id)),
            (own(key_prop), own(cert_prop)),
            "key_in={key_in:?} cert_in={cert_in:?}"
        );
    }
}
