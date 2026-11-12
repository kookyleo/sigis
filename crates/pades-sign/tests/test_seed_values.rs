//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_seed_values.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use lopdf::{Dictionary, Object};
use sigis_pades_sign::pdf::fields::{self, FieldMdpAction, FieldMdpSpec, SigFieldSpec};
use sigis_pades_sign::pdf::seed::*;
use sigis_pades_sign::pdf::writer::PdfUpdate;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SubFilter};
use sigis_pdf::MdpPerm;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::HankoError;
use sigis_pki_core::sign::KeySigner;
use support::pdfcheck::*;
use support::*;

const T: &str = "2020-11-01T00:00:00+00:00";

fn from_ca() -> sigis_pades_sign::SimpleSigner {
    pki("testing-ca").signer("signer1")
}

fn self_sign_cert() -> Cert {
    sigis_pades_sign::keys::load_cert_from_pemder_data(&pyhanko_data(&[
        "crypto",
        "selfsigned.cert.pem",
    ]))
    .unwrap()
}

fn tsa_cert() -> Cert {
    pki("testing-ca").cert("tsa")
}

/// Parse a seed value dictionary given as a standalone PDF dictionary.
fn parse_sv(d: Dictionary) -> sigis_pki_core::errors::Result<SigSeedValueSpec> {
    let w = PdfUpdate::new(&pdf("minimal.pdf")).unwrap();
    SigSeedValueSpec::from_pdf_object(&w, &d)
}

fn render_sv(sv: &SigSeedValueSpec) -> Dictionary {
    let w = PdfUpdate::new(&pdf("minimal.pdf")).unwrap();
    sv.as_pdf_object(&w).unwrap()
}

fn name(n: &str) -> Object {
    Object::Name(n.as_bytes().to_vec())
}

#[test]
fn test_sv_deserialisation() {
    let mut d = Dictionary::new();
    d.set(
        "SubFilter",
        Object::Array(vec![name("foo"), name("adbe.pkcs7.detached"), name("bleh")]),
    );
    d.set(
        "LegalAttestation",
        Object::Array(vec![
            Object::string_literal("xyz"),
            Object::string_literal("abc"),
            Object::string_literal("def"),
        ]),
    );
    d.set("AppearanceFilter", Object::string_literal("blah"));
    d.set("LockDocument", name("true"));
    let sv = parse_sv(d.clone()).unwrap();
    assert_eq!(sv.subfilters.as_ref().unwrap().len(), 1);
    assert_eq!(sv.legal_attestations.as_ref().unwrap().len(), 3);
    assert_eq!(sv.lock_document, Some(SeedLockDocument::Lock));
    let out = render_sv(&sv);
    for k in [
        b"AppearanceFilter".as_slice(),
        b"LockDocument",
        b"LegalAttestation",
    ] {
        assert_eq!(out.get(k).unwrap(), d.get(k).unwrap());
    }
    let mut bad = Dictionary::new();
    bad.set("LockDocument", name("nonsense"));
    assert!(matches!(parse_sv(bad), Err(HankoError::Signing(_))));
    let mut bad_filter = Dictionary::new();
    bad_filter.set("Filter", name("unsupported"));
    parse_sv(bad_filter.clone()).unwrap();
    bad_filter.set("Ff", Object::Integer(i64::from(SigSeedValFlags::FILTER.0)));
    assert!(matches!(parse_sv(bad_filter), Err(HankoError::Signing(_))));
}

#[test]
fn test_sv_version() {
    let mut d = Dictionary::new();
    d.set("Ff", Object::Integer(i64::from(SigSeedValFlags::V.0)));
    parse_sv(d).unwrap();
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::V,
        sv_dict_version: Some(SeedValueDictVersion::Pdf20 as u32),
        ..Default::default()
    };
    parse_sv(render_sv(&sv)).unwrap();
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::V,
        sv_dict_version: Some(4),
        ..Default::default()
    };
    assert!(matches!(
        parse_sv(render_sv(&sv)),
        Err(HankoError::Signing(_))
    ));
}

#[test]
fn test_sv_mdp_type() {
    assert!(render_sv(&SigSeedValueSpec::default()).get(b"MDP").is_err());
    let mdp = |sv: SigSeedValueSpec| {
        render_sv(&sv)
            .get(b"MDP")
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"P")
            .unwrap()
            .clone()
    };
    assert_eq!(
        mdp(SigSeedValueSpec {
            seed_signature_type: Some(None),
            ..Default::default()
        }),
        Object::Integer(0)
    );
    assert_eq!(
        mdp(SigSeedValueSpec {
            seed_signature_type: Some(Some(MdpPerm::NoChanges)),
            ..Default::default()
        }),
        Object::Integer(1)
    );
    let with_mdp = |v: Object| {
        let mut d = Dictionary::new();
        d.set("MDP", v);
        parse_sv(d)
    };
    let p = |o: Object| {
        let mut m = Dictionary::new();
        m.set("P", o);
        Object::Dictionary(m)
    };
    assert_eq!(
        with_mdp(p(Object::Integer(0))).unwrap().seed_signature_type,
        Some(None)
    );
    assert_eq!(
        with_mdp(p(Object::Integer(2))).unwrap().seed_signature_type,
        Some(Some(MdpPerm::FillForms))
    );
    assert!(matches!(
        with_mdp(p(Object::Integer(5))),
        Err(HankoError::Signing(_))
    ));
    assert!(matches!(
        with_mdp(p(Object::Null)),
        Err(HankoError::Signing(_))
    ));
    assert!(matches!(
        with_mdp(Object::Dictionary(Dictionary::new())),
        Err(HankoError::Signing(_))
    ));
    assert!(matches!(
        with_mdp(Object::Integer(5)),
        Err(HankoError::Signing(_))
    ));
}

fn subject_dn(pairs: &[(&str, &str)]) -> Option<Vec<(String, String)>> {
    Some(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    )
}

const CN: &str = "2.5.4.3";
const C: &str = "2.5.4.6";

#[test]
fn test_append_sig_field_with_simple_sv() {
    let signer_cert = from_ca().signing_cert().clone();
    let sv = SigSeedValueSpec {
        reasons: Some(vec!["a".into(), "b".into(), "c".into()]),
        cert: Some(SigCertConstraints {
            subject_dn: Some(name_keyval_pairs(signer_cert.subject())),
            issuers: Some(vec![pki("testing-ca").cert("interm")]),
            subjects: Some(vec![signer_cert.clone()]),
            key_usage: Some(vec![SigCertKeyUsage::from_sets(
                &["digital_signature", "non_repudiation"],
                &["key_agreement"],
            )]),
            ..SigCertConstraints::new()
        }),
        digest_methods: Some(vec!["ssh256".into()]),
        add_rev_info: Some(true),
        subfilters: Some(vec![SigSeedSubFilter::AdobePkcs7Detached]),
        timestamp_server_url: Some("https://tsa.example.com".into()),
        ..Default::default()
    };
    let mut sp = SigFieldSpec::new("InvisibleSig");
    sp.seed_value_dict = Some(sv.clone());
    let mut w = PdfUpdate::new(&pdf("minimal.pdf")).unwrap();
    fields::append_signature_field(&mut w, &sp).unwrap();
    let out = w.write().unwrap().0;
    let r = PdfUpdate::new(&out).unwrap();
    let f = &fields::enumerate_sig_fields(&r, None, None).unwrap()[0];
    let Some(Object::Dictionary(sv_dict)) = r.dict_get(r.get_dict(f.id).unwrap(), b"SV").unwrap()
    else {
        panic!()
    };
    let mut sv_dict = sv_dict.clone();
    assert_eq!(sv_dict.get(b"V").unwrap(), &Object::Integer(2));
    sv_dict.remove(b"V");
    let recovered = SigSeedValueSpec::from_pdf_object(&r, &sv_dict).unwrap();
    assert_eq!(recovered, sv);
}

const SV_KU_SATISFIED: &str = "11XXXXXX0";
const SV_KU_NOT_SATISFIED: &str = "10XXXXXX0";

fn ku_constraint(strs: &[&str]) -> SigCertConstraints {
    SigCertConstraints {
        flags: SigCertConstraintFlags::KEY_USAGE,
        key_usage: Some(
            strs.iter()
                .map(|s| SigCertKeyUsage::read_from_sv_string(s))
                .collect(),
        ),
        ..SigCertConstraints::new()
    }
}

#[test]
fn test_cert_constraint_key_usage_ok() {
    for strs in [
        vec![SV_KU_SATISFIED],
        vec![SV_KU_SATISFIED, SV_KU_NOT_SATISFIED],
    ] {
        ku_constraint(&strs)
            .satisfied_by(from_ca().signing_cert(), None)
            .unwrap();
    }
}

#[test]
fn test_cert_constraint_key_usage_not_ok() {
    for strs in [vec![SV_KU_NOT_SATISFIED], vec![]] {
        let e = ku_constraint(&strs)
            .satisfied_by(from_ca().signing_cert(), None)
            .unwrap_err();
        assert!(e.to_string().contains("UnacceptableSigner"), "{e}");
    }
}

fn dn_constraint(flags: SigCertConstraintFlags, pairs: &[(&str, &str)]) -> SigCertConstraints {
    SigCertConstraints {
        flags,
        subject_dn: subject_dn(pairs),
        ..SigCertConstraints::new()
    }
}

#[test]
fn test_cert_constraint_subject_dn() {
    let alice = from_ca().signing_cert().clone();
    let f = SigCertConstraintFlags::SUBJECT_DN;
    let scc = dn_constraint(f, &[(CN, "Alice")]);
    scc.satisfied_by(&alice, None).unwrap();
    assert!(scc.satisfied_by(&tsa_cert(), None).is_err());
    let scc = dn_constraint(f, &[(CN, "Alice"), (C, "BE")]);
    scc.satisfied_by(&alice, None).unwrap();
    assert!(scc.satisfied_by(&tsa_cert(), None).is_err());
    let scc = dn_constraint(f, &[(CN, "Alice & Bob"), (C, "BE")]);
    assert!(scc.satisfied_by(&alice, None).is_err());
    dn_constraint(
        SigCertConstraintFlags::default(),
        &[(CN, "Alice & Bob"), (C, "BE")],
    )
    .satisfied_by(&alice, None)
    .unwrap();
}

#[test]
fn test_cert_constraint_subject() {
    let alice = from_ca().signing_cert().clone();
    let scc = SigCertConstraints {
        flags: SigCertConstraintFlags::SUBJECT,
        subjects: Some(vec![alice.clone()]),
        ..SigCertConstraints::new()
    };
    scc.satisfied_by(&alice, None).unwrap();
    assert!(scc.satisfied_by(&tsa_cert(), None).is_err());
    let scc = SigCertConstraints {
        flags: SigCertConstraintFlags::SUBJECT,
        subjects: Some(vec![alice.clone(), self_sign_cert()]),
        ..SigCertConstraints::new()
    };
    scc.satisfied_by(&alice, None).unwrap();
    assert!(scc.satisfied_by(&tsa_cert(), None).is_err());
    let scc = SigCertConstraints {
        subjects: Some(vec![alice.clone(), self_sign_cert()]),
        ..SigCertConstraints::new()
    };
    scc.satisfied_by(&alice, None).unwrap();
    scc.satisfied_by(&tsa_cert(), None).unwrap();
}

/// Issuer certificates of the validation path of `cert`.
fn path_issuers(cert: &Cert) -> Vec<Cert> {
    let vc = support::services::live_testing_vc("testing-ca", T, &[]);
    let mut info = sigis_pades_sign::ltv::ValidationInfo::default();
    let path =
        sigis_pades_sign::ltv::validate_and_collect(&vc, cert, from_ca().cert_chain(), &mut info)
            .unwrap();
    path[1..].to_vec()
}

#[test]
fn test_cert_constraint_issuer() {
    let alice = from_ca().signing_cert().clone();
    let sp = path_issuers(&alice);
    let tp = path_issuers(&tsa_cert());
    let root = pki("testing-ca").cert("root");
    let interm = pki("testing-ca").cert("interm");
    let iss = |flags, list: Vec<Cert>| SigCertConstraints {
        flags,
        issuers: Some(list),
        ..SigCertConstraints::new()
    };
    let f = SigCertConstraintFlags::ISSUER;
    let scc = iss(f, vec![root]);
    scc.satisfied_by(&alice, Some(&sp)).unwrap();
    scc.satisfied_by(&tsa_cert(), Some(&tp)).unwrap();
    assert!(scc.satisfied_by(&alice, None).is_err());
    let scc = iss(f, vec![interm.clone()]);
    scc.satisfied_by(&alice, Some(&sp)).unwrap();
    assert!(scc.satisfied_by(&tsa_cert(), Some(&tp)).is_err());
    let scc = iss(f, vec![interm.clone(), self_sign_cert()]);
    scc.satisfied_by(&alice, Some(&sp)).unwrap();
    assert!(scc.satisfied_by(&tsa_cert(), Some(&tp)).is_err());
    let scc = iss(SigCertConstraintFlags::default(), vec![interm]);
    scc.satisfied_by(&alice, Some(&sp)).unwrap();
    scc.satisfied_by(&tsa_cert(), Some(&tp)).unwrap();
    let _ = from_ca().signing_cert();
}

#[test]
fn test_cert_constraint_composite() {
    let alice = from_ca().signing_cert().clone();
    let sp = path_issuers(&alice);
    let tp = path_issuers(&tsa_cert());
    let interm = pki("testing-ca").cert("interm");
    let f = SigCertConstraintFlags::ISSUER | SigCertConstraintFlags::SUBJECT_DN;
    let scc = SigCertConstraints {
        flags: f,
        issuers: Some(vec![interm.clone()]),
        subject_dn: subject_dn(&[(CN, "Alice"), (C, "BE")]),
        ..SigCertConstraints::new()
    };
    scc.satisfied_by(&alice, Some(&sp)).unwrap();
    assert!(scc.satisfied_by(&tsa_cert(), Some(&tp)).is_err());
    let scc = SigCertConstraints {
        flags: f,
        issuers: Some(vec![interm]),
        subject_dn: subject_dn(&[(CN, "Alice & Bob"), (C, "BE")]),
        ..SigCertConstraints::new()
    };
    assert!(scc.satisfied_by(&alice, Some(&sp)).is_err());
}

fn prepare_sv_field(sv: &SigSeedValueSpec, add_field_lock: bool) -> Vec<u8> {
    let mut sp = SigFieldSpec::new("Sig");
    sp.seed_value_dict = Some(sv.clone());
    if add_field_lock {
        sp.field_mdp_spec = Some(FieldMdpSpec {
            action: FieldMdpAction::Include,
            fields: vec!["blah".into()],
        });
        sp.doc_mdp_update_value = Some(MdpPerm::NoChanges);
    }
    let mut w = PdfUpdate::new(&pdf("minimal.pdf")).unwrap();
    fields::append_signature_field(&mut w, &sp).unwrap();
    w.write().unwrap().0
}

/// `sign_with_sv`: sign the `Sig` field carrying `sv`, then check pyHanko's
/// seed value verdict. Returns the signed file.
fn sign_with_sv_opts(
    sv: &SigSeedValueSpec,
    meta: PdfSignatureMetadata,
    test_violation: bool,
    add_field_lock: bool,
    with_ts: bool,
) -> sigis_pki_core::errors::Result<Vec<u8>> {
    let input = prepare_sv_field(sv, add_field_lock);
    let mut s = PdfSigner::new(meta, Arc::new(from_ca())).at(at(T));
    if with_ts {
        s = s.with_timestamper(Arc::new(pki("testing-ca").tsa("tsa", at(T))));
    }
    s.ignore_sv = test_violation;
    let out = s.sign_pdf(&input)?;
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &[]) {
        let st = &v[0];
        assert!(st.get("error").is_none(), "{st}");
        assert_eq!(st["seed_value_ok"], !test_violation, "{st}");
    }
    Ok(out)
}

fn sign_with_sv(
    sv: &SigSeedValueSpec,
    meta: PdfSignatureMetadata,
    test_violation: bool,
) -> sigis_pki_core::errors::Result<Vec<u8>> {
    sign_with_sv_opts(sv, meta, test_violation, false, true)
}

fn meta() -> PdfSignatureMetadata {
    PdfSignatureMetadata::pyhanko_defaults("Sig")
}

fn meta_md(md: DigestAlgorithm) -> PdfSignatureMetadata {
    let mut m = meta();
    m.md_algorithm = Some(md);
    m
}

fn md_of(out: &[u8]) -> String {
    let s = &embedded_signatures(out)[0];
    let sd = sigis_pades_sign::cms::decode_signed_data(&cms_bytes(s)).unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap();
    DigestAlgorithm::from_oid(&si.digest_alg.oid)
        .unwrap()
        .name()
        .to_owned()
}

fn is_signing_err(r: sigis_pki_core::errors::Result<Vec<u8>>) -> bool {
    matches!(r, Err(HankoError::Signing(_)))
}

#[test]
fn test_sv_sign_md_req() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::DIGEST_METHOD,
        digest_methods: Some(vec!["sha256".into(), "sha512".into()]),
        ..Default::default()
    };
    assert!(is_signing_err(sign_with_sv(
        &sv,
        meta_md(DigestAlgorithm::Sha1),
        false
    )));
    sign_with_sv(&sv, meta_md(DigestAlgorithm::Sha1), true).unwrap();
    assert_eq!(md_of(&sign_with_sv(&sv, meta(), false).unwrap()), "sha256");
    assert_eq!(
        md_of(&sign_with_sv(&sv, meta_md(DigestAlgorithm::Sha512), false).unwrap()),
        "sha512"
    );
}

#[test]
fn test_sv_sign_md_hint() {
    let sv = SigSeedValueSpec {
        digest_methods: Some(vec!["sha256".into(), "sha512".into()]),
        ..Default::default()
    };
    assert_eq!(
        md_of(&sign_with_sv(&sv, meta_md(DigestAlgorithm::Sha1), false).unwrap()),
        "sha1"
    );
    assert_eq!(md_of(&sign_with_sv(&sv, meta(), false).unwrap()), "sha256");
    assert_eq!(
        md_of(&sign_with_sv(&sv, meta_md(DigestAlgorithm::Sha512), false).unwrap()),
        "sha512"
    );
}

fn subfilter_of(out: &[u8]) -> String {
    embedded_signatures(out)[0].subfilter()
}

fn meta_sf(sf: Option<SubFilter>) -> PdfSignatureMetadata {
    let mut m = meta_md(DigestAlgorithm::Sha1);
    m.subfilter = sf;
    m
}

#[test]
fn test_sv_sign_subfilter_req() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::SUBFILTER,
        subfilters: Some(vec![SigSeedSubFilter::Pades]),
        ..Default::default()
    };
    assert!(is_signing_err(sign_with_sv(
        &sv,
        meta_sf(Some(SubFilter::Pkcs7Detached)),
        false
    )));
    sign_with_sv(&sv, meta_sf(Some(SubFilter::Pkcs7Detached)), true).unwrap();
    assert_eq!(
        subfilter_of(&sign_with_sv(&sv, meta(), false).unwrap()),
        "ETSI.CAdES.detached"
    );
}

#[test]
fn test_sv_sign_subfilter_hint() {
    let sv = SigSeedValueSpec {
        subfilters: Some(vec![SigSeedSubFilter::Pades]),
        ..Default::default()
    };
    assert_eq!(
        subfilter_of(&sign_with_sv(&sv, meta_sf(Some(SubFilter::Pkcs7Detached)), false).unwrap()),
        "adbe.pkcs7.detached"
    );
    assert_eq!(
        subfilter_of(&sign_with_sv(&sv, meta(), false).unwrap()),
        "ETSI.CAdES.detached"
    );
}

fn revinfo_meta(
    sf: SubFilter,
    embed: bool,
    vc: sigis_pki_certvalidator::ValidationContext,
) -> PdfSignatureMetadata {
    let mut m = meta();
    m.validation_context = Some(Arc::new(vc));
    m.subfilter = Some(sf);
    m.embed_validation_info = embed;
    m
}

#[test]
fn test_sv_sign_addrevinfo_req() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::ADD_REV_INFO,
        add_rev_info: Some(true),
        ..Default::default()
    };
    let vc = || support::services::live_testing_vc("testing-ca", T, &[]);
    sign_with_sv(
        &sv,
        revinfo_meta(SubFilter::Pkcs7Detached, true, vc()),
        false,
    )
    .unwrap();
    let m = revinfo_meta(SubFilter::Pkcs7Detached, false, vc());
    assert!(is_signing_err(sign_with_sv(&sv, m.clone(), false)));
    sign_with_sv(&sv, m, true).unwrap();
    let m = revinfo_meta(SubFilter::Pades, true, vc());
    assert!(is_signing_err(sign_with_sv(&sv, m.clone(), false)));
    sign_with_sv(&sv, m, true).unwrap();
}

#[test]
fn test_sv_sign_addrevinfo_subfilter_conflict() {
    let dummy = || support::services::dummy_ocsp_vc(T);
    let with_vc = |embed: bool| {
        let mut m = meta();
        m.validation_context = Some(Arc::new(dummy()));
        m.embed_validation_info = embed;
        m
    };
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::ADD_REV_INFO,
        subfilters: Some(vec![SigSeedSubFilter::Pades]),
        add_rev_info: Some(true),
        ..Default::default()
    };
    assert!(is_signing_err(sign_with_sv(&sv, with_vc(true), false)));
    let both = SigSeedValFlags::ADD_REV_INFO | SigSeedValFlags::SUBFILTER;
    let sv = SigSeedValueSpec {
        flags: both,
        subfilters: Some(vec![SigSeedSubFilter::Pades]),
        add_rev_info: Some(true),
        ..Default::default()
    };
    assert!(is_signing_err(sign_with_sv(&sv, with_vc(true), false)));
    sign_with_sv(&sv, with_vc(true), true).unwrap();
    let sv = SigSeedValueSpec {
        flags: both,
        subfilters: Some(vec![SigSeedSubFilter::Pades]),
        add_rev_info: Some(false),
        ..Default::default()
    };
    sign_with_sv(&sv, with_vc(false), false).unwrap();
}

#[test]
fn test_add_revinfo_wrong_subfilter() {
    use sigis_pades_sign::pdf::signer as ps;
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::ADD_REV_INFO,
        add_rev_info: Some(true),
        ..Default::default()
    };
    let input = prepare_sv_field(&sv, false);
    let mut w = PdfUpdate::new(&input).unwrap();
    let field = fields::enumerate_sig_fields(&w, None, Some("Sig"))
        .unwrap()
        .remove(0);
    let spec = ps::SignatureObjectSpec {
        subfilter: Some(SigSeedSubFilter::Pades),
        ..Default::default()
    };
    let sig_id = w.add(Object::Dictionary(spec.to_dict(false)));
    w.get_dict_mut(field.id)
        .unwrap()
        .set("V", Object::Reference(sig_id));
    let prepared = ps::write_and_digest(&mut w, sig_id, 8192, DigestAlgorithm::Sha256).unwrap();
    let signer = from_ca();
    let settings = sigis_pades_sign::CmsSignedAttributes {
        adobe_revinfo_attr: Some(sigis_pades_sign::attributes::RevocationInfoArchival {
            ocsp: Some(vec![]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let cms = sigis_pades_sign::cms::CmsSigner {
        signer: &signer,
        options: &Default::default(),
    }
    .sign(
        &prepared.document_digest,
        DigestAlgorithm::Sha256,
        &settings,
        sigis_pades_sign::cms::AttrProfile::GenericPdf,
        None,
        false,
        None,
    )
    .unwrap();
    let out = ps::PdfTbsDocument::finish_signing(prepared, &cms, None, None).unwrap();
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &[]) {
        let s = &v[0];
        assert_eq!(s["intact"], true, "{s}");
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["seed_value_ok"], false, "{s}");
        assert!(
            s["seed_value_error"]
                .as_str()
                .unwrap()
                .contains("requires subfilter"),
            "{s}"
        );
    }
}

#[test]
fn test_sv_sign_cert_constraint() {
    let dn = |cn: &str| SigSeedValueSpec {
        cert: Some(SigCertConstraints {
            flags: SigCertConstraintFlags::SUBJECT_DN,
            subject_dn: subject_dn(&[(CN, cn)]),
            ..SigCertConstraints::new()
        }),
        ..Default::default()
    };
    sign_with_sv(&dn("Alice"), meta(), false).unwrap();
    assert!(is_signing_err(sign_with_sv(
        &dn("Not Alice"),
        meta(),
        false
    )));
    sign_with_sv(&dn("Not Alice"), meta(), true).unwrap();
}

#[test]
fn test_sv_flag_unsupported() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::LEGAL_ATTESTATION | SigSeedValFlags::APPEARANCE_FILTER,
        legal_attestations: Some(vec!["abc".into()]),
        appearance: Some("test".into()),
        ..Default::default()
    };
    // pyHanko's validator refuses with NotImplementedError
    let input = prepare_sv_field(&sv, false);
    let mut s = PdfSigner::new(meta(), Arc::new(from_ca())).at(at(T));
    s.ignore_sv = true;
    let out = s.sign_pdf(&input).unwrap();
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &[]) {
        assert!(
            v[0]["error"]
                .as_str()
                .unwrap_or_default()
                .contains("NotImplementedError"),
            "{}",
            v[0]
        );
    }
}

#[test]
fn test_sv_cert_flag_unsupported() {
    let sv = SigSeedValueSpec {
        cert: Some(SigCertConstraints {
            flags: SigCertConstraintFlags::RESERVED,
            ..SigCertConstraints::new()
        }),
        ..Default::default()
    };
    assert!(matches!(
        sign_with_sv(&sv, meta(), false),
        Err(HankoError::Unsupported(_))
    ));
}

#[test]
fn test_sv_flag_appearance_required() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::APPEARANCE_FILTER,
        appearance: Some("test".into()),
        ..Default::default()
    };
    assert!(is_signing_err(sign_with_sv(&sv, meta(), false)));
}

fn certify(p: MdpPerm) -> PdfSignatureMetadata {
    let mut m = meta();
    m.certify = Some(p);
    m
}

#[test]
fn test_sv_mdp_no_certify() {
    let sv = SigSeedValueSpec {
        seed_signature_type: Some(None),
        ..Default::default()
    };
    sign_with_sv(&sv, meta(), false).unwrap();
    assert!(is_signing_err(sign_with_sv(
        &sv,
        certify(MdpPerm::FillForms),
        false
    )));
    sign_with_sv(&sv, certify(MdpPerm::FillForms), true).unwrap();
}

#[test]
fn test_sv_mdp_must_certify() {
    let sv = SigSeedValueSpec {
        seed_signature_type: Some(Some(MdpPerm::FillForms)),
        ..Default::default()
    };
    sign_with_sv(&sv, certify(MdpPerm::FillForms), false).unwrap();
    assert!(is_signing_err(sign_with_sv(&sv, meta(), false)));
    sign_with_sv(&sv, meta(), true).unwrap();
    sign_with_sv(&sv, certify(MdpPerm::NoChanges), true).unwrap();
}

#[test]
fn test_sv_mdp_must_certify_wrong_docmdp() {
    let sv = SigSeedValueSpec {
        seed_signature_type: Some(Some(MdpPerm::FillForms)),
        ..Default::default()
    };
    assert!(is_signing_err(sign_with_sv(
        &sv,
        certify(MdpPerm::NoChanges),
        false
    )));
}

/// Replace the first `/SubFilter` entry of the field's `/SV` with an
/// unknown name.
fn break_sv_subfilter(sv: &SigSeedValueSpec) -> Vec<u8> {
    let input = prepare_sv_field(sv, false);
    let mut w = PdfUpdate::new(&input).unwrap();
    let field = fields::enumerate_sig_fields(&w, None, Some("Sig"))
        .unwrap()
        .remove(0);
    let sv_id = w
        .get_dict(field.id)
        .unwrap()
        .get(b"SV")
        .unwrap()
        .as_reference()
        .unwrap();
    let d = w.get_dict_mut(sv_id).unwrap();
    if let Ok(Object::Array(a)) = d.get_mut(b"SubFilter") {
        a[0] = name("this.doesnt.exist");
    }
    w.write().unwrap().0
}

fn sign_plain(input: &[u8], m: PdfSignatureMetadata) -> sigis_pki_core::errors::Result<Vec<u8>> {
    PdfSigner::new(m, Arc::new(from_ca()))
        .at(at(T))
        .with_timestamper(Arc::new(pki("testing-ca").tsa("tsa", at(T))))
        .sign_pdf(input)
}

#[test]
fn test_sv_subfilter_unsupported() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::SUBFILTER,
        subfilters: Some(vec![SigSeedSubFilter::Pades]),
        ..Default::default()
    };
    let frozen = break_sv_subfilter(&sv);
    assert!(matches!(
        sign_plain(&frozen, meta()),
        Err(HankoError::Unsupported(_))
    ));
    let mut m = meta();
    m.subfilter = Some(SubFilter::Pades);
    assert!(matches!(
        sign_plain(&frozen, m),
        Err(HankoError::Unsupported(_))
    ));
}

#[test]
fn test_sv_subfilter_unsupported_partial() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::SUBFILTER,
        subfilters: Some(vec![
            SigSeedSubFilter::AdobePkcs7Detached,
            SigSeedSubFilter::Pades,
        ]),
        ..Default::default()
    };
    let frozen = break_sv_subfilter(&sv);
    sign_plain(&frozen, meta()).unwrap();
    let mut m = meta();
    m.subfilter = Some(SubFilter::Pkcs7Detached);
    assert!(matches!(
        sign_plain(&frozen, m),
        Err(HankoError::Signing(_))
    ));
}

#[test]
fn test_sv_sign_reason_req() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::REASONS,
        reasons: Some(vec!["I agree".into(), "Works for me".into()]),
        ..Default::default()
    };
    let reason = |r: &str| {
        let mut m = meta();
        m.reason = Some(r.into());
        m
    };
    assert!(is_signing_err(sign_with_sv(&sv, reason("Aw yiss"), false)));
    sign_with_sv(&sv, reason("Aw yiss"), true).unwrap();
    assert!(is_signing_err(sign_with_sv(&sv, meta(), false)));
    sign_with_sv(&sv, meta(), true).unwrap();
    let out = sign_with_sv(&sv, reason("I agree"), false).unwrap();
    assert_eq!(
        embedded_signatures(&out)[0].sig.get(b"Reason").unwrap(),
        &Object::string_literal("I agree")
    );
}

#[test]
fn test_sv_sign_reason_prohibited() {
    for reasons in [None, Some(vec![]), Some(vec![".".to_owned()])] {
        let sv = SigSeedValueSpec {
            flags: SigSeedValFlags::REASONS,
            reasons: reasons.clone(),
            ..Default::default()
        };
        let reason = |r: &str| {
            let mut m = meta();
            m.reason = Some(r.into());
            m
        };
        assert!(is_signing_err(sign_with_sv(&sv, reason("Aw yiss"), false)));
        sign_with_sv(&sv, reason("Aw yiss"), true).unwrap();
        assert!(is_signing_err(sign_with_sv(&sv, reason("."), false)));
        sign_with_sv(&sv, reason("."), true).unwrap();
        let out = sign_with_sv(&sv, meta(), false).unwrap();
        assert!(embedded_signatures(&out)[0].sig.get(b"Reason").is_err());
    }
}

#[test]
fn test_sv_lock_certify() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::LOCK_DOCUMENT,
        lock_document: Some(SeedLockDocument::Lock),
        ..Default::default()
    };
    sign_with_sv(&sv, certify(MdpPerm::NoChanges), false).unwrap();
    sign_with_sv(&sv, certify(MdpPerm::FillForms), false).unwrap();
    sign_with_sv(&sv, certify(MdpPerm::FillForms), true).unwrap();
    sign_with_sv(&sv, certify(MdpPerm::Annotate), false).unwrap();
    sign_with_sv(&sv, certify(MdpPerm::Annotate), true).unwrap();
    sign_with_sv(&sv, meta(), false).unwrap();
}

#[test]
fn test_sv_no_lock_certify() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::LOCK_DOCUMENT,
        lock_document: Some(SeedLockDocument::DoNotLock),
        ..Default::default()
    };
    sign_with_sv(&sv, certify(MdpPerm::FillForms), false).unwrap();
    sign_with_sv(&sv, certify(MdpPerm::Annotate), false).unwrap();
    sign_with_sv(&sv, certify(MdpPerm::FillForms), false).unwrap();
    sign_with_sv(&sv, meta(), false).unwrap();
    sign_with_sv(&sv, certify(MdpPerm::NoChanges), true).unwrap();
}

#[test]
fn test_field_lock_compat() {
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::LOCK_DOCUMENT,
        lock_document: Some(SeedLockDocument::Lock),
        ..Default::default()
    };
    sign_with_sv_opts(&sv, meta(), false, true, true).unwrap();
    let sv = SigSeedValueSpec {
        flags: SigSeedValFlags::LOCK_DOCUMENT,
        lock_document: Some(SeedLockDocument::DoNotLock),
        ..Default::default()
    };
    assert!(is_signing_err(sign_with_sv_opts(
        &sv,
        meta(),
        false,
        true,
        true
    )));
}

#[test]
fn test_key_usage_decode() {
    let cases: [(&[&str], &[&str], &str); 3] = [
        (&["digital_signature", "crl_sign"], &[], "1XXXXX1XX"),
        (&[], &["digital_signature", "crl_sign"], "0XXXXX0XX"),
        (
            &["digital_signature", "non_repudiation"],
            &["data_encipherment"],
            "11X0XXXXX",
        ),
    ];
    for (must, forbidden, s) in cases {
        let ku = SigCertKeyUsage::read_from_sv_string(s);
        assert_eq!(ku, SigCertKeyUsage::from_sets(must, forbidden));
        assert_eq!(ku.encode_to_sv_string(), s);
    }
}

#[test]
fn test_key_usage_decode_tolerance() {
    let empty = SigCertKeyUsage::read_from_sv_string("");
    assert!(empty.must_have.is_empty() && empty.forbidden.is_empty());
    let too_long = SigCertKeyUsage::read_from_sv_string("100XX1XX0XX11X");
    assert_eq!(
        too_long,
        SigCertKeyUsage::from_sets(
            &["digital_signature", "key_cert_sign"],
            &["non_repudiation", "key_encipherment", "decipher_only"]
        )
    );
}

#[test]
fn test_cert_constraint_deserialisation() {
    let w = PdfUpdate::new(&pdf("minimal.pdf")).unwrap();
    let s1 = from_ca().signing_cert().clone();
    let s2 = self_sign_cert();
    let c = SigCertConstraints {
        subjects: Some(vec![s1.clone(), s2.clone()]),
        ..SigCertConstraints::new()
    };
    let parsed = SigCertConstraints::from_pdf_object(&w, &c.as_pdf_object()).unwrap();
    assert_eq!(parsed.subjects.unwrap(), vec![s1.clone(), s2.clone()]);
    assert!(parsed.issuers.is_none());
    let c = SigCertConstraints {
        issuers: Some(vec![s1.clone(), s2.clone()]),
        ..SigCertConstraints::new()
    };
    let parsed = SigCertConstraints::from_pdf_object(&w, &c.as_pdf_object()).unwrap();
    assert_eq!(parsed.issuers.unwrap(), vec![s1.clone(), s2]);
    assert!(parsed.subjects.is_none());
    let dn = name_keyval_pairs(s1.subject());
    let c = SigCertConstraints {
        subject_dn: Some(dn.clone()),
        ..SigCertConstraints::new()
    };
    let ser = c.as_pdf_object();
    let entry = ser.get(b"SubjectDN").unwrap().as_array().unwrap()[0]
        .as_dict()
        .unwrap();
    assert!(entry.get(b"C").is_ok());
    let parsed = SigCertConstraints::from_pdf_object(&w, &ser).unwrap();
    assert_eq!(parsed.subject_dn.unwrap(), dn);
}
