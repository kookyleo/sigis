// Ported from pyhanko-certvalidator 0.33.0 `tests/test_common_utils.py`
// (MIT, see LICENSE-pyHanko).

mod common;

use common::{load_cert, read_cv};
use der::Decode;
use hanko_core::asn1::tlv;
use hanko_fetch::common::{
    enumerate_delivery_point_urls, gather_aia_issuer_urls, gather_aia_issuer_urls_ac,
    unpack_cert_content, ACCEPTABLE_CERT_DER_ALIASES, ACCEPTABLE_PKCS7_DER_ALIASES,
};
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::CrlDistributionPoints;

const URL: &str = "http://example.com";

fn with_ldap_urls() -> hanko_core::cert::Cert {
    load_cert(&["testing-aia", "with-ldap-urls.der"])
}

fn attribute_cert(name: &str) -> Vec<u8> {
    read_cv(&["attribute-certs", "basic-aa", "aa", name])
}

#[test]
fn test_unpack_cert_content_der() {
    let der = with_ldap_urls().der().to_vec();
    let mut cts: Vec<Option<&str>> = vec![None];
    cts.extend(ACCEPTABLE_CERT_DER_ALIASES.iter().map(|c| Some(*c)));
    for ct in cts {
        let certs = unpack_cert_content(&der, ct, URL, false).expect("unpack");
        assert_eq!(certs.len(), 1, "{ct:?}");
    }
}

#[test]
fn test_unpack_content_unknown_der() {
    let empty_seq = [0x30, 0x00];
    let e = unpack_cert_content(&empty_seq, None, URL, false).expect_err("unknown");
    assert!(e.0.contains("Failed to heuristically"), "{e}");
}

fn content_info(content_type_der: &[u8], content: &[u8]) -> Vec<u8> {
    let mut body = content_type_der.to_vec();
    body.extend(tlv::encode(0xa0, content));
    tlv::encode(0x30, &body)
}

#[test]
fn test_unpack_content_bad_pkcs7() {
    use der::Encode;
    let data = content_info(
        &hanko_core::asn1::oids::CT_DATA.to_der().unwrap(),
        &tlv::encode(0x04, b""),
    );
    let e = unpack_cert_content(&data, None, URL, false).expect_err("bad pkcs7");
    assert!(e.0.contains("Expected CMS SignedData"), "{e}");
}

#[test]
fn test_unpack_cert_content_pem() {
    let pem = read_cv(&["testing-ca-ed25519", "interm.cert.pem"]);
    let certs = unpack_cert_content(&pem, Some("anything/goes"), URL, true).expect("pem");
    assert_eq!(certs.len(), 1);
}

#[test]
fn test_unpack_cert_content_pem_multiple() {
    let pem = read_cv(&["certs_to_unpack", "many-certs.pem"]);
    let certs = unpack_cert_content(&pem, Some("any"), URL, true).expect("pem");
    assert_eq!(certs.len(), 2);
}

#[test]
fn test_unpack_cert_content_forbid_pem() {
    let pem = read_cv(&["testing-ca-ed25519", "interm.cert.pem"]);
    let e = unpack_cert_content(&pem, Some("anything/goes"), URL, false).expect_err("forbid");
    assert!(e.0.contains("Failed to extract"), "{e}");
}

#[test]
fn test_unpack_cert_content_pkcs7() {
    let p7 = read_cv(&["certs_to_unpack", "test.p7b"]);
    let mut cts: Vec<Option<&str>> = vec![None];
    cts.extend(ACCEPTABLE_PKCS7_DER_ALIASES.iter().map(|c| Some(*c)));
    for ct in cts {
        let certs = unpack_cert_content(&p7, ct, URL, true).expect("pkcs7");
        assert_eq!(certs.len(), 2, "{ct:?}");
    }
}

#[test]
fn test_unpack_cert_content_pkcs7_pem() {
    let p7 = read_cv(&["certs_to_unpack", "test.p7b.pem"]);
    let certs = unpack_cert_content(&p7, Some("any"), URL, true).expect("pkcs7 pem");
    assert_eq!(certs.len(), 2);
}

fn cert_dps() -> Vec<DistributionPoint> {
    with_ldap_urls()
        .extension::<CrlDistributionPoints>()
        .unwrap()
        .unwrap()
        .1
        .0
}

#[test]
fn test_crl_distribution_point_enumeration_skip_ldap() {
    let dps = cert_dps();
    assert_eq!(dps.len(), 1);
    let urls = enumerate_delivery_point_urls(&dps[0]);
    assert_eq!(urls.len(), 1);
    assert!(urls[0].starts_with("http://"));
}

#[test]
fn test_crl_distribution_point_enumeration_skip_relative() {
    let cert = with_ldap_urls();
    let rdn = cert.issuer().as_ref().iter().next().unwrap().clone();
    let dp = DistributionPoint {
        distribution_point: Some(DistributionPointName::NameRelativeToCRLIssuer(rdn)),
        reasons: None,
        crl_issuer: None,
    };
    assert!(enumerate_delivery_point_urls(&dp).is_empty());
}

#[test]
fn test_crl_distribution_point_enumeration_skip_non_uri() {
    let cert = with_ldap_urls();
    let dp = DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![
            GeneralName::DirectoryName(cert.issuer().clone()),
        ])),
        reasons: None,
        crl_issuer: None,
    };
    assert!(enumerate_delivery_point_urls(&dp).is_empty());
}

#[test]
fn test_gather_issuer_urls_cert() {
    assert_eq!(
        gather_aia_issuer_urls(&with_ldap_urls()),
        vec!["http://repo.ca.example.com".to_owned()]
    );
}

#[test]
fn test_gather_issuer_urls_ac() {
    assert_eq!(
        gather_aia_issuer_urls_ac(&attribute_cert("alice-role-with-rev.attr.crt")),
        vec!["http://localhost:9000/basic-aa/certs/interm/ca.crt".to_owned()]
    );
}

#[test]
fn test_gather_issuer_urls_ac_no_aia() {
    assert!(gather_aia_issuer_urls_ac(&attribute_cert("alice-role-norev.attr.crt")).is_empty());
}

#[test]
fn test_unpack_content_empty_pkcs7() {
    use der::Encode;
    // SignedData { v1, {}, {data}, [certificates], {} } in three variants.
    let ac = attribute_cert("alice-role-with-rev.attr.crt");
    let ac_tlv = tlv::Tlv::parse_exact(&ac).unwrap();
    let ac_choice = tlv::encode(0xa2, ac_tlv.value);
    let eci = tlv::encode(0x30, &hanko_core::asn1::oids::CT_DATA.to_der().unwrap());
    for certificates in [None, Some(Vec::new()), Some(ac_choice)] {
        let mut sd = tlv::encode(0x02, &[1]);
        sd.extend(tlv::encode(0x31, &[]));
        sd.extend(&eci);
        if let Some(c) = certificates {
            sd.extend(tlv::encode(0xa0, &c));
        }
        sd.extend(tlv::encode(0x31, &[]));
        let data = content_info(
            &hanko_core::asn1::oids::CT_SIGNED_DATA.to_der().unwrap(),
            &tlv::encode(0x30, &sd),
        );
        let certs = unpack_cert_content(&data, None, URL, false).expect("empty pkcs7");
        assert!(certs.is_empty());
    }
    let _ = DistributionPoint::from_der(&[]).is_err();
}
