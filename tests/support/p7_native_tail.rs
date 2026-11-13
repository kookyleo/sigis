// Tests-first ROOT integration helper draft. No standalone test is registered.
// Apply only after an actual P sign_case factory is composed at ROOT; do not
// add a pades dev dependency to pades-sign or count a helper as an upstream ID.
use der::Decode;
use sigis_cms::attributes::{IetfAttrSyntax, IetfAttrValue, RoleSyntax};
use sigis_cms::status::{AttributeMap, StandardCmsSignatureStatus};
use sigis_cms::CmsValidationOptions;
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_options, LtaOptions},
};
use sigis_pdf::{PdfFile, SignatureKind};
use sigis_pki_certvalidator::{CertRevTrustPolicy, ValidationContext, REQUIRE_REVINFO};
use sigis_pki_core::time::Moment;
use x509_cert::ext::pkix::name::GeneralName;

fn p7_role(attrs: &AttributeMap) {
    let role = attrs.get("role").expect("authenticated role");
    let value = role.attr_values.first().expect("original first role value");
    let role = RoleSyntax::from_der(value).expect("typed original RoleSyntax");
    let GeneralName::Rfc822Name(name) = role.role_name else {
        panic!("original roleName must be rfc822Name");
    };
    assert_eq!(name.as_str(), "bigboss@example.com");
}

fn p7_claimed_group(attrs: &AttributeMap) {
    assert_eq!(attrs.len(), 1);
    assert!(!attrs.contains("role"));
    let single = attrs.0.values().next().unwrap();
    assert_eq!(single, attrs.get("group").unwrap());
    assert_eq!(single.attr_values.len(), 1);
    let syntax = IetfAttrSyntax::from_der(&single.attr_values[0]).unwrap();
    let groups: std::collections::BTreeSet<_> = syntax
        .values
        .iter()
        .map(|value| match value {
            IetfAttrValue::String(text) => text.as_str(),
            _ => panic!("original IetfAttrSyntax groups are strings"),
        })
        .collect();
    assert_eq!(
        groups,
        std::collections::BTreeSet::from(["Executives", "Employees"])
    );
}

// Supplemental zero-ID control. Historical main-signature recovery does not
// authorize a role from stale current-time AC evidence under REQUIRE_REVINFO.
pub(crate) fn assert_stale_current_ac_response_not_authenticated(
    output: &[u8],
    main: &ValidationContext,
    ac: &ValidationContext,
) {
    assert_eq!(
        ac.moment(),
        Moment::parse_rfc3339("2028-02-01T00:00:00Z").unwrap()
    );
    assert_eq!(
        ac.revinfo_policy().revocation_checking_policy,
        REQUIRE_REVINFO
    );
    let file = PdfFile::parse(output).unwrap();
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.kind == SignatureKind::Signature)
        .unwrap();
    let result = lta_validation_with_options(
        &file,
        &signature,
        main,
        &QualificationSpec::default(),
        &LtaOptions {
            ac_validation_context: Some(ac),
            ..Default::default()
        },
    )
    .unwrap();
    let status = result.api_status.unwrap();
    assert!(status.bottom_line());
    assert!(status
        .ac_attrs
        .as_ref()
        .is_some_and(|attrs| !attrs.contains("role")));
    let errors = status.ac_validation_errs.as_ref().unwrap();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("OCSP response is not recent enough")),
        "{errors:?}"
    );
    eprintln!(
        "P7_STALE_AC_DENIAL {}",
        serde_json::json!({"validation_time":"2028-02-01T00:00:00Z","mandatory_ac_policy":true,"authenticated_role":false,"errors":errors})
    );
}

// Context contract: FRESH validation contexts, root-only/no preloaded revinfo.
// First two cases use REQUIRE_REVINFO; remaining cases use live_ac_vcs' default
// soft-fail. The historical LTA case uses 2028-02-01, not the signing epoch.
pub(crate) fn assert_p7_native_tail(
    name: &str,
    output: &[u8],
    main: &ValidationContext,
    ac: &ValidationContext,
) {
    let historical = name == "test_pades_lta_live_ac_presign_validation";
    let live = name.contains("live_ac_presign_validation");
    let at = Moment::parse_rfc3339(if historical {
        "2028-02-01T00:00:00Z"
    } else {
        "2020-11-01T00:00:00Z"
    })
    .unwrap();
    for context in [main, ac] {
        assert_eq!(context.moment(), at);
        assert!(!context.timing().point_in_time_validation);
        assert!(context.other_certs().is_empty());
        assert!(context.crls().next().is_none());
        assert!(context.ocsps().next().is_none());
        assert_eq!(context.trust_anchors().len(), 1);
        if live {
            assert_eq!(
                context.revinfo_policy().revocation_checking_policy,
                REQUIRE_REVINFO
            );
        } else {
            assert_eq!(context.revinfo_policy(), &CertRevTrustPolicy::default());
        }
    }
    let file = PdfFile::parse(output).unwrap();
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.kind == SignatureKind::Signature)
        .unwrap();
    let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
    let embedded = sigis_cms::signed_data::extract_certificate_info(&sd).unwrap();
    if name == "test_cades_signer_attrs_autofill_dss" {
        assert_eq!(
            file.dss()
                .unwrap()
                .expect("autofilled DSS")
                .material
                .certs
                .len(),
            7
        );
        return; // This original case has ONE post-sign assertion, no status check.
    }
    if live {
        if !historical {
            assert_eq!(embedded.other_certs.len(), 5);
            assert_eq!(embedded.attribute_certs.len(), 1);
            let material = file.dss().unwrap().expect("collected DSS").material;
            assert_eq!(material.certs.len(), 8);
            assert_eq!(material.ocsps.len(), 2);
            assert_eq!(material.crls.len(), 3);
        }
        let result = lta_validation_with_options(
            &file,
            &signature,
            main,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(ac),
                ..Default::default()
            },
        )
        .expect("actual V archival API over actual new P output");
        let sub = result.ades_subindic.standard_name();
        let status = result.api_status.expect("original API status");
        eprintln!(
            "P7_NATIVE_AC_STATUS case={name} subindication={sub} ac_errors={:?}",
            status.ac_validation_errs
        );
        assert!(status.bottom_line(), "{sub}: {status:?}");
        let attrs = status
            .ac_attrs
            .as_ref()
            .expect("authenticated AC attributes");
        assert_eq!(attrs.len(), 1);
        p7_role(attrs);
        // Original checks api_status.bottom_line, not final AdESPassed.OK.
        eprintln!("P7_NATIVE_LTA case={name} actual_subindication={sub}");
        return;
    }

    assert!(embedded.attribute_certs.is_empty());
    let wrong = name == "test_cades_signer_attrs_validate_acs_wrong_vc";
    let missing = name == "test_cades_signer_attrs_validate_acs_missing_vc";
    let no_claimed = name == "test_cades_signer_attrs_validate_acs_no_claimed";
    let options = CmsValidationOptions {
        ac_validation_context: if missing {
            None
        } else if wrong {
            Some(main)
        } else {
            Some(ac)
        },
        ..Default::default()
    };
    let status = sigis_pades::validate_pdf_signature_with_options(
        &file,
        &signature,
        main,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
        &options,
    )
    .unwrap();
    let cms: &StandardCmsSignatureStatus = &status.cms;
    let cades = cms
        .cades_signer_attrs
        .as_ref()
        .expect("actual signer-attrs-v2 status");
    if wrong {
        assert!(!cades.valid());
        assert!(status.summary().contains("CERTIFIED_SIGNER_ATTRS_INVALID"));
        assert_eq!(cms.ac_attrs.as_ref().unwrap().len(), 0);
        assert_eq!(cades.claimed_attrs.len(), 1);
        assert_eq!(cades.certified_attrs.as_ref().unwrap().len(), 0);
        assert_eq!(cms.ac_validation_errs.as_ref().unwrap().len(), 1);
        assert_eq!(cades.ac_validation_errs.as_ref().unwrap().len(), 1);
        assert!(!cades.unknown_attrs_present);
    } else if missing {
        assert!(status.bottom_line());
        assert!(!status.summary().contains("CERTIFIED_SIGNER_ATTRS_INVALID"));
        assert!(cms.ac_attrs.is_none());
        assert_eq!(cades.claimed_attrs.len(), 1);
        assert!(cades.certified_attrs.is_none());
        assert!(cms.ac_validation_errs.is_none());
        assert!(cades.ac_validation_errs.is_none());
    } else {
        assert!(status.bottom_line());
        let attrs = cms.ac_attrs.as_ref().unwrap();
        p7_role(attrs);
        let certified = cades.certified_attrs.as_ref().unwrap();
        assert_eq!(certified.len(), 1);
        p7_role(certified);
        if no_claimed {
            assert!(!status.summary().contains("CERTIFIED_SIGNER_ATTRS_INVALID"));
            assert!(cades.claimed_attrs.is_empty());
            assert!(!cades.unknown_attrs_present);
        } else {
            assert!(!attrs.contains("group"));
            p7_claimed_group(&cades.claimed_attrs);
            assert!(!certified.contains("group"));
        }
    }
}
