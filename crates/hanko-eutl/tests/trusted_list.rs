// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_trusted_list.py`
// (MIT, see LICENSE-pyHanko). Test names keep the upstream names; a
// `__<case>` suffix marks a parametrized case.

#![allow(non_snake_case)]

mod common;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use hanko_core::time::Moment;
use hanko_eutl::fetch::{
    bootstrap_lotl_signers, lotl_to_registry, FetchOptions, FileSystemTlCache, InMemoryTlCache,
    PathFetcher, RetryPolicy, TlCache, TlFetchError,
};
use hanko_eutl::parse::{
    self, interpret_service, interpret_service_info_for_tsps, latest_known_lotl_tlso_certs,
    ServiceInterpreter, STATUS_GRANTED,
};
use hanko_eutl::tsp::{Qualifier, CA_QC_URI};
use hanko_eutl::util::load_certs_from_pemder;
use hanko_eutl::xml;

fn read_cas(name: &str) -> Vec<hanko_eutl::tsp::QualifiedServiceInformation> {
    let (sds, _) = parse::read_qualified_service_definitions(&tl_file(name)).unwrap();
    sds.into_iter().filter(|s| s.is_ca()).collect()
}

fn read_qtsts(name: &str) -> Vec<hanko_eutl::tsp::QualifiedServiceInformation> {
    let (sds, _) = parse::read_qualified_service_definitions(&tl_file(name)).unwrap();
    sds.into_iter().filter(|s| !s.is_ca()).collect()
}

#[test]
fn test_parse_cas_from_real_tl_smoke_test() {
    let cas = read_cas(TEST_REAL_TL_BE_OLD);
    let current = cas
        .iter()
        .filter(|c| c.base_info.valid_until.is_none())
        .count();
    assert_eq!(current, 28);
    assert_eq!(cas.len(), 74);
}

#[test]
fn test_parse_qtsts_from_real_tl_smoke_test() {
    let q = read_qtsts(TEST_REAL_TL_BE_OLD);
    let current = q
        .iter()
        .filter(|c| c.base_info.valid_until.is_none())
        .count();
    assert_eq!(current, 17);
    assert_eq!(q.len(), 18);
}

#[test]
fn test_parse_services_from_real_tl_smoke_test() {
    let (registry, errors) =
        parse::trust_list_to_registry_unsafe(&tl_file(TEST_REAL_TL_BE_OLD), None).unwrap();
    assert!(errors.is_empty());
    assert_eq!(registry.known_timestamp_authorities().len(), 17);
    assert_eq!(registry.known_certificate_authorities().len(), 20);
}

#[test]
fn test_parse_services_from_real_tl_with_validation_smoke_test() {
    // freeze_time("2025-06-01T00:05:00+00:00")
    let at = moment("2025-06-01T00:05:00Z");
    let (registry, errors) = parse::trust_list_to_registry(
        &tl_file(TEST_REAL_TL_BE_OLD),
        &[be_tlso_cert()],
        None,
        Some(at),
    )
    .unwrap();
    assert!(errors.is_empty());
    assert_eq!(registry.known_timestamp_authorities().len(), 17);
    assert_eq!(registry.known_certificate_authorities().len(), 20);
}

#[test]
fn test_validate_tl_wrong_signature() {
    // Upstream runs at the current time; the outcome does not depend on it.
    let at = moment("2025-06-01T00:05:00Z");
    let err =
        parse::trust_list_to_registry(&tl_file(TEST_REAL_TL_EE), &[be_tlso_cert()], None, Some(at))
            .unwrap_err();
    assert!(matches!(err, parse::EutlError::Signature(_)), "{err:?}");
    // Also at the current time.
    let err =
        parse::trust_list_to_registry(&tl_file(TEST_REAL_TL_EE), &[be_tlso_cert()], None, None)
            .unwrap_err();
    assert!(matches!(err, parse::EutlError::Signature(_)), "{err:?}");
}

#[test]
fn test_parse_lotl() {
    parse::parse_lotl_unsafe(&tl_file(TEST_REAL_LOTL)).unwrap();
}

const LOTL_PIVOTS: [&str; 4] = [
    "eu-lotl-pivot-282.xml",
    "eu-lotl-pivot-300.xml",
    "eu-lotl-pivot-335.xml",
    "eu-lotl-pivot-341.xml",
];

fn serve_tl_file(url: &str) -> Result<String, TlFetchError> {
    let name = PathFetcher::path_of(url)
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_owned();
    Ok(tl_file(&name))
}

fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        tries: 3,
        base_delay: Duration::from_millis(10),
    }
}

fn check_lotl_signers(results: &[hanko_core::cert::Cert], reference: &str) {
    let got: BTreeSet<[u8; 32]> = results.iter().map(|c| c.sha256()).collect();
    let target = if reference == "pre-reanchor" {
        load_certs_from_pemder(&std::fs::read(tl_path("pre-reanchor.cert.pem")).unwrap()).unwrap()
    } else {
        latest_known_lotl_tlso_certs()
    };
    let want: BTreeSet<[u8; 32]> = target.iter().map(|c| c.sha256()).collect();
    assert_eq!(got, want);
}

fn bootstrap_post_reanchor(pass_empty_cache: bool) {
    let fetcher = PathFetcher::new();
    let cache = InMemoryTlCache::new();
    let opts = FetchOptions {
        cache: pass_empty_cache.then_some(&cache as &dyn TlCache),
        retry: fast_retry(),
    };
    let results =
        bootstrap_lotl_signers(&tl_file(TEST_REAL_LOTL), &fetcher, None, opts, 1).unwrap();
    check_lotl_signers(&results, "latest");
}

#[test]
fn test_bootstrap_signers_post_reanchor__pass_empty_cache_true() {
    bootstrap_post_reanchor(true);
}

#[test]
fn test_bootstrap_signers_post_reanchor__pass_empty_cache_false() {
    bootstrap_post_reanchor(false);
}

fn pivot_fetcher() -> PathFetcher {
    let mut f = PathFetcher::new();
    for p in LOTL_PIVOTS {
        f = f.route(&format!("/tools/lotl/{p}"), serve_tl_file);
    }
    f
}

fn bootstrap_old(pass_empty_cache: bool) {
    let fetcher = pivot_fetcher();
    let cache = InMemoryTlCache::new();
    let opts = FetchOptions {
        cache: pass_empty_cache.then_some(&cache as &dyn TlCache),
        retry: fast_retry(),
    };
    let results =
        bootstrap_lotl_signers(&tl_file(TEST_REAL_LOTL_OLD), &fetcher, None, opts, 1).unwrap();
    check_lotl_signers(&results, "pre-reanchor");
}

#[test]
fn test_bootstrap_signers_old__pass_empty_cache_true() {
    bootstrap_old(true);
}

#[test]
fn test_bootstrap_signers_old__pass_empty_cache_false() {
    bootstrap_old(false);
}

#[test]
fn test_bootstrap_signers_with_populated_cache() {
    let cache = InMemoryTlCache::new();
    for p in LOTL_PIVOTS {
        cache.set(&format!("https://ec.europa.eu/tools/lotl/{p}"), &tl_file(p));
    }
    let fetcher = PathFetcher::new();
    let opts = FetchOptions {
        cache: Some(&cache),
        retry: fast_retry(),
    };
    let results =
        bootstrap_lotl_signers(&tl_file(TEST_REAL_LOTL_OLD), &fetcher, None, opts, 1).unwrap();
    check_lotl_signers(&results, "pre-reanchor");
}

#[test]
fn test_bootstrap_signers_request_retry() {
    let seen = Arc::new(Mutex::new(BTreeSet::<String>::new()));
    let mut fetcher = PathFetcher::new();
    for p in LOTL_PIVOTS {
        let seen = seen.clone();
        fetcher = fetcher.route(&format!("/tools/lotl/{p}"), move |url| {
            let path = PathFetcher::path_of(url).to_owned();
            if seen.lock().unwrap().insert(path) {
                Err(TlFetchError::Status {
                    status: 503,
                    reason: "Service Unavailable".into(),
                    url: url.into(),
                })
            } else {
                serve_tl_file(url)
            }
        });
    }
    let opts = FetchOptions {
        cache: None,
        retry: fast_retry(),
    };
    let results =
        bootstrap_lotl_signers(&tl_file(TEST_REAL_LOTL_OLD), &fetcher, None, opts, 0).unwrap();
    check_lotl_signers(&results, "pre-reanchor");
}

#[test]
fn test_bootstrap_signers_request_fail() {
    let fetcher = PathFetcher::new();
    let opts = FetchOptions {
        cache: None,
        retry: fast_retry(),
    };
    let err =
        bootstrap_lotl_signers(&tl_file(TEST_REAL_LOTL_OLD), &fetcher, None, opts, 0).unwrap_err();
    assert!(err.0.contains("Failed to process pivot LOTL"), "{err}");
}

#[test]
fn test_bootstrap_signers_request_outage() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut fetcher = PathFetcher::new();
    for p in LOTL_PIVOTS {
        let calls = calls.clone();
        fetcher = fetcher.route(&format!("/tools/lotl/{p}"), move |url| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(TlFetchError::Status {
                status: 503,
                reason: "Service Unavailable".into(),
                url: url.into(),
            })
        });
    }
    let opts = FetchOptions {
        cache: None,
        retry: fast_retry(),
    };
    let err =
        bootstrap_lotl_signers(&tl_file(TEST_REAL_LOTL_OLD), &fetcher, None, opts, 0).unwrap_err();
    assert!(err.0.contains("Failed to process pivot LOTL"), "{err}");
    // Three attempts on the first pivot, then the bootstrap gives up.
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn test_validate_and_parse_lotl_default_certs() {
    // Upstream validates at the current time; pin it to the issuance date.
    let lotl = tl_file(TEST_REAL_LOTL);
    let issued = parse::parse_lotl_unsafe(&lotl).unwrap().claimed_date_issued;
    parse::validate_and_parse_lotl(&lotl, None, Some(issued)).unwrap();
}

fn lotl_app() -> PathFetcher {
    PathFetcher::new()
        .route("/tools/lotl/eu-lotl.xml", serve_tl_file)
        .route("/tsl-be-v6.xml", serve_tl_file)
}

/// Pinned validation time for the LOTL tests (upstream: current time).
fn lotl_time() -> Moment {
    moment("2026-06-16T00:00:00Z")
}

#[test]
fn test_parse_services_from_real_tl_via_lotl() {
    let fetcher = lotl_app();
    let opts = FetchOptions {
        cache: None,
        retry: fast_retry(),
    };
    let (registry, errors) =
        lotl_to_registry(None, &fetcher, None, opts, None, None, Some(lotl_time())).unwrap();
    let dl = errors
        .iter()
        .filter(|e| e.0.contains("Failed to download"))
        .count();
    assert_eq!(dl, 30, "{errors:?}");
    assert_eq!(registry.known_timestamp_authorities().len(), 19);
    assert_eq!(registry.known_certificate_authorities().len(), 29);
}

#[test]
fn test_parse_services_from_real_tl_via_selective_lotl() {
    let fetcher = lotl_app();
    let opts = FetchOptions {
        cache: None,
        retry: fast_retry(),
    };
    let only: BTreeSet<String> = ["BE".to_owned()].into_iter().collect();
    let (registry, errors) = lotl_to_registry(
        None,
        &fetcher,
        None,
        opts,
        None,
        Some(&only),
        Some(lotl_time()),
    )
    .unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(registry.known_timestamp_authorities().len(), 19);
    assert_eq!(registry.known_certificate_authorities().len(), 29);
}

const NAMESPACES: &str = concat!(
    r#"xmlns="http://uri.etsi.org/02231/v2#" "#,
    r#"xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" "#,
    r#"xmlns:q="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" "#,
    r#"xmlns:extra="http://uri.etsi.org/02231/v2/additionaltypes#""#
);

fn service_xml(info_body: &str) -> String {
    format!("<TSPService {NAMESPACES}><ServiceInformation>{info_body}</ServiceInformation></TSPService>")
}

const DEFAULT_HEAD: &str = r#"
            <ServiceName>
                <Name xml:lang="en">Test</Name>
            </ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>"#;

fn interpret_ca(
    xml_text: &str,
) -> Result<hanko_eutl::tsp::QualifiedServiceInformation, hanko_eutl::tsp::TspServiceParsingError> {
    let doc = xml::parse(xml_text).unwrap();
    interpret_service(doc.root_element(), ServiceInterpreter::Ca)
}

#[test]
fn test_parse_ca_with_unsupported_critical_qualifier() {
    let x = service_xml(&format!(
        r#"{DEFAULT_HEAD}
            <ServiceInformationExtensions>
                <Extension Critical="true">
                    <blah/>
                </Extension>
            </ServiceInformationExtensions>"#
    ));
    let err = interpret_ca(&x).unwrap_err();
    assert!(err.0.contains("critical"), "{err}");
}

#[test]
fn test_parse_ca_with_unsupported_noncritical_extension() {
    let x = service_xml(&format!(
        r#"{DEFAULT_HEAD}
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <blah/>
                </Extension>
            </ServiceInformationExtensions>"#
    ));
    interpret_ca(&x).unwrap();
}

#[test]
fn test_parse_ca_with_extensions() {
    let qual_xml = r#"
    <q:Qualifiers>
        <q:Qualifier
        uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"/>
    </q:Qualifiers>
    <q:CriteriaList assert="all">
        <q:KeyUsage>
            <q:KeyUsageBit name="nonRepudiation">true</q:KeyUsageBit>
        </q:KeyUsage>
        <q:PolicySet>
            <q:PolicyIdentifier>
                <xades:Identifier>2.999</xades:Identifier>
            </q:PolicyIdentifier>
        </q:PolicySet>
        <q:otherCriteriaList>
            <extra:CertSubjectDNAttribute>
                <extra:AttributeOID>
                    <xades:Identifier>2.999</xades:Identifier>
                </extra:AttributeOID>
            </extra:CertSubjectDNAttribute>
            <extra:ExtendedKeyUsage>
                <extra:KeyPurposeId>
                    <xades:Identifier>2.999</xades:Identifier>
                </extra:KeyPurposeId>
            </extra:ExtendedKeyUsage>
        </q:otherCriteriaList>
    </q:CriteriaList>"#;
    let x = service_xml(&format!(
        r#"{DEFAULT_HEAD}
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <q:Qualifications>
                        <q:QualificationElement>
                            {qual_xml}
                        </q:QualificationElement>
                    </q:Qualifications>
                </Extension>
                <Extension Critical="false">
                    <ExpiredCertsRevocationInfo>
                        2016-06-30T21:00:00Z
                    </ExpiredCertsRevocationInfo>
                </Extension>
            </ServiceInformationExtensions>"#
    ));
    let result = interpret_ca(&x).unwrap();
    assert_eq!(
        result.expired_certs_revocation_info(),
        Some(moment("2016-06-30T21:00:00Z"))
    );
    let q = &result.qualifications[0];
    assert_eq!(q.qualifiers, [Qualifier::WithSscd].into_iter().collect());
    let crit = &q.criteria_list.criteria;
    use hanko_eutl::tsp::Criterion;
    use hanko_validate::settings::KeyUsageConstraints;
    assert!(crit.contains(&Criterion::PolicySet(set(&["2.999"]))));
    assert!(crit.contains(&Criterion::KeyUsage(KeyUsageConstraints {
        key_usage: Some(set(&["non_repudiation"])),
        key_usage_forbidden: Some(BTreeSet::new()),
        ..KeyUsageConstraints::new()
    })));
    assert!(crit.contains(&Criterion::KeyUsage(
        KeyUsageConstraints::with_extd_key_usage(["2.999"])
    )));
    assert!(crit.contains(&Criterion::CertSubjectDn(set(&["2.999"]))));
}

fn omit_empty_or_unknown_quals(qualifiers: &str) {
    let qual_xml = format!(
        r#"
    {qualifiers}
    <q:CriteriaList assert="all">
        <q:KeyUsage>
            <q:KeyUsageBit name="nonRepudiation">true</q:KeyUsageBit>
        </q:KeyUsage>
        <q:PolicySet>
            <q:PolicyIdentifier>
                <xades:Identifier>2.999</xades:Identifier>
            </q:PolicyIdentifier>
        </q:PolicySet>
    </q:CriteriaList>"#
    );
    let x = service_xml(&format!(
        r#"{DEFAULT_HEAD}
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <q:Qualifications>
                        <q:QualificationElement>
                            {qual_xml}
                        </q:QualificationElement>
                    </q:Qualifications>
                </Extension>
            </ServiceInformationExtensions>"#
    ));
    assert!(interpret_ca(&x).unwrap().qualifications.is_empty());
}

#[test]
fn test_parse_omit_empty_or_unknown_quals__none() {
    omit_empty_or_unknown_quals("");
}

#[test]
fn test_parse_omit_empty_or_unknown_quals__empty() {
    omit_empty_or_unknown_quals("<q:Qualifiers/>");
}

#[test]
fn test_parse_omit_empty_or_unknown_quals__unknown() {
    omit_empty_or_unknown_quals(r#"<q:Qualifiers><q:Qualifier uri="urn:blah"/></q:Qualifiers>"#);
}

#[test]
fn test_parse_service_name() {
    for names in [
        r#"<Name xml:lang="en">Test</Name>"#,
        r#"<Name xml:lang="nl">Test</Name>"#,
        r#"<Name xml:lang="en">Test</Name><Name xml:lang="nl">Fout</Name>"#,
        r#"<Name xml:lang="nl">Fout</Name><Name xml:lang="en">Test</Name>"#,
        r#"<Name xml:lang="nl">Test</Name><Name xml:lang="zz">Zzz</Name>"#,
    ] {
        let x = service_xml(&format!(
            r#"<ServiceName>{names}</ServiceName>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>2020-11-01T00:00:00Z</StatusStartingTime>"#
        ));
        assert_eq!(
            interpret_ca(&x).unwrap().base_info.service_name,
            "Test",
            "{names}"
        );
    }
}

#[test]
fn test_parse_service_validity_dates() {
    for date in ["2020-11-01T00:00:00Z", "2020-11-01T01:00:00+01:00"] {
        let x = service_xml(&format!(
            r#"<ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                {date}
            </StatusStartingTime>"#
        ));
        assert_eq!(
            interpret_ca(&x).unwrap().base_info.valid_from,
            moment("2020-11-01T00:00:00Z")
        );
    }
}

#[test]
fn test_reject_service_without_status_starting_time() {
    let x = service_xml(
        r#"<ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>"#,
    );
    let err = interpret_ca(&x).unwrap_err();
    assert!(err.0.contains("validity start"), "{err}");
}

#[test]
fn test_criteria_parsing_failure() {
    let qual_xml = r#"
    <q:Qualifiers>
        <q:Qualifier
        uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"/>
    </q:Qualifiers>"#;
    for criteria_xml in [
        " ",
        r#"<q:CriteriaList assert="all"/>"#,
        r#"<q:CriteriaList assert="all"><q:otherCriteriaList><blah/></q:otherCriteriaList></q:CriteriaList>"#,
        r#"<q:CriteriaList assert="all"><q:KeyUsage><q:KeyUsageBit name="nonRepudiation">true</q:KeyUsageBit></q:KeyUsage><q:otherCriteriaList><blah/></q:otherCriteriaList></q:CriteriaList>"#,
    ] {
        let x = service_xml(&format!(
            r#"{DEFAULT_HEAD}
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <q:Qualifications>
                        <q:QualificationElement>
                            {qual_xml}
                            {criteria_xml}
                        </q:QualificationElement>
                    </q:Qualifications>
                </Extension>
            </ServiceInformationExtensions>"#
        ));
        assert!(interpret_ca(&x).is_err(), "{criteria_xml}");
    }
}

#[test]
fn test_parse_service_no_type() {
    let x = service_xml(
        r#"<ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>2020-11-01T00:00:00Z</StatusStartingTime>"#,
    );
    let err = interpret_ca(&x).unwrap_err();
    assert!(err.0.contains("Service type"), "{err}");
}

fn history_xml(second_item: &str) -> String {
    format!(
        r#"<TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
            <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
        </ServiceInformation>
        <ServiceHistory>
            <ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
                <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
                <ServiceDigitalIdentity/>
                <StatusStartingTime>
                    2017-11-01T00:00:00Z
                </StatusStartingTime>
            </ServiceHistoryInstance>
            {second_item}
        </ServiceHistory>
    </TSPService>"#
    )
}

fn intervals(x: &str) -> Vec<(Moment, Option<Moment>)> {
    let doc = xml::parse(x).unwrap();
    let (sds, _) =
        interpret_service_info_for_tsps([doc.root_element()], CA_QC_URI, ServiceInterpreter::Ca);
    sds.iter()
        .map(|r| (r.base_info.valid_from, r.base_info.valid_until))
        .collect()
}

#[test]
fn test_parse_service_history_intervals() {
    let x = history_xml(&format!(
        r#"<ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
                <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
                <ServiceDigitalIdentity/>
                <StatusStartingTime>
                    2019-11-01T00:00:00Z
                </StatusStartingTime>
            </ServiceHistoryInstance>"#
    ));
    let (d1, d2, d3) = (
        moment("2017-11-01T00:00:00Z"),
        moment("2019-11-01T00:00:00Z"),
        moment("2020-11-01T00:00:00Z"),
    );
    assert_eq!(
        intervals(&x),
        vec![(d3, None), (d2, Some(d3)), (d1, Some(d2))]
    );
}

#[test]
fn test_parse_service_history_intervals_skip_not_granted() {
    let x = history_xml(&format!(
        r#"<ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
                <ServiceStatus>urn:blah</ServiceStatus>
                <ServiceDigitalIdentity/>
                <StatusStartingTime>
                    2019-11-01T00:00:00Z
                </StatusStartingTime>
            </ServiceHistoryInstance>"#
    ));
    let (d1, d2, d3) = (
        moment("2017-11-01T00:00:00Z"),
        moment("2019-11-01T00:00:00Z"),
        moment("2020-11-01T00:00:00Z"),
    );
    assert_eq!(intervals(&x), vec![(d3, None), (d1, Some(d2))]);
}

#[test]
fn test_parse_service_history_intervals_skip_invalid_entries() {
    let x = history_xml(&format!(
        r#"<ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
                <StatusStartingTime>2019-11-01T00:00:00Z</StatusStartingTime>
            </ServiceHistoryInstance>"#
    ));
    let iv = intervals(&x);
    assert_eq!(iv.len(), 2);
    assert_eq!(iv[0], (moment("2020-11-01T00:00:00Z"), None));
}

// FileSystemTLCache tests.

fn clock_at(m: &Arc<Mutex<Moment>>) -> hanko_eutl::fetch::Clock {
    let m = m.clone();
    Arc::new(move || *m.lock().unwrap())
}

fn tmp() -> TempDir {
    TempDir::new()
}

#[test]
fn test_fs_cache_reload_from_disk() {
    let d = tmp();
    let fs = FileSystemTlCache::new(d.path(), Duration::from_secs(60)).unwrap();
    fs.set("foo", "bar");
    fs.set("baz", "quux");
    let fs2 = FileSystemTlCache::new(d.path(), Duration::from_secs(60)).unwrap();
    assert_eq!(fs2.get("foo").as_deref(), Some("bar"));
    assert_eq!(fs2.get("baz").as_deref(), Some("quux"));
}

#[test]
fn test_fs_cache_accepts_str_path() {
    let d = tmp();
    let p: String = d.path().to_str().unwrap().to_owned();
    let fs = FileSystemTlCache::new(p.as_str(), Duration::from_secs(60)).unwrap();
    fs.set("foo", "bar");
    assert_eq!(fs.get("foo").as_deref(), Some("bar"));
}

const DAY: u64 = 86_400;

#[test]
fn test_fs_cache_keep_until_expiry() {
    let d = tmp();
    let now = Arc::new(Mutex::new(moment("2025-08-28T00:00:00Z")));
    let fs = FileSystemTlCache::with_clock(d.path(), Duration::from_secs(10 * DAY), clock_at(&now))
        .unwrap();
    fs.set("foo", "bar");
    fs.set("baz", "quux");
    *now.lock().unwrap() = moment("2025-08-31T00:00:00Z");
    assert_eq!(fs.get("foo").as_deref(), Some("bar"));
    assert_eq!(fs.get("baz").as_deref(), Some("quux"));
}

#[test]
fn test_fs_cache_reload_from_disk_before_expiry() {
    let d = tmp();
    let now = Arc::new(Mutex::new(moment("2025-08-28T00:00:00Z")));
    let fs = FileSystemTlCache::with_clock(d.path(), Duration::from_secs(10 * DAY), clock_at(&now))
        .unwrap();
    fs.set("foo", "bar");
    fs.set("baz", "quux");
    *now.lock().unwrap() = moment("2025-08-31T00:00:00Z");
    let fs2 =
        FileSystemTlCache::with_clock(d.path(), Duration::from_secs(10 * DAY), clock_at(&now))
            .unwrap();
    assert_eq!(fs2.get("foo").as_deref(), Some("bar"));
    assert_eq!(fs2.get("baz").as_deref(), Some("quux"));
}

#[test]
fn test_fs_cache_expire() {
    let d = tmp();
    let now = Arc::new(Mutex::new(moment("2025-08-28T00:00:00Z")));
    let fs =
        FileSystemTlCache::with_clock(d.path(), Duration::from_secs(DAY), clock_at(&now)).unwrap();
    fs.set("foo", "bar");
    fs.set("baz", "quux");
    *now.lock().unwrap() = moment("2025-08-31T00:00:00Z");
    assert_eq!(fs.get("foo"), None);
}

#[test]
fn test_fs_cache_expire_after_reload() {
    let d = tmp();
    let now = Arc::new(Mutex::new(moment("2025-08-28T00:00:00Z")));
    let fs =
        FileSystemTlCache::with_clock(d.path(), Duration::from_secs(DAY), clock_at(&now)).unwrap();
    fs.set("foo", "bar");
    fs.set("baz", "quux");
    *now.lock().unwrap() = moment("2025-08-31T00:00:00Z");
    let fs2 =
        FileSystemTlCache::with_clock(d.path(), Duration::from_secs(DAY), clock_at(&now)).unwrap();
    assert_eq!(fs2.get("foo"), None);
}

#[test]
fn test_fs_cache_io_failure() {
    let d = tmp();
    let now = Arc::new(Mutex::new(moment("2025-08-28T00:00:00Z")));
    let fs = FileSystemTlCache::with_clock(d.path(), Duration::from_secs(10 * DAY), clock_at(&now))
        .unwrap();
    fs.set("foo", "bar");
    fs.set("baz", "quux");
    std::fs::remove_file(d.path().join(fs.file_name("foo").unwrap())).unwrap();
    assert_eq!(fs.get("foo"), None);
}

#[test]
fn test_fs_cache_reload_and_reset() {
    let d = tmp();
    let now = Arc::new(Mutex::new(moment("2025-08-28T00:00:00Z")));
    let fs = FileSystemTlCache::with_clock(d.path(), Duration::from_secs(10 * DAY), clock_at(&now))
        .unwrap();
    fs.set("foo", "bar");
    fs.set("baz", "quux");
    *now.lock().unwrap() = moment("2025-08-31T00:00:00Z");
    let fs2 =
        FileSystemTlCache::with_clock(d.path(), Duration::from_secs(10 * DAY), clock_at(&now))
            .unwrap();
    fs2.reset();
    assert_eq!(fs.get("foo"), None);
    assert_eq!(fs.get("baz"), None);
    assert_eq!(fs2.get("foo"), None);
    assert_eq!(fs2.get("baz"), None);
}

// Qualification of real certificates against a real trusted list.

fn validation_context_from_file(
    name: &str,
    at: Moment,
) -> (
    hanko_eutl::tsp::TspRegistry,
    hanko_certvalidator::ValidationContext,
) {
    let (registry, _) = parse::trust_list_to_registry_unsafe(&tl_file(name), None).unwrap();
    let tm = hanko_eutl::tsp::TspTrustManager::new(&registry);
    let mut b = hanko_certvalidator::ValidationContext::builder()
        .revinfo_policy(hanko_certvalidator::CertRevTrustPolicy::new(
            hanko_certvalidator::NO_REVOCATION,
        ))
        .moment(at);
    for a in tm.trust_anchors_at(at) {
        b = b.trust_anchor(a);
    }
    let ctx = b.build().unwrap();
    (registry, ctx)
}

fn crypto_cert(name: &str) -> hanko_core::cert::Cert {
    let data = std::fs::read(common::data(&["pyhanko", "crypto", name])).unwrap();
    load_certs_from_pemder(&data).unwrap().remove(0)
}

#[test]
fn test_validate_real_qcert_no_revo() {
    use hanko_eutl::q_status::QcPrivateKeyManagementType;
    use hanko_eutl::tsp::QcCertType;
    let at = moment("2025-08-06T00:00:00Z");
    let cert = crypto_cert("real-qcert.cer");
    let (registry, ctx) = validation_context_from_file(TEST_REAL_TL_BE_OLD, at);
    let path = hanko_certvalidator::CertificateValidator::new(&ctx, cert)
        .validate()
        .unwrap();
    let result = hanko_eutl::assess::QualificationAssessor::new(&registry)
        .check_entity_cert_qualified(&path, Some(at))
        .unwrap();
    assert!(path
        .trust_anchor()
        .cert()
        .subject()
        .to_string()
        .contains("itsme"));
    assert_eq!(path.len() - 1, 1);
    assert!(result.status.qualified);
    assert_eq!(
        result.service_definition.unwrap().base_info.service_type,
        CA_QC_URI
    );
    assert_eq!(result.status.qc_type, QcCertType::QcEsign);
    assert_eq!(
        result.status.qc_key_security,
        QcPrivateKeyManagementType::Qscd
    );
}

#[test]
fn test_validate_real_qtst_cert_no_revo() {
    use hanko_eutl::q_status::QcPrivateKeyManagementType;
    use hanko_eutl::tsp::{QcCertType, QTST_URI};
    let at = moment("2025-08-06T00:00:00Z");
    let cert = crypto_cert("real-qtst-cert.cer");
    let (registry, ctx) = validation_context_from_file(TEST_REAL_TL_BE_OLD, at);
    let path = hanko_certvalidator::CertificateValidator::new(&ctx, cert)
        .validate()
        .unwrap();
    let result = hanko_eutl::assess::QualificationAssessor::new(&registry)
        .check_entity_cert_qualified(&path, Some(at))
        .unwrap();
    assert!(path
        .trust_anchor()
        .cert()
        .subject()
        .to_string()
        .contains("QTSP: FPS Policy and Support - BOSA"));
    assert_eq!(path.len() - 1, 0);
    assert!(result.status.qualified);
    assert_eq!(
        result.service_definition.unwrap().base_info.service_type,
        QTST_URI
    );
    assert_eq!(result.status.qc_type, QcCertType::QcEseal);
    assert_eq!(
        result.status.qc_key_security,
        QcPrivateKeyManagementType::Unknown
    );
}

#[test]
fn test_conclude_not_qualified_qtst_lacking_qc_statements() {
    use hanko_eutl::tsp::QTST_URI;
    let at = moment("2025-08-06T00:00:00Z");
    let cert = crypto_cert("real-misissued-qtst-cert.cer");
    let (registry, ctx) = validation_context_from_file(TEST_REAL_TL_EE, at);
    let path = hanko_certvalidator::CertificateValidator::new(&ctx, cert)
        .validate()
        .unwrap();
    let result = hanko_eutl::assess::QualificationAssessor::new(&registry)
        .check_entity_cert_qualified(&path, Some(at))
        .unwrap();
    assert!(path
        .trust_anchor()
        .cert()
        .subject()
        .to_string()
        .contains("SK TIMESTAMPING UNIT 2025E"));
    assert_eq!(path.len() - 1, 0);
    assert!(!result.status.qualified);
    assert_eq!(
        result.service_definition.unwrap().base_info.service_type,
        QTST_URI
    );
}

#[test]
fn test_tl_override_processing() {
    use hanko_eutl::assess::QualificationAssessor;
    use hanko_eutl::q_status::{QcPrivateKeyManagementType as K, QualifiedStatus};
    use hanko_eutl::tsp::QcCertType as T;
    let st = |qualified, qc_type, qc_key_security| QualifiedStatus {
        qualified,
        qc_type,
        qc_key_security,
    };
    // (prelim, qualifiers, expected (qualified?, qc_type?, key?))
    #[allow(clippy::type_complexity)]
    let cases: Vec<(
        QualifiedStatus,
        Vec<Qualifier>,
        (Option<bool>, Option<T>, Option<K>),
    )> = vec![
        (
            st(true, T::QcEsign, K::Qscd),
            vec![Qualifier::NotQualified],
            (Some(false), None, Some(K::Unknown)),
        ),
        (
            st(false, T::QcEsign, K::Qscd),
            vec![Qualifier::QcStatement],
            (Some(true), None, Some(K::Qscd)),
        ),
        (
            st(false, T::QcEsign, K::Qscd),
            vec![Qualifier::WithQscd],
            (Some(false), None, Some(K::Unknown)),
        ),
        (
            st(true, T::QcEsign, K::Unknown),
            vec![Qualifier::WithQscd],
            (Some(true), None, Some(K::Qscd)),
        ),
        (
            st(true, T::QcEsign, K::Unknown),
            vec![Qualifier::WithSscd],
            (Some(true), None, Some(K::Qscd)),
        ),
        (
            st(true, T::QcEsign, K::Unknown),
            vec![Qualifier::ForEseal],
            (Some(true), Some(T::QcEseal), None),
        ),
        (
            st(true, T::QcEseal, K::Unknown),
            vec![Qualifier::ForEsig],
            (Some(true), Some(T::QcEsign), None),
        ),
        (
            st(true, T::QcEsign, K::Unknown),
            vec![Qualifier::ForWsa],
            (Some(true), Some(T::QcWeb), None),
        ),
        (
            st(true, T::QcEseal, K::Qscd),
            vec![Qualifier::QscdManagedOnBehalf],
            (None, None, Some(K::QscdDelegated)),
        ),
        (
            st(true, T::QcEsign, K::Qscd),
            vec![Qualifier::NoQscd],
            (Some(true), None, Some(K::Unknown)),
        ),
        (
            st(true, T::QcEsign, K::Qscd),
            vec![Qualifier::NoSscd],
            (Some(true), None, Some(K::Unknown)),
        ),
        (
            st(true, T::QcEsign, K::Qscd),
            vec![Qualifier::QscdAsInCert],
            (Some(true), None, Some(K::Qscd)),
        ),
    ];
    assert_eq!(cases.len(), 12);
    for (prelim, quals, (q, t, k)) in cases {
        let r = QualificationAssessor::final_status(prelim, &quals.iter().copied().collect());
        if let Some(q) = q {
            assert_eq!(r.qualified, q, "{prelim:?} {quals:?}");
        }
        if let Some(t) = t {
            assert_eq!(r.qc_type, t, "{prelim:?} {quals:?}");
        }
        if let Some(k) = k {
            assert_eq!(r.qc_key_security, k, "{prelim:?} {quals:?}");
        }
    }
}
