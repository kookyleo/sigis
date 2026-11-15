//! Finite EUTL-only AdES command derived from pyHanko 0.38.1 (MIT).
//!
//! The authenticated registry remains owned for the complete full-LTA operation.
//! Configured roots follow the upstream non-qualified CA-service synthesis.
use crate::{config::CliConfig, runtime::ValidationRuntime};
use clap::Parser;
use serde_json::{Map, Value};
use sigis_eutl::{
    assess::{enforce_requirements, QualificationRequirements, RequiredServiceType},
    fetch::{fetch_lotl, FetchOptions, FileSystemTlCache, RetryPolicy, TlFetchError, TlFetcher},
    parse::{self, LOTL_RULE, STATUS_GRANTED},
    tsp::{
        Authority, BaseServiceInformation, CriteriaCombination, CriteriaList, Qualification,
        QualifiedServiceInformation, Qualifier, TspRegistry, CA_QC_URI, QTST_URI,
    },
    xml::{self, DSIG_NS, TSL_NS, XML_NS},
};
use sigis_pades::ades::{
    basic::{qualification_analysis, QualificationSpec},
    lta::{lta_validation_with_ades_options, LtaOptions, LtaValidationResult},
    AdesIndeterminate, AdesPassed, AdesSubIndic, AdesValidationOptions,
};
use sigis_pdf::{reader::ReaderOptions, PdfFile, SignatureKind};
use sigis_pki_certvalidator::{
    authority::{
        Authority as CvAuthority, TrustAnchor, TrustManager, TrustQualifiers, TrustedServiceType,
    },
    policy::{CertRevTrustPolicy, FreshnessReqType, NO_REVOCATION, REQUIRE_REVINFO},
    ValidationContext,
};
use sigis_pki_core::{cert::Cert, key_usage::KeyUsageConstraints, time::Moment};
use sigis_pki_fetch::{transport::HttpRequest, HttpTransport, ReqwestTransport};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

const MAX_TL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "adesverify")]
struct Args {
    #[arg(long)]
    eutl_all: bool,
    #[arg(long)]
    require_qualified: bool,
    #[arg(long)]
    pretty_print: bool,
    #[arg(long)]
    validation_context: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    no_strict_syntax: bool,
    #[arg(long)]
    no_decode_limits: bool,
    #[arg(long)]
    eutl_force_redownload: bool,
    #[arg(long)]
    validation_time: Option<String>,
    #[arg(long)]
    no_revocation_check: bool,
    infile: String,
}

/// Only represented inputs reach this carrier; no opaque context slot exists.
struct Resolved {
    tolerance: Duration,
    cache: PathBuf,
    lotl_url: String,
    tlso_path: Option<String>,
    force: bool,
    extra_trust: Vec<Cert>,
    territories: Option<BTreeSet<String>>,
    // Retained provenance: EUTL mode never adds OS roots.
    _trust_replace: bool,
}

fn get<'a>(m: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    m.get(key).or_else(|| m.get(key.replace('-', "_").as_str()))
}

fn typed_bool(m: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    get(m, key)
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| format!("ENTRY: '{key}' must be a boolean."))
        })
        .transpose()
}

fn optional_string(m: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match get(m, key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(v.clone())),
        _ => Err(format!("ENTRY: '{key}' must be a string or null.")),
    }
}

fn resolve(a: &Args, config: Option<&CliConfig>) -> Result<Resolved, String> {
    let config =
        config.ok_or("ENTRY: EUTL validation requires an explicit config file and cache-dir.")?;
    let raw = config.validation_settings_raw(a.validation_context.as_deref())?;
    let m = raw
        .as_object()
        .ok_or("ENTRY: The validation context requires a dictionary.")?;
    let allowed = [
        "trust",
        "trust-replace",
        "other-certs",
        "time-tolerance",
        "retroactive-revinfo",
        "signer-key-usage",
        "signer-extd-key-usage",
        "signer-key-usage-policy",
        "eutl-force-redownload",
        "eutl-lotl-url",
        "lotl-tlso-certs",
        "eutl-territories",
        "revocation-policy",
    ];
    crate::config::reject_unsupported_outer_aliases(m, &allowed)?;
    for key in m.keys() {
        if !allowed.contains(&key.replace('_', "-").as_str()) {
            return Err(format!(
                "ENTRY: Unsupported qualified-validation setting '{key}'."
            ));
        }
    }
    // Check source values before a permissive getter can coerce them or load
    // certificate paths. Nonempty static/other certificates are not this mode.
    if let Some(value) = get(m, "other-certs") {
        if !value.as_array().is_some_and(Vec::is_empty) {
            return Err(
                "ENTRY: Nonempty or malformed 'other-certs' is unsupported in EUTL-only mode."
                    .into(),
            );
        }
    }
    let trust_replace = typed_bool(m, "trust-replace")?.unwrap_or(false);
    let force = typed_bool(m, "eutl-force-redownload")?.unwrap_or(false);
    if let Some(v) = get(m, "revocation-policy") {
        if v.as_str() != Some("require") {
            return Err("ENTRY: Only the default revocation-policy 'require' is supported.".into());
        }
    }
    let global = config
        .raw_config
        .as_object()
        .ok_or("ENTRY: CLIConfig requires a dictionary.")?;
    // Root-level unknown values must not become an opaque policy input.
    let global_allowed = [
        "validation-contexts",
        "default-validation-context",
        "time-tolerance",
        "retroactive-revinfo",
        "cache-dir",
        "logging",
        "plugins",
        "stamp-styles",
        "default-stamp-style",
        "identities",
    ];
    crate::config::reject_unsupported_outer_aliases(global, &global_allowed)?;
    for key in global.keys() {
        if !global_allowed.contains(&key.replace('_', "-").as_str()) {
            return Err(format!("ENTRY: Unsupported CLIConfig setting '{key}'."));
        }
    }
    let global_retroactive = typed_bool(global, "retroactive-revinfo")?.unwrap_or(false);
    if typed_bool(m, "retroactive-revinfo")?.unwrap_or(global_retroactive) {
        return Err(
            "ENTRY: Retroactive revocation information is unsupported in this profile.".into(),
        );
    }
    let seconds = |mapping: &Map<String, Value>| -> Result<Option<u64>, String> {
        match get(mapping, "time-tolerance") {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .map(Some)
                .ok_or_else(|| "ENTRY: time-tolerance must be a nonnegative integer.".into()),
        }
    };
    let global_tolerance = seconds(global)?;
    let tolerance = seconds(m)?.unwrap_or(global_tolerance.filter(|v| *v != 0).unwrap_or(30));
    if let Some(v) = get(m, "eutl-territories") {
        let valid = match v {
            Value::String(s) => !s.trim().is_empty(),
            Value::Array(ss) => {
                !ss.is_empty()
                    && ss
                        .iter()
                        .all(|s| s.as_str().is_some_and(|s| !s.trim().is_empty()))
            }
            _ => false,
        };
        if !valid {
            return Err("ENTRY: eutl-territories must be a nonempty string or string list before --eutl-all override.".into());
        }
    }
    // Validate nested flags strictly; key_usages owns aliases and usage syntax.
    if let Some(policy) = get(m, "signer-key-usage-policy") {
        let policy = policy
            .as_object()
            .ok_or("ENTRY: signer-key-usage-policy requires a dictionary.")?;
        typed_bool(policy, "match-all-key-usages")?;
        typed_bool(policy, "explicit-extd-key-usage-required")?;
    }
    let usage = config.key_usages(a.validation_context.as_deref())?;
    if usage != crate::config::KeyUsagePolicy::default() {
        return Err(
            "ENTRY: Nondefault MAIN key usage policy is unsupported by the original AdES profile."
                .into(),
        );
    }
    // The effective getter is validation, never a context factory. Raw schema
    // and certificate admission above precede every potential certificate I/O.
    let effective = config.validation_settings(a.validation_context.as_deref())?;
    if !effective.other_certs.is_empty() {
        return Err("ENTRY: Nonempty other-certificate evidence is unsupported.".into());
    }
    if effective.retroactive_revinfo
        || effective.key_usage != crate::config::KeyUsagePolicy::default()
    {
        return Err(
            "ENTRY: The effective policy is outside the original default AdES profile.".into(),
        );
    }
    let cache = config
        .cache_dir
        .as_ref()
        .ok_or("ENTRY: An explicit cache-dir is required.")?;
    if get(global, "cache-dir").and_then(Value::as_str) != Some(cache.as_str()) {
        return Err("ENTRY: cache-dir must be an explicit string.".into());
    }
    Ok(Resolved {
        tolerance: Duration::from_secs(tolerance),
        cache: PathBuf::from(cache).join("eutl"),
        lotl_url: optional_string(m, "eutl-lotl-url")?
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| sigis_eutl::fetch::EU_LOTL_LOCATION.into()),
        tlso_path: optional_string(m, "lotl-tlso-certs")?.filter(|s| !s.is_empty()),
        force: a.eutl_force_redownload || force,
        extra_trust: effective.trust_roots,
        territories: None,
        _trust_replace: trust_replace,
    })
}

#[derive(Debug)]
struct TransportFetcher(Arc<dyn HttpTransport>);

impl TlFetcher for TransportFetcher {
    fn get(&self, url: &str) -> Result<String, TlFetchError> {
        let response = self
            .0
            .send(&HttpRequest {
                method: "GET",
                url,
                headers: vec![("Accept".into(), sigis_eutl::fetch::ACCEPT_TYPES.join(", "))],
                body: None,
            })
            .map_err(|e| TlFetchError::Network(e.to_string()))?;
        if !(200..300).contains(&response.status) {
            return Err(TlFetchError::Status {
                status: response.status,
                reason: "HTTP request failed".into(),
                url: url.into(),
            });
        }
        if response.body.len() > MAX_TL_BYTES {
            return Err(TlFetchError::Network(format!(
                "Trusted-list body exceeds {MAX_TL_BYTES} bytes."
            )));
        }
        String::from_utf8(response.body)
            .map_err(|e| TlFetchError::Network(format!("Trusted list is not UTF-8: {e}")))
    }
}

#[derive(Debug)]
struct ServiceSlot {
    provider: usize,
    service: usize,
    role: String,
    name: String,
    start: String,
    certificates: usize,
}

/// Inspect the exact authenticated Reference string, without serialising it.
/// Every element outside a retained XMLDSig subtree has a closed QName shape.
fn guard(signed: &str) -> Result<Vec<ServiceSlot>, String> {
    let doc = xml::parse(signed).map_err(|e| format!("GUARD: {e}"))?;
    let root = doc.root_element();
    if !xml::is(root, TSL_NS, "TrustServiceStatusList") {
        return Err("GUARD: The authenticated root is not TSL TrustServiceStatusList.".into());
    }
    let mut ids = BTreeSet::new();
    for node in doc.descendants() {
        if node.is_pi() {
            return Err("GUARD: Processing instructions are unsupported.".into());
        }
        if !node.is_element() {
            continue;
        }
        for attr in node.attributes() {
            if matches!(attr.name(), "Id" | "ID" | "id") && !ids.insert(attr.value().to_owned()) {
                return Err("GUARD: Duplicate XML identity attribute.".into());
            }
        }
        let in_signature = node.ancestors().any(|a| xml::is(a, DSIG_NS, "Signature"));
        if in_signature && !xml::is(node, DSIG_NS, "Signature") {
            let security_name = matches!(
                node.tag_name().name(),
                "TrustServiceStatusList"
                    | "TrustServiceProviderList"
                    | "TrustServiceProvider"
                    | "TSPServices"
                    | "TSPService"
                    | "ServiceInformation"
                    | "ServiceTypeIdentifier"
                    | "ServiceName"
                    | "ServiceDigitalIdentity"
                    | "ServiceStatus"
                    | "StatusStartingTime"
                    | "ServiceHistory"
                    | "ServiceHistoryInstance"
                    | "ServiceInformationExtensions"
            );
            if node.tag_name().namespace() == Some(TSL_NS) || security_name {
                return Err("GUARD: TSL structures inside Signature are unsupported.".into());
            }
            continue;
        }
        let name = node.tag_name().name();
        if node.tag_name().namespace() == Some(DSIG_NS) && name == "Signature" {
            if node.parent_element() != Some(root)
                || root
                    .children()
                    .filter(|n| xml::is(*n, DSIG_NS, "Signature"))
                    .count()
                    > 1
            {
                return Err("GUARD: Misplaced or duplicate retained Signature.".into());
            }
            continue;
        }
        if node.tag_name().namespace() != Some(TSL_NS) {
            return Err(format!("GUARD: Unsupported QName for '{name}'."));
        }
        let (parent, children, text_only): (&str, &[(&str, usize, usize)], bool) = match name {
            "TrustServiceStatusList" => (
                "",
                &[
                    ("SchemeInformation", 1, 1),
                    ("TrustServiceProviderList", 1, 1),
                    ("Signature", 0, 1),
                ],
                false,
            ),
            "SchemeInformation" => (
                "TrustServiceStatusList",
                &[("ListIssueDateTime", 1, 1)],
                false,
            ),
            "ListIssueDateTime" => ("SchemeInformation", &[], true),
            "TrustServiceProviderList" => (
                "TrustServiceStatusList",
                &[("TrustServiceProvider", 1, usize::MAX)],
                false,
            ),
            "TrustServiceProvider" => ("TrustServiceProviderList", &[("TSPServices", 1, 1)], false),
            "TSPServices" => (
                "TrustServiceProvider",
                &[("TSPService", 1, usize::MAX)],
                false,
            ),
            "TSPService" => ("TSPServices", &[("ServiceInformation", 1, 1)], false),
            "ServiceInformation" => (
                "TSPService",
                &[
                    ("ServiceTypeIdentifier", 1, 1),
                    ("ServiceName", 1, 1),
                    ("ServiceDigitalIdentity", 1, 1),
                    ("ServiceStatus", 1, 1),
                    ("StatusStartingTime", 1, 1),
                ],
                false,
            ),
            "ServiceTypeIdentifier" | "ServiceStatus" | "StatusStartingTime" => {
                ("ServiceInformation", &[], true)
            }
            "ServiceName" => ("ServiceInformation", &[("Name", 1, 1)], false),
            "Name" => ("ServiceName", &[], true),
            "ServiceDigitalIdentity" => {
                ("ServiceInformation", &[("DigitalId", 1, usize::MAX)], false)
            }
            "DigitalId" => (
                "ServiceDigitalIdentity",
                &[("X509Certificate", 1, 1)],
                false,
            ),
            "X509Certificate" => ("DigitalId", &[], true),
            "ServiceHistory" | "ServiceHistoryInstance" | "ServiceInformationExtensions" => {
                return Err(format!(
                    "GUARD: Unsupported history/extensions structure '{name}'."
                ))
            }
            _ => return Err(format!("GUARD: Unsupported TSL element '{name}'.")),
        };
        if parent.is_empty() {
            if node != root {
                return Err("GUARD: Misplaced TSL root.".into());
            }
        } else if !node
            .parent_element()
            .is_some_and(|p| xml::is(p, TSL_NS, parent))
        {
            return Err(format!("GUARD: Misplaced '{name}'."));
        }
        for attr in node.attributes() {
            let permitted = (node == root && attr.namespace().is_none() && attr.name() == "Id")
                || (name == "Name" && attr.namespace() == Some(XML_NS) && attr.name() == "lang");
            if !permitted {
                return Err(format!("GUARD: Unsupported attribute on '{name}'."));
            }
        }
        for child in node.children() {
            if child.is_text() && !text_only && child.text().is_some_and(|t| !t.trim().is_empty()) {
                return Err(format!("GUARD: Mixed text in '{name}'."));
            }
            if child.is_element()
                && !children.iter().any(|(allowed, _, _)| {
                    let ns = if node == root && *allowed == "Signature" {
                        DSIG_NS
                    } else {
                        TSL_NS
                    };
                    xml::is(child, ns, allowed)
                })
            {
                return Err(format!("GUARD: Unsupported child in '{name}'."));
            }
        }
        for (child, min, max) in children {
            let ns = if node == root && *child == "Signature" {
                DSIG_NS
            } else {
                TSL_NS
            };
            let count = node.children().filter(|n| xml::is(*n, ns, child)).count();
            if count < *min || count > *max {
                return Err(format!(
                    "GUARD: Invalid cardinality of '{child}' in '{name}'."
                ));
            }
        }
        if text_only && xml::text_content(node).trim().is_empty() {
            return Err(format!("GUARD: Empty '{name}'."));
        }
        if name == "ServiceTypeIdentifier"
            && !matches!(xml::collapsed_text(node).as_str(), CA_QC_URI | QTST_URI)
        {
            return Err("GUARD: Unsupported service role.".into());
        }
        if name == "ServiceStatus" && xml::collapsed_text(node) != STATUS_GRANTED {
            return Err("GUARD: Only granted current services are supported.".into());
        }
    }
    let mut slots = Vec::new();
    // Match the public reader's provider order, then CA/QTST partition order.
    for (provider, tsp) in root
        .descendants()
        .filter(|n| xml::is(*n, TSL_NS, "TrustServiceProvider"))
        .enumerate()
    {
        for role in [CA_QC_URI, QTST_URI] {
            for (service, info) in tsp
                .descendants()
                .filter(|n| xml::is(*n, TSL_NS, "ServiceInformation"))
                .enumerate()
            {
                // Cardinalities above establish each lookup is unique.
                let field = |name| info.children().find(|n| xml::is(*n, TSL_NS, name));
                let actual_role = field("ServiceTypeIdentifier")
                    .map(xml::collapsed_text)
                    .ok_or("GUARD: Missing role.")?;
                if actual_role != role {
                    continue;
                }
                let name = field("ServiceName")
                    .and_then(|n| n.children().find(|n| xml::is(*n, TSL_NS, "Name")))
                    .map(xml::text_content)
                    .ok_or("GUARD: Missing name.")?;
                let start = field("StatusStartingTime")
                    .map(xml::collapsed_text)
                    .ok_or("GUARD: Missing start.")?;
                let certificates = info
                    .descendants()
                    .filter(|n| xml::is(*n, TSL_NS, "X509Certificate"))
                    .count();
                slots.push(ServiceSlot {
                    provider,
                    service,
                    role: actual_role,
                    name,
                    start,
                    certificates,
                });
            }
        }
    }
    Ok(slots)
}

fn guarded_definitions(signed: &str) -> Result<Vec<QualifiedServiceInformation>, String> {
    let slots = guard(signed)?;
    // The immutable authenticated string is passed to this semantic reader once.
    let (definitions, errors) =
        parse::read_qualified_service_definitions(signed).map_err(|e| format!("SEMANTIC: {e}"))?;
    if !errors.is_empty() {
        return Err(format!(
            "SEMANTIC: {}",
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    if definitions.len() != slots.len() {
        return Err("CENSUS: Service-definition occurrence mismatch.".into());
    }
    for (index, (definition, slot)) in definitions.iter().zip(&slots).enumerate() {
        let info = &definition.base_info;
        if info.service_type != slot.role
            || info.service_name != slot.name
            || Some(info.valid_from) != sigis_eutl::util::parse_xsd_datetime(&slot.start)
            || info.provider_certs.len() != slot.certificates
        {
            return Err(format!(
                "CENSUS: Provider {} service {} differs from its authenticated slot.",
                slot.provider, slot.service
            ));
        }
        for (i, cert) in info.provider_certs.iter().enumerate() {
            if info.provider_certs[..i]
                .iter()
                .any(|prior| prior.der() == cert.der())
            {
                return Err(format!(
                    "CENSUS: Duplicate provider DER in service {index}."
                ));
            }
        }
        if definitions[..index].contains(definition) {
            return Err(
                "CENSUS: Exact duplicate service definition within one trusted list.".into(),
            );
        }
    }
    Ok(definitions)
}

fn load_registry(
    resolved: &Resolved,
    runtime: &ValidationRuntime,
    at: Option<Moment>,
) -> Result<Arc<TspRegistry>, String> {
    let candidates = resolved
        .tlso_path
        .as_ref()
        .map(|path| -> Result<Vec<Cert>, String> {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("LOTL: Failed to read TLSO certificate file: {e}"))?;
            let certs = sigis_pades_sign::keys::load_certs_from_pemder_data(&bytes)
                .map_err(|e| format!("LOTL: {e}"))?;
            if certs.is_empty() {
                return Err("LOTL: TLSO certificate file contains no certificates.".into());
            }
            Ok(certs)
        })
        .transpose()?;
    let cache = FileSystemTlCache::new(&resolved.cache, Duration::from_secs(1_296_000))
        .map_err(|e| format!("CACHE: {e}"))?;
    if resolved.force {
        cache.reset();
    }
    let transport = match &runtime.trusted_list_transport {
        Some(transport) => transport.clone(),
        // Existing transport exposes total timeout, not a separate 2s read
        // hook, TLS-root selection or HTTP reason phrase fidelity.
        None => Arc::new(
            ReqwestTransport::new(Duration::from_secs(30), MAX_TL_BYTES)
                .map_err(|e| format!("TRANSPORT: {e}"))?,
        ),
    };
    let fetcher = TransportFetcher(transport);
    let options = FetchOptions {
        cache: Some(&cache),
        retry: RetryPolicy::default(),
    };
    let lotl = fetch_lotl(&fetcher, options, Some(&resolved.lotl_url))
        .map_err(|e| format!("LOTL download: {e}"))?;
    // Cache reads allocate in the existing cache implementation. This is a
    // parsed-body limit, not a claim that cache-file allocation is bounded.
    if lotl.len() > MAX_TL_BYTES {
        return Err(format!(
            "LOTL: Parsed trusted-list body exceeds {MAX_TL_BYTES} bytes."
        ));
    }
    // The original command does not bootstrap pivots. None/empty candidate
    // fallback belongs to validate_and_parse_lotl, not this factory.
    let lotl = parse::validate_and_parse_lotl(&lotl, candidates.as_deref(), at)
        .map_err(|e| format!("LOTL authentication/parse: {e}"))?;
    let mut errors: Vec<String> = lotl.errors.iter().map(ToString::to_string).collect();
    let mut definitions = Vec::new();
    // --eutl-all resolves to None, so preserve original reference order and
    // LOTL_RULE skipping without exposing a different territory mode.
    for reference in &lotl.references {
        if resolved
            .territories
            .as_ref()
            .is_some_and(|territories| !territories.contains(&reference.territory.to_lowercase()))
        {
            continue;
        }
        if reference.scheme_rules.contains(LOTL_RULE) {
            continue;
        }
        let label = format!("{} at {}", reference.territory, reference.location_uri);
        let raw = match fetch_lotl(&fetcher, options, Some(&reference.location_uri)) {
            Ok(raw) => raw,
            Err(e) => {
                errors.push(format!("Failed to download trusted list for {label}: {e}"));
                continue;
            }
        };
        if raw.len() > MAX_TL_BYTES {
            errors.push(format!("Failed to read trusted list for {label}: Parsed trusted-list body exceeds {MAX_TL_BYTES} bytes."));
            continue;
        }
        let signed = match parse::validate_and_extract_tl_data(&raw, &reference.tlso_certs, at) {
            Ok(signed) => signed,
            Err(e) => {
                errors.push(format!(
                    "Failed to authenticate trusted list for {label}: {e}"
                ));
                continue;
            }
        };
        if signed.len() > MAX_TL_BYTES {
            errors.push(format!("Failed to read authenticated trusted list for {label}: Parsed trusted-list body exceeds {MAX_TL_BYTES} bytes."));
            continue;
        }
        match guarded_definitions(&signed) {
            Ok(rows) => definitions.extend(rows),
            Err(e) => errors.push(format!(
                "Unsupported authenticated trusted-list for {label}: {e}"
            )),
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "Trusted-list loading failed; no registry published:\n{}",
            errors.join("\n")
        ));
    }
    // Upstream EUTL trust roots become non-qualified CA service definitions,
    // rather than static anchors that bypass the dynamic service role/window.
    for cert in &resolved.extra_trust {
        let authority = Authority::of_cert(cert);
        if definitions
            .iter()
            .filter(|service| service.is_ca())
            .any(|service| {
                service
                    .base_info
                    .provider_certs
                    .iter()
                    .any(|provider| Authority::of_cert(provider) == authority)
            })
        {
            continue;
        }
        definitions.push(QualifiedServiceInformation::ca(
            BaseServiceInformation {
                service_type: CA_QC_URI.into(),
                service_name: "Configured certificate authority".into(),
                valid_from: cert.not_before(),
                valid_until: Some(cert.not_after()),
                provider_certs: vec![cert.clone()],
                additional_info_certificate_type: Default::default(),
                other_additional_info: Default::default(),
            },
            [Qualification {
                qualifiers: [Qualifier::NotQualified].into_iter().collect(),
                criteria_list: CriteriaList::new(CriteriaCombination::All, []),
            }],
            None,
        ));
    }
    check_profiles(&definitions)
        .map_err(|error| format!("Unsupported authenticated trusted-list profile: {error}"))?;
    let mut registry = TspRegistry::new();
    // Every occurrence reaches register; identical definitions across separate
    // authenticated lists retain the lower registry's normal dedup semantics.
    for definition in definitions {
        registry.register(definition);
    }
    Ok(Arc::new(registry))
}

/// Ordinary EUTL caller supplies its fully resolved territory selection and
/// validates its complete configuration/policy before this loader-only seam.
/// No AdES default-MAIN/revinfo restrictions or context reconstruction occurs.
pub(crate) fn load_for_validation(
    config: &CliConfig,
    name: Option<&str>,
    runtime: &ValidationRuntime,
    force: bool,
    territories: Option<&BTreeSet<String>>,
) -> Result<Arc<TspRegistry>, String> {
    let raw = config.validation_settings_raw(name)?;
    let mapping = raw
        .as_object()
        .ok_or("Validation context requires a dictionary.")?;
    let settings = config.validation_settings(name)?;
    let cache = config
        .cache_dir
        .as_ref()
        .ok_or("EUTL validation requires an explicit cache-dir.")?;
    let resolved = Resolved {
        tolerance: Duration::from_secs(30),
        cache: PathBuf::from(cache).join("eutl"),
        lotl_url: optional_string(mapping, "eutl-lotl-url")?
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| sigis_eutl::fetch::EU_LOTL_LOCATION.into()),
        tlso_path: optional_string(mapping, "lotl-tlso-certs")?.filter(|s| !s.is_empty()),
        force: force || typed_bool(mapping, "eutl-force-redownload")?.unwrap_or(false),
        extra_trust: settings.trust_roots,
        territories: territories.map(|values| values.iter().map(|s| s.to_lowercase()).collect()),
        _trust_replace: settings.trust_replace,
    };
    load_registry(&resolved, runtime, Some(runtime.now))
}

/// Own the same complete authenticated registry while preserving exact queried
/// DER, actual service roles/windows and CA-only issuer candidates.
pub(crate) fn registry_trust_manager(registry: Arc<TspRegistry>) -> Arc<dyn TrustManager> {
    Arc::new(RegistryTrustManager { registry })
}

fn cv_authority(cert: &Cert) -> CvAuthority {
    CvAuthority {
        name: cert.subject().clone(),
        public_key: cert.public_key(),
    }
}

fn same_raw_authority(a: &Cert, b: &Cert) -> bool {
    a.subject() == b.subject() && a.public_key() == b.public_key()
}

fn equivalent_profile(a: &QualifiedServiceInformation, b: &QualifiedServiceInformation) -> bool {
    // Names and provider DERs identify the descriptive row, not its service
    // transformation for a fixed queried certificate. Intrinsic QC stays on
    // that queried certificate, including the 4099/4098 reference pair.
    a.kind == b.kind
        && a.qualifications == b.qualifications
        && a.base_info.service_type == b.base_info.service_type
        && a.base_info.valid_from == b.base_info.valid_from
        && a.base_info.valid_until == b.base_info.valid_until
        && a.base_info.additional_info_certificate_type
            == b.base_info.additional_info_certificate_type
        && a.base_info.other_additional_info == b.base_info.other_additional_info
}

fn check_profiles(definitions: &[QualifiedServiceInformation]) -> Result<(), String> {
    let providers: Vec<_> = definitions
        .iter()
        .flat_map(|sd| sd.base_info.provider_certs.iter().map(move |c| (c, sd)))
        .collect();
    for (i, (cert, profile)) in providers.iter().enumerate() {
        for (other, other_profile) in &providers[..i] {
            let raw_equal = same_raw_authority(cert, other);
            if cv_authority(cert) == cv_authority(other) && !raw_equal {
                return Err("IDENTITY: CV-normalized-equal/raw-name-distinct registry authorities are unsupported.".into());
            }
            if raw_equal && !equivalent_profile(profile, other_profile) {
                return Err(
                    "PROFILE: Conflicting service transformations for one registry authority."
                        .into(),
                );
            }
        }
    }
    Ok(())
}

/// Own the whole registry. No snapshot or certificate substitution is used.
#[derive(Debug)]
struct RegistryTrustManager {
    registry: Arc<TspRegistry>,
}

impl TrustManager for RegistryTrustManager {
    fn as_trust_anchor(&self, cert: &Cert) -> Option<TrustAnchor> {
        let services = self
            .registry
            .applicable_service_definitions(&Authority::of_cert(cert), None);
        // Authority lookup alone is insufficient: direct trust requires exact
        // registered DER. None is lack of direct permission, never a veto.
        if !services.iter().any(|sd| {
            sd.base_info
                .provider_certs
                .iter()
                .any(|c| c.der() == cert.der())
        }) {
            return None;
        }
        let service = services.first()?;
        Some(TrustAnchor::with_qualifiers(
            cert.clone(),
            TrustQualifiers {
                valid_from: Some(service.base_info.valid_from),
                valid_until: service.base_info.valid_until,
                trusted_service_type: if service.is_ca() {
                    TrustedServiceType::CertificateAuthority
                } else {
                    TrustedServiceType::TimeStampingAuthority
                },
                ..Default::default()
            },
        ))
    }

    fn find_potential_issuers(&self, cert: &Cert) -> Vec<TrustAnchor> {
        let mut anchors: Vec<TrustAnchor> = Vec::new();
        for authority in self.registry.known_certificate_authorities() {
            for service in self
                .registry
                .applicable_service_definitions(authority, None)
            {
                if !service.is_ca() {
                    continue;
                }
                for provider in &service.base_info.provider_certs {
                    if !Authority::of_cert(provider).is_potential_issuer_of(cert) {
                        continue;
                    }
                    if let Some(anchor) = self.as_trust_anchor(provider) {
                        if anchor.can_issue()
                            && !anchors.iter().any(|a| a.cert().der() == provider.der())
                        {
                            anchors.push(anchor);
                        }
                    }
                }
            }
        }
        anchors
    }
}

/// A new presentation assessment, not an assessment retained by full LTA.
/// It cannot change admission, validation, evidence, policy or the result.
struct TimestampDisplay {
    qualification: Option<sigis_eutl::q_status::QualificationResult>,
    reference_time: Option<Moment>,
    direct_qtst: bool,
}

fn timestamp_display(
    result: &LtaValidationResult,
    specification: &QualificationSpec<'_>,
) -> TimestampDisplay {
    let unavailable = || TimestampDisplay {
        qualification: None,
        reference_time: None,
        direct_qtst: false,
    };
    let Some(timestamp) = result
        .api_status
        .as_ref()
        .and_then(|status| status.timestamp_validity.as_ref())
    else {
        return unavailable();
    };
    let signature = &timestamp.signature;
    if !signature.intact || !signature.valid || !signature.trusted() {
        return unavailable();
    }
    let (Some(registry), Some(path), Some(reference_time)) = (
        specification.registry,
        signature.validation_path.as_ref(),
        signature.validation_time,
    ) else {
        return unavailable();
    };
    // Exactly one pure, read-only assessment at the actual retained reference
    // time. Never use genTime, NOW, a new validation or an inferred POE.
    let Ok(qualification) = qualification_analysis(registry, path, Some(reference_time)) else {
        return TimestampDisplay {
            reference_time: Some(reference_time),
            ..unavailable()
        };
    };
    let direct_requirement = QualificationRequirements {
        require_service_type: Some(RequiredServiceType::Uri(QTST_URI.into())),
        ..Default::default()
    };
    let direct_qtst = qualification.status.qualified
        && path.len() == 1
        && enforce_requirements(&direct_requirement, &qualification, path).is_ok()
        && qualification
            .service_definition
            .as_ref()
            .is_some_and(|service| {
                !service.is_ca()
                    && service.base_info.service_type == QTST_URI
                    && signature.signing_cert.as_ref().is_some_and(|cert| {
                        cert.der() == path.trust_anchor().cert().der()
                        // Equivalent service rows may describe different DER
                        // members of the same authority. Membership belongs to
                        // the whole registry, not the first descriptive row.
                        && registry.applicable_service_definitions(
                            &Authority::of_cert(cert), Some(reference_time),
                        ).iter().any(|definition| definition.base_info.provider_certs
                            .iter().any(|provider| provider.der() == cert.der()))
                    })
            });
    TimestampDisplay {
        qualification: Some(qualification),
        reference_time: Some(reference_time),
        direct_qtst,
    }
}

fn render(
    field: &str,
    index: usize,
    result: &LtaValidationResult,
    specification: &QualificationSpec<'_>,
    pretty: bool,
    valid: bool,
) -> String {
    let mut output = String::new();
    let timestamp = timestamp_display(result, specification);
    let timestamp_label = match &timestamp.qualification {
        Some(q) if q.status.qualified => "QUALIFIED",
        Some(_) => "NOT_QUALIFIED",
        None => "QUALIFICATION_UNAVAILABLE",
    };
    if pretty {
        output.push_str(&format!("Field {index}: {field}\n"));
        if let Some(status) = &result.api_status {
            // The pinned CLI renders the actual API status, including its
            // bottom line, separately from the archival sub-indication.
            for (heading, body) in status.pretty_print_sections() {
                output.push_str(&format!(
                    "{heading}\n{}\n{body}\n\n",
                    "-".repeat(heading.chars().count())
                ));
            }
        }
        match &result.qualification {
            Some(q) if q.status.qualified => {
                output.push_str(&format!(
                    "The signer's certificate is qualified ({}, {}).\n",
                    q.status.qc_type.name(),
                    q.status.qc_key_security.name()
                ));
                let purpose = match q.status.qc_type {
                    sigis_eutl::tsp::QcCertType::QcEsign => "electronic signatures",
                    sigis_eutl::tsp::QcCertType::QcEseal => "electronic seals",
                    sigis_eutl::tsp::QcCertType::QcWeb => "website authentication",
                };
                output.push_str(&format!("The certificate is qualified for {purpose}.\n"));
            }
            Some(_) => output.push_str("The signer's certificate is not qualified.\n"),
            None => output.push_str("Signer qualification is unavailable.\n"),
        }
        output.push_str(&format!(
            "AdES result: {}\n",
            result.ades_subindic.standard_name()
        ));
        if let Some(time) = result.best_signature_time {
            output.push_str(&format!("Best signature time: {time}\n"));
        }
        output.push_str(&format!(
            "The signature is judged {}.\n",
            if valid { "VALID" } else { "INVALID" }
        ));
    } else {
        let fingerprint = result
            .api_status
            .as_ref()
            .and_then(|s| s.signature.signing_cert.as_ref())
            .map(|c| {
                c.sha256()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            })
            .unwrap_or_else(|| "unknown".into());
        let mut summary = result
            .api_status
            .as_ref()
            .map(|status| {
                if !status.signature.intact || !status.signature.valid {
                    return status.summary();
                }
                let mut fields = status.summary_fields();
                if let Some(token) = status.timestamp_validity.as_ref() {
                    let actual = format!("TIMESTAMP_TOKEN<{}>", token.signature.summary_with("|"));
                    if let Some(field) = fields
                        .iter_mut()
                        .find(|field| field.as_str() == actual.as_str())
                    {
                        *field = format!(
                            "TIMESTAMP_TOKEN<{}|{timestamp_label}>",
                            token.signature.summary_with("|")
                        );
                    }
                }
                format!("INTACT:{}", fields.join(","))
            })
            .unwrap_or_else(|| "STATUS_UNAVAILABLE".into());
        if let Some(qualification) = &result.qualification {
            let label = if qualification.status.qualified {
                "QUALIFIED"
            } else {
                "NOT_QUALIFIED"
            };
            // Insert immediately after the actual CMS trust field, preserving
            // the actual timestamp and content-timestamp summary fields.
            if let Some((first, rest)) = summary.split_once(',') {
                summary = format!("{first},{label},{rest}");
            } else {
                summary.push_str(&format!(",{label}"));
            }
        }
        output.push_str(&format!("{field}:{fingerprint}:{summary}\n"));
        if result.ades_subindic != AdesSubIndic::Passed(AdesPassed::OK) {
            output.push_str(&format!(
                "AdES result: {}\n",
                result.ades_subindic.standard_name()
            ));
        }
    }
    output.push_str(&format!(
        "Signature timestamp qualification: {timestamp_label}"
    ));
    if let Some(time) = timestamp.reference_time {
        output.push_str(&format!(" at {time}"));
    }
    output.push('\n');
    if pretty
        && timestamp
            .qualification
            .as_ref()
            .is_some_and(|q| !q.status.qualified)
    {
        output.push_str("The time stamping authority is not qualified.\n");
    }
    if pretty && timestamp.direct_qtst {
        output
            .push_str("The signature timestamp's certificate is directly identified as a QTST.\n");
    }
    if let Some(message) = &result.failure_msg {
        output.push_str(message);
        output.push('\n');
    }
    output
}

pub(crate) fn run(
    args: &[String],
    config: Option<&CliConfig>,
    verbose: bool,
    runtime: &ValidationRuntime,
    injected_runtime: bool,
) -> Result<String, String> {
    let a =
        Args::try_parse_from(std::iter::once("adesverify".to_owned()).chain(args.iter().cloned()))
            .map_err(|e| format!("ENTRY: {e}"))?;
    if a.require_qualified && !a.eutl_all {
        return Err("ENTRY: --require-qualified needs an authenticated EUTL registry.".into());
    }
    // The source AdES MAIN defaults are explicit below. A nondefault mandatory
    // CLI usage policy cannot silently disappear when choosing that profile.
    // Keep ordinary validation's configurable MAIN path unchanged.
    if !a.eutl_all {
        if let Some(config) = config {
            let policy = config.key_usages(a.validation_context.as_deref())?;
            if policy != crate::config::KeyUsagePolicy::default() {
                return Err("ENTRY: Nondefault MAIN key usage policy is unsupported by the original AdES profile.".into());
            }
        }
    }
    let resolved = a.eutl_all.then(|| resolve(&a, config)).transpose()?;
    let validation_time = a
        .validation_time
        .as_ref()
        .map(|time| {
            Moment::parse_rfc3339(time)
                .ok_or_else(|| "Validation time could not be parsed.".to_owned())
        })
        .transpose()?;
    let reference_time = validation_time.unwrap_or(runtime.now);
    let mut output = if verbose {
        "Running with --verbose\n".into()
    } else {
        String::new()
    };
    let execute = |output: &mut String| -> Result<bool, String> {
        // Product TLSO/LOTL authentication captures its own NOW, as upstream.
        // Only the explicit runtime-injection entry supplies a historical at.
        let registry = resolved
            .as_ref()
            .map(|resolved| {
                load_registry(resolved, runtime, injected_runtime.then_some(runtime.now))
            })
            .transpose()?;
        let mut policy = CertRevTrustPolicy::new(if a.no_revocation_check {
            NO_REVOCATION
        } else {
            REQUIRE_REVINFO
        });
        policy.freshness = None;
        if !a.no_revocation_check {
            policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
        }
        policy.expected_post_expiry_revinfo_time = None;
        policy.retroactive_revinfo = false;
        // Exactly one original factory/build; no ordinary context/getter rebuild.
        let context = if let (Some(resolved), Some(registry)) = (&resolved, &registry) {
            ValidationContext::builder()
                .moment(reference_time)
                .point_in_time_validation(validation_time.is_some())
                .best_signature_time(reference_time)
                .time_tolerance(resolved.tolerance)
                .revinfo_policy(policy)
                .fetchers(runtime.fetchers.clone())
                .trust_manager(registry_trust_manager(registry.clone()))
                .build()
                .map_err(|e| format!("CONTEXT: {e}"))?
        } else {
            let mut reference_runtime = runtime.clone();
            reference_runtime.now = reference_time;
            crate::validation::context_for_ades(
                config,
                a.validation_context.as_deref(),
                &reference_runtime,
                a.no_revocation_check,
                validation_time.is_some(),
            )?
        };
        let qualification = QualificationSpec {
            registry: registry.as_deref(),
            requirements: a.require_qualified.then(QualificationRequirements::default),
            ts_requirements: a.require_qualified.then(|| QualificationRequirements {
                require_service_type: Some(RequiredServiceType::Uri(QTST_URI.into())),
                ..Default::default()
            }),
        };
        let lta_options = LtaOptions {
            known_poes: None,
            ac_validation_context: None,
        };
        let mut ades_options = AdesValidationOptions::default();
        ades_options.exact_key_usage_settings = Some(KeyUsageConstraints::default());
        let bytes = std::fs::read(&a.infile).map_err(|e| format!("Failed to read PDF: {e}"))?;
        let mut options = if a.no_strict_syntax {
            ReaderOptions::lenient()
        } else {
            ReaderOptions::default()
        };
        if a.no_decode_limits {
            options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
        }
        let file =
            PdfFile::parse_with(&bytes, options).map_err(|e| format!("Failed to read PDF: {e}"))?;
        // Reuse the unchanged authentication path, including decrypt/MAC and
        // runtime password prompting, on the continuing reader exactly once.
        crate::validation::authenticate(&file, a.password.as_deref(), runtime)?;
        let mut all_valid = true;
        for (index, signature) in file
            .embedded_signatures()
            .map_err(|e| e.to_string())?
            .into_iter()
            .enumerate()
        {
            if signature.kind != SignatureKind::Signature {
                continue;
            }
            let result = lta_validation_with_ades_options(
                &file,
                &signature,
                &context,
                &qualification,
                &lta_options,
                &ades_options,
            )
            .map_err(|e| e.to_string())?;
            // The pinned CLI projects a PDF API status. Our API payload is
            // CMS-only: PDF coverage, modification and seed-value refusals
            // remain in the AdES indication, so they must not disappear here.
            // Only missing archival proof can coexist with a trusted current
            // API status. Keep NO_POE and its diagnostic visible; never alter
            // trust, retry validation or manufacture historical evidence.
            let complete_pdf_constraints = match result.ades_subindic {
                AdesSubIndic::Passed(AdesPassed::OK) => true,
                AdesSubIndic::Indeterminate(AdesIndeterminate::NO_POE) => {
                    // LTA may return NO_POE before its final seed-value check.
                    // A CMS-only payload cannot certify that check completed:
                    // retain the prior refusal for seed-constrained signatures.
                    // Read the signed field, never a later replacement state.
                    let field = file
                        .get_object_at(signature.field_object, Some(signature.signed_revision))
                        .map_err(|e| e.to_string())?;
                    !field.as_dict().map_err(|e| e.to_string())?.has(b"SV")
                }
                _ => false,
            };
            let valid = complete_pdf_constraints
                && result
                    .api_status
                    .as_ref()
                    .is_some_and(|status| status.bottom_line());
            all_valid &= valid;
            output.push_str(&render(
                &signature.field_name,
                index + 1,
                &result,
                &qualification,
                a.pretty_print,
                valid,
            ));
        }
        Ok(all_valid)
    };
    match execute(&mut output) {
        Ok(true) => Ok(output),
        Ok(false) => Err(format!("{output}Validation failed")),
        Err(error) => Err(format!("{output}{error}\nValidation failed")),
    }
}
