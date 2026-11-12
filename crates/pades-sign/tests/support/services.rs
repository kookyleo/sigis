//! Network-free stand-ins for Certomancer's live PKI services
//! (`pki_services` in pyHanko's tests): OCSP and CRL fetchers that serve the
//! responses exported by `oracle/export_revinfo.py` for a pinned time.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchError, FetchErrorKind};
use sigis_pki_core::fetch::{CrlFetcher, Fetchers, OcspFetcher};

use super::{at, data_path, pki, Pki};

/// Fetchers for the given architectures at `time` (`YYYY-MM-DD`).
#[derive(Debug)]
pub struct Services {
    archs: Vec<String>,
    time: String,
}

impl Services {
    pub fn new(archs: &[&str], time: &str) -> Arc<Self> {
        Arc::new(Self {
            archs: archs.iter().map(|s| (*s).to_owned()).collect(),
            time: time[..10].to_owned(),
        })
    }

    fn find(&self, cert: &Cert) -> Option<(Pki, String)> {
        for a in &self.archs {
            let p = pki(a);
            for label in p.labels() {
                if &p.cert(&label) == cert {
                    return Some((p, label));
                }
            }
        }
        None
    }

    pub fn fetchers(self: &Arc<Self>) -> Fetchers {
        Fetchers {
            ocsp: Some(self.clone()),
            crl: Some(self.clone()),
            cert: None,
        }
    }
}

fn not_found(what: String) -> FetchError {
    FetchError::new(FetchErrorKind::NotFound, what)
}

impl OcspFetcher for Services {
    fn fetch_ocsp(&self, cert: &Cert, _issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let (p, label) = self
            .find(cert)
            .ok_or_else(|| not_found("unknown cert".into()))?;
        let f = data_path(&[
            "lanes",
            "d",
            "revinfo",
            &p.arch,
            &self.time,
            &format!("ocsp-{label}.der"),
        ]);
        std::fs::read(&f).map_err(|_| not_found(format!("{}", f.display())))
    }
}

impl CrlFetcher for Services {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let dps = cert
            .crl_distribution_points()
            .ok_or_else(|| not_found("no CRL DP".into()))?;
        let mut out = Vec::new();
        for dp in dps.0 {
            let Some(x509_cert::ext::pkix::name::DistributionPointName::FullName(names)) =
                dp.distribution_point
            else {
                continue;
            };
            for n in names {
                if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(u) = n {
                    // http://pyhanko.tests/<arch>/crls/<repo>/latest.crl
                    let url = u.as_str();
                    let parts: Vec<&str> = url
                        .trim_start_matches("http://pyhanko.tests/")
                        .split('/')
                        .collect();
                    if parts.len() >= 3 && parts[1] == "crls" {
                        let f = data_path(&[
                            "lanes",
                            "d",
                            "revinfo",
                            parts[0],
                            &self.time,
                            &format!("crl-{}.der", parts[2]),
                        ]);
                        if let Ok(d) = std::fs::read(&f) {
                            out.push(d);
                        }
                    }
                }
            }
        }
        if out.is_empty() {
            return Err(not_found("no CRL".into()));
        }
        Ok(out)
    }
}

/// `live_testing_vc`: trust the arch root, fetch from the services, at
/// `time`.
pub fn live_testing_vc(arch: &str, time: &str, extra_archs: &[&str]) -> ValidationContext {
    let mut archs = vec![arch];
    archs.extend_from_slice(extra_archs);
    let svc = Services::new(&archs, time);
    let mut b = ValidationContext::builder()
        .trust_root(pki(arch).cert("root"))
        .moment(at(time))
        .fetchers(svc.fetchers());
    for a in extra_archs {
        b = b.trust_root(pki(a).cert("root"));
    }
    b.build().unwrap()
}

/// `simple_v_context`: trust the arch root, no fetching.
pub fn simple_vc(arch: &str, time: &str) -> ValidationContext {
    ValidationContext::builder()
        .trust_root(pki(arch).cert("root"))
        .moment(at(time))
        .build()
        .unwrap()
}

/// A fetcher that always returns the same OCSP response.
#[derive(Debug)]
pub struct FixedOcsp(pub Vec<u8>);

impl OcspFetcher for FixedOcsp {
    fn fetch_ocsp(&self, _cert: &Cert, _issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        Ok(self.0.clone())
    }
}

/// `dummy_ocsp_vc`: trust the testing CA root; `FIXED_OCSP`
/// (`crypto/ocsp.resp.der`, unrelated to the current keys) is the only
/// revocation information. pyHanko supplies it in the context
/// (`ocsps=[FIXED_OCSP]`); the port serves it through an OCSP fetcher, since
/// a `ValidationContext` does not expose supplied responses (see
/// `docs/lanes/d.md`, requests).
pub fn dummy_ocsp_vc(time: &str) -> ValidationContext {
    let ocsp = super::pyhanko_data(&["crypto", "ocsp.resp.der"]);
    ValidationContext::builder()
        .trust_root(pki("testing-ca").cert("root"))
        .moment(at(time))
        .ocsp_response(ocsp.clone())
        .fetchers(Fetchers {
            ocsp: Some(Arc::new(FixedOcsp(ocsp))),
            crl: None,
            cert: None,
        })
        .build()
        .unwrap()
}
