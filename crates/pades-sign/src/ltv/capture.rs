//! Operation-local raw evidence collection through the caller's own providers.

use std::sync::{Arc, Mutex, MutexGuard};

use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::FetchError;
use sigis_pki_core::fetch::{CrlFetcher, Fetchers, OcspFetcher};

use super::ValidationInfo;

/// Download outcomes are untrusted bytes, never a cached validation verdict.
#[derive(Clone, Debug, Default)]
pub(super) struct RevinfoCapture(Arc<Mutex<ValidationInfo>>);

impl RevinfoCapture {
    fn lock(&self) -> MutexGuard<'_, ValidationInfo> {
        // No provider or validation callback runs while this lock is held.
        // The protected value contains only raw evidence, not trust decisions.
        self.0.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(super) fn context(&self, context: &ValidationContext) -> ValidationContext {
        let original = context.fetchers();
        context.with_fetchers(Fetchers {
            ocsp: original.ocsp.as_ref().map(|delegate| {
                Arc::new(CaptureOcsp {
                    delegate: delegate.clone(),
                    capture: self.clone(),
                }) as Arc<dyn OcspFetcher>
            }),
            crl: original.crl.as_ref().map(|delegate| {
                Arc::new(CaptureCrl {
                    delegate: delegate.clone(),
                    capture: self.clone(),
                }) as Arc<dyn CrlFetcher>
            }),
            cert: original.cert.clone(),
        })
    }

    pub(super) fn snapshot(&self) -> ValidationInfo {
        self.lock().clone()
    }

    fn ocsp(&self, response: &[u8]) {
        let mut info = self.lock();
        if !info.ocsps.iter().any(|existing| existing == response) {
            info.ocsps.push(response.to_vec());
        }
    }

    fn crls(&self, responses: &[Vec<u8>]) {
        let mut info = self.lock();
        for response in responses {
            if !info.crls.contains(response) {
                info.crls.push(response.clone());
            }
        }
    }
}

#[derive(Debug)]
struct CaptureOcsp {
    delegate: Arc<dyn OcspFetcher>,
    capture: RevinfoCapture,
}

impl OcspFetcher for CaptureOcsp {
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let response = self.delegate.fetch_ocsp(cert, issuer)?;
        self.capture.ocsp(&response);
        Ok(response)
    }

    fn fetch_ac_ocsp(&self, ac_der: &[u8], issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let response = self.delegate.fetch_ac_ocsp(ac_der, issuer)?;
        self.capture.ocsp(&response);
        Ok(response)
    }
}

#[derive(Debug)]
struct CaptureCrl {
    delegate: Arc<dyn CrlFetcher>,
    capture: RevinfoCapture,
}

impl CrlFetcher for CaptureCrl {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let responses = self.delegate.fetch_crls(cert)?;
        self.capture.crls(&responses);
        Ok(responses)
    }

    fn fetch_ac_crls(&self, ac_der: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        let responses = self.delegate.fetch_ac_crls(ac_der)?;
        self.capture.crls(&responses);
        Ok(responses)
    }
}
