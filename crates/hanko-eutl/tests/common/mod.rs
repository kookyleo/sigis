#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use hanko_core::cert::Cert;
use hanko_core::time::Moment;

pub const TEST_REAL_TL_BE: &str = "tsl-be-v6.xml";
pub const TEST_REAL_TL_BE_OLD: &str = "tsl-be-old.xml";
pub const TEST_REAL_TL_EE: &str = "tsl-ee.xml";
pub const TEST_REAL_LOTL: &str = "eu-lotl.xml";
pub const TEST_REAL_LOTL_OLD: &str = "eu-lotl-old.xml";

pub fn tl_path(name: &str) -> PathBuf {
    hanko_testdata::pyhanko(&["tl", name])
}

pub fn tl_file(name: &str) -> String {
    std::fs::read_to_string(tl_path(name)).unwrap()
}

pub fn moment(s: &str) -> Moment {
    hanko_eutl::util::parse_xsd_datetime(s).unwrap()
}

pub fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

pub const BE_TLSO_CERT_B64: &str = "
MIID3zCCAsegAwIBAgIJAOv7FV6q0Or/MA0GCSqGSIb3DQ
EBBQUAMIGHMS0wKwYDVQQDEyRCZWxnaWFuIFRydXN0ZWQg
TGlzdCBTY2hlbWUgT3BlcmF0b3IxSTBHBgNVBAoTQEZQUy
BFY29ub215LCBTTUVzLCBTZWxmLWVtcGxveWVkIGFuZCBF
bmVyZ3kgLSBRdWFsaXR5IGFuZCBTYWZldHkxCzAJBgNVBA
YTAkJFMB4XDTE0MDIxOTEzMzgwNFoXDTI1MDYxMTEzMzgw
NFowgYcxLTArBgNVBAMTJEJlbGdpYW4gVHJ1c3RlZCBMaX
N0IFNjaGVtZSBPcGVyYXRvcjFJMEcGA1UEChNARlBTIEVj
b25vbXksIFNNRXMsIFNlbGYtZW1wbG95ZWQgYW5kIEVuZX
JneSAtIFF1YWxpdHkgYW5kIFNhZmV0eTELMAkGA1UEBhMC
QkUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQ
DAgEFkoDPTYDvGk+/IPnGSPm58NRE7mpzLHk8lxpYnTAtb
Mhn7FWru9GlNi+blYYNOEmzN2E5KO9+7AAAMmx2x8zmEMw
c3oUQ7E0WN5Gl+Y+7n6NtX50D/4Sbw4IjVvwwRRru8Coj5
vq5Hz3JKTgft8teEpwb5vSFZh6+o9irdX342RJU4AtG78s
xZvzIqpa3WsddMf5XDyjnGK3dRgkDuOaBxWEexuUiN4LvO
+MacwoaxEqLhEZ6TALGWS2WmNEW3OlUdf7nc0Tz/lnyQsu
Fn01c4pg56hjyxLtpjyHwNwbTDx+cjBpBveOT9Nb6UfKFH
knC5AfrIOWnFLXUmyKD/AgMBAAGjTDBKMAkGA1UdEwQCMA
AwCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBRf745pXfv0l1rx
BwgOUhlQqteQUTARBgNVHSUECjAIBgYEAJE3AwAwDQYJKo
ZIhvcNAQEFBQADggEBAJQt17IzKeqnxakdgysT1FlymocZ
UUHGhfbQAfr4OEm48LMoN4M5ZeeRMVIwk4jODURuhawtKJ
3hRdGB+zTzIMLheOmAGGRDUNrDwctpn8G+RqEFjlgc5yi1
ICHBZJrvyud7cPwz8AwMtV+K1iFmbEWqsGASZ96J9uilJJ
+RkPcV3Olwtgi3+IxOxHfhmq0PCdRk1k8+c7frdT935Z8S
fFgnaPy4RFg2eKdvC2qsvsF3J19eP/BKlGdVVe44yTB3UC
E3KSLiySvgM/JXIQN5VE+lGPeURKnoXsW5E71IdUEi30Pt
d0YBxTjEairZKyzhgGbZEnBUWSkn6n9uZ5Ai2lo=
";

pub fn be_tlso_cert() -> Cert {
    let s: String = BE_TLSO_CERT_B64.split_whitespace().collect();
    Cert::from_der(&base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
}

/// A temporary directory removed on drop (no external crate needed).
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "hanko-eutl-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A certificate from the lane E export of the Certomancer test PKIs.
pub fn pki_cert(arch: &str, label: &str) -> Cert {
    let p = hanko_testdata::path(&["lanes", "e", "pki", arch, &format!("{label}.cert.pem")]);
    hanko_eutl::util::load_certs_from_pemder(&std::fs::read(p).unwrap())
        .unwrap()
        .remove(0)
}
