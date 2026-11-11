// Derived from pyHanko `sign/validation/qualified/eutl_fetch.py` (MIT, see LICENSE-pyHanko).

//! Fetching trusted lists: caches, LOTL signer bootstrapping and LOTL to
//! registry processing (`pyhanko.sign.validation.qualified.eutl_fetch`).
//!
//! pyHanko uses an `aiohttp` session; here HTTP access goes through the
//! synchronous [`TlFetcher`] trait, so callers choose the client and tests use
//! in-memory fakes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sigis_pki_core::cert::Cert;
use sigis_pki_core::time::Moment;

use crate::parse::{
    ojeu_bootstrap_lotl_tlso_certs, parse_lotl_unsafe, trust_list_to_registry,
    validate_and_parse_lotl, EutlError, ETSI_TSL_MIME_TYPE, LOTL_RULE,
};
use crate::tsp::{TspRegistry, TspServiceParsingError};

/// Location of the EU list of the lists (`EU_LOTL_LOCATION`).
pub const EU_LOTL_LOCATION: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
/// Number of attempts per download (`FETCH_TRIES`).
pub const FETCH_TRIES: u32 = 3;
/// Initial retry delay (`FETCH_BASE_DELAY_SECONDS`).
pub const FETCH_BASE_DELAY: Duration = Duration::from_secs(2);
/// Total timeout of one request (`FETCH_TIMEOUT_SECONDS`).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Socket read timeout (`FETCH_CONNECT_TIMEOUT_SECONDS`).
pub const FETCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// `Accept` header values sent with each request.
pub const ACCEPT_TYPES: [&str; 2] = ["text/xml", ETSI_TSL_MIME_TYPE];

/// Error of a single download attempt.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TlFetchError {
    /// The server answered with an error status.
    #[error("{status}, message='{reason}', url='{url}'")]
    Status {
        /// HTTP status.
        status: u16,
        /// Reason phrase.
        reason: String,
        /// URL.
        url: String,
    },
    /// Connection or protocol failure, or timeout.
    #[error("{0}")]
    Network(String),
}

/// Synchronous HTTP GET for trusted lists (the `aiohttp.ClientSession` of
/// pyHanko). Implementations send [`ACCEPT_TYPES`] and apply
/// [`FETCH_TIMEOUT`] / [`FETCH_CONNECT_TIMEOUT`].
pub trait TlFetcher {
    /// Fetch `url` and return the body as text.
    fn get(&self, url: &str) -> Result<String, TlFetchError>;
}

/// Retry policy of [`fetch_with_retries`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Number of attempts.
    pub tries: u32,
    /// Initial delay, doubled after each failed attempt.
    pub base_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            tries: FETCH_TRIES,
            base_delay: FETCH_BASE_DELAY,
        }
    }
}

/// `_get`: retry network errors and 5xx responses; other errors fail at
/// once.
pub fn fetch_with_retries(
    fetcher: &dyn TlFetcher,
    url: &str,
    policy: RetryPolicy,
) -> Result<String, TlFetchError> {
    let mut delay = policy.base_delay;
    let mut last = TlFetchError::Network(format!("no attempt made for {url}"));
    for attempt in 0..policy.tries {
        match fetcher.get(url) {
            Ok(s) => return Ok(s),
            Err(e @ TlFetchError::Status { status, .. }) if status < 500 => return Err(e),
            Err(e) => {
                last = e;
                if attempt + 1 < policy.tries {
                    std::thread::sleep(delay);
                    delay *= 2;
                }
            }
        }
    }
    Err(last)
}

/// Cache for downloaded trusted lists, keyed by URL (`TLCache`).
pub trait TlCache {
    /// Cached value, if present and fresh.
    fn get(&self, key: &str) -> Option<String>;
    /// Store a value.
    fn set(&self, key: &str, value: &str);
}

/// Unbounded in-memory cache (`InMemoryTLCache`).
#[derive(Debug, Default)]
pub struct InMemoryTlCache {
    map: Mutex<HashMap<String, String>>,
}

impl InMemoryTlCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TlCache for InMemoryTlCache {
    fn get(&self, key: &str) -> Option<String> {
        self.map.lock().ok()?.get(key).cloned()
    }

    fn set(&self, key: &str, value: &str) {
        if let Ok(mut m) = self.map.lock() {
            m.insert(key.to_owned(), value.to_owned());
        }
    }
}

/// Clock used by [`FileSystemTlCache`].
pub type Clock = Arc<dyn Fn() -> Moment + Send + Sync>;

/// File system cache with expiry (`FileSystemTLCache`). Entries are stored
/// as files named by the SHA-256 of the key, with an `index.json` holding
/// expiry times, in the same format as pyHanko.
pub struct FileSystemTlCache {
    root: PathBuf,
    expire_after: Duration,
    clock: Clock,
    cache: Mutex<HashMap<String, (f64, String)>>,
}

impl std::fmt::Debug for FileSystemTlCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSystemTlCache")
            .field("root", &self.root)
            .field("expire_after", &self.expire_after)
            .finish_non_exhaustive()
    }
}

fn read_index(path: &Path) -> Option<serde_json::Map<String, serde_json::Value>> {
    let data = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&data).ok()? {
        serde_json::Value::Object(m) => Some(m),
        _ => None,
    }
}

impl FileSystemTlCache {
    /// Open (or create) a cache directory, using the system clock.
    pub fn new(root: impl AsRef<Path>, expire_after: Duration) -> std::io::Result<Self> {
        Self::with_clock(root, expire_after, Arc::new(Moment::now))
    }

    /// Open (or create) a cache directory with an explicit clock.
    pub fn with_clock(
        root: impl AsRef<Path>,
        expire_after: Duration,
        clock: Clock,
    ) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let mut cache = HashMap::new();
        if let Some(index) = read_index(&root.join("index.json")) {
            for (key, entry) in index {
                let exp = entry
                    .get("exp_epoch_seconds")
                    .and_then(serde_json::Value::as_f64);
                let fname = entry.get("fname").and_then(serde_json::Value::as_str);
                if let (Some(exp), Some(fname)) = (exp, fname) {
                    cache.insert(key, (exp, fname.to_owned()));
                }
            }
        }
        Ok(Self {
            root,
            expire_after,
            clock,
            cache: Mutex::new(cache),
        })
    }

    /// Delete all files in the cache directory (`reset`).
    pub fn reset(&self) {
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for e in entries.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// File name of `key` in the cache directory.
    pub fn file_name(&self, key: &str) -> Option<String> {
        self.cache.lock().ok()?.get(key).map(|(_, f)| f.clone())
    }

    fn now_secs(&self) -> f64 {
        (self.clock)().unix_secs() as f64
    }
}

impl TlCache for FileSystemTlCache {
    fn get(&self, key: &str) -> Option<String> {
        let (exp, fname) = self.cache.lock().ok()?.get(key).cloned()?;
        if self.now_secs() > exp {
            return None;
        }
        std::fs::read_to_string(self.root.join(fname)).ok()
    }

    fn set(&self, key: &str, value: &str) {
        let exp = self.now_secs() + self.expire_after.as_secs_f64();
        let fname =
            hex(&sigis_pki_core::algorithms::DigestAlgorithm::Sha256.digest(key.as_bytes()));
        let index_path = self.root.join("index.json");
        let mut index = read_index(&index_path).unwrap_or_default();
        index.insert(
            key.to_owned(),
            serde_json::json!({ "exp_epoch_seconds": exp, "fname": fname }),
        );
        let _ = std::fs::write(&index_path, serde_json::Value::Object(index).to_string());
        let _ = std::fs::write(self.root.join(&fname), value);
        if let Ok(mut c) = self.cache.lock() {
            c.insert(key.to_owned(), (exp, fname));
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `_fetch`: consult the cache, else download (and store).
fn fetch(
    cache: Option<&dyn TlCache>,
    uri: &str,
    fetcher: &dyn TlFetcher,
    retry: RetryPolicy,
) -> Result<String, TlFetchError> {
    match cache {
        None => fetch_with_retries(fetcher, uri, retry),
        Some(c) => {
            if let Some(v) = c.get(uri) {
                return Ok(v);
            }
            let v = fetch_with_retries(fetcher, uri, retry)?;
            c.set(uri, &v);
            Ok(v)
        }
    }
}

/// Options shared by the fetching functions.
#[derive(Clone, Copy, Default)]
pub struct FetchOptions<'a> {
    /// Cache, if any.
    pub cache: Option<&'a dyn TlCache>,
    /// Retry policy.
    pub retry: RetryPolicy,
}

/// Determine the current LOTL signers by walking the pivot LOTLs from an
/// OJEU anchor (Commission Implementing Decision (EU) 2015/1505, Art. 4)
/// (`bootstrap_lotl_signers`).
pub fn bootstrap_lotl_signers(
    latest_lotl_xml: &str,
    fetcher: &dyn TlFetcher,
    bootstrap_lotl_tlso_certs: Option<&[Cert]>,
    opts: FetchOptions<'_>,
    anchor: u32,
) -> Result<Vec<Cert>, TspServiceParsingError> {
    let pivots = parse_lotl_unsafe(latest_lotl_xml)
        .map_err(|e| TspServiceParsingError(e.to_string()))?
        .pivot_urls;
    let sorted: BTreeSet<String> = pivots.into_iter().collect();
    let mut current: Vec<Cert> = match bootstrap_lotl_tlso_certs {
        Some(c) if !c.is_empty() => c.to_vec(),
        _ => ojeu_bootstrap_lotl_tlso_certs(anchor),
    };
    // `sorted()` keeps duplicates; a set only drops exact repeats, which
    // would be processed identically.
    for pivot in sorted {
        let step = || -> Result<_, String> {
            let xml = fetch(opts.cache, &pivot, fetcher, opts.retry).map_err(|e| e.to_string())?;
            let claimed = parse_lotl_unsafe(&xml)
                .map_err(|e| e.to_string())?
                .claimed_date_issued;
            validate_and_parse_lotl(&xml, Some(&current), Some(claimed)).map_err(|e| e.to_string())
        };
        let result = step().map_err(|e| {
            TspServiceParsingError(format!("Failed to process pivot LOTL {pivot}: {e}"))
        })?;
        let reference = result
            .references
            .iter()
            .find(|r| r.scheme_rules.contains(LOTL_RULE))
            .ok_or_else(|| {
                TspServiceParsingError(format!(
                    "Failed to process pivot LOTL {pivot}: could not extract TLSO certs"
                ))
            })?;
        current = reference.tlso_certs.clone();
    }
    Ok(current)
}

/// Fetch the LOTL (`fetch_lotl`).
pub fn fetch_lotl(
    fetcher: &dyn TlFetcher,
    opts: FetchOptions<'_>,
    url: Option<&str>,
) -> Result<String, TlFetchError> {
    fetch(
        opts.cache,
        url.unwrap_or(EU_LOTL_LOCATION),
        fetcher,
        opts.retry,
    )
}

/// Populate a registry from a LOTL, validating the signatures of the LOTL
/// and of every trusted list (`lotl_to_registry`).
///
/// Signatures are checked at `at` (now if `None`, as in pyHanko).
#[allow(clippy::too_many_arguments)]
pub fn lotl_to_registry(
    lotl_xml: Option<&str>,
    fetcher: &dyn TlFetcher,
    lotl_tlso_certs: Option<&[Cert]>,
    opts: FetchOptions<'_>,
    registry: Option<TspRegistry>,
    only_territories: Option<&BTreeSet<String>>,
    at: Option<Moment>,
) -> Result<(TspRegistry, Vec<TspServiceParsingError>), EutlError> {
    let fetched;
    let lotl_xml = match lotl_xml {
        Some(x) => x,
        None => {
            fetched = fetch_lotl(fetcher, opts, None)
                .map_err(|e| TspServiceParsingError(format!("Failed to download LOTL: {e}")))?;
            &fetched
        }
    };
    let lotl = validate_and_parse_lotl(lotl_xml, lotl_tlso_certs, at)?;
    let mut errors = lotl.errors;
    let mut registry = registry.unwrap_or_default();
    let territories: Option<BTreeSet<String>> =
        only_territories.map(|t| t.iter().map(|x| x.to_lowercase()).collect());
    for r in &lotl.references {
        if let Some(t) = &territories {
            if !t.contains(&r.territory.to_lowercase()) {
                continue;
            }
        }
        if r.scheme_rules.contains(LOTL_RULE) {
            continue;
        }
        let tl = match fetch(opts.cache, &r.location_uri, fetcher, opts.retry) {
            Ok(x) => x,
            Err(e) => {
                errors.push(TspServiceParsingError(format!(
                    "Failed to download trusted list for {} at {}: {e}",
                    r.territory, r.location_uri
                )));
                continue;
            }
        };
        match trust_list_to_registry(&tl, &r.tlso_certs, Some(std::mem::take(&mut registry)), at) {
            Ok((reg, errs)) => {
                registry = reg;
                errors.extend(errs);
            }
            Err(e) => {
                errors.push(TspServiceParsingError(format!(
                    "Failed to parse trusted list for {} at {}: {e}",
                    r.territory, r.location_uri
                )));
            }
        }
    }
    Ok((registry, errors))
}

type Handler = Box<dyn Fn(&str) -> Result<String, TlFetchError> + Send + Sync>;

/// An in-memory [`TlFetcher`] mapping URL paths to handlers, like the
/// `PathRetainingClient` of pyHanko's tests (the host part is ignored).
#[derive(Default)]
pub struct PathFetcher {
    handlers: BTreeMap<String, Handler>,
}

impl std::fmt::Debug for PathFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathFetcher")
            .field("paths", &self.handlers.keys())
            .finish()
    }
}

impl PathFetcher {
    /// No routes: every request gets a 404.
    pub fn new() -> Self {
        Self::default()
    }

    /// Route `path` to a handler.
    pub fn route(
        mut self,
        path: &str,
        handler: impl Fn(&str) -> Result<String, TlFetchError> + Send + Sync + 'static,
    ) -> Self {
        self.handlers.insert(path.to_owned(), Box::new(handler));
        self
    }

    /// The path part of a URL.
    pub fn path_of(url: &str) -> &str {
        let rest = url.split_once("://").map_or(url, |(_, r)| r);
        let path = rest.find('/').map_or("/", |i| &rest[i..]);
        path.split(['?', '#']).next().unwrap_or(path)
    }
}

impl TlFetcher for PathFetcher {
    fn get(&self, url: &str) -> Result<String, TlFetchError> {
        let path = Self::path_of(url);
        match self.handlers.get(path) {
            Some(h) => h(url),
            None => Err(TlFetchError::Status {
                status: 404,
                reason: "Not Found".into(),
                url: url.to_owned(),
            }),
        }
    }
}
