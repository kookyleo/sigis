// Derived from pyhanko-certvalidator `ltv/poe.py` (MIT, see LICENSE-pyHanko).

//! Proofs of existence (POE).

use std::collections::BTreeMap;

use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::time::Moment;

/// Where a proof of existence comes from (`POEType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PoeType {
    /// Supplied by the caller (`provided`).
    Provided,
    /// From a timestamp token (Sigis addition; pyHanko records these as
    /// `validation`).
    Timestamp,
    /// Established during validation (`validation`).
    Validation,
    /// Assumed by policy (`policy`).
    Policy,
}

impl PoeType {
    /// The ETSI TS 119 102-2 URN (`POEType.urn`).
    pub fn urn(self) -> &'static str {
        match self {
            Self::Provided => "urn:etsi:019102:poetype:provided",
            Self::Timestamp | Self::Validation => "urn:etsi:019102:poetype:validation",
            Self::Policy => "urn:etsi:019102:poetype:policy",
        }
    }
}

/// A known proof of existence (`KnownPOE`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownPoe {
    /// The kind of POE.
    pub poe_type: PoeType,
    /// SHA-256 digest of the data.
    pub digest: Vec<u8>,
    /// The POE time.
    pub poe_time: Moment,
}

/// Records the earliest known time at which data existed (`POEManager`).
///
/// Keys are digests of the data (SHA-256, see [`digest_for_poe`]). Data
/// without a recorded POE exists "now" (`current_time`, by default the
/// system time), as `POEManager.__getitem__` assumes.
#[derive(Clone, Debug, Default)]
pub struct PoeManager {
    entries: BTreeMap<Vec<u8>, (Moment, PoeType)>,
    current_time: Option<Moment>,
}

impl PoeManager {
    /// An empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty manager whose "now" is `at` (`current_dt_override`).
    pub fn with_current_time(at: Moment) -> Self {
        Self {
            entries: BTreeMap::new(),
            current_time: Some(at),
        }
    }

    /// The manager's current time.
    pub fn current_time(&self) -> Moment {
        self.current_time.unwrap_or_else(Moment::now)
    }

    /// Register a POE for `data` at `at`; keeps the earliest one.
    pub fn register(&mut self, data: &[u8], at: Moment, kind: PoeType) {
        self.register_by_digest(digest_for_poe(data), at, kind);
    }

    /// Register a POE by digest (`register_by_digest`).
    pub fn register_by_digest(&mut self, digest: Vec<u8>, at: Moment, kind: PoeType) {
        let entry = self.entries.entry(digest).or_insert((at, kind));
        if at < entry.0 {
            *entry = (at, kind);
        }
    }

    /// The earliest POE for `data`, if any.
    pub fn get(&self, data: &[u8]) -> Option<(Moment, PoeType)> {
        self.entries.get(&digest_for_poe(data)).copied()
    }

    /// The earliest POE time for `data`, or the current time
    /// (`POEManager[data]`).
    pub fn poe_time(&self, data: &[u8]) -> Moment {
        let now = self.current_time();
        self.get(data).map_or(now, |(t, _)| t.min(now))
    }

    /// Every known POE.
    pub fn iter(&self) -> impl Iterator<Item = KnownPoe> + '_ {
        self.entries.iter().map(|(d, (t, k))| KnownPoe {
            poe_type: *k,
            digest: d.clone(),
            poe_time: *t,
        })
    }

    /// Merge the POEs of `other` into this manager (`|=`).
    pub fn merge(&mut self, other: &PoeManager) {
        for p in other.iter() {
            self.register_by_digest(p.digest, p.poe_time, p.poe_type);
        }
    }
}

/// Digest under which a POE is recorded (`digest_for_poe`).
pub fn digest_for_poe(data: &[u8]) -> Vec<u8> {
    DigestAlgorithm::Sha256.digest(data)
}
