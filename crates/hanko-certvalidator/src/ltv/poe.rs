// Interfaces derived from pyhanko-certvalidator `ltv/poe.py` (MIT, see LICENSE-pyHanko).

//! Proofs of existence (POE).

use std::collections::BTreeMap;

use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::time::Moment;

/// Where a proof of existence comes from (`POEType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PoeType {
    /// Supplied by the caller.
    Provided,
    /// From a timestamp token.
    Timestamp,
    /// From a validated signature.
    Validation,
}

/// Records the earliest known time at which data existed (`POEManager`).
///
/// Keys are digests of the data (SHA-256 by default, see [`digest_for_poe`]).
#[derive(Clone, Debug, Default)]
pub struct PoeManager {
    entries: BTreeMap<Vec<u8>, (Moment, PoeType)>,
}

impl PoeManager {
    /// An empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a POE for `data` at `at`; keeps the earliest one.
    pub fn register(&mut self, data: &[u8], at: Moment, kind: PoeType) {
        let key = digest_for_poe(data);
        let entry = self.entries.entry(key).or_insert((at, kind));
        if at < entry.0 {
            *entry = (at, kind);
        }
    }

    /// The earliest POE for `data`, if any.
    pub fn get(&self, data: &[u8]) -> Option<(Moment, PoeType)> {
        self.entries.get(&digest_for_poe(data)).copied()
    }
}

/// Digest under which a POE is recorded (`digest_for_poe`).
pub fn digest_for_poe(data: &[u8]) -> Vec<u8> {
    DigestAlgorithm::Sha256.digest(data)
}
