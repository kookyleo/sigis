//! AdES main and sub-indications (ETSI EN 319 102-1, §5.1.3), re-exported
//! from [`sigis_pki_core::ades`].
//!
//! CMS validation reports trust problems as AdES sub-indications, as pyHanko
//! does (`trust_problem_indic`).

pub use sigis_pki_core::ades::{
    AdesFailure, AdesIndeterminate, AdesPassed, AdesStatus, AdesSubIndic,
};
