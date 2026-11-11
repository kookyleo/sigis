// Derived from pyhanko-certvalidator `fetchers/` and pyHanko
// `sign/timestamps/` (MIT, see LICENSE-pyHanko).

//! HTTP implementations of the retrieval traits in [`sigis_pki_core::fetch`] and
//! of [`sigis_pki_core::sign::TimeStamper`].
//!
//! | pyHanko | module |
//! | --- | --- |
//! | `fetchers/api.py` (`FetchLimits`), `fetchers/common_utils.py` (`FetchBudget`) | [`budget`] |
//! | `fetchers/common_utils.py`, `util.py` (URL gathering) | [`common`] |
//! | `fetchers/requests_fetchers/`, `fetchers/aiohttp_fetchers/` | [`fetchers`] |
//! | `sign/timestamps/{api,common_utils,requests_client,aiohttp_client}.py` | [`tsa`] |
//! | HTTP sessions (`requests`, `aiohttp`) | [`transport`] (`reqwest` blocking) |
//!
//! Owned by lane A. Tests never use the network; they use in-memory
//! transports or a local HTTP server on 127.0.0.1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod budget;
pub mod common;
pub mod fetchers;
pub mod transport;
pub mod tsa;

pub use budget::{FetchBudget, FetchKind, FetchLimits};
pub use fetchers::{FetcherSettings, HttpFetchers};
pub use transport::{HttpResponse, HttpTransport, ReqwestTransport, TransportError};
pub use tsa::{HttpTimeStamper, NonceMode, TimestampRequestError};
