//! # attestix
//!
//! Offline verifier for credentials and delegation chains issued by the
//! [Attestix](https://attestix.io) Python core — **no Python runtime needed**.
//!
//! It reproduces the Attestix **JCS-style canonical form** byte-for-byte (see
//! [`canonicalize`]). This is **not** strict RFC 8785: Attestix additionally
//! NFC-normalizes every string value and object key, and collapses whole-number
//! floats to integers. See the canonical-form spec at
//! <https://attestix.io/spec/bundle/v1> and the conformance vectors at
//! `spec/verify/v1/vectors.json` in <https://github.com/VibeTensor/attestix>.
//!
//! ## Quick start
//!
//! ```no_run
//! use attestix::{verify_credential, parse_rfc3339};
//! use serde_json::Value;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let vc: Value = serde_json::from_str(r#"{ "...": "a full W3C VC JSON" }"#)?;
//! let now = parse_rfc3339("2026-06-01T00:00:00+00:00")?;
//! let result = verify_credential(&vc, now)?;
//! if result.verify() {
//!     println!("credential is valid");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The crate is `no_std`-friendly for the canonicalization and crypto core (the
//! `std` default feature only adds `std::error::Error` and the JSON/JWT helpers).

#![forbid(unsafe_code)]

mod canonical;
mod credential;
mod delegation;
mod didkey;
mod error;

pub use canonical::canonicalize;
pub use credential::{verify_credential, CredentialResult};
pub use delegation::{verify_delegation_chain, DelegationResult};
pub use didkey::{
    decode_did_key, decode_multibase, encode_did_key, encode_multibase, ED25519_MULTICODEC_PREFIX,
};
pub use error::VerifyError;

use time::OffsetDateTime;

/// Parse an RFC 3339 / ISO 8601 timestamp (e.g. `2026-06-01T00:00:00+00:00`)
/// into an [`OffsetDateTime`] suitable for [`verify_credential`].
pub fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, VerifyError> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| VerifyError::Time("invalid RFC 3339 timestamp"))
}

/// Re-export of [`time::OffsetDateTime`] so downstream crates need not depend on
/// `time` directly to call [`verify_credential`].
pub use time::OffsetDateTime as DateTime;
