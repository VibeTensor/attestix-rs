//! Error type for the Attestix verifier.

use core::fmt;

/// Errors raised while decoding inputs or verifying credentials / delegations.
///
/// Note: a *cryptographically invalid* signature is **not** an `Err` — it is a
/// successful verification whose result reports `signature_valid: false`. An
/// `Err` is reserved for malformed inputs (bad base64, missing fields, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The `did:key` / multibase string was malformed.
    DidKey(&'static str),
    /// A required JSON field was missing or of the wrong type.
    Structure(&'static str),
    /// A base64 / base64url value could not be decoded.
    Base64(&'static str),
    /// A JWT was malformed (wrong number of segments, bad header, etc.).
    Jwt(&'static str),
    /// A timestamp could not be parsed.
    Time(&'static str),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::DidKey(m) => write!(f, "did:key error: {m}"),
            VerifyError::Structure(m) => write!(f, "structure error: {m}"),
            VerifyError::Base64(m) => write!(f, "base64 error: {m}"),
            VerifyError::Jwt(m) => write!(f, "jwt error: {m}"),
            VerifyError::Time(m) => write!(f, "time error: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {}
