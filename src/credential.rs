//! W3C Verifiable Credential verification (Ed25519 + JCS-style canonical form).
//!
//! Matches `attestix/services/credential_service.py`:
//! the VC is signed over every top-level field EXCEPT `proof` and
//! `credentialStatus` (`MUTABLE_FIELDS`). Verification ANDs three checks:
//! `signature_valid AND not_expired AND not_revoked`.

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::canonical::canonicalize;
use crate::didkey::decode_did_key;
use crate::error::VerifyError;

/// Top-level fields excluded from the signing payload (mutable post-issuance).
const MUTABLE_FIELDS: [&str; 2] = ["proof", "credentialStatus"];

/// Structured result of verifying a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialResult {
    /// The Ed25519 proof signature verifies over the canonical signing payload.
    pub signature_valid: bool,
    /// `now < expirationDate` (or no `expirationDate` present).
    pub not_expired: bool,
    /// `credentialStatus.revoked` is falsy (an external verifier without a
    /// revocation list assumes not-revoked).
    pub not_revoked: bool,
    /// Required structural fields are present and well-typed.
    pub structure_valid: bool,
}

impl CredentialResult {
    /// `verify` = signature_valid AND not_expired AND not_revoked.
    /// (`structure_valid` is reported separately; a structurally broken VC
    /// surfaces as an `Err` from [`verify_credential`].)
    pub fn verify(&self) -> bool {
        self.signature_valid && self.not_expired && self.not_revoked
    }
}

/// Verify a full W3C VC JSON object against the wall-clock time `now`.
///
/// The issuer public key is decoded from `issuer.id` (a `did:key`). `now` is
/// supplied explicitly so verification is deterministic and `no_std`-friendly.
pub fn verify_credential(vc: &Value, now: OffsetDateTime) -> Result<CredentialResult, VerifyError> {
    let obj = vc
        .as_object()
        .ok_or(VerifyError::Structure("credential must be a JSON object"))?;

    // --- issuer public key (did:key) ---
    let issuer_did = obj
        .get("issuer")
        .and_then(|i| i.get("id"))
        .and_then(Value::as_str)
        .or_else(|| obj.get("issuer").and_then(Value::as_str))
        .ok_or(VerifyError::Structure("missing issuer.id"))?;
    let pubkey = decode_did_key(issuer_did)?;

    // --- proof.proofValue (padded base64url Ed25519 signature) ---
    let proof_value = obj
        .get("proof")
        .and_then(|p| p.get("proofValue"))
        .and_then(Value::as_str)
        .ok_or(VerifyError::Structure("missing proof.proofValue"))?;

    let structure_valid = true;

    let signature_valid = verify_proof(obj, &pubkey, proof_value)?;
    let not_expired = check_not_expired(obj, now)?;
    let not_revoked = check_not_revoked(obj);

    Ok(CredentialResult {
        signature_valid,
        not_expired,
        not_revoked,
        structure_valid,
    })
}

/// Build the signing payload (VC minus `MUTABLE_FIELDS`), canonicalize it, and
/// Ed25519-verify the proof signature against `pubkey`.
fn verify_proof(
    obj: &Map<String, Value>,
    pubkey: &[u8; 32],
    proof_value: &str,
) -> Result<bool, VerifyError> {
    let mut signing: Map<String, Value> = Map::new();
    for (k, v) in obj {
        if !MUTABLE_FIELDS.contains(&k.as_str()) {
            signing.insert(k.clone(), v.clone());
        }
    }
    let canonical = canonicalize(&Value::Object(signing));

    let sig_bytes = decode_b64url(proof_value)?;
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let key = match VerifyingKey::from_bytes(pubkey) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    Ok(key.verify_strict(&canonical, &sig).is_ok())
}

/// `now < expirationDate`. Absent `expirationDate` ⇒ not expired.
fn check_not_expired(obj: &Map<String, Value>, now: OffsetDateTime) -> Result<bool, VerifyError> {
    match obj.get("expirationDate").and_then(Value::as_str) {
        None => Ok(true),
        Some(exp_str) => {
            let exp = parse_rfc3339(exp_str)?;
            Ok(now < exp)
        }
    }
}

/// `credentialStatus.revoked` falsy ⇒ not revoked.
fn check_not_revoked(obj: &Map<String, Value>) -> bool {
    match obj.get("credentialStatus") {
        None => true,
        Some(status) => match status.get("revoked") {
            Some(Value::Bool(b)) => !b,
            Some(Value::Null) | None => true,
            // Any non-false, non-null truthy value ⇒ revoked.
            Some(other) => other.as_bool().map(|b| !b).unwrap_or(false),
        },
    }
}

/// Decode a padded base64url string (the VC `proofValue` form).
fn decode_b64url(s: &str) -> Result<Vec<u8>, VerifyError> {
    use base64::engine::general_purpose::URL_SAFE;
    use base64::Engine;
    URL_SAFE
        .decode(s.as_bytes())
        .map_err(|_| VerifyError::Base64("invalid padded base64url"))
}

/// Parse an RFC 3339 / ISO 8601 timestamp (e.g. `2027-01-01T00:00:00+00:00`).
fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, VerifyError> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| VerifyError::Time("invalid RFC 3339 timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_true_is_revoked() {
        let v: Value = serde_json::from_str(r#"{"credentialStatus":{"revoked":true}}"#).unwrap();
        assert!(!check_not_revoked(v.as_object().unwrap()));
    }

    #[test]
    fn revoked_false_is_not_revoked() {
        let v: Value = serde_json::from_str(r#"{"credentialStatus":{"revoked":false}}"#).unwrap();
        assert!(check_not_revoked(v.as_object().unwrap()));
    }
}
