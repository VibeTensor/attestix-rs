//! UCAN delegation-chain verification (EdDSA JWTs).
//!
//! Matches `attestix/services/delegation_service.py`. Delegations are **NOT**
//! JCS-signed: each is a compact EdDSA JWT. The signed message is
//! `base64url(header).base64url(payload)` (unpadded, per the JWT spec — distinct
//! from the *padded* base64url of the VC `proofValue`). Only `alg=EdDSA` is
//! accepted (`alg:none` is rejected).
//!
//! Chain verification (recursive over `prf[]`):
//!  1. each JWT signature verifies under the server key;
//!  2. each JWT is not expired (`exp`) — checked when `now` is supplied;
//!  3. cycles (a repeated `jti`) are rejected;
//!  4. capability attenuation: a child's `att` MUST be a subset of its parent's.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use std::collections::BTreeSet;

use crate::error::VerifyError;

/// Structured result of verifying a two-link delegation chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationResult {
    /// The parent (root) JWT signature verifies under the server key.
    pub parent_signature_valid: bool,
    /// The child JWT signature verifies under the server key.
    pub child_signature_valid: bool,
    /// The child's `att` is a subset of the parent's `att`.
    pub attenuation_is_subset: bool,
    /// No token in the chain is expired (only meaningful when `now` is given).
    pub not_expired: bool,
}

impl DelegationResult {
    /// `verify` = both signatures valid AND attenuation is a subset AND not expired.
    pub fn verify(&self) -> bool {
        self.parent_signature_valid
            && self.child_signature_valid
            && self.attenuation_is_subset
            && self.not_expired
    }
}

/// A decoded JWT: its header/payload JSON plus the exact signed bytes.
struct DecodedJwt {
    header: Value,
    payload: Value,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

/// Split a compact JWT into header / payload / signature and recover the signed
/// bytes (`b64url(header).b64url(payload)`).
fn decode_jwt(token: &str) -> Result<DecodedJwt, VerifyError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::Jwt("compact JWT must have 3 segments"));
    }
    let header_bytes = b64url_decode(parts[0])?;
    let payload_bytes = b64url_decode(parts[1])?;
    let signature = b64url_decode(parts[2])?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| VerifyError::Jwt("bad header JSON"))?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| VerifyError::Jwt("bad payload JSON"))?;

    let mut signing_input = Vec::with_capacity(parts[0].len() + 1 + parts[1].len());
    signing_input.extend_from_slice(parts[0].as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(parts[1].as_bytes());

    Ok(DecodedJwt {
        header,
        payload,
        signing_input,
        signature,
    })
}

/// Verify a single JWT's EdDSA signature under `server_pubkey`.
///
/// Rejects any `alg` other than `EdDSA` (notably `none`).
fn verify_jwt_signature(jwt: &DecodedJwt, server_pubkey: &[u8; 32]) -> bool {
    match jwt.header.get("alg").and_then(Value::as_str) {
        Some("EdDSA") => {}
        _ => return false, // reject alg:none and anything else
    }
    let sig = match Signature::from_slice(&jwt.signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_bytes(server_pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    key.verify_strict(&jwt.signing_input, &sig).is_ok()
}

/// `att` claim as a set of capability strings.
fn att_set(payload: &Value) -> BTreeSet<String> {
    payload
        .get("att")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// `exp` claim (Unix seconds) if present.
fn exp_seconds(payload: &Value) -> Option<i64> {
    payload.get("exp").and_then(Value::as_i64)
}

/// Verify a parent→child delegation chain.
///
/// - `parent_token`, `token` are the compact EdDSA JWTs.
/// - `server_pubkey` is the single server key that signs every token.
/// - `now_unix` is the current time in Unix seconds for expiry checks; pass
///   `None` to skip the expiry check (signature + attenuation only).
pub fn verify_delegation_chain(
    parent_token: &str,
    token: &str,
    server_pubkey: &[u8; 32],
    now_unix: Option<i64>,
) -> Result<DelegationResult, VerifyError> {
    let parent = decode_jwt(parent_token)?;
    let child = decode_jwt(token)?;

    let parent_signature_valid = verify_jwt_signature(&parent, server_pubkey);
    let child_signature_valid = verify_jwt_signature(&child, server_pubkey);

    // Cycle detection over jti across the chain.
    let parent_jti = parent.payload.get("jti").and_then(Value::as_str);
    let child_jti = child.payload.get("jti").and_then(Value::as_str);
    let cycle = match (parent_jti, child_jti) {
        (Some(p), Some(c)) => p == c,
        _ => false,
    };

    // Attenuation: child att MUST be a subset of parent att.
    let parent_att = att_set(&parent.payload);
    let child_att = att_set(&child.payload);
    let attenuation_is_subset = child_att.is_subset(&parent_att);

    // Expiry: every token must satisfy now < exp.
    let not_expired = match now_unix {
        None => true,
        Some(now) => {
            let ok = |p: &Value| exp_seconds(p).map(|e| now < e).unwrap_or(true);
            ok(&parent.payload) && ok(&child.payload)
        }
    };

    Ok(DelegationResult {
        parent_signature_valid,
        child_signature_valid,
        attenuation_is_subset: attenuation_is_subset && !cycle,
        not_expired,
    })
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, VerifyError> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| VerifyError::Base64("invalid unpadded base64url"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn subset_attenuation() {
        let parent = json!({"att": ["read", "write", "delete"]});
        let child = json!({"att": ["read", "write"]});
        assert!(att_set(&child).is_subset(&att_set(&parent)));
    }

    #[test]
    fn escalation_not_subset() {
        let parent = json!({"att": ["read", "write", "delete"]});
        let child = json!({"att": ["read", "admin"]});
        assert!(!att_set(&child).is_subset(&att_set(&parent)));
    }
}
