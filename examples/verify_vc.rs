//! Minimal example: verify a W3C Verifiable Credential offline.
//!
//! Run with:  cargo run --example verify_vc

use attestix::{parse_rfc3339, verify_credential};
use serde_json::json;

fn main() {
    // A VC issued by the Attestix core (issuer.id is a did:key; the proof
    // carries a padded-base64url Ed25519 signature over the JCS-canonical form
    // of every top-level field except `proof` and `credentialStatus`).
    let vc = json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": ["VerifiableCredential", "EUAIActComplianceCredential"],
        "id": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "issuer": {
            "id": "did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev",
            "name": "VibeTensor"
        },
        "issuanceDate": "2026-01-01T00:00:00+00:00",
        "expirationDate": "2027-01-01T00:00:00+00:00",
        "credentialSubject": {
            "id": "did:key:zSubjectAgentPlaceholder",
            "conformityAssessed": true,
            "riskTier": "high"
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "2026-01-01T00:00:00+00:00",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev#z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev",
            "proofValue": "ksvGxJxaJqz7Vg1aRfOoHCbKiyEGcWtpcY-vcD2iGmIjsRDNJn3fsplhicGdIBYC7l8rvwnyn3VT7w3jk9SAAw=="
        }
    });

    let now = parse_rfc3339("2026-06-01T00:00:00+00:00").unwrap();
    let result = verify_credential(&vc, now).expect("well-formed VC");

    println!("signature_valid = {}", result.signature_valid);
    println!("not_expired     = {}", result.not_expired);
    println!("not_revoked     = {}", result.not_revoked);
    println!("verify          = {}", result.verify());
    assert!(result.verify(), "this VC should verify");
}
