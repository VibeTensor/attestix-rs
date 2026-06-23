//! Conformance suite: load `testdata/vectors.json` (the shared cross-language
//! vectors vendored verbatim from VibeTensor/attestix `spec/verify/v1`) and
//! assert every vector against the Rust verifier.
//!
//! A failing vector means this port is wrong, not the vector - the canonical
//! byte-match (`canon-001`) is the highest-signal test.

use attestix::{
    canonicalize, decode_did_key, decode_multibase, parse_rfc3339, verify_credential,
    verify_delegation_chain,
};
use serde_json::Value;

fn load_vectors() -> Value {
    let raw = include_str!("../testdata/vectors.json");
    serde_json::from_str(raw).expect("vectors.json must be valid JSON")
}

/// A fixed "now" inside (2021, 2027): valid VC is in-window, expired VC is out.
fn now() -> time::OffsetDateTime {
    parse_rfc3339("2026-06-01T00:00:00+00:00").unwrap()
}

#[test]
fn all_vectors_pass() {
    let doc = load_vectors();
    let vectors = doc["vectors"].as_array().expect("vectors[] array");
    let declared = doc["vector_count"].as_u64().unwrap_or(0) as usize;
    assert_eq!(
        vectors.len(),
        declared,
        "vector_count ({declared}) must match vectors[].len() ({})",
        vectors.len()
    );

    let mut passed = 0usize;
    for v in vectors {
        let id = v["id"].as_str().unwrap_or("<no id>");
        let kind = v["kind"].as_str().unwrap_or("<no kind>");
        match kind {
            "canonicalize" => check_canonicalize(id, v),
            "did_key_decode" => check_did_key(id, v),
            "verify_credential" => check_verify_credential(id, v),
            "verify_delegation_chain" => check_delegation(id, v),
            other => panic!("[{id}] unknown vector kind: {other}"),
        }
        passed += 1;
    }
    assert_eq!(passed, declared, "all {declared} vectors must run");
    eprintln!("conformance: {passed}/{declared} vectors passed");
}

fn check_canonicalize(id: &str, v: &Value) {
    let input = &v["input"];
    let got = canonicalize(input);
    let want_hex = v["canonical_bytes_hex"].as_str().unwrap();
    let got_hex = hex::encode(&got);
    assert_eq!(
        got_hex, want_hex,
        "[{id}] canonical bytes mismatch\n got: {got_hex}\nwant: {want_hex}\n got_str: {}",
        String::from_utf8_lossy(&got)
    );

    // Cross-check the human-readable expected.canonical_utf8 when present.
    if let Some(expected_utf8) = v["expected"]["canonical_utf8"].as_str() {
        assert_eq!(
            String::from_utf8(got).unwrap(),
            expected_utf8,
            "[{id}] canonical_utf8 mismatch"
        );
    }
}

fn check_did_key(id: &str, v: &Value) {
    let did = v["input"]["did"].as_str().unwrap();
    let raw = decode_did_key(did).expect("decode did:key");
    let want_hex = v["expected"]["pubkey_raw_hex"].as_str().unwrap();
    assert_eq!(hex::encode(raw), want_hex, "[{id}] raw pubkey mismatch");

    // The `z…` multibase body must decode to the same key.
    if let Some(mb) = v["pubkey_multibase"].as_str() {
        let raw2 = decode_multibase(mb).expect("decode multibase");
        assert_eq!(raw, raw2, "[{id}] multibase decode mismatch");
    }
}

fn check_verify_credential(id: &str, v: &Value) {
    let vc = &v["input"];
    let result = verify_credential(vc, now()).expect("verify_credential");
    let exp = &v["expected"];

    assert_eq!(
        result.signature_valid,
        exp["signature_valid"].as_bool().unwrap(),
        "[{id}] signature_valid"
    );
    assert_eq!(
        result.not_expired,
        exp["not_expired"].as_bool().unwrap(),
        "[{id}] not_expired"
    );
    assert_eq!(
        result.not_revoked,
        exp["not_revoked"].as_bool().unwrap(),
        "[{id}] not_revoked"
    );
    assert_eq!(
        result.verify(),
        exp["verify"].as_bool().unwrap(),
        "[{id}] verify"
    );

    // If the vector ships the signing payload + canonical hex, the port's
    // canonicalizer must reproduce it (the load-bearing byte-match).
    if let (Some(payload), Some(want_hex)) = (
        v.get("signing_payload"),
        v["canonical_bytes_hex"].as_str(),
    ) {
        if !payload.is_null() {
            let got_hex = hex::encode(canonicalize(payload));
            assert_eq!(got_hex, want_hex, "[{id}] signing-payload canonical hex");
        }
    }
}

fn check_delegation(id: &str, v: &Value) {
    let parent = v["input"]["parent_token"].as_str().unwrap();
    let token = v["input"]["token"].as_str().unwrap();
    let pubkey_hex = v["pubkey_raw_hex"].as_str().unwrap();
    let pubkey_vec = hex::decode(pubkey_hex).unwrap();
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pubkey_vec);

    // now well before the fixed exp (4102444800 = 2100) so tokens are live.
    let result = verify_delegation_chain(parent, token, &pubkey, Some(1_800_000_000))
        .expect("verify_delegation_chain");
    let exp = &v["expected"];

    assert_eq!(
        result.parent_signature_valid,
        exp["parent_signature_valid"].as_bool().unwrap(),
        "[{id}] parent_signature_valid"
    );
    assert_eq!(
        result.child_signature_valid,
        exp["child_signature_valid"].as_bool().unwrap(),
        "[{id}] child_signature_valid"
    );
    assert_eq!(
        result.attenuation_is_subset,
        exp["attenuation_is_subset"].as_bool().unwrap(),
        "[{id}] attenuation_is_subset"
    );
    assert_eq!(
        result.verify(),
        exp["verify"].as_bool().unwrap(),
        "[{id}] verify"
    );
}
