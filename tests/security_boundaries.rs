use attestix::{parse_rfc3339, try_canonicalize, verify_credential};
use serde_json::{json, Value};

#[test]
fn ambiguous_keys_are_rejected() {
    let value: Value = serde_json::from_str(r#"{"\u00e9":1,"e\u0301":2}"#).unwrap();
    assert!(try_canonicalize(&value).is_err());
}

#[test]
fn unsupported_float_magnitudes_are_rejected() {
    for raw in ["1e309", "1e308", "-0.0", "1e-7"] {
        let value: Value = serde_json::from_str(raw).unwrap();
        assert!(try_canonicalize(&value).is_err());
    }
}

#[test]
fn malformed_expiry_is_rejected() {
    let vectors: Value = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let original = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["kind"] == "verify_credential" && v["expected"]["verify"] == true)
        .unwrap()["input"]
        .clone();
    let now = parse_rfc3339("2026-06-01T00:00:00Z").unwrap();
    for expiry in [Value::Null, json!(123), json!(false), json!("")] {
        let mut vc = original.clone();
        vc["expirationDate"] = expiry;
        assert!(verify_credential(&vc, now).is_err());
    }
}

#[test]
fn unsigned_verification_method_cannot_replace_issuer() {
    let vectors: Value = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let mut vc = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["kind"] == "verify_credential" && v["expected"]["verify"] == true)
        .unwrap()["input"]
        .clone();
    vc["proof"]["verificationMethod"] = json!("did:key:invalid#invalid");
    assert!(verify_credential(&vc, parse_rfc3339("2026-06-01T00:00:00Z").unwrap()).is_err());
}
