# Attestix verifier for Rust

Offline verification of Attestix Ed25519 credentials and parent/child UCAN
delegations, without Python. The crate uses the custom Attestix v1 canonical
format and returns technical verification results. Those results do not establish
issuer trust or the truth or legal conformity of signed claims.

## Install from source

Requires Rust 1.88 or later. Pin the reviewed source revision:

```toml
[dependencies]
attestix = { git = "https://github.com/VibeTensor/attestix-rs", rev = "527dbfc6340d73e842cc8bbd7192e7c6295a9760" }
serde_json = "1"
```

This documents source installation. Package-registry publication and production
adoption require their own release review.

## Verify a credential

```rust
use attestix::{parse_rfc3339, verify_credential};
use serde_json::Value;

fn verify_at(vc_json: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let vc: Value = serde_json::from_str(vc_json)?;
    // Choose the actual evaluation time in the calling application.
    let now = parse_rfc3339("2026-06-01T00:00:00+00:00")?;
    let result = verify_credential(&vc, now)?;
    Ok(result.verify())
}
```

The verifier resolves the Ed25519 key from the signed issuer `did:key` and rejects
a conflicting present `proof.verificationMethod`. Malformed expiry, signature,
key or unsupported canonical input returns an error or a failed result. An absent
expiry is accepted by this profile; enforce mandatory expiry in the application.

`credentialStatus` is excluded from the signature. `not_revoked` only describes
the supplied status flag; this verifier does not fetch fresh external revocation
state. Enforce expected issuer, trusted status, evaluation time and replay policy
before using the result to authorize an action.

## API and checked canonicalization

| API | Scope |
| --- | --- |
| `verify_credential(&Value, now)` | Issuer-bound signature and supplied expiry/status checks. |
| `verify_delegation_chain(parent, child, server_pubkey, now_unix)` | One EdDSA parent/child pair and capability attenuation. `None` skips expiry checks. |
| `try_canonicalize(&Value)` | Checked custom-format bytes; rejects NFC-key collisions and unsupported numeric edges. |
| `canonicalize(&Value)` | Legacy compatibility helper for trusted values; does not reject ambiguous keys. |
| `decode_did_key(&str)` | Raw Ed25519 `did:key` decoding. |
| `parse_rfc3339(&str)` | Explicit timestamp parsing. |

Use `try_canonicalize` on untrusted values; credential verification already uses
it. Standard `serde_json::Value` parsing may discard exact duplicate JSON members
before this check. Reject duplicates at an earlier parsing boundary if required.
Do not substitute the legacy helper to bypass a checked-format error.

Delegation verification takes a caller-trusted server key and evaluates a pair,
not an arbitrary full delegation graph. Apply resource/action, identity,
revocation and freshness rules outside the helper. Set `now_unix` when expiry
matters; disabling that argument is a deliberate policy choice.

## Wire profile and limitations

The Attestix format NFC-normalizes strings/keys and collapses supported
whole-number floats. It is not strict RFC 8785/JCS. Large integer tokens are
preserved; arbitrary floating-point compatibility with other serializers is not
guaranteed. Verification supports the profile exercised in
[`testdata/vectors.json`](testdata/vectors.json) and security-boundary tests,
rather than every W3C credential proof suite.

See the [parent verification contract](https://github.com/VibeTensor/attestix/tree/main/spec/verify/v1).
A valid signature is evidence about the key and signed bytes, not a compliance
certification, legal assessment or proof that an event was completely captured.
The crate forbids unsafe Rust in its own source; that does not establish the same
property for all dependencies or deployment environments.

## Development and WebAssembly

```sh
cargo test
cargo doc --no-deps
cargo run --example verify_vc
```

The bundled example uses a fixed signed fixture and evaluation time, not the
current date or a live issuer/status service. CI tests Rust 1.88 and stable,
checks clippy, and builds the library for `wasm32-unknown-unknown`. A WASM build
is not a browser application or a tested embedded integration.

```sh
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --lib
```

## License

[Apache-2.0](LICENSE). Part of [Attestix](https://github.com/VibeTensor/attestix).
