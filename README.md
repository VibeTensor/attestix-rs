# attestix (Rust)

[![test](https://github.com/VibeTensor/attestix-rs/actions/workflows/test.yml/badge.svg)](https://github.com/VibeTensor/attestix-rs/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](./LICENSE)

Offline verifier for credentials and delegation chains issued by the
[Attestix](https://attestix.io) Python core: **no Python runtime needed**.

It re-implements the Attestix verification surface in pure, idiomatic Rust and
passes the shared cross-language [conformance vectors][vectors] byte-for-byte.
Strong fit for WebAssembly and embedded targets; the verify + canonicalize core
is `unsafe`-free and the Rust crate is intended to become the canonical crypto
core other language ports can FFI into.

- `canonicalize(&Value) -> Vec<u8>`: the Attestix **JCS-style** canonical bytes
- `decode_did_key(&str) -> [u8; 32]`: `did:key` (Ed25519) → raw public key
- `verify_credential(&vc, now) -> CredentialResult`: W3C VC: signature + expiry + revocation
- `verify_delegation_chain(parent, child, server_pubkey, now) -> DelegationResult`: UCAN EdDSA JWT chain + capability attenuation

## Install

```toml
[dependencies]
attestix = "0.4"
```

(Not yet published to crates.io; see [Publishing](#publishing). Until then,
depend on the git source:)

```toml
[dependencies]
attestix = { git = "https://github.com/VibeTensor/attestix-rs" }
```

## Verify a credential (10 lines)

```rust
use attestix::{verify_credential, parse_rfc3339};
use serde_json::Value;

let vc: Value = serde_json::from_str(vc_json)?;      // a full W3C VC from Attestix
let now = parse_rfc3339("2026-06-01T00:00:00+00:00")?;
let r = verify_credential(&vc, now)?;
assert!(r.signature_valid && r.not_expired && r.not_revoked);
println!("valid = {}", r.verify());
```

Run the bundled example:

```sh
cargo run --example verify_vc
```

## The canonical form is JCS-*style*, NOT strict RFC 8785

This is the single most error-prone part of any Attestix port. The Attestix
canonical form is a **practical subset of JCS** with two load-bearing
divergences from strict RFC 8785:

1. **NFC Unicode normalization**: every string value *and* every object key is
   `NFC`-normalized before serialization. RFC 8785 explicitly does **not**
   normalize. (`"cafe" + U+0301` → `"café"`.)
2. **Whole-number floats collapse to integers**: `1.0` → `1`. Large integers
   (`> 2^53`, e.g. `9007199254740993`) keep full precision.

Everything else matches JCS: keys sorted by Unicode code point, `(",", ":")`
separators (no whitespace), raw UTF-8 output (no `\uXXXX` escapes). The result is
exactly:

```text
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

after the recursive whole-float→int pass. Signatures are **Ed25519** (RFC 8032)
over those canonical bytes; the VC `proofValue` is **padded** base64url, while
UCAN JWT signatures use the **unpadded** base64url JWT compact form.

See the canonical-form spec at <https://attestix.io/spec/bundle/v1> and the full
conformance contract in the parent repo at
[`spec/verify/v1/README.md`][readme].

## Conformance

The shared vectors are vendored verbatim at
[`testdata/vectors.json`](./testdata/vectors.json) and asserted by
[`tests/conformance.rs`](./tests/conformance.rs):

```sh
cargo test
# conformance: 7/7 vectors passed
```

| vector | asserts |
|---|---|
| `canon-001` | byte-identical JCS-style canonicalization (NFC, codepoint sort, raw UTF-8, whole-float→int, big int) |
| `didkey-001` | `0xed01 ‖ raw32` base58btc → 32-byte key |
| `vc-valid-001` | valid VC ⇒ verify **true** |
| `vc-tampered-001` | flipped claim byte ⇒ signature invalid ⇒ verify **false** |
| `vc-expired-001` | past `expirationDate` ⇒ verify **false** (signature still valid) |
| `ucan-chain-valid-001` | child `att` ⊆ parent `att` ⇒ verify **true** |
| `ucan-chain-escalation-002` | child `att` ⊄ parent `att` (`admin`) ⇒ verify **false** |

## WebAssembly

The verifier is verify-only (no signing, no RNG), so it builds for the browser
and embedded WASM targets:

```sh
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --lib
```

CI builds this target on every push.

## Publishing

This crate is **publish-ready but not yet published**. To release to
[crates.io](https://crates.io):

```sh
# one-time: get a token from https://crates.io/settings/tokens
cargo login <CRATES_IO_TOKEN>
cargo publish --dry-run     # verify packaging
cargo publish               # release v0.4.0
```

No token is bundled here; publishing is an explicit, owner-run step.

## License

[Apache-2.0](./LICENSE) © 2026 VibeTensor.

Part of the Attestix project: [VibeTensor/attestix][parent] (Python core +
conformance vectors).

[parent]: https://github.com/VibeTensor/attestix
[vectors]: https://github.com/VibeTensor/attestix/tree/main/spec/verify/v1
[readme]: https://github.com/VibeTensor/attestix/blob/main/spec/verify/v1/README.md
