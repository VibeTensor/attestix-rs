//! `did:key` (Ed25519) decoding, matching `attestix/auth/crypto.py`.
//!
//! `did:key:z` + base58btc(`0xed 0x01` ‖ 32-byte raw Ed25519 public key).
//! The `0xed01` prefix is the unsigned-varint multicodec code for `ed25519-pub`.

use crate::error::VerifyError;

/// Multicodec prefix for an Ed25519 public key (`ed25519-pub`).
pub const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Decode a full `did:key:z…` string into the raw 32-byte Ed25519 public key.
///
/// Strips the `did:key:z` prefix, base58btc-decodes, asserts the first two bytes
/// are `0xed 0x01`, and returns the remaining 32 bytes.
pub fn decode_did_key(did: &str) -> Result<[u8; 32], VerifyError> {
    let multibase = did
        .strip_prefix("did:key:")
        .ok_or(VerifyError::DidKey("missing 'did:key:' prefix"))?;
    decode_multibase(multibase)
}

/// Decode a `z…` multibase body (the part after `did:key:`) into the raw key.
pub fn decode_multibase(multibase: &str) -> Result<[u8; 32], VerifyError> {
    let b58 = multibase
        .strip_prefix('z')
        .ok_or(VerifyError::DidKey("missing 'z' multibase prefix"))?;
    let decoded = bs58::decode(b58)
        .into_vec()
        .map_err(|_| VerifyError::DidKey("invalid base58btc"))?;
    if decoded.len() != 2 + 32 {
        return Err(VerifyError::DidKey("unexpected multicodec length"));
    }
    if decoded[0..2] != ED25519_MULTICODEC_PREFIX {
        return Err(VerifyError::DidKey("not an ed25519-pub multicodec (expected 0xed01)"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..]);
    Ok(key)
}

/// Encode a raw 32-byte Ed25519 public key as the `z…` multibase body.
pub fn encode_multibase(raw: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(2 + 32);
    buf.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    buf.extend_from_slice(raw);
    format!("z{}", bs58::encode(buf).into_string())
}

/// Encode a raw 32-byte Ed25519 public key as a full `did:key:z…` string.
pub fn encode_did_key(raw: &[u8; 32]) -> String {
    format!("did:key:{}", encode_multibase(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev";
    const RAW_HEX: &str = "8022fe847be6106443a4030d74d390c8d9a91319b9f51526bc7c3d88a27c9b7b";

    #[test]
    fn decode_roundtrip() {
        let key = decode_did_key(DID).unwrap();
        assert_eq!(hex::encode(key), RAW_HEX);
        assert_eq!(encode_did_key(&key), DID);
    }

    #[test]
    fn rejects_non_ed25519() {
        // 0x12 0x00 is not the ed25519 multicodec.
        let mut bad = vec![0x12u8, 0x00];
        bad.extend_from_slice(&[0u8; 32]);
        let mb = format!("z{}", bs58::encode(bad).into_string());
        assert!(decode_multibase(&mb).is_err());
    }
}
