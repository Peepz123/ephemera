//! Key derivation, per PROTOCOL.md sections 5.2, 5.3 and 5.4.
//!
//! These three functions are the arithmetic core of the ratchet. They are
//! implemented here rather than stubbed because they are short, total, and
//! independently testable — get these right first and the ratchet becomes
//! bookkeeping.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Domain separation string for the root chain KDF.
pub const INFO_ROOT: &[u8] = b"ephemera_ratchet_root_v1";
/// Domain separation string for message key expansion.
pub const INFO_MSG: &[u8] = b"ephemera_msg_v1";
/// Domain separation string for X3DH.
pub const INFO_X3DH: &[u8] = b"ephemera_x3dh_v1";

/// A 32-byte root key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

/// A 32-byte chain key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

/// A 32-byte message key, consumed exactly once.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

/// An expanded AEAD key and nonce pair.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadParams {
    /// XChaCha20-Poly1305 key.
    pub key: [u8; 32],
    /// XChaCha20-Poly1305 192-bit nonce.
    pub nonce: [u8; 24],
}

/// Root KDF: advances the root chain on a DH ratchet step.
///
/// `KDF_RK(rk, dh_out) -> (RK', CK)` — PROTOCOL.md 5.2.
pub fn kdf_rk(rk: &RootKey, dh_out: &[u8; 32]) -> (RootKey, ChainKey) {
    let hk = Hkdf::<Sha256>::new(Some(&rk.0), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(INFO_ROOT, &mut okm)
        .expect("64 bytes is a valid HKDF-SHA256 output length");

    let mut next_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    next_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();

    (RootKey(next_rk), ChainKey(ck))
}

/// Symmetric chain KDF: advances a sending or receiving chain by one.
///
/// `KDF_CK(ck) -> (CK', MK)` — PROTOCOL.md 5.3.
pub fn kdf_ck(ck: &ChainKey) -> (ChainKey, MessageKey) {
    let mut mac = HmacSha256::new_from_slice(&ck.0).expect("HMAC accepts any key length");
    mac.update(&[0x01]);
    let mk: [u8; 32] = mac.finalize().into_bytes().into();

    let mut mac = HmacSha256::new_from_slice(&ck.0).expect("HMAC accepts any key length");
    mac.update(&[0x02]);
    let next: [u8; 32] = mac.finalize().into_bytes().into();

    (ChainKey(next), MessageKey(mk))
}

/// Expands a message key into an AEAD key and nonce.
///
/// Because the message key is unique per message, the nonce is unique per key
/// and the XChaCha20 nonce space is never at risk — PROTOCOL.md 5.4.
pub fn expand_message_key(mk: &MessageKey) -> AeadParams {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &mk.0);
    let mut okm = [0u8; 56];
    hk.expand(INFO_MSG, &mut okm)
        .expect("56 bytes is a valid HKDF-SHA256 output length");

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();

    AeadParams { key, nonce }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_kdf_advances_and_differs() {
        let ck = ChainKey([7u8; 32]);
        let (next, mk) = kdf_ck(&ck);
        assert_ne!(next.0, ck.0, "chain key must advance");
        assert_ne!(mk.0, ck.0, "message key must differ from chain key");
        assert_ne!(next.0, mk.0, "0x01 and 0x02 domains must not collide");
    }

    #[test]
    fn chain_kdf_is_deterministic() {
        let ck = ChainKey([9u8; 32]);
        let (a, ma) = kdf_ck(&ck);
        let (b, mb) = kdf_ck(&ck);
        assert_eq!(a.0, b.0);
        assert_eq!(ma.0, mb.0);
    }

    #[test]
    fn root_kdf_separates_outputs() {
        let rk = RootKey([1u8; 32]);
        let (next, ck) = kdf_rk(&rk, &[2u8; 32]);
        assert_ne!(next.0, ck.0);
        assert_ne!(next.0, rk.0);
    }

    #[test]
    fn message_key_expansion_is_deterministic() {
        let mk = MessageKey([3u8; 32]);
        let a = expand_message_key(&mk);
        let b = expand_message_key(&mk);
        assert_eq!(a.key, b.key);
        assert_eq!(a.nonce, b.nonce);
    }
}
