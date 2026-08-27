//! X3DH key agreement — PROTOCOL.md section 4.
//!
//! # Status: not implemented
//!
//! This is Phase 1 work and deliberately left as `todo!()`. The type signatures,
//! the constants, and the associated-data derivation are provided; the four
//! Diffie-Hellman operations and the HKDF call are yours.
//!
//! Conformance test 3 in `tests/conformance.rs` is the definition of done.
use rand_core::OsRng;
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::kdf::{RootKey, INFO_X3DH};
use crate::keys::{IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey};

/// The 32-byte 0xFF prefix that domain-separates X25519 X3DH from other
/// protocols sharing the curve (PROTOCOL.md 4).
pub const F_PREFIX: [u8; 32] = [0xFF; 32];

/// Parameters the initiator must transmit so the responder can reconstruct the
/// same shared secret.
#[derive(Clone, Debug)]
pub struct InitialMessage {
    /// Initiator's ephemeral public key.
    pub ek_a: PublicKey,
    /// Which signed prekey was used.
    pub spk_id: u32,
    /// Which one-time prekey was used, or `keys::OPK_NONE`.
    pub opk_id: u32,
}

/// Compute `AD_ident` — PROTOCOL.md 4.1.
///
/// Ordering is always initiator first, so both parties derive identical bytes
/// regardless of which direction a message travels.
pub fn associated_data(initiator: &VerifyingKey, responder: &VerifyingKey) -> [u8; 64] {
    let mut ad = [0u8; 64];
    ad[..32].copy_from_slice(initiator.as_bytes());
    ad[32..].copy_from_slice(responder.as_bytes());
    ad
}

/// Reject the all-zero DH output produced by low-order points.
pub fn check_dh(out: &[u8; 32]) -> Result<()> {
    if out.iter().all(|b| *b == 0) {
        return Err(Error::DegenerateDh);
    }
    Ok(())
}

/// Derive `SK` from the concatenated DH outputs.
///
/// Provided because it is mechanical; `dh_concat` must already contain
/// `F_PREFIX || DH1 || DH2 || DH3 [|| DH4]`.
pub fn derive_sk(dh_concat: &mut Vec<u8>) -> RootKey {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), dh_concat);
    let mut sk = [0u8; 32];
    hk.expand(INFO_X3DH, &mut sk)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    dh_concat.zeroize();
    RootKey(sk)
}

/// Initiator side of X3DH.
///
/// # Implementation checklist
///
/// 1. `bundle.verify()?` — never skip, this is T-4.
/// 2. Generate an ephemeral `EK_A`.
/// 3. `DH1 = X25519(IK_dh_A, SPK_B)`
/// 4. `DH2 = X25519(EK_A, IK_dh_B)`
/// 5. `DH3 = X25519(EK_A, SPK_B)`
/// 6. `DH4 = X25519(EK_A, OPK_B)` — omit entirely if there is no OPK
/// 7. `check_dh` each output.
/// 8. Concatenate behind `F_PREFIX`, call `derive_sk`.
/// 9. Zeroise every DH output.
#[allow(unused_variables)] // remove once implemented
pub fn initiate(
    identity: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<(RootKey, InitialMessage)> {
    bundle.verify()?;
    let ek_a = StaticSecret::random_from_rng(OsRng);
    let dh1 = agree(&identity.dh, &bundle.spk_pub)?;
    let dh2 = agree(&ek_a, &bundle.identity.dh)?;
    let dh3 = agree(&ek_a, &bundle.spk_pub)?;
    todo!("rest of X3DH")
    }

/// Responder side of X3DH.
///
/// Must reproduce the same DH values from the private counterparts, in the same
/// order. Before deriving, check replay conditions per PROTOCOL.md 4.2:
/// the one-time prekey must not already be consumed, and `ek_a` must be unseen.
#[allow(unused_variables)] // remove once implemented
pub fn respond(
    identity: &IdentityKeyPair,
    spk: &SignedPreKey,
    opk: Option<&OneTimePreKey>,
    initiator_ik_dh: &PublicKey,
    initial: &InitialMessage,
) -> Result<RootKey> {
    todo!("Phase 1: mirror `initiate`, same DH order")
}

/// Helper retained for the implementation: performs one agreement and checks it.
pub fn agree(secret: &StaticSecret, public: &PublicKey) -> Result<[u8; 32]> {
    let shared = secret.diffie_hellman(public);
    let out = *shared.as_bytes();
    check_dh(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeyPair;

    #[test]
    fn associated_data_is_order_sensitive() {
        let a = IdentityKeyPair::generate().public().sign;
        let b = IdentityKeyPair::generate().public().sign;
        assert_ne!(associated_data(&a, &b), associated_data(&b, &a));
    }

    #[test]
    fn degenerate_dh_is_rejected() {
        assert!(check_dh(&[0u8; 32]).is_err());
        assert!(check_dh(&[1u8; 32]).is_ok());
    }
}
