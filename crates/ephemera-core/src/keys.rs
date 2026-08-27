//! Identity keys, prekeys, and the signatures binding them together.
//!
//! PROTOCOL.md sections 1.1 and 3. Split identity keys: Ed25519 for signing,
//! X25519 for agreement, bound by a self-signature. See 1.1 for why this
//! differs from Signal's single-key XEdDSA approach.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};

/// Domain separation for the identity-DH binding signature.
pub const CTX_IKDH: &[u8] = b"ephemera_ikdh_v1";
/// Domain separation for signed prekey signatures.
pub const CTX_SPK: &[u8] = b"ephemera_spk_v1";
/// Sentinel meaning no one-time prekey was available.
pub const OPK_NONE: u32 = 0xFFFF_FFFF;

/// A full local identity: the two long-term private keys.
pub struct IdentityKeyPair {
    /// Ed25519 signing key. This is the canonical identity.
    pub sign: SigningKey,
    /// X25519 agreement key, bound to `sign` by [`IdentityKeyPair::bind_dh`].
    pub dh: StaticSecret,
}

/// The public half of an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityPublic {
    /// Ed25519 verifying key.
    pub sign: VerifyingKey,
    /// X25519 public agreement key.
    pub dh: PublicKey,
}

impl IdentityKeyPair {
    /// Generate a fresh identity from the OS random source.
    pub fn generate() -> Self {
        IdentityKeyPair {
            sign: SigningKey::generate(&mut OsRng),
            dh: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// The public half.
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            sign: self.sign.verifying_key(),
            dh: PublicKey::from(&self.dh),
        }
    }

    /// Produce the signature binding the X25519 key to the Ed25519 identity.
    pub fn bind_dh(&self) -> Signature {
        let mut msg = Vec::with_capacity(CTX_IKDH.len() + 32);
        msg.extend_from_slice(CTX_IKDH);
        msg.extend_from_slice(PublicKey::from(&self.dh).as_bytes());
        self.sign.sign(&msg)
    }

    /// Sign a prekey so recipients can verify it came from this identity.
    pub fn sign_prekey(&self, id: u32, prekey: &PublicKey) -> Signature {
        let mut msg = Vec::with_capacity(CTX_SPK.len() + 4 + 32);
        msg.extend_from_slice(CTX_SPK);
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(prekey.as_bytes());
        self.sign.sign(&msg)
    }
}

impl IdentityPublic {
    /// Verify that `dh` is genuinely bound to `sign`.
    ///
    /// Clients MUST call this before using `dh` in any agreement. Skipping it
    /// hands a malicious relay a substitution attack (T-1).
    pub fn verify_binding(&self, sig: &Signature) -> Result<()> {
        let mut msg = Vec::with_capacity(CTX_IKDH.len() + 32);
        msg.extend_from_slice(CTX_IKDH);
        msg.extend_from_slice(self.dh.as_bytes());
        self.sign.verify(&msg, sig).map_err(|_| Error::BadSignature)
    }

    /// Verify a signed prekey against this identity (T-4).
    pub fn verify_prekey(&self, id: u32, prekey: &PublicKey, sig: &Signature) -> Result<()> {
        let mut msg = Vec::with_capacity(CTX_SPK.len() + 4 + 32);
        msg.extend_from_slice(CTX_SPK);
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(prekey.as_bytes());
        self.sign.verify(&msg, sig).map_err(|_| Error::BadSignature)
    }
}

/// A rotated signed prekey with its private half.
pub struct SignedPreKey {
    /// Identifier referenced by initiators.
    pub id: u32,
    /// Private half.
    pub secret: StaticSecret,
    /// Signature over `(CTX_SPK || id || public)`.
    pub signature: Signature,
}

impl SignedPreKey {
    /// Generate and sign a new signed prekey.
    pub fn generate(id: u32, identity: &IdentityKeyPair) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let signature = identity.sign_prekey(id, &public);
        SignedPreKey { id, secret, signature }
    }

    /// The public half.
    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }
}

/// A one-time prekey, deleted on first use.
pub struct OneTimePreKey {
    /// Identifier referenced by initiators.
    pub id: u32,
    /// Private half.
    pub secret: StaticSecret,
}

impl OneTimePreKey {
    /// Generate a batch of one-time prekeys with sequential identifiers.
    pub fn generate_batch(start_id: u32, count: u32) -> Vec<Self> {
        (0..count)
            .map(|i| OneTimePreKey {
                id: start_id + i,
                secret: StaticSecret::random_from_rng(OsRng),
            })
            .collect()
    }

    /// The public half.
    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }
}

/// The public bundle an initiator fetches from the relay (PROTOCOL.md 3.2).
///
/// Every field here arrives from an untrusted server and must be verified
/// before use.
#[derive(Clone)]
pub struct PreKeyBundle {
    /// Claimed identity of the recipient.
    pub identity: IdentityPublic,
    /// Signature binding `identity.dh` to `identity.sign`.
    pub identity_binding: Signature,
    /// Signed prekey identifier.
    pub spk_id: u32,
    /// Signed prekey public.
    pub spk_pub: PublicKey,
    /// Signature over the signed prekey.
    pub spk_sig: Signature,
    /// One-time prekey identifier, or [`OPK_NONE`].
    pub opk_id: u32,
    /// One-time prekey public, `None` when unavailable.
    pub opk_pub: Option<PublicKey>,
}

impl PreKeyBundle {
    /// Verify every signature in the bundle.
    ///
    /// Returns `Ok(())` only if the identity binding and the signed prekey both
    /// verify. Note this proves the bundle is internally consistent; it proves
    /// nothing about whether `identity` is the person you meant to talk to.
    /// That is what safety numbers are for (PROTOCOL.md 9).
    pub fn verify(&self) -> Result<()> {
        self.identity.verify_binding(&self.identity_binding)?;
        self.identity
            .verify_prekey(self.spk_id, &self.spk_pub, &self.spk_sig)?;
        Ok(())
    }

    /// Whether this bundle forces the weaker three-DH X3DH variant (T-2).
    ///
    /// Callers MUST surface this to the user interface rather than proceeding
    /// silently.
    pub fn is_reduced_forward_secrecy(&self) -> bool {
        self.opk_id == OPK_NONE || self.opk_pub.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_binding_roundtrips() {
        let id = IdentityKeyPair::generate();
        let sig = id.bind_dh();
        assert!(id.public().verify_binding(&sig).is_ok());
    }

    #[test]
    fn binding_from_another_identity_is_rejected() {
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::generate();
        assert!(a.public().verify_binding(&b.bind_dh()).is_err());
    }

    #[test]
    fn prekey_signature_roundtrips() {
        let id = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(42, &id);
        assert!(id.public().verify_prekey(42, &spk.public(), &spk.signature).is_ok());
    }

    #[test]
    fn prekey_signature_is_bound_to_its_id() {
        let id = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(42, &id);
        assert!(
            id.public().verify_prekey(43, &spk.public(), &spk.signature).is_err(),
            "swapping the prekey id must invalidate the signature"
        );
    }

    #[test]
    fn batch_ids_are_sequential_and_keys_distinct() {
        let batch = OneTimePreKey::generate_batch(100, 5);
        assert_eq!(batch.len(), 5);
        assert_eq!(batch[0].id, 100);
        assert_eq!(batch[4].id, 104);
        assert_ne!(batch[0].public().as_bytes(), batch[1].public().as_bytes());
    }
}
