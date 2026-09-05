//! Double Ratchet session state and message processing — PROTOCOL.md section 5.
//!
//! # Status: not implemented
//!
//! State layout and limits are given; `encrypt` and `decrypt` are Phase 1 work.
//! Conformance tests 4 through 10 are the definition of done, and tests 5 to 9
//! are where ratchet implementations actually break — write them first.

use std::collections::HashMap;
use rand_core::OsRng;   
use ed25519_dalek::VerifyingKey;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::Result;
use crate::kdf::{kdf_rk, ChainKey, MessageKey, RootKey};
use ephemera_wire::RatchetMessage;

/// Maximum messages that may be skipped within a single chain (T-6).
pub const MAX_SKIP: u32 = 1000;
/// Maximum skipped keys retained across the whole session (T-6).
pub const MAX_STORED_SKIPPED: usize = 2000;

/// Key identifying a stored skipped message key.
pub type SkipId = ([u8; 32], u32);

/// Lifecycle of a session — PROTOCOL.md 5.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    /// Initiator has sent but not yet received; outbound messages must be
    /// wrapped as `PreKeyEnvelope`.
    PendingInitial,
    /// Both directions active.
    Established,
    /// Peer identity key changed. Terminal until the user re-verifies. Sending
    /// MUST be blocked (T-1).
    IdentityChanged,
}

/// A live Double Ratchet session with exactly one peer.
pub struct SessionState {
    /// `AD_ident`, fixed for the session lifetime.
    pub ad_ident: [u8; 64],
    /// Peer's Ed25519 identity, pinned on first contact.
    pub peer_identity: VerifyingKey,
    /// Current lifecycle phase.
    pub phase: SessionPhase,
    /// Root key.
    pub rk: RootKey,
    /// Our current ratchet private key.
    pub ratchet_priv: Option<StaticSecret>,
    /// Our current ratchet public key.
    pub ratchet_pub: PublicKey,
    /// Peer's most recently seen ratchet public key.
    pub remote_ratchet_pub: Option<PublicKey>,
    /// Sending chain key.
    pub ck_send: Option<ChainKey>,
    /// Receiving chain key.
    pub ck_recv: Option<ChainKey>,
    /// Messages sent in the current sending chain.
    pub n_send: u32,
    /// Messages received in the current receiving chain.
    pub n_recv: u32,
    /// Length of the previous sending chain.
    pub pn: u32,
    /// Message keys derived but not yet consumed, for out-of-order delivery.
    pub skipped: HashMap<SkipId, MessageKey>,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.ad_ident.zeroize();
        self.skipped.clear();
    }
}

impl SessionState {
    /// Build the initiator's session immediately after X3DH.
    ///
    /// Per PROTOCOL.md 5.1: generate a ratchet keypair, DH against the peer's
    /// signed prekey, and derive the first sending chain. Phase starts as
    /// `PendingInitial`.
    #[allow(unused_variables)] // remove once implemented
    pub fn initiator(
        rk: RootKey,
        ad_ident: [u8; 64],
        peer_identity: VerifyingKey,
        peer_spk: PublicKey,
    ) -> Result<Self> {
        let ratchet_priv = StaticSecret::random_from_rng(OsRng);
        let dh_out = ratchet_priv.diffie_hellman(&peer_spk);
        let (rk, ck_send) = kdf_rk(&rk, dh_out.as_bytes());
        Ok(SessionState {
            ad_ident,
            peer_identity,
            phase: SessionPhase::PendingInitial,
            rk,
            ratchet_pub: PublicKey::from(&ratchet_priv),
            ratchet_priv: Some(ratchet_priv),
            remote_ratchet_pub: Some(peer_spk),
            ck_send: Some(ck_send),
            ck_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: HashMap::new(),
        })
    }

    /// Build the responder's session immediately after X3DH.
    ///
    /// The responder's initial ratchet keypair *is* the signed prekey pair, and
    /// both chains start empty. The first DH ratchet happens on first receive.
    pub fn responder(
        rk: RootKey,
        ad_ident: [u8; 64],
        peer_identity: VerifyingKey,
        spk_secret: StaticSecret,
    ) -> Result<Self> {
        Ok(SessionState {
            ad_ident,
            peer_identity,
            phase: SessionPhase::Established,
            rk,
            ratchet_pub: PublicKey::from(&spk_secret),
            ratchet_priv: Some(spk_secret),
            remote_ratchet_pub: None,
            ck_send: None,
            ck_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: HashMap::new(),
        })
    }

    /// Encrypt one message, advancing the sending chain.
    ///
    /// # Implementation checklist
    ///
    /// 1. Refuse if `phase == IdentityChanged`.
    /// 2. `kdf_ck` the sending chain to get `(CK', MK)`.
    /// 3. `expand_message_key(&MK)` for the AEAD key and nonce.
    /// 4. Build the header, compute AD as `ad_prefix() || ad_ident` (6.3).
    /// 5. Seal with XChaCha20-Poly1305.
    /// 6. Increment `n_send`, zeroise `MK`.
    #[allow(unused_variables)] // remove once implemented
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        todo!("Phase 1: PROTOCOL.md 5.3, 5.4, 6.3")
    }

    /// Decrypt one message, performing a DH ratchet step if the peer's ratchet
    /// key has changed.
    ///
    /// # Implementation checklist
    ///
    /// 1. Try `skipped` first, keyed by `(msg.ratchet_pub, msg.n)`. On hit,
    ///    decrypt and **delete the entry** — that deletion is what makes replay
    ///    detection work (T-5).
    /// 2. If `msg.ratchet_pub` differs from `remote_ratchet_pub`, skip to
    ///    `msg.pn` in the current receiving chain, then DH ratchet.
    /// 3. Skip forward to `msg.n`, storing intermediate keys, refusing past
    ///    `MAX_SKIP` **without mutating state** (T-6).
    /// 4. Derive, decrypt, verify. On AEAD failure return `DecryptFailed` and
    ///    leave the session unchanged.
    #[allow(unused_variables)] // remove once implemented
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        todo!("Phase 1: PROTOCOL.md 5.5, and note step 3's atomicity requirement")
    }
}
