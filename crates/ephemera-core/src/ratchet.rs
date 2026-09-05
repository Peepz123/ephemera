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
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use crate::error::{Error, Result};
use crate::kdf::{expand_message_key, kdf_ck, kdf_rk, ChainKey, MessageKey, RootKey};
use ephemera_wire::RatchetMessage;
use std::time::{Duration, Instant};

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
#[derive(Clone)]
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
    pub skipped: HashMap<SkipId, (MessageKey, Instant)>,
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
        fn skip_to(&mut self, ratchet_pub: [u8; 32], target: u32) -> Result<()> {
        let ck = match self.ck_recv.as_ref() {
            Some(ck) => ck,
            None => return Ok(()),
        };

        if target < self.n_recv {
            return Ok(());
        }

        let needed = target - self.n_recv;
        if needed > MAX_SKIP {
            return Err(Error::SkipLimitExceeded(needed));
        }

        let mut chain = ck.clone();
        for n in self.n_recv..target {
            let (next, mk) = kdf_ck(&chain);
            self.skipped.insert((ratchet_pub, n), (mk, Instant::now()));
            chain = next;
        }

        self.ck_recv = Some(chain);
        self.n_recv = target;
                self.skipped
            .retain(|_, (_, t)| t.elapsed() < Duration::from_secs(7 * 24 * 3600));

        while self.skipped.len() > MAX_STORED_SKIPPED {
            let oldest = self
                .skipped
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    self.skipped.remove(&k);
                }
                None => break,
            }
        }
        Ok(())
    }


    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        if self.phase == SessionPhase::IdentityChanged {
            return Err(Error::IdentityChanged);
            }

        let ck = self.ck_send.as_ref().ok_or(Error::NotEstablished)?;
        let (next_ck, mk) = kdf_ck(ck);
        let params = expand_message_key(&mk);
                let mut ad_msg = RatchetMessage {
            ratchet_pub: *self.ratchet_pub.as_bytes(),
            pn: self.pn,
            n: self.n_send,
            ciphertext: vec![0u8; plaintext.len() + 16],
        };

        let mut ad = ad_msg.ad_prefix();
        ad.extend_from_slice(&self.ad_ident);

        let cipher = XChaCha20Poly1305::new((&params.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&params.nonce),
                Payload { msg: plaintext, aad: &ad },
            )
            .map_err(|_| Error::DecryptFailed)?;

        ad_msg.ciphertext = ciphertext;

        self.ck_send = Some(next_ck);
        self.n_send += 1;

        Ok(ad_msg)      
    }

    /// Decrypt one message. State changes commit only on success (T-6, T-7).
    ///
    /// All work happens on a clone; the session is replaced only after the
    /// AEAD verifies. A forged or replayed message therefore cannot advance
    /// the receiving chain or populate the skipped-key map.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        let mut next = self.clone();
        let plaintext = next.decrypt_inner(msg)?;
        *self = next;
        Ok(plaintext)
    }
        fn decrypt_inner(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        if let Some((mk, _)) = self.skipped.remove(&(msg.ratchet_pub, msg.n)) {
            let params = expand_message_key(&mk);
            let mut ad = msg.ad_prefix();
            ad.extend_from_slice(&self.ad_ident);
            let cipher = XChaCha20Poly1305::new((&params.key).into());
            return cipher
                .decrypt(
                    XNonce::from_slice(&params.nonce),
                    Payload { msg: &msg.ciphertext, aad: &ad },
                )
                .map_err(|_| Error::DecryptFailed);
        }
        let incoming = PublicKey::from(msg.ratchet_pub);
        let is_new_ratchet = self.remote_ratchet_pub.map(|k| k.as_bytes() != &msg.ratchet_pub).unwrap_or(true);

        if is_new_ratchet {
            if let Some(prev) = self.remote_ratchet_pub {
                self.skip_to(*prev.as_bytes(), msg.pn)?;
            }
            self.pn = self.n_send;
            self.n_send = 0;
            self.n_recv = 0;

            let priv_key = self.ratchet_priv.as_ref().ok_or(Error::NotEstablished)?;
            let dh_recv = priv_key.diffie_hellman(&incoming);
            let (rk1, ck_recv) = kdf_rk(&self.rk, dh_recv.as_bytes());

            let new_priv = StaticSecret::random_from_rng(OsRng);
            let dh_send = new_priv.diffie_hellman(&incoming);
            let (rk2, ck_send) = kdf_rk(&rk1, dh_send.as_bytes());

            self.rk = rk2;
            self.ratchet_pub = PublicKey::from(&new_priv);
            self.ratchet_priv = Some(new_priv);
            self.remote_ratchet_pub = Some(incoming);
            self.ck_recv = Some(ck_recv);
            self.ck_send = Some(ck_send);
            self.phase = SessionPhase::Established;
        }
        self.skip_to(msg.ratchet_pub, msg.n)?;
        let ck = self.ck_recv.as_ref().ok_or(Error::NotEstablished)?;
        let (next_ck, mk) = kdf_ck(ck);
        let params = expand_message_key(&mk);

        let mut ad = msg.ad_prefix();
        ad.extend_from_slice(&self.ad_ident);

        let cipher = XChaCha20Poly1305::new((&params.key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&params.nonce),
                Payload { msg: &msg.ciphertext, aad: &ad },
            )
            .map_err(|_| Error::DecryptFailed)?;

        self.ck_recv = Some(next_ck);
        self.n_recv += 1;

        Ok(plaintext)
    }
}
