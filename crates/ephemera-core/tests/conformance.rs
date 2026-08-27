//! Conformance tests 3 through 10 — PROTOCOL.md section 11.
//!
//! # These are supposed to fail right now
//!
//! Every test here exercises code that is still `todo!()`. They are the
//! specification of Phase 1, expressed as executable checks. Work through them
//! roughly in order; tests 5 to 9 are where ratchet implementations actually
//! break, so do not leave them until last.
//!
//! Run just these with:
//!     cargo test --test conformance

use ephemera_core::keys::{IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey, OPK_NONE};
use ephemera_core::ratchet::{SessionState, MAX_SKIP};
use ephemera_core::x3dh;

/// Two parties with everything needed to establish a session.
struct Pair {
    alice: IdentityKeyPair,
    bob: IdentityKeyPair,
    bob_spk: SignedPreKey,
    bob_opk: OneTimePreKey,
}

impl Pair {
    fn new() -> Self {
        let bob = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob);
        let bob_opk = OneTimePreKey::generate_batch(1, 1).pop().expect("one key");
        Pair { alice: IdentityKeyPair::generate(), bob, bob_spk, bob_opk }
    }

    fn bundle(&self, with_opk: bool) -> PreKeyBundle {
        PreKeyBundle {
            identity: self.bob.public(),
            identity_binding: self.bob.bind_dh(),
            spk_id: self.bob_spk.id,
            spk_pub: self.bob_spk.public(),
            spk_sig: self.bob_spk.signature,
            opk_id: if with_opk { self.bob_opk.id } else { OPK_NONE },
            opk_pub: if with_opk { Some(self.bob_opk.public()) } else { None },
        }
    }

    /// Establish both sides. Returns (alice_session, bob_session).
    fn establish(&self, with_opk: bool) -> (SessionState, SessionState) {
        let bundle = self.bundle(with_opk);
        let (sk_a, initial) = x3dh::initiate(&self.alice, &bundle).expect("initiate");
        let sk_b = x3dh::respond(
            &self.bob,
            &self.bob_spk,
            if with_opk { Some(&self.bob_opk) } else { None },
            &self.alice.public().dh,
            &initial,
        )
        .expect("respond");

        let ad = x3dh::associated_data(&self.alice.public().sign, &self.bob.public().sign);
        let a = SessionState::initiator(sk_a, ad, self.bob.public().sign, self.bob_spk.public())
            .expect("initiator session");
        let b = SessionState::responder(
            sk_b,
            ad,
            self.alice.public().sign,
            x25519_dalek::StaticSecret::from(*self.bob_spk.secret.as_bytes()),
        )
        .expect("responder session");
        (a, b)
    }
}

/// Test 3 — X3DH produces an identical shared secret on both sides.
#[test]
fn t3_x3dh_agreement_four_dh() {
    let p = Pair::new();
    let bundle = p.bundle(true);
    let (sk_a, initial) = x3dh::initiate(&p.alice, &bundle).expect("initiate");
    let sk_b = x3dh::respond(
        &p.bob,
        &p.bob_spk,
        Some(&p.bob_opk),
        &p.alice.public().dh,
        &initial,
    )
    .expect("respond");
    assert_eq!(sk_a.0, sk_b.0, "both parties must derive the same SK");
}

/// Test 3b — the three-DH variant, when no one-time prekey was available (T-2).
#[test]
fn t3b_x3dh_agreement_three_dh() {
    let p = Pair::new();
    let bundle = p.bundle(false);
    assert!(bundle.is_reduced_forward_secrecy());
    let (sk_a, initial) = x3dh::initiate(&p.alice, &bundle).expect("initiate");
    let sk_b = x3dh::respond(&p.bob, &p.bob_spk, None, &p.alice.public().dh, &initial)
        .expect("respond");
    assert_eq!(sk_a.0, sk_b.0);
}

/// Test 4 — 100 messages each direction, alternating.
#[test]
fn t4_ratchet_in_order() {
    let p = Pair::new();
    let (mut a, mut b) = p.establish(true);
    for i in 0..100u32 {
        let msg = format!("a->b {i}");
        let ct = a.encrypt(msg.as_bytes()).expect("encrypt");
        assert_eq!(b.decrypt(&ct).expect("decrypt"), msg.as_bytes());

        let msg = format!("b->a {i}");
        let ct = b.encrypt(msg.as_bytes()).expect("encrypt");
        assert_eq!(a.decrypt(&ct).expect("decrypt"), msg.as_bytes());
    }
}

/// Test 5 — 50 messages delivered in reverse order must all decrypt.
#[test]
fn t5_ratchet_out_of_order() {
    let p = Pair::new();
    let (mut a, mut b) = p.establish(true);
    let sent: Vec<_> = (0..50u32)
        .map(|i| {
            let m = format!("msg {i}");
            (m.clone(), a.encrypt(m.as_bytes()).expect("encrypt"))
        })
        .collect();

    for (plain, ct) in sent.iter().rev() {
        assert_eq!(b.decrypt(ct).expect("out-of-order decrypt"), plain.as_bytes());
    }
}

/// Test 6 — messages 10..20 dropped; 21 onward must still decrypt.
#[test]
fn t6_ratchet_dropped_messages() {
    let p = Pair::new();
    let (mut a, mut b) = p.establish(true);
    let sent: Vec<_> = (0..30u32)
        .map(|i| {
            let m = format!("msg {i}");
            (m.clone(), a.encrypt(m.as_bytes()).expect("encrypt"))
        })
        .collect();

    for (i, (plain, ct)) in sent.iter().enumerate() {
        if (10..20).contains(&i) {
            continue;
        }
        assert_eq!(b.decrypt(ct).expect("decrypt after gap"), plain.as_bytes());
    }
}

/// Test 7 — exceeding MAX_SKIP errors and leaves session state untouched (T-6).
#[test]
fn t7_skip_limit_is_enforced_atomically() {
    let p = Pair::new();
    let (mut a, mut b) = p.establish(true);

    let mut far = None;
    for i in 0..=MAX_SKIP + 1 {
        let ct = a.encrypt(format!("msg {i}").as_bytes()).expect("encrypt");
        if i == MAX_SKIP + 1 {
            far = Some(ct);
        }
    }
    let skipped_before = b.skipped.len();
    let n_recv_before = b.n_recv;

    assert!(b.decrypt(&far.expect("message")).is_err(), "must refuse");
    assert_eq!(b.skipped.len(), skipped_before, "must not store partial keys");
    assert_eq!(b.n_recv, n_recv_before, "must not advance the chain");
}

/// Test 8 — replaying a decrypted message must fail (T-5).
#[test]
fn t8_replay_is_rejected() {
    let p = Pair::new();
    let (mut a, mut b) = p.establish(true);
    let ct = a.encrypt(b"once").expect("encrypt");
    assert_eq!(b.decrypt(&ct).expect("first delivery"), b"once");
    assert!(b.decrypt(&ct).is_err(), "second delivery must fail");
}

/// Test 9 — flipping any header bit must fail the AEAD (T-7).
#[test]
fn t9_header_tampering_fails_aead() {
    let p = Pair::new();
    let (mut a, mut b) = p.establish(true);

    let base = a.encrypt(b"header integrity").expect("encrypt");

    let mut tampered_n = base.clone();
    tampered_n.n ^= 1;
    assert!(b.decrypt(&tampered_n).is_err(), "n must be authenticated");

    let mut tampered_pn = base.clone();
    tampered_pn.pn ^= 1;
    assert!(b.decrypt(&tampered_pn).is_err(), "pn must be authenticated");

    let mut tampered_key = base.clone();
    tampered_key.ratchet_pub[0] ^= 1;
    assert!(b.decrypt(&tampered_key).is_err(), "ratchet_pub must be authenticated");
}

/// Test 10 — a valid envelope from one session must fail against another.
#[test]
fn t10_cross_session_rejection() {
    let p1 = Pair::new();
    let p2 = Pair::new();
    let (mut a1, _b1) = p1.establish(true);
    let (_a2, mut b2) = p2.establish(true);

    let ct = a1.encrypt(b"wrong session").expect("encrypt");
    assert!(b2.decrypt(&ct).is_err(), "AD_ident must bind the session");
}
