//! Envelope encoding tests — PROTOCOL.md section 6.

use ephemera_wire::*;

fn sample_ratchet() -> RatchetMessage {
    RatchetMessage {
        ratchet_pub: [0xAB; 32],
        pn: 7,
        n: 42,
        ciphertext: vec![1, 2, 3, 4, 5],
    }
}

#[test]
fn ratchet_message_roundtrips() {
    let msg = sample_ratchet();
    let bytes = msg.encode();
    match Envelope::decode(&bytes).expect("decodes") {
        Envelope::Ratchet(got) => assert_eq!(got, msg),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn prekey_envelope_roundtrips() {
    let env = PreKeyEnvelope {
        ik_sig_a: [1; 32],
        ik_dh_a: [2; 32],
        ek_a: [3; 32],
        spk_id: 9,
        opk_id: OPK_NONE,
        inner: sample_ratchet(),
    };
    let bytes = env.encode();
    match Envelope::decode(&bytes).expect("decodes") {
        Envelope::PreKey(got) => assert_eq!(got, env),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn bad_magic_is_rejected() {
    let mut bytes = sample_ratchet().encode();
    bytes[0] = b'X';
    assert_eq!(Envelope::decode(&bytes), Err(WireError::BadMagic));
}

#[test]
fn nonzero_reserved_is_rejected() {
    let mut bytes = sample_ratchet().encode();
    bytes[6] = 0x01;
    assert_eq!(Envelope::decode(&bytes), Err(WireError::ReservedNonZero));
}

#[test]
fn unknown_version_is_rejected() {
    let mut bytes = sample_ratchet().encode();
    bytes[4] = 0x99;
    assert_eq!(Envelope::decode(&bytes), Err(WireError::BadVersion(0x99)));
}

#[test]
fn truncation_is_rejected() {
    let bytes = sample_ratchet().encode();
    for cut in 1..bytes.len() {
        assert!(
            Envelope::decode(&bytes[..cut]).is_err(),
            "truncating to {cut} bytes must fail"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = sample_ratchet().encode();
    bytes.push(0x00);
    assert_eq!(Envelope::decode(&bytes), Err(WireError::LengthMismatch));
}

#[test]
fn lying_length_field_is_rejected() {
    let mut bytes = sample_ratchet().encode();
    let len = bytes.len();
    bytes[len - 5 - 4..len - 5].copy_from_slice(&9999u32.to_be_bytes());
    assert!(Envelope::decode(&bytes).is_err());
}

#[test]
fn ad_prefix_excludes_ciphertext_but_covers_header() {
    let msg = sample_ratchet();
    let ad = msg.ad_prefix();
    let full = msg.encode();
    assert_eq!(ad.len(), full.len() - msg.ciphertext.len());
    assert_eq!(&full[..ad.len()], &ad[..]);
}
