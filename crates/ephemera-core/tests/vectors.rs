//! Conformance tests 1 and 2 from PROTOCOL.md section 11.
//!
//! These validate that the primitives underneath us behave as the RFCs specify.
//! They should pass on a clean checkout, before any protocol code is written.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test vector is valid hex")
}

fn arr32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

/// Conformance test 1 — RFC 5869 Test Case 1.
#[test]
fn vector_1_hkdf_sha256_rfc5869_case_1() {
    let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm).expect("valid length");

    assert_eq!(
        hex::encode(okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

/// Conformance test 1b — RFC 5869 Test Case 3, empty salt and info.
#[test]
fn vector_1b_hkdf_sha256_rfc5869_case_3() {
    let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&[], &mut okm).expect("valid length");

    assert_eq!(
        hex::encode(okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

/// Conformance test 2 — RFC 7748 section 6.1 public key derivation.
#[test]
fn vector_2_x25519_rfc7748_public_keys() {
    let a_priv = StaticSecret::from(arr32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let b_priv = StaticSecret::from(arr32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));

    assert_eq!(
        hex::encode(PublicKey::from(&a_priv).as_bytes()),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(PublicKey::from(&b_priv).as_bytes()),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
}

/// Conformance test 2b — RFC 7748 section 6.1 shared secret, both directions.
#[test]
fn vector_2b_x25519_rfc7748_shared_secret() {
    let a_priv = StaticSecret::from(arr32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let b_priv = StaticSecret::from(arr32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));

    let ab = a_priv.diffie_hellman(&PublicKey::from(&b_priv));
    let ba = b_priv.diffie_hellman(&PublicKey::from(&a_priv));

    let expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assert_eq!(hex::encode(ab.as_bytes()), expected);
    assert_eq!(
        hex::encode(ba.as_bytes()),
        expected,
        "agreement must commute"
    );
}
