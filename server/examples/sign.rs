//! Sign an authentication challenge nonce.
//!
//! Usage: cargo run -q -p ephemera-server --example sign -- alice <base64-nonce>

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

/// Must match `auth::CTX_AUTH`. Duplicated because an example cannot reach a
/// binary crate's private modules. PROTOCOL.md §10 does not yet specify this
/// string; when it does, this comment should point there instead.
const CTX_AUTH: &[u8] = b"ephemera_auth_v1";

fn main() {
    let mut args = std::env::args().skip(1);
    let username = args.next().expect("usage: sign <username> <base64-nonce>");
    let nonce_b64 = args.next().expect("usage: sign <username> <base64-nonce>");

    let key_b64 = std::fs::read_to_string(format!("{username}.sign.key"))
        .expect("read signing key");
    let key_bytes: [u8; 32] = STANDARD
        .decode(key_b64.trim())
        .expect("decode signing key")
        .as_slice()
        .try_into()
        .expect("signing key is not 32 bytes");
    let sk = SigningKey::from_bytes(&key_bytes);

    let nonce: [u8; 32] = STANDARD
        .decode(nonce_b64.trim())
        .expect("decode nonce")
        .as_slice()
        .try_into()
        .expect("nonce is not 32 bytes");

    // Exactly what verify_challenge builds: CTX_AUTH || nonce.
    let mut msg = Vec::with_capacity(CTX_AUTH.len() + 32);
    msg.extend_from_slice(CTX_AUTH);
    msg.extend_from_slice(&nonce);

    println!("{}", STANDARD.encode(sk.sign(&msg).to_bytes()));
}