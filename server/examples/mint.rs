//! Generate a registration payload and persist the identity for later signing.
//!
//! Usage: cargo run -q -p ephemera-server --example mint -- alice

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ephemera_core::keys::IdentityKeyPair;

fn main() {
    let username = std::env::args().nth(1).unwrap_or_else(|| "alice".into());
    let id = IdentityKeyPair::generate();
    let pubkeys = id.public();

    std::fs::write(
        format!("{username}.sign.key"),
        STANDARD.encode(id.sign.to_bytes()),
    )
    .expect("write signing key");
    std::fs::write(
        format!("{username}.dh.key"),
        STANDARD.encode(id.dh.to_bytes()),
    )
    .expect("write dh key");

    println!(
        r#"{{"username":"{}","ik_sig":"{}","ik_dh":"{}","ik_dh_sig":"{}"}}"#,
        username,
        STANDARD.encode(pubkeys.sign.as_bytes()),
        STANDARD.encode(pubkeys.dh.as_bytes()),
        STANDARD.encode(id.bind_dh().to_bytes()),
    );
}