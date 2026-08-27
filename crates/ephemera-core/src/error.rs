//! Error type for the core protocol.

/// Convenient result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Every way the core protocol can refuse to proceed.
///
/// Variants map to threat IDs in `docs/THREAT-MODEL.md` where applicable.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A signature failed verification (T-4).
    #[error("signature verification failed")]
    BadSignature,

    /// A public key was not a valid point or had the wrong length.
    #[error("malformed key")]
    MalformedKey,

    /// An X25519 agreement produced the all-zero output, indicating a
    /// low-order point was supplied (PROTOCOL.md 4).
    #[error("degenerate diffie-hellman output")]
    DegenerateDh,

    /// The message required skipping more keys than `MAX_SKIP` allows (T-6).
    #[error("skip limit exceeded: would skip {0} messages")]
    SkipLimitExceeded(u32),

    /// No message key is available for this counter; either it was never
    /// derived, or it was already used and deleted (T-5).
    #[error("no message key for chain position {0}")]
    NoMessageKey(u32),

    /// AEAD decryption failed: wrong key, or the ciphertext or header was
    /// tampered with (T-7).
    #[error("decryption failed")]
    DecryptFailed,

    /// An operation required an established session.
    #[error("session not established")]
    NotEstablished,

    /// The peer's identity key changed; sending is blocked until the user
    /// re-verifies (T-1).
    #[error("peer identity key changed")]
    IdentityChanged,

    /// The referenced one-time prekey was already consumed (T-3).
    #[error("prekey already consumed")]
    PrekeyConsumed,

    /// An initiator ephemeral key was replayed (T-3).
    #[error("replayed initial message")]
    ReplayedInitial,

    /// Envelope encoding or decoding failed.
    #[error("wire error: {0}")]
    Wire(#[from] ephemera_wire::WireError),
}
