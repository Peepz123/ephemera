//! Core cryptographic protocol for ephemera: X3DH key agreement and the
//! Double Ratchet, per `docs/PROTOCOL.md`.
//!
//! This crate is deliberately synchronous and performs no I/O, no networking,
//! and no persistence. Everything here is a pure function of its inputs, which
//! is what makes the whole protocol testable against deterministic vectors and
//! what makes the WASM and JNI targets cheap.
//!
//! # Pairwise only
//!
//! Every session is between exactly two identities. There are no conversation
//! identifiers and no membership state, by design and permanently.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod kdf;
pub mod keys;
pub mod ratchet;
pub mod x3dh;

pub use error::{Error, Result};
