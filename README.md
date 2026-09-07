# ephemera

A private, end-to-end encrypted 1:1 messaging service. Text, attachments,
recorded audio and video, real-time calls, and single-view messages.

**Status: Phase 1 complete.** The cryptographic core is implemented and passes its
conformance suite. Not audited, not deployed, no server yet. Do not use this for
anything real.

## Documents

Read these before the code. They are normative; the code follows them.

- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — what is protected, from whom,
  and explicitly what is not
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — wire format, key derivation, session
  state machine
- [`NEXT.md`](NEXT.md) — the single next action

## Design constraints

**Pairwise, permanently.** Every session is between exactly two identities.
There are no conversation IDs, no membership state, no group key agreement.
This is not a deferred feature — see `THREAT-MODEL.md` section 1.

**No hand-rolled primitives.** X25519, Ed25519, HKDF-SHA-256, HMAC-SHA-256 and
XChaCha20-Poly1305 all come from the RustCrypto and dalek ecosystems. What is
implemented here is the protocol on top: X3DH, the Double Ratchet, the key
lifecycle, and the wire format.

**The core does no I/O.** `ephemera-core` is synchronous and has no networking,
no persistence, and no async. That is what makes it testable against
deterministic vectors and cheap to target at WASM and JNI later.

## What the specifications caught

Both documents were written before any code existed, and both found defects that
tests would not have.

`THREAT-MODEL.md` T-11 originally required a server-attested timestamp inside the
encrypted envelope, to stop a recipient extending a disappearing-message timer by
changing their clock. Writing `PROTOCOL.md` §8.2 showed this is not constructible:
the server cannot write into a payload it cannot read. Replaced with a monotonic
clock that fails closed. Recorded in THREAT-MODEL.md §12.

T-22 came out of a code review after the suite was already green. Decryption
advanced the receiving chain before the AEAD verified, so forged ciphertext with
an inflated counter could desynchronise a session without breaking any
cryptography. Decryption now commits only on success, and conformance test 11
holds it to that.

## Layout

    crates/ephemera-core/   X3DH + Double Ratchet. Pure computation.
    crates/ephemera-wire/   Envelope encoding. No crypto, no I/O.
    docs/                   Normative specifications.

## Building

Requires a current stable Rust toolchain.

    cargo test

25 tests pass across three suites: RFC 5869 and RFC 7748 vectors, wire-format
round-trips and rejection cases, and twelve conformance tests encoding
PROTOCOL.md section 11.

## What is not here yet

Relay server, blob storage, web client, WebRTC calls. Phase 2 begins with the
relay; see NEXT.md.
