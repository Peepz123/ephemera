# ephemera

A private, end-to-end encrypted 1:1 messaging service. Text, attachments,
recorded audio and video, real-time calls, and single-view messages.

**Status: Phase 1, in progress.** Not usable, not audited, not secure yet.
Do not use this for anything.

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

## Layout

    crates/ephemera-core/   X3DH + Double Ratchet. Pure computation.
    crates/ephemera-wire/   Envelope encoding. No crypto, no I/O.
    docs/                   Normative specifications.

## Building

Requires a current stable Rust toolchain.

    cargo test

24 tests pass. 9 fail. The 9 failures are `tests/conformance.rs`, which encodes
PROTOCOL.md section 11 as executable checks and defines "Phase 1 complete".

## What is not here yet

Relay server, blob storage, web client, WebRTC calls. Those are Phases 2 to 5
and none of them should start before the conformance suite is green.
