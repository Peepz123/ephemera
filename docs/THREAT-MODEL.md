# Threat model

**Project:** `ephemera` (working name)
**Document status:** Phase 1 complete
**Version:** 0.2
**Last reviewed:** 2026-08-25

---

## 1. Purpose and scope

This document defines what `ephemera` protects, who it protects against, and — equally important — what it does not protect against. Every security control in the codebase should trace to a goal (`G*`) or a threat (`T*`) listed here. Controls that trace to neither are unjustified complexity and should be removed.

Scope is a two-party (1:1) messaging system supporting text, file attachments, recorded audio/video, real-time calls, and a single-view message mode.

**`ephemera` is pairwise by design.** Group messaging is not a deferred feature; it is outside the architecture. Every session is a Double Ratchet between exactly two identities, and the codebase is free to assume this everywhere — no conversation IDs, no membership state, no group key agreement abstraction, no MLS. A future requirement for groups is a different product, not a later phase of this one.

Deferred (not permanently excluded): multi-device accounts, federation, phone-number identity.

---

## 2. System overview

Four components:

| Component | Runs where | Trusted for confidentiality? |
|---|---|---|
| Client | User device (browser/PWA, later Android) | Yes |
| Relay server | Operator-controlled VPS | **No** |
| Blob store | Object storage (R2/MinIO) | **No** |
| TURN/SFU | Operator-controlled VPS | **No** |

The relay is a store-and-forward queue for opaque ciphertext. The blob store holds encrypted attachments it cannot interpret. TURN relays media packets to prevent peer IP disclosure; media payloads are encrypted above the DTLS-SRTP layer using SFrame, so the relay cannot read them.

---

## 3. Assets

| ID | Asset | Impact if lost |
|---|---|---|
| A-1 | Message plaintext (text and media) | Critical |
| A-2 | Real-time call media | Critical |
| A-3 | Long-term identity private keys | Critical — enables impersonation and future MITM |
| A-4 | Double Ratchet session state (chain keys, message keys) | High — decrypts a window of traffic |
| A-5 | Social graph (who communicates with whom) | High |
| A-6 | Communication metadata (timing, frequency, message sizes) | Medium |
| A-7 | Account existence and username enumeration | Low–Medium |
| A-8 | Service availability | Medium |

---

## 4. Trust assumptions

These are assumed true. If any is false, the corresponding guarantees do not hold, and that is stated rather than defended against.

- **TA-1** The client device is uncompromised and the user is in physical control of it while unlocked.
- **TA-2** The platform keystore (WebCrypto non-extractable keys; Android Keystore/StrongBox) protects keys at rest as documented by the platform.
- **TA-3** The underlying primitives are sound: X25519, Ed25519, HKDF-SHA-256, XChaCha20-Poly1305, AES-GCM.
- **TA-4** The user can perform an out-of-band verification (safety number comparison) when they need certainty about a peer's identity key.
- **TA-5** TLS to the relay is defence in depth only. All confidentiality guarantees hold with TLS entirely stripped.

---

## 5. Adversaries

| ID | Adversary | Capability |
|---|---|---|
| ADV-1 | Passive network observer | Reads all traffic in transit; ISP, Wi-Fi operator, or national-scale collection |
| ADV-2 | Active network attacker | Additionally drops, delays, reorders, replays, and injects; attempts MITM |
| ADV-3 | Honest-but-curious operator | Full read access to relay DB, blob store, and logs; follows the protocol |
| ADV-4 | Malicious operator | Additionally serves forged prekey bundles, withholds or replays messages, substitutes identity keys |
| ADV-5 | Malicious recipient | A legitimate conversation participant who abuses their access |
| ADV-6 | Device thief | Physical possession of a locked device |
| ADV-7 | Legal compulsion of the operator | Compels disclosure of all server-side state |

ADV-4 is the design driver. If the system is secure against a fully malicious operator, it is secure against ADV-3 and ADV-7 by construction — the operator has nothing useful to disclose.

---

## 6. Security goals

| ID | Goal | Against |
|---|---|---|
| G-1 | Message and media confidentiality | ADV-1 … ADV-4, ADV-7 |
| G-2 | Message integrity and authenticity | ADV-2, ADV-4 |
| G-3 | Forward secrecy — compromise of current keys does not decrypt past traffic | ADV-3 … ADV-6 |
| G-4 | Post-compromise security — sessions self-heal after key compromise | ADV-3, ADV-4, ADV-6 |
| G-5 | Replay and reorder resistance | ADV-2, ADV-4 |
| G-6 | Participant deniability — authenticated to the peer, not cryptographically attributable to a third party | ADV-3, ADV-7 |
| G-7 | Metadata minimisation — the relay learns as little as is practical | ADV-3, ADV-4, ADV-7 |
| G-8 | Server-enforced single retrieval of one-view content | ADV-3 |
| G-9 | Peer IP address non-disclosure during calls | ADV-5 |

---

## 7. Explicit non-goals

Listing these is a security control in its own right: a guarantee the UI implies but the protocol does not provide is a vulnerability in the user's mental model.

- **NG-1 — Screenshots, screen recording, and second-camera capture by ADV-5.** Once a recipient holds a decryption key, retention is outside our control. Platform controls (`FLAG_SECURE`) raise the cost on Android; nothing prevents a photograph of the screen. **The UI must not claim otherwise.**
- **NG-2 — Endpoint malware.** A compromised client sees plaintext by definition (violates TA-1).
- **NG-3 — Traffic analysis.** v1 performs no message padding and generates no cover traffic. Message sizes and timing are observable to ADV-1 and ADV-3.
- **NG-4 — Sender anonymity.** The relay learns the recipient of each envelope in order to route it. Sealed sender is deferred to a later phase and tracked as residual risk R-3.
- **NG-5 — Availability under DoS.** Rate limiting only; no capacity guarantees.
- **NG-6 — Recovery from total device loss.** No key escrow. Losing the device loses the message history. This is a deliberate trade against G-3.

---

## 8. Threat register

### Key agreement and identity

| ID | Threat | Mitigation |
|---|---|---|
| T-1 | Malicious relay serves an attacker-controlled identity key in a prekey bundle, enabling MITM | Safety numbers derived from both identity keys, comparable out of band (TA-4). Client pins the identity key on first contact and raises a hard warning on change. Key transparency log deferred → R-1 |
| T-2 | One-time prekey exhaustion forces fallback to signed-prekey-only X3DH, weakening initial-message forward secrecy | Client replenishes at a threshold; server rate-limits bundle fetches per requester; fallback is logged and surfaced to the client, never silent |
| T-3 | Replay of an initial X3DH message to create a duplicate session | Server and client both deduplicate on the sender's ephemeral public key; recipient rejects a repeated one-time prekey ID |
| T-4 | Signed prekey signature not verified, accepting an attacker's prekey | Ed25519 verification against the pinned identity key is mandatory before any DH; failure aborts session establishment |

### Session and message handling

| ID | Threat | Mitigation |
|---|---|---|
| T-5 | Message replay within an established session | Per-chain message counter; recipient rejects previously-seen `(chain_id, counter)` pairs within the skipped-key window |
| T-6 | Unbounded skipped-message key retention exhausts memory or extends the forward-secrecy window | `MAX_SKIP = 1000` per chain, checked before any state mutation; `MAX_STORED_SKIPPED = 2000` across the session, evicted oldest-first; entries expire after 7 days and are zeroised on eviction |
| T-7 | Ciphertext modification or truncation | AEAD over the full payload; associated data binds the header (sender identity, chain ID, counter) so headers cannot be swapped between messages |
| T-8 | Key material lingering in memory after use | Wrap all secrets in `Zeroize`/`ZeroizeOnDrop` types; never place them in `String` or `Vec<u8>` without the wrapper |
| T-22 | Forged ciphertext with an advanced counter desynchronises a session without breaking any cryptography | Decryption operates on a copy of the session state and commits only after the AEAD verifies; a failed decrypt leaves `rk`, chain keys, counters, and the skipped map unchanged |

### Attachments and one-view content

| ID | Threat | Mitigation |
|---|---|---|
| T-9 | Blob store enumeration reveals ciphertext volumes and sizes | 256-bit unguessable blob IDs; no list endpoint; authenticated fetch bound to the intended recipient |
| T-10 | Race condition allows two successful GETs on a one-view blob | Atomic compare-and-delete: a single `UPDATE … WHERE state = 'unread' RETURNING …` transaction, never read-then-delete |
| T-11 | Recipient device clock manipulation extends a disappearing-message timer | Timer starts at local view time on a monotonic clock; `sent_at_ms` is advisory only; loss of the monotonic reference (restart, reboot, tab discard) expires the content — fail closed. A server-attested timestamp is not constructible: the server cannot write into a payload it cannot read. See PROTOCOL.md §8.2 |
| T-12 | Decrypted media persisted to disk cache or OS thumbnail pipeline | Decrypt to an in-memory buffer, render from a blob URL, revoke and zeroise on dismissal; never hand the plaintext to a platform media API that caches |
| T-13 | Attachment key reuse across blobs | One random content encryption key per blob, generated at encrypt time, transported only inside the ratcheted message body |

### Real-time calls

| ID | Threat | Mitigation |
|---|---|---|
| T-14 | ICE candidate exchange discloses both peers' IP addresses | `iceTransportPolicy: 'relay'` enforced; client rejects any non-relay candidate |
| T-15 | SFU or TURN operator decrypts call media | SFrame (RFC 9605) applied via insertable streams; SFrame base key derived from the ratcheted session, never from DTLS or from anything the server supplies |
| T-16 | TURN credential theft enables open relay abuse | Short-lived HMAC credentials (coturn `use-auth-secret`), issued per call, expiring in minutes |

### Platform and operational

| ID | Threat | Mitigation |
|---|---|---|
| T-17 | Push notification payload leaks message content to APNs/FCM | Push carries a wake signal only; zero message content, zero sender identity |
| T-18 | Platform cloud backup exfiltrates the local key store or message DB | Explicit backup exclusion (`allowBackup=false`, iCloud exclusion attributes); documented in the deployment guide |
| T-19 | Server logs retain routing metadata beyond operational need | No message-level logging; IP logs disabled at the reverse proxy; documented retention policy of zero for delivery records post-ack |
| T-20 | Dependency compromise in the supply chain | `cargo-audit` and `cargo-deny` in CI as blocking checks; lockfile committed; SBOM generated per release |
| T-21 | Username enumeration via registration or lookup timing | Constant-time-ish uniform responses on lookup; per-IP rate limiting; accepted as low severity (A-7) |


---

## 9. The one-view guarantee, stated precisely

This feature attracts more overclaiming than any other, so it is specified exactly.

**What is enforced:** the relay permits exactly one successful retrieval of the ciphertext, then deletes it (T-10). The sending client deletes its copy on receipt of a view acknowledgement. The receiving client ratchets past the message key so it cannot be re-derived locally, and holds the plaintext in memory only (T-12).

**What is not enforced:** anything the recipient chooses to do with the plaintext once decrypted (NG-1). `FLAG_SECURE` on Android blocks the OS compositor from capturing, which is a real control against a casual recipient and no control at all against a determined one. iOS offers detection but not prevention. A camera pointed at a screen defeats all of it.

**Required UI language:** the interface describes this as "deleted after viewing," never as "the recipient cannot save this."

---

## 10. Residual risks

| ID | Risk | Why accepted for v1 | Retire in |
|---|---|---|---|
| R-1 | No key transparency; a malicious relay can attempt silent key substitution, detectable only by manual safety number comparison | KT requires a verifiable log and auditor infrastructure disproportionate to v1 | Phase 6 |
| R-2 | Single device per account; no session migration | Multi-device is the largest single source of protocol complexity and correctness bugs | v2 |
| R-3 | Relay learns the recipient of every envelope (NG-4) | Sealed sender requires delivery tokens and a separate anti-abuse design | Phase 6 |
| R-4 | Web client cannot prevent screen capture and depends on browser key storage rather than a hardware-backed keystore | Ships the product without app store friction; Android client closes the gap | Phase 6 |
| R-5 | No padding; message sizes leak (NG-3) | Bucketed padding is cheap to add but interacts with the attachment design | v2 |

---

## 11. Review triggers

Re-open this document when any of the following occur:

- A new component enters the trust boundary
- A key is stored, transported, or derived in a way not described in §8
- The one-view or disappearing-message semantics change in any respect
- A dependency providing a primitive named in TA-3 is replaced
- Multi-device support is added — this invalidates large parts of §6
- Anyone proposes group messaging — see §1; this requires re-deriving the document from scratch, not amending it
- A conformance test is added, removed, or weakened

## 12. Corrections

- **T-11, v0.1 → v0.2.** The original mitigation specified a server-attested timestamp delivered inside the encrypted envelope. This is not constructible — the server cannot write into a payload it cannot read. Caught while writing PROTOCOL.md §8.2, before any implementation existed. Replaced with the monotonic-clock, fail-closed design.