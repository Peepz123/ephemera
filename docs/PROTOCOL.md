# Protocol specification

**Project:** `ephemera`
**Version:** 0.2
**Status:** Phase 1 complete. Normative for the `ephemera-core` and `ephemera-wire` crates.
**Companion document:** `THREAT-MODEL.md` — goal and threat IDs referenced here (`G-*`, `T-*`) are defined there.

Requirement keywords (MUST, SHOULD, MAY) follow RFC 2119.

**Pairwise constraint.** Every session is between exactly two identities. Implementations MUST NOT introduce conversation identifiers, membership lists, sender-key distribution, or any abstraction anticipating more than two participants. A session is fully identified by the pair of identity keys in `AD_ident` (§4.1). This is a permanent property of the protocol, and code may rely on it.

---

## 1. Cryptographic suite

| Purpose | Algorithm | Crate |
|---|---|---|
| Signatures | Ed25519 | `ed25519-dalek` |
| Key agreement | X25519 | `x25519-dalek` |
| KDF | HKDF-SHA-256 | `hkdf` |
| Chain KDF | HMAC-SHA-256 | `hmac` + `sha2` |
| AEAD | XChaCha20-Poly1305 | `chacha20poly1305` |
| Hash | SHA-256 / SHA-512 | `sha2` |

### 1.1 Rationale for split identity keys

Each identity consists of **two** keys: an Ed25519 signing key `IK_sig` and an X25519 agreement key `IK_dh`. Signal uses a single Curve25519 key for both via XEdDSA. This specification deliberately does not, because XEdDSA is not available in an audited Rust crate and implementing it would violate the rule against writing our own primitives.

`IK_sig` is the canonical identity. `IK_dh` is bound to it by a self-signature included in the registration bundle (§3.1). A verifier that trusts `IK_sig` MUST verify that signature before using `IK_dh` for any agreement.

Cost: 32 additional bytes per identity, and the binding signature is a step that MUST NOT be skipped. Benefit: no bespoke primitive anywhere in the system.

### 1.2 Encoding conventions

- All integers are **big-endian**.
- All public keys are 32 bytes; Ed25519 signatures are 64 bytes.
- `Encode(pk)` for use in associated data is the raw 32-byte key with no framing.
- Byte-string literals in KDF `info` parameters are ASCII with no terminator.

---

## 2. Key hierarchy

```
IK_sig (Ed25519, long-term)
  └─ signs ─> IK_dh   (X25519, long-term)
  └─ signs ─> SPK     (X25519, rotated ~weekly, retained one generation)
              OPK_n   (X25519, one-time, unsigned, consumed on use)

X3DH ──> SK ──> RK (root key)
                 └─ DH ratchet ──> RK', CK (chain key)
                                    └─ symmetric ratchet ──> MK (message key)
                                                              └─ HKDF ──> (aead_key, aead_nonce)
```

---

## 3. Registration and prekeys

### 3.1 Registration bundle

Published once at account creation.

```
RegistrationBundle
  ik_sig       : [u8; 32]   Ed25519 public
  ik_dh        : [u8; 32]   X25519 public
  ik_dh_sig    : [u8; 64]   Ed25519(IK_sig, "ephemera_ikdh_v1" || ik_dh)
  username     : UTF-8, 3..=32 bytes, NFC-normalised, [a-z0-9_.-]
```

The server MUST verify `ik_dh_sig` at registration and reject on failure. This is a courtesy check only; clients MUST NOT rely on it (T-1 — the server is untrusted).

### 3.2 Prekey bundle

```
PreKeyBundle
  spk_id       : u32
  spk_pub      : [u8; 32]
  spk_sig      : [u8; 64]   Ed25519(IK_sig, "ephemera_spk_v1" || spk_id_be || spk_pub)
  opk_id       : u32        0xFFFFFFFF signals "none available"
  opk_pub      : [u8; 32]   all-zero when opk_id == 0xFFFFFFFF
```

Client behaviour:

- Clients MUST verify `spk_sig` against the pinned `ik_sig` before any DH (T-4). Failure aborts session establishment with no fallback.
- Clients MUST maintain at least 100 unconsumed OPKs and MUST replenish when the count drops below 25.
- The server MUST delete an OPK on issue and MUST NOT issue the same `opk_id` twice.
- When `opk_id == 0xFFFFFFFF`, the initiator MAY proceed with the three-DH variant but MUST surface this to the user interface layer as reduced initial forward secrecy. It MUST NOT be silent (T-2).
- SPK rotation retains the previous generation for 7 days to accommodate in-flight bundles.

---

## 4. X3DH

Alice initiates to Bob. Alice has fetched and verified Bob's bundle.

Alice generates an ephemeral `EK_A` (X25519).

```
DH1 = X25519(IK_dh_A,  SPK_B)
DH2 = X25519(EK_A,     IK_dh_B)
DH3 = X25519(EK_A,     SPK_B)
DH4 = X25519(EK_A,     OPK_B)      // omitted entirely if no OPK
```

```
F  = 0xFF repeated 32 times
SK = HKDF-SHA-256(
       ikm  = F || DH1 || DH2 || DH3 [|| DH4],
       salt = [0u8; 32],
       info = "ephemera_x3dh_v1",
       len  = 32
     )
```

All DH outputs and `SK` MUST be zeroised immediately after `SK` is derived (T-8). Implementations MUST check each X25519 output for the all-zero result and abort if found.

### 4.1 Associated data

```
AD_ident = Encode(IK_sig_A) || Encode(IK_sig_B)
```

`AD_ident` is fixed for the lifetime of the session and is a component of the AEAD associated data of every message (§6.3). Ordering is initiator first, and both parties MUST compute it identically regardless of message direction.

### 4.2 Bob's side

Bob derives the same `SK` using the private counterparts. He MUST:

1. Reject if `opk_id` refers to an already-consumed OPK (T-3).
2. Reject if `EK_A` has been seen before in any session (T-3). A bounded LRU of the last 10,000 ephemeral keys is sufficient.
3. Delete the OPK private key immediately upon successful derivation.

---

## 5. Double Ratchet

### 5.1 Initialisation

Alice, after X3DH, holds `SK` and Bob's `SPK_B` as his initial ratchet public key:

```
RK_0 = SK
generate ratchet keypair (rpriv_A, rpub_A)
(RK_1, CK_send) = KDF_RK(RK_0, X25519(rpriv_A, SPK_B))
CK_recv = None
```

Bob initialises with `RK_0 = SK`, his ratchet keypair set to the SPK pair, and both chains empty. He performs his first DH ratchet step on receipt of Alice's first message.

### 5.2 Root KDF

```
KDF_RK(rk, dh_out):
  okm = HKDF-SHA-256(ikm = dh_out, salt = rk,
                     info = "ephemera_ratchet_root_v1", len = 64)
  return (okm[0..32] as RK', okm[32..64] as CK)
```

### 5.3 Chain KDF

```
KDF_CK(ck):
  MK  = HMAC-SHA-256(key = ck, data = 0x01)
  CK' = HMAC-SHA-256(key = ck, data = 0x02)
  return (CK', MK)
```

### 5.4 Message key expansion

```
okm         = HKDF-SHA-256(ikm = MK, salt = [0u8; 32],
                           info = "ephemera_msg_v1", len = 56)
aead_key    = okm[0..32]
aead_nonce  = okm[32..56]
```

Because `MK` is unique per message, `aead_nonce` is unique per key and the 192-bit XChaCha20 nonce space is never at risk. `MK` MUST be zeroised after expansion.

### 5.5 Skipped keys

On receiving a message with `n` greater than expected, the receiver advances the chain and stores intermediate `MK`s keyed by `(ratchet_pub, n)`.

- `MAX_SKIP = 1000` per chain. Exceeding it aborts processing of that message and MUST NOT partially mutate session state (T-6).
- `MAX_STORED_SKIPPED = 2000` across the session, evicted oldest-first.
- Skipped keys expire after 7 days and are zeroised on eviction or expiry.
- A skipped key MUST be deleted immediately on use — this is what makes replay detection (T-5) work.
- Decryption MUST NOT mutate session state unless the AEAD verifies. An implementation that advances the chain, stores skipped keys, or performs a DH ratchet step before authenticating the payload allows an attacker to desynchronise a session with forged ciphertext, without breaking any cryptography. Implementations SHOULD operate on a copy of the session and commit only on success.

### 5.6 Session state

```
SessionState
  ad_ident            : [u8; 64]
  peer_identity       : [u8; 32]   Ed25519, pinned
  phase               : SessionPhase
  rk                  : [u8; 32]
  ratchet_priv        : Option<X25519Secret>
  ratchet_pub         : [u8; 32]
  remote_ratchet_pub  : Option<[u8; 32]>
  ck_send, ck_recv    : Option<[u8; 32]>
  n_send, n_recv      : u32
  pn                  : u32
  skipped             : Map<([u8;32], u32), (MessageKey, Instant)>
```

Every secret-bearing field MUST be `ZeroizeOnDrop`.

### 5.7 State machine

```
Uninitialised
     │ send first message
     ▼
PendingInitial ──── receive any message ────► Established
     │                                             │
     │ receive first message                       │ peer ik_sig changes
     ▼                                             ▼
Established ◄──────────────────────────────── IdentityChanged
                                                   │ user re-verifies
                                                   ▼
                                              Established
```

`PendingInitial` means Alice has sent but not received; every outbound message in this state MUST be wrapped as a `PreKeyEnvelope` (§6.1), because Bob may not have processed any of them yet.

`IdentityChanged` is terminal until the user acts. Clients MUST block sending and MUST display a hard warning (T-1). Auto-accepting a changed identity key defeats the only defence against a malicious relay.

---

## 6. Wire format

### 6.1 Envelope framing

```
Offset  Size  Field
0       4     magic       = "EPHM"
4       1     version     = 0x01
5       1     type        0x01 PreKeyEnvelope | 0x02 RatchetMessage
6       2     reserved    = 0x0000, MUST be zero, receiver MUST reject otherwise
8       ...   body
```

### 6.2 Bodies

**PreKeyEnvelope (type 0x01)**

```
0    32   ik_sig_a
32   32   ik_dh_a
64   32   ek_a
96   4    spk_id
100  4    opk_id
104  4    inner_len
108  ...   inner  — a complete RatchetMessage, magic and all
```

**RatchetMessage (type 0x02)**

```
0    32   ratchet_pub
32   4    pn        previous sending chain length
36   4    n         message number in current chain
40   4    ct_len
44   ...   ciphertext
```

### 6.3 Associated data

```
AD = envelope_header(8 bytes) || body_header || AD_ident
```

where `body_header` is every byte of the body preceding `ciphertext`. This binds the ratchet public key, `pn`, `n`, and both identities into the AEAD tag, so headers cannot be swapped between messages or replayed into another session (T-7).

Headers are **not** encrypted in v1. An observer sees ratchet public keys and message counters, which permits conversation linkage at the relay. Header encryption is deferred; tracked as residual risk in the threat model alongside R-3.

### 6.4 Size limits

Envelopes exceeding 64 KiB MUST be rejected. Larger content goes to the blob store as an attachment (§7).

---

## 7. Content payload

The AEAD plaintext is a `Content` structure. This layer is invisible to the server.

```
0    1    content_type
1    1    flags
2    8    sent_at_ms      sender-claimed, UTC milliseconds — advisory only
10   4    ttl_ms          0 = no expiry
14   4    body_len
18   ...  body
```

| `content_type` | Meaning |
|---|---|
| 0x01 | Text (UTF-8) |
| 0x02 | Attachment descriptor |
| 0x03 | Call signalling |
| 0x04 | Receipt |
| 0x05 | Session control |

| `flags` bit | Meaning |
|---|---|
| 0 | One-view content |
| 1 | Expires after `ttl_ms` |
| 2–7 | Reserved, MUST be zero |

### 7.1 Attachment descriptor (0x02)

```
0    32   blob_id       random, 256-bit
32   32   cek           content encryption key, unique per blob (T-13)
64   24   cek_nonce
88   32   ct_digest     SHA-256 of the stored ciphertext
120  8    plaintext_len
128  2    mime_len
130  ...  mime          IANA type, ASCII
```

Encryption is XChaCha20-Poly1305 over the whole plaintext with `cek`. The client MUST verify `ct_digest` before attempting decryption, so a malicious blob store cannot feed arbitrary bytes into the AEAD.

`cek` exists only inside this descriptor, which is itself inside the ratcheted envelope. It is never transmitted separately and never reaches the server.

### 7.2 Receipt (0x04)

```
0    16   ref_id        message identifier being acknowledged
16   1    kind          0x01 delivered | 0x02 viewed | 0x03 expired
```

A `viewed` receipt for one-view content triggers local deletion of the sender's copy.

---

## 8. Ephemeral content

### 8.1 Server-enforced single retrieval

The blob record carries `state ∈ {unread, consumed}`. Retrieval is a single atomic statement (T-10):

```sql
UPDATE blobs
   SET state = 'consumed', consumed_at = now()
 WHERE blob_id = $1
   AND recipient_id = $2
   AND state = 'unread'
RETURNING storage_key;
```

Zero rows returned means already consumed, and the handler returns 410 Gone. A read-then-delete sequence is **non-conformant** — two concurrent requests would both succeed.

The object is deleted from storage asynchronously within 60 seconds of the state transition. The state flag, not the object lifetime, is the enforcement point.

### 8.2 Timers

Expiry timers cannot depend on a server-supplied timestamp: the server cannot insert one into a payload it cannot read, and anything it attaches outside the envelope is unauthenticated and attacker-controllable under ADV-4. Nor can they depend on the device's wall clock, which the user controls.

- The expiry timer starts at **local view time**, measured on a monotonic clock (`Instant` / `performance.now()`).
- `sent_at_ms` in the `Content` header is advisory display metadata only and MUST NOT drive expiry.
- If the monotonic reference is lost — process restart, tab discard, device reboot — unexpired ephemeral content MUST be treated as expired and deleted. Failing closed is correct here: the cost is a lost message, and the alternative is an unbounded window.


### 8.3 Client obligations for one-view content

- Decrypt into memory only; never write plaintext to disk, IndexedDB, or a platform media cache (T-12).
- Render from an object URL, revoke it on dismissal, zeroise the buffer.
- Delete the message key and any skipped-key entry immediately after render.
- On Android, set `FLAG_SECURE` for the duration of display.
- The UI states "deleted after viewing". It MUST NOT state or imply that the recipient cannot retain the content (NG-1).

---

## 9. Safety numbers

Displayed for out-of-band identity verification (TA-4), 60 decimal digits total.

```
fingerprint(ik_sig, username):
    h = "ephemera_fp_v1" || 0x00 || ik_sig || username
    repeat 5200 times: h = SHA-512(h || ik_sig)
    take h[0..30], split into six 5-byte groups
    each group -> be_u40 mod 100000, zero-padded to 5 digits
```

The displayed number is the concatenation of both parties' fingerprints, ordered by lexicographic comparison of the two `ik_sig` values so both sides render identically.

The iteration count is a deliberate cost to make bulk fingerprint-collision search expensive. It MUST NOT be reduced.

---

## 10. Server API surface

The relay stores and forwards. It performs no cryptographic operation on user content.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/accounts` | Register; publishes `RegistrationBundle` |
| `PUT` | `/v1/keys/prekeys` | Upload SPK and a batch of OPKs |
| `GET` | `/v1/keys/{username}` | Fetch a `PreKeyBundle`; consumes one OPK |
| `GET` | `/v1/keys/count` | Remaining OPK count, drives replenishment |
| `WS` | `/v1/ws` | Bidirectional envelope stream |
| `POST` | `/v1/blobs` | Upload attachment ciphertext, returns `blob_id` |
| `GET` | `/v1/blobs/{blob_id}` | Retrieve; atomic consume for one-view (§8.1) |

Authentication is a signature over a server-issued challenge using `IK_sig`. No password, no recoverable credential.

The server MUST NOT log envelope bodies, blob contents, or delivery pairs beyond acknowledgement (T-19).

---

## 11. Conformance vectors

`ephemera-core` MUST ship deterministic tests covering:

1. **HKDF** — RFC 5869 vectors.
2. **X25519** — RFC 7748 §6.1 vectors.
3. **X3DH** — fixed keypairs, four-DH and three-DH variants, asserting both parties derive identical `SK`.
4. **Ratchet, in order** — 100 messages each direction, alternating.
5. **Ratchet, out of order** — deliver 1..50 in reverse; all MUST decrypt.
6. **Ratchet, dropped** — drop messages 10–20; 21 onward MUST decrypt.
7. **Skip cap** — a jump of `MAX_SKIP + 1` MUST error and leave session state unchanged.
8. **Replay** — re-delivering a decrypted message MUST error.
9. **Header tamper** — flipping any bit in `pn`, `n`, or `ratchet_pub` MUST fail the AEAD.
10. **Cross-session** — a valid envelope from session A MUST fail against session B.
11. **Atomicity under forgery** — a message with a valid header, an advanced `n`, and a forged ciphertext MUST error and leave `rk`, `n_recv`, and the skipped-key map unchanged.
12. **Map ceiling** *(not yet implemented)* — the skipped-key map MUST NOT exceed `MAX_STORED_SKIPPED` across repeated large skips and ratchet steps.

Tests 4–6 SHOULD additionally be expressed as `proptest` properties over randomised delivery orderings.

---

## 12. Open items

| ID | Item |
|---|---|
| O-1 | Header encryption to reduce relay-side linkability |
| O-2 | Sealed sender; interacts with the auth model in §10 |
| O-3 | SFrame key derivation from the ratchet root for calls — Phase 5 |
| O-4 | Bucketed padding for envelope sizes (R-5) |
| O-5 | Key transparency log (R-1) |
