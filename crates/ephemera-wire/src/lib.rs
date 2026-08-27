//! Envelope encoding for the ephemera protocol.
//!
//! This crate implements PROTOCOL.md section 6 and nothing else. It performs no
//! cryptography and no I/O. It exists as a separate crate so that the server can
//! parse envelope headers for routing without linking any crypto code at all.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Four-byte magic prefixing every envelope.
pub const MAGIC: [u8; 4] = *b"EPHM";
/// Protocol version this crate encodes and accepts.
pub const VERSION: u8 = 0x01;
/// Envelopes larger than this are rejected (PROTOCOL.md 6.4).
pub const MAX_ENVELOPE: usize = 64 * 1024;
/// Sentinel `opk_id` meaning no one-time prekey was available.
pub const OPK_NONE: u32 = 0xFFFF_FFFF;

const HEADER_LEN: usize = 8;
const TYPE_PREKEY: u8 = 0x01;
const TYPE_RATCHET: u8 = 0x02;

/// Errors produced while decoding an envelope.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// Buffer ended before a required field was complete.
    #[error("truncated: needed {needed} bytes, had {had}")]
    Truncated {
        /// Bytes required.
        needed: usize,
        /// Bytes present.
        had: usize,
    },
    /// Magic prefix did not match.
    #[error("bad magic")]
    BadMagic,
    /// Version is not one this crate understands.
    #[error("unsupported version {0}")]
    BadVersion(u8),
    /// Type byte is not a known envelope type.
    #[error("unknown envelope type {0}")]
    BadType(u8),
    /// Reserved field was non-zero.
    #[error("reserved field must be zero")]
    ReservedNonZero,
    /// Envelope exceeded `MAX_ENVELOPE`.
    #[error("envelope too large: {0} bytes")]
    TooLarge(usize),
    /// A length field disagreed with the bytes actually present.
    #[error("length field mismatch")]
    LengthMismatch,
}

/// A decoded envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    /// Session-establishing envelope carrying X3DH parameters (PROTOCOL.md 6.2).
    PreKey(PreKeyEnvelope),
    /// Ordinary ratcheted message.
    Ratchet(RatchetMessage),
}

/// X3DH session-establishing envelope wrapping a complete `RatchetMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreKeyEnvelope {
    /// Initiator Ed25519 identity key.
    pub ik_sig_a: [u8; 32],
    /// Initiator X25519 agreement key.
    pub ik_dh_a: [u8; 32],
    /// Initiator ephemeral key.
    pub ek_a: [u8; 32],
    /// Signed prekey identifier used.
    pub spk_id: u32,
    /// One-time prekey identifier, or [`OPK_NONE`].
    pub opk_id: u32,
    /// The wrapped ratchet message.
    pub inner: RatchetMessage,
}

/// An ordinary Double Ratchet message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetMessage {
    /// Sender's current ratchet public key.
    pub ratchet_pub: [u8; 32],
    /// Length of the previous sending chain.
    pub pn: u32,
    /// Message number within the current chain.
    pub n: u32,
    /// AEAD ciphertext including tag.
    pub ciphertext: Vec<u8>,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::LengthMismatch)?;
        if end > self.buf.len() {
            return Err(WireError::Truncated {
                needed: n,
                had: self.buf.len().saturating_sub(self.pos),
            });
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn key(&mut self) -> Result<[u8; 32], WireError> {
        let mut k = [0u8; 32];
        k.copy_from_slice(self.take(32)?);
        Ok(k)
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
}

fn write_header(out: &mut Vec<u8>, ty: u8) {
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(ty);
    out.extend_from_slice(&0u16.to_be_bytes());
}

fn read_header(r: &mut Reader<'_>) -> Result<u8, WireError> {
    let magic = r.take(4)?;
    if magic != MAGIC {
        return Err(WireError::BadMagic);
    }
    let version = r.u8()?;
    if version != VERSION {
        return Err(WireError::BadVersion(version));
    }
    let ty = r.u8()?;
    if r.u16()? != 0 {
        return Err(WireError::ReservedNonZero);
    }
    Ok(ty)
}

impl RatchetMessage {
    /// Encode to bytes including the 8-byte envelope header.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 44 + self.ciphertext.len());
        write_header(&mut out, TYPE_RATCHET);
        out.extend_from_slice(&self.ratchet_pub);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Bytes covered by the AEAD associated data, i.e. everything before the
    /// ciphertext (PROTOCOL.md 6.3). `AD_ident` is appended by the caller.
    pub fn ad_prefix(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 44);
        write_header(&mut out, TYPE_RATCHET);
        out.extend_from_slice(&self.ratchet_pub);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let ratchet_pub = r.key()?;
        let pn = r.u32()?;
        let n = r.u32()?;
        let ct_len = r.u32()? as usize;
        let ciphertext = r.take(ct_len)?.to_vec();
        Ok(RatchetMessage { ratchet_pub, pn, n, ciphertext })
    }
}

impl PreKeyEnvelope {
    /// Encode to bytes including the 8-byte envelope header.
    pub fn encode(&self) -> Vec<u8> {
        let inner = self.inner.encode();
        let mut out = Vec::with_capacity(HEADER_LEN + 108 + inner.len());
        write_header(&mut out, TYPE_PREKEY);
        out.extend_from_slice(&self.ik_sig_a);
        out.extend_from_slice(&self.ik_dh_a);
        out.extend_from_slice(&self.ek_a);
        out.extend_from_slice(&self.spk_id.to_be_bytes());
        out.extend_from_slice(&self.opk_id.to_be_bytes());
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        out.extend_from_slice(&inner);
        out
    }
}

impl Envelope {
    /// Encode any envelope variant.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Envelope::PreKey(p) => p.encode(),
            Envelope::Ratchet(m) => m.encode(),
        }
    }

    /// Decode an envelope from a complete buffer.
    ///
    /// Rejects trailing bytes: a buffer must contain exactly one envelope.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() > MAX_ENVELOPE {
            return Err(WireError::TooLarge(buf.len()));
        }
        let mut r = Reader::new(buf);
        let ty = read_header(&mut r)?;
        let env = match ty {
            TYPE_RATCHET => Envelope::Ratchet(RatchetMessage::decode_body(&mut r)?),
            TYPE_PREKEY => {
                let ik_sig_a = r.key()?;
                let ik_dh_a = r.key()?;
                let ek_a = r.key()?;
                let spk_id = r.u32()?;
                let opk_id = r.u32()?;
                let inner_len = r.u32()? as usize;
                let inner_bytes = r.take(inner_len)?;
                let inner = match Envelope::decode(inner_bytes)? {
                    Envelope::Ratchet(m) => m,
                    Envelope::PreKey(_) => return Err(WireError::BadType(TYPE_PREKEY)),
                };
                Envelope::PreKey(PreKeyEnvelope {
                    ik_sig_a,
                    ik_dh_a,
                    ek_a,
                    spk_id,
                    opk_id,
                    inner,
                })
            }
            other => return Err(WireError::BadType(other)),
        };
        if r.pos != buf.len() {
            return Err(WireError::LengthMismatch);
        }
        Ok(env)
    }
}
