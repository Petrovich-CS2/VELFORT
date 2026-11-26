//! Envelope: version(1) || aead_alg(1) || nonce(24) || ciphertext||tag(16).
//! The nonce is generated inside `seal`; callers cannot supply one.

use crate::{Error, random};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

pub const ENVELOPE_VERSION: u8 = 1;
pub const AEAD_XCHACHA20POLY1305: u8 = 1;
pub const OVERHEAD: usize = 2 + 24 + 16;
pub const PAD_BLOCK: usize = 256;

pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Format("key"))?;
    let nonce: [u8; 24] = random()?;
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::TooLarge)?;
    let mut out = Vec::with_capacity(2 + 24 + ct.len());
    out.push(ENVELOPE_VERSION);
    out.push(AEAD_XCHACHA20POLY1305);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; 32], envelope: &[u8], aad: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    if envelope.len() < OVERHEAD {
        return Err(Error::Format("envelope too short"));
    }
    if envelope[0] != ENVELOPE_VERSION || envelope[1] != AEAD_XCHACHA20POLY1305 {
        return Err(Error::Format("envelope version/alg"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Format("key"))?;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&envelope[2..26]);
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: &envelope[26..], aad })
        .map(zeroize::Zeroizing::new)
        .map_err(|_| Error::Auth)
}

/// len(u32 LE) || data || zero padding to a multiple of PAD_BLOCK.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let total = (4 + data.len()).div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut v = Vec::with_capacity(total);
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(data);
    v.resize(total, 0);
    v
}

pub fn unpad(p: &[u8]) -> Result<&[u8], Error> {
    if p.len() < 4 || !p.len().is_multiple_of(PAD_BLOCK) {
        return Err(Error::Format("padding"));
    }
    let n = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize;
    if 4 + n > p.len() || p[4 + n..].iter().any(|&b| b != 0) {
        return Err(Error::Format("padding"));
    }
    Ok(&p[4..4 + n])
}
