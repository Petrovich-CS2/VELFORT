//! W11 — black-box robustness tests of aead-stream 0.6.0 (StreamBE32 over XChaCha20-Poly1305).
//! Spike only. The crate is NOT approved for production (no independent audit found).
//!
//! Segments are produced with `encrypt_next` ... `encrypt_last`; a correct reader must call
//! `decrypt_next` for every non-final segment and `decrypt_last` exactly once for the final one.

use aead_stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::XChaCha20Poly1305;

pub type Enc = EncryptorBE32<XChaCha20Poly1305>;
pub type Dec = DecryptorBE32<XChaCha20Poly1305>;

pub const KEY: [u8; 32] = [0x42; 32];
pub const PREFIX: [u8; 19] = [0x24; 19];

pub fn encrypt(segments: &[&[u8]], aad: &[u8]) -> Vec<Vec<u8>> {
    let key = KEY.into();
    let nonce = PREFIX.into();
    let mut e = Enc::new(&key, &nonce);
    let mut out = Vec::new();
    for s in &segments[..segments.len() - 1] {
        out.push(e.encrypt_next(chacha20poly1305::aead::Payload { msg: s, aad }).unwrap());
    }
    out.push(e.encrypt_last(chacha20poly1305::aead::Payload { msg: segments[segments.len() - 1], aad }).unwrap());
    out
}

/// Reference reader: all but the final segment via decrypt_next, final via decrypt_last.
#[allow(clippy::result_unit_err)]
pub fn decrypt(segments: &[Vec<u8>], aad: &[u8]) -> Result<Vec<u8>, ()> {
    if segments.is_empty() {
        return Err(());
    }
    let key = KEY.into();
    let nonce = PREFIX.into();
    let mut d = Dec::new(&key, &nonce);
    let mut out = Vec::new();
    for s in &segments[..segments.len() - 1] {
        out.extend(d.decrypt_next(chacha20poly1305::aead::Payload { msg: s, aad }).map_err(|_| ())?);
    }
    out.extend(d.decrypt_last(chacha20poly1305::aead::Payload { msg: &segments[segments.len() - 1], aad }).map_err(|_| ())?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Vec<u8>> {
        encrypt(&[b"seg-0", b"seg-1", b"seg-2", b"seg-3"], b"hdr")
    }

    #[test]
    fn roundtrip() {
        assert_eq!(decrypt(&sample(), b"hdr").unwrap(), b"seg-0seg-1seg-2seg-3");
    }

    #[test]
    fn truncation_at_segment_boundary_is_detected() {
        let s = sample();
        for n in 1..s.len() {
            assert!(decrypt(&s[..n], b"hdr").is_err(), "truncated to {n} segments accepted");
        }
    }

    #[test]
    fn reordering_is_detected() {
        let mut s = sample();
        s.swap(1, 2);
        assert!(decrypt(&s, b"hdr").is_err());
    }

    #[test]
    fn duplicate_segment_is_detected() {
        let s = sample();
        let dup = vec![s[0].clone(), s[0].clone(), s[1].clone(), s[2].clone(), s[3].clone()];
        assert!(decrypt(&dup, b"hdr").is_err());
    }

    #[test]
    fn data_after_last_segment_is_detected_by_reader_structure() {
        // Appending a copy of the last segment makes it non-final in position -> must fail.
        let mut s = sample();
        let last = s[3].clone();
        s.push(last);
        assert!(decrypt(&s, b"hdr").is_err());
    }

    #[test]
    fn single_bit_corruption_in_any_segment_is_detected() {
        let s = sample();
        for i in 0..s.len() {
            for j in 0..s[i].len() {
                let mut x = s.clone();
                x[i][j] ^= 0x80;
                assert!(decrypt(&x, b"hdr").is_err(), "segment {i} byte {j}");
            }
        }
    }

    #[test]
    fn wrong_aad_is_detected() {
        assert!(decrypt(&sample(), b"other").is_err());
    }

    #[test]
    fn decryptor_state_after_error() {
        // After a failed decrypt_next the position is NOT advanced (source: `?` before `position += 1`),
        // so retrying with the correct segment succeeds. A reader MUST still abort on first error.
        let s = sample();
        let key = KEY.into();
        let nonce = PREFIX.into();
        let mut d = Dec::new(&key, &nonce);
        assert!(d.decrypt_next(chacha20poly1305::aead::Payload { msg: &s[1], aad: b"hdr" }).is_err());
        assert_eq!(d.decrypt_next(chacha20poly1305::aead::Payload { msg: &s[0], aad: b"hdr" }).unwrap(), b"seg-0");
    }

    #[test]
    fn last_segment_cannot_be_read_as_next() {
        let s = encrypt(&[b"only"], b"hdr");
        let key = KEY.into();
        let nonce = PREFIX.into();
        let mut d = Dec::new(&key, &nonce);
        assert!(d.decrypt_next(chacha20poly1305::aead::Payload { msg: &s[0], aad: b"hdr" }).is_err());
    }

    #[test]
    fn interrupted_encryption_yields_undecryptable_prefix() {
        // Writer crashed before encrypt_last: only "next" segments exist -> reader rejects.
        let key = KEY.into();
        let nonce = PREFIX.into();
        let mut e = Enc::new(&key, &nonce);
        let s0 = e.encrypt_next(chacha20poly1305::aead::Payload { msg: b"a", aad: b"hdr" }).unwrap();
        let s1 = e.encrypt_next(chacha20poly1305::aead::Payload { msg: b"b", aad: b"hdr" }).unwrap();
        drop(e);
        assert!(decrypt(&[s0, s1], b"hdr").is_err());
    }

    #[test]
    fn same_key_and_prefix_reuse_is_caller_responsibility() {
        // Two streams with identical key+prefix produce identical keystream for equal positions:
        // the crate cannot prevent this; VELFORT would need a fresh key or prefix per stream.
        let a = encrypt(&[b"AAAA", b"x"], b"hdr");
        let b = encrypt(&[b"BBBB", b"x"], b"hdr");
        let xa: Vec<u8> = a[0][..4].iter().zip(&b[0][..4]).map(|(p, q)| p ^ q).collect();
        let xp: Vec<u8> = b"AAAA".iter().zip(b"BBBB").map(|(p, q)| p ^ q).collect();
        assert_eq!(xa, xp, "nonce reuse leaks XOR of plaintexts (expected property of the primitive)");
    }
}
