//! Key hierarchy: Master Password -> Argon2id -> HKDF -> KEK -> (wrap) DEK -> HKDF-Expand subkeys.
//! Distinct Rust types per key class so a key cannot be passed where another class is expected.

use crate::{Error, random};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Approved minimum: RFC 9106 SECOND RECOMMENDED.
    pub const MIN: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 4 };
    /// Upper bounds enforced when READING a header (DoS protection).
    pub const MAX: KdfParams = KdfParams { m_kib: 4 * 1024 * 1024, t: 16, p: 16 };

    pub fn validate(&self, allow_insecure_test_params: bool) -> Result<(), Error> {
        let above_min = self.m_kib >= Self::MIN.m_kib && self.t >= Self::MIN.t && self.p >= Self::MIN.p;
        let below_max = self.m_kib <= Self::MAX.m_kib && self.t <= Self::MAX.t && self.p <= Self::MAX.p;
        if !below_max || (!above_min && !allow_insecure_test_params) {
            return Err(Error::KdfParamsOutOfRange);
        }
        Ok(())
    }
}

macro_rules! key_type {
    ($name:ident) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);
        impl $name {
            pub fn bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}
key_type!(Kek);
key_type!(Dek);
key_type!(ItemsKey);
key_type!(AttachKey);
key_type!(ManifestKey);
key_type!(SettingsKey);
key_type!(LocalStateKey);
key_type!(BackupKek);
key_type!(BackupContentKey);

/// Argon2id with a caller-owned memory buffer that is wiped after use
/// (argon2 0.6.0 frees its internal `Blocks` without zeroizing: src/block.rs Drop impl).
fn argon2id(password: &[u8], salt: &[u8; 16], p: KdfParams) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|_| Error::Kdf)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let n = params.block_count();
    let mut blocks: Vec<argon2::Block> = Vec::new();
    blocks.try_reserve_exact(n).map_err(|_| Error::Kdf)?;
    blocks.resize(n, argon2::Block::default());
    let mut out = Zeroizing::new([0u8; 32]);
    let r = a.hash_password_into_with_memory(password, salt, &mut out[..], &mut blocks[..]);
    for b in blocks.iter_mut() {
        b.zeroize();
    }
    r.map_err(|_| Error::Kdf)?;
    Ok(out)
}

fn hkdf_extract_expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut okm[..]).expect("32 <= 255*HashLen");
    okm
}

/// Password transform identifier stored in vault and backup headers (bound into AAD).
/// 1 = UTF-8 encoding of the Unicode NFC form (UAX #15) produced by `unicode-normalization` 0.1.
/// NFKC/NFKD are deliberately NOT used: they remove distinctions (e.g. "ﬁ" vs "fi").
pub const PW_TRANSFORM_NFC_UTF8: u8 = 1;

/// Upper bound on the password length in bytes accepted by the KDF path (memory bound for NFC).
pub const MAX_PASSWORD_BYTES: usize = 4096;

/// The ONLY password-to-bytes conversion in the protocol. Every KDF entry point calls it, so
/// create, unlock, change-password, backup and restore cannot diverge.
///
/// Memory: the output buffer is reserved up front (12 bytes per input byte is an upper bound:
/// NFC expands at most 3x in code points and a code point is at most 4 bytes, while each input
/// code point is at least 1 byte), so the String never reallocates and leaves no stale copy.
pub fn normalize_password(password: &str, transform: u8) -> Result<Zeroizing<String>, Error> {
    use unicode_normalization::UnicodeNormalization;
    if transform != PW_TRANSFORM_NFC_UTF8 {
        return Err(Error::Format("unknown password transform"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Error::Format("password too long"));
    }
    let cap = password.len() * 12 + 16;
    let mut out = Zeroizing::new(String::with_capacity(cap));
    for ch in password.nfc() {
        out.push(ch);
    }
    if out.capacity() != cap {
        // Would mean a reallocation happened (a stale copy may exist): treat as a hard error.
        return Err(Error::Format("normalization buffer reallocated"));
    }
    Ok(out)
}

pub fn derive_vault_kek(password: &str, transform: u8, salt: &[u8; 16], vault_id: &[u8; 16], p: KdfParams) -> Result<Kek, Error> {
    let pw = normalize_password(password, transform)?;
    let muk = argon2id(pw.as_bytes(), salt, p)?;
    Ok(Kek(*hkdf_extract_expand(vault_id, &muk[..], b"VELFORT/v1/kek")))
}

pub fn derive_backup_kek(password: &str, transform: u8, salt: &[u8; 16], backup_id: &[u8; 16], p: KdfParams) -> Result<BackupKek, Error> {
    let pw = normalize_password(password, transform)?;
    let muk = argon2id(pw.as_bytes(), salt, p)?;
    Ok(BackupKek(*hkdf_extract_expand(backup_id, &muk[..], b"VELFORT/v1/backup-kek")))
}

impl Dek {
    pub fn generate() -> Result<Dek, Error> {
        Ok(Dek(random()?))
    }
    pub fn from_bytes(b: [u8; 32]) -> Dek {
        Dek(b)
    }
    /// Only for wrapping under a KEK.
    pub(crate) fn raw(&self) -> &[u8; 32] {
        &self.0
    }
    fn expand(&self, info: &[u8]) -> [u8; 32] {
        // RFC 5869 §3.3: Extract may be skipped when IKM is already a uniformly random key.
        let hk = Hkdf::<Sha256>::from_prk(&self.0).expect("PRK length 32");
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm).expect("32 <= 255*HashLen");
        okm
    }
    pub fn items_key(&self) -> ItemsKey {
        ItemsKey(self.expand(b"VELFORT/v1/items"))
    }
    pub fn attach_key(&self) -> AttachKey {
        AttachKey(self.expand(b"VELFORT/v1/attach"))
    }
    pub fn manifest_key(&self) -> ManifestKey {
        ManifestKey(self.expand(b"VELFORT/v1/manifest"))
    }
    pub fn settings_key(&self) -> SettingsKey {
        SettingsKey(self.expand(b"VELFORT/v1/settings"))
    }
    pub fn local_state_key(&self) -> LocalStateKey {
        LocalStateKey(self.expand(b"VELFORT/v1/local-state"))
    }
}

impl BackupContentKey {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self(random()?))
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}
