//! VELFORT Phase 0.5 spike — key hierarchy, AAD (D1), and single-shot backup prototype (W10, W13).
//!
//! NOT production code. Lives in `spikes/` only; nothing here is linked into the application.
//! Purpose: produce reproducible evidence for the approved design in docs/CRYPTOGRAPHY.md.

#![deny(unsafe_code)] // only `fsutil` (Windows MoveFileExW FFI) is allowed unsafe

pub mod aad;
pub mod backup;
pub mod keys;
pub mod seal;
pub mod fsutil;
pub mod store;

/// Errors are deliberately coarse: they never carry key material, passwords, or plaintext.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Rng,
    Kdf,
    KdfParamsOutOfRange,
    /// AEAD authentication failure (wrong key, tampered data, or wrong context/AAD).
    Auth,
    Format(&'static str),
    TooLarge,
    Io(std::io::ErrorKind),
    Sqlite(String),
    TargetExists,
    TargetIsSource,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.kind())
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        // rusqlite errors may embed SQL text, never bound values; still keep only the display.
        Error::Sqlite(e.to_string())
    }
}

pub fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}
