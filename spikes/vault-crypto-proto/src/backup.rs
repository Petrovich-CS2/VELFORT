//! Single-shot backup prototype (approved v1 approach, NO aead-stream):
//! 1) consistent in-memory SQLite snapshot (`serialize` inside a read transaction),
//! 2) size check, 3) ONE XChaCha20-Poly1305 call (in place), 4) write to a NEW file, 5) verify.
//!
//! File layout (all integers little-endian):
//!   MAGIC "VELFORT-BACKUP\0" (15) | format u16 | header_len u32 | header (77) |
//!   wrapped_bk envelope (74) | payload envelope: ver(1) alg(1) nonce(24) ct(payload_len) tag(16)
//! header = backup_id(16) created_at(u64) source_vault_id(16) kdf m,t,p (u32 x3) salt(16) payload_len(u64) pw_transform(u8)
//! Format 2 (Phase 0.6): adds pw_transform (1 = UTF-8 NFC), bound into both AADs via the header bytes.

use crate::fsutil::{same_existing_file, write_new_file_no_replace};
use crate::keys::{BackupContentKey, KdfParams, PW_TRANSFORM_NFC_UTF8, derive_backup_kek};
use crate::seal::{self, AEAD_XCHACHA20POLY1305, ENVELOPE_VERSION};
use crate::store::{APPLICATION_ID, read_header, unlock};
use crate::{Error, random};
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, MAIN_DB};
use std::io::Read;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 15] = b"VELFORT-BACKUP\0";
pub const FORMAT: u16 = 2;
const HEADER_LEN: usize = 77;
const WRAPPED_LEN: usize = 2 + 24 + 32 + 16;
const PREFIX_LEN: usize = 15 + 2 + 4;
/// Per-message limit of chacha20poly1305 0.11.0 (src/cipher.rs: len/64 >= u32::MAX -> Error).
pub const AEAD_MAX_PLAINTEXT: u64 = (u32::MAX as u64 - 1) * 64;

pub struct BackupHeader {
    pub backup_id: [u8; 16],
    pub created_at: u64,
    pub source_vault_id: [u8; 16],
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub payload_len: u64,
    pub pw_transform: u8,
}

impl BackupHeader {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..16].copy_from_slice(&self.backup_id);
        b[16..24].copy_from_slice(&self.created_at.to_le_bytes());
        b[24..40].copy_from_slice(&self.source_vault_id);
        b[40..44].copy_from_slice(&self.kdf.m_kib.to_le_bytes());
        b[44..48].copy_from_slice(&self.kdf.t.to_le_bytes());
        b[48..52].copy_from_slice(&self.kdf.p.to_le_bytes());
        b[52..68].copy_from_slice(&self.salt);
        b[68..76].copy_from_slice(&self.payload_len.to_le_bytes());
        b[76] = self.pw_transform;
        b
    }
    fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != HEADER_LEN {
            return Err(Error::Format("backup header length"));
        }
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Ok(Self {
            backup_id: b[0..16].try_into().unwrap(),
            created_at: u64_at(16),
            source_vault_id: b[24..40].try_into().unwrap(),
            kdf: KdfParams { m_kib: u32_at(40), t: u32_at(44), p: u32_at(48) },
            salt: b[52..68].try_into().unwrap(),
            payload_len: u64_at(68),
            pw_transform: b[76],
        })
    }
}

fn prefix() -> Vec<u8> {
    let mut v = Vec::with_capacity(PREFIX_LEN);
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&FORMAT.to_le_bytes());
    v.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    v
}
fn wrap_aad(header: &[u8]) -> Vec<u8> {
    let mut v = prefix();
    v.extend_from_slice(header);
    v.push(0x01); // purpose: backup key wrap
    v
}
fn payload_aad(header: &[u8], wrapped: &[u8]) -> Vec<u8> {
    let mut v = prefix();
    v.extend_from_slice(header);
    v.extend_from_slice(wrapped);
    v.push(0x02); // purpose: backup payload
    v
}

pub struct CreateReport {
    pub snapshot_bytes: usize,
    pub file_bytes: usize,
}

/// Creates a backup of `conn` (an unlocked or locked vault — the snapshot is field-encrypted anyway).
/// Requires the Master Password again (separate salt + Argon2id context for the backup KEK).
pub fn create_backup(
    conn: &mut Connection,
    password: &str,
    kdf: KdfParams,
    allow_test_params: bool,
    max_snapshot_bytes: u64,
    out: &Path,
) -> Result<CreateReport, Error> {
    kdf.validate(allow_test_params)?;
    let (vh, _) = read_header(conn)?;
    // Re-authenticate: the backup password must be the vault's current Master Password.
    let _ = unlock(conn, password, allow_test_params)?;

    // 1) consistent snapshot: hold a read transaction (SHARED lock) while serializing.
    conn.execute_batch("BEGIN DEFERRED; SELECT count(*) FROM sqlite_master;")?;
    let snap = conn.serialize(MAIN_DB);
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let snap_res = (|| -> Result<(), Error> {
        let mut data = snap?;
        // 2) size check BEFORE the second allocation
        if data.len() as u64 > max_snapshot_bytes.min(AEAD_MAX_PLAINTEXT) {
            return Err(Error::TooLarge);
        }
        buf.try_reserve_exact(data.len() + 16).map_err(|_| Error::TooLarge)?;
        buf.extend_from_slice(&data);
        if let rusqlite::serialize::Data::Owned(ref mut o) = data {
            o.zeroize(); // sqlite3_free does not wipe
        }
        Ok(())
    })();
    conn.execute_batch("COMMIT;")?;
    snap_res?;
    let snapshot_bytes = buf.len();

    let header = BackupHeader {
        backup_id: random()?,
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        source_vault_id: vh.vault_id,
        kdf,
        salt: random()?, // separate salt, never the vault salt
        payload_len: snapshot_bytes as u64,
        pw_transform: PW_TRANSFORM_NFC_UTF8,
    }
    .encode();
    let hdr = BackupHeader::decode(&header)?;
    let kek_b = derive_backup_kek(password, hdr.pw_transform, &hdr.salt, &hdr.backup_id, kdf)?;
    let bk = BackupContentKey::generate()?;
    let wrapped = seal::seal(kek_b.bytes(), bk.bytes(), &wrap_aad(&header))?;
    debug_assert_eq!(wrapped.len(), WRAPPED_LEN);

    // 3) one AEAD call, in place
    let cipher = XChaCha20Poly1305::new_from_slice(bk.bytes()).map_err(|_| Error::Format("key"))?;
    let nonce: [u8; 24] = random()?;
    cipher
        .encrypt_in_place(&XNonce::from(nonce), &payload_aad(&header, &wrapped), &mut *buf)
        .map_err(|_| Error::TooLarge)?;

    let mut file = Vec::new();
    file.try_reserve_exact(PREFIX_LEN + HEADER_LEN + WRAPPED_LEN + 26 + buf.len()).map_err(|_| Error::TooLarge)?;
    file.extend_from_slice(&prefix());
    file.extend_from_slice(&header);
    file.extend_from_slice(&wrapped);
    file.push(ENVELOPE_VERSION);
    file.push(AEAD_XCHACHA20POLY1305);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&buf);
    // 4) new file only
    write_new_file_no_replace(out, &file)?;
    Ok(CreateReport { snapshot_bytes, file_bytes: file.len() })
}

/// Decrypts and fully verifies a backup IN MEMORY. Returns the plaintext SQLite image.
pub fn verify_backup(path: &Path, password: &str, allow_test_params: bool, max_snapshot_bytes: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
    let meta = std::fs::metadata(path)?;
    let fixed = (PREFIX_LEN + HEADER_LEN + WRAPPED_LEN + 26 + 16) as u64;
    if meta.len() < fixed {
        return Err(Error::Format("backup too short"));
    }
    if meta.len() - fixed > max_snapshot_bytes.min(AEAD_MAX_PLAINTEXT) {
        return Err(Error::TooLarge); // checked before allocating
    }
    let mut f = std::fs::File::open(path)?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(meta.len() as usize).map_err(|_| Error::TooLarge)?;
    f.read_to_end(&mut raw)?;
    if raw.len() as u64 != meta.len() {
        return Err(Error::Format("file changed while reading"));
    }
    if raw[..PREFIX_LEN] != prefix()[..] {
        return Err(Error::Format("magic/format/header_len"));
    }
    let header = &raw[PREFIX_LEN..PREFIX_LEN + HEADER_LEN];
    let hdr = BackupHeader::decode(header)?;
    hdr.kdf.validate(allow_test_params)?;
    if hdr.payload_len != meta.len() - fixed {
        return Err(Error::Format("payload length mismatch (truncated or extended file)"));
    }
    let wrapped = &raw[PREFIX_LEN + HEADER_LEN..PREFIX_LEN + HEADER_LEN + WRAPPED_LEN];
    let kek_b = derive_backup_kek(password, hdr.pw_transform, &hdr.salt, &hdr.backup_id, hdr.kdf)?;
    let bk_pt = seal::open(kek_b.bytes(), wrapped, &wrap_aad(header))?; // wrong password => Auth
    let bk = BackupContentKey::from_bytes(bk_pt[..].try_into().map_err(|_| Error::Format("bk len"))?);
    let env = &raw[PREFIX_LEN + HEADER_LEN + WRAPPED_LEN..];
    if env[0] != ENVELOPE_VERSION || env[1] != AEAD_XCHACHA20POLY1305 {
        return Err(Error::Format("payload envelope version"));
    }
    let nonce: [u8; 24] = env[2..26].try_into().unwrap();
    let aad = payload_aad(header, wrapped);
    let mut body: Zeroizing<Vec<u8>> = Zeroizing::new(env[26..].to_vec());
    raw.zeroize();
    let cipher = XChaCha20Poly1305::new_from_slice(bk.bytes()).map_err(|_| Error::Format("key"))?;
    cipher.decrypt_in_place(&XNonce::from(nonce), &aad, &mut *body).map_err(|_| Error::Auth)?;

    // Structural verification of the snapshot, in memory only.
    let mut mem = Connection::open_in_memory()?;
    mem.deserialize_read_exact(MAIN_DB, &body[..], body.len(), true)?;
    let ic: String = mem.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if ic != "ok" {
        return Err(Error::Format("integrity_check failed"));
    }
    let app: i32 = mem.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    if app != APPLICATION_ID {
        return Err(Error::Format("not a VELFORT vault"));
    }
    let (vh, _) = read_header(&mem)?;
    if vh.vault_id != hdr.source_vault_id {
        return Err(Error::Format("vault_id mismatch"));
    }
    // The inner vault must unlock with the same Master Password (proves the snapshot is usable).
    let _ = unlock(&mem, password, allow_test_params)?;
    Ok(body)
}

/// Restores ONLY into a new file. Refuses an existing target and refuses target == source.
pub fn restore_to_new(
    backup: &Path,
    password: &str,
    target: &Path,
    allow_test_params: bool,
    max_snapshot_bytes: u64,
) -> Result<(), Error> {
    if same_existing_file(backup, target) {
        return Err(Error::TargetIsSource);
    }
    if target.exists() {
        return Err(Error::TargetExists);
    }
    let image = verify_backup(backup, password, allow_test_params, max_snapshot_bytes)?;
    write_new_file_no_replace(target, &image)
}
