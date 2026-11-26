//! Minimal SQLite vault for the spike: header (wrapped DEK) + items(summary, payload).
//! Schema subset of docs/DATA_MODEL.md §3. journal_mode=DELETE, synchronous=FULL, secure_delete=ON.

use crate::aad::{Aad, Purpose};
use crate::keys::{Dek, KdfParams, Kek, derive_vault_kek};
use crate::seal::{open, pad, seal, unpad};
use crate::{Error, random};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

pub const APPLICATION_ID: i32 = 0x5645_4C46; // 'VELF'
const MAGIC: &[u8; 8] = b"VELFORT\0";

pub struct Header {
    pub vault_id: [u8; 16],
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub wrap_nonce_envelope: Vec<u8>, // envelope (contains its own nonce)
}

/// Canonical header bytes = AAD `extra` for HEADER_WRAP (binds KDF params, ids, versions).
pub fn canonical_header(vault_id: &[u8; 16], kdf: KdfParams, salt: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&crate::aad::FORMAT_VERSION.to_le_bytes());
    v.extend_from_slice(vault_id);
    v.push(1); // kdf_alg = Argon2id v0x13
    v.extend_from_slice(&kdf.m_kib.to_le_bytes());
    v.extend_from_slice(&kdf.t.to_le_bytes());
    v.extend_from_slice(&kdf.p.to_le_bytes());
    v.extend_from_slice(salt);
    v.push(1); // aead_alg = XChaCha20-Poly1305
    v
}

fn header_aad(vault_id: &[u8; 16], kdf: KdfParams, salt: &[u8; 16]) -> Vec<u8> {
    let extra = canonical_header(vault_id, kdf, salt);
    Aad { vault_id: *vault_id, purpose: Purpose::HeaderWrap, record_id: [0; 16], revision: 0, extra: &extra }.encode()
}

pub fn apply_pragmas(c: &Connection) -> Result<(), Error> {
    c.execute_batch(
        "PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA secure_delete = ON; PRAGMA foreign_keys = ON;",
    )?;
    Ok(())
}

pub fn create_vault(path: &Path, password: &[u8], kdf: KdfParams, allow_test_params: bool) -> Result<(Connection, Dek, [u8; 16]), Error> {
    kdf.validate(allow_test_params)?;
    if path.exists() {
        return Err(Error::TargetExists);
    }
    let c = Connection::open(path)?;
    apply_pragmas(&c)?;
    c.execute_batch(&format!(
        "PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = 1;
         CREATE TABLE vault_header (id INTEGER PRIMARY KEY CHECK (id = 1), vault_id BLOB NOT NULL,
            kdf_m INTEGER NOT NULL, kdf_t INTEGER NOT NULL, kdf_p INTEGER NOT NULL, salt BLOB NOT NULL,
            wrapped_dek BLOB NOT NULL);
         CREATE TABLE items (id BLOB PRIMARY KEY, revision INTEGER NOT NULL, summary BLOB NOT NULL, payload BLOB NOT NULL);"
    ))?;
    let vault_id: [u8; 16] = random()?;
    let salt: [u8; 16] = random()?;
    let dek = Dek::generate()?;
    let kek = derive_vault_kek(password, &salt, &vault_id, kdf)?;
    let wrapped = seal(kek.bytes(), dek_bytes(&dek), &header_aad(&vault_id, kdf, &salt))?;
    c.execute(
        "INSERT INTO vault_header VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![&vault_id[..], kdf.m_kib, kdf.t, kdf.p, &salt[..], wrapped],
    )?;
    Ok((c, dek, vault_id))
}

fn dek_bytes(d: &Dek) -> &[u8; 32] {
    d.raw()
}

pub fn read_header(c: &Connection) -> Result<(Header, Vec<u8>), Error> {
    let row = c
        .query_row("SELECT vault_id, kdf_m, kdf_t, kdf_p, salt, wrapped_dek FROM vault_header WHERE id = 1", [], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u32>(1)?, r.get::<_, u32>(2)?, r.get::<_, u32>(3)?, r.get::<_, Vec<u8>>(4)?, r.get::<_, Vec<u8>>(5)?))
        })
        .optional()?
        .ok_or(Error::Format("no header"))?;
    let vault_id: [u8; 16] = row.0.try_into().map_err(|_| Error::Format("vault_id"))?;
    let salt: [u8; 16] = row.4.try_into().map_err(|_| Error::Format("salt"))?;
    let kdf = KdfParams { m_kib: row.1, t: row.2, p: row.3 };
    let canon = canonical_header(&vault_id, kdf, &salt);
    Ok((Header { vault_id, kdf, salt, wrap_nonce_envelope: row.5 }, canon))
}

pub fn unlock(c: &Connection, password: &[u8], allow_test_params: bool) -> Result<(Dek, [u8; 16]), Error> {
    let (h, _) = read_header(c)?;
    h.kdf.validate(allow_test_params)?;
    let kek: Kek = derive_vault_kek(password, &h.salt, &h.vault_id, h.kdf)?;
    let pt = open(kek.bytes(), &h.wrap_nonce_envelope, &header_aad(&h.vault_id, h.kdf, &h.salt))?;
    let b: [u8; 32] = pt[..].try_into().map_err(|_| Error::Format("dek len"))?;
    Ok((Dek::from_bytes(b), h.vault_id))
}

/// Change Master Password: new salt, new KEK, re-wrap the SAME DEK, in one transaction.
pub fn change_password(c: &mut Connection, old: &[u8], new: &[u8], new_kdf: KdfParams, allow_test_params: bool) -> Result<(), Error> {
    new_kdf.validate(allow_test_params)?;
    let (dek, vault_id) = unlock(c, old, allow_test_params)?; // full re-authentication
    let salt: [u8; 16] = random()?;
    let kek = derive_vault_kek(new, &salt, &vault_id, new_kdf)?;
    let wrapped = seal(kek.bytes(), dek.raw(), &header_aad(&vault_id, new_kdf, &salt))?;
    let tx = c.transaction()?;
    tx.execute(
        "UPDATE vault_header SET kdf_m = ?1, kdf_t = ?2, kdf_p = ?3, salt = ?4, wrapped_dek = ?5 WHERE id = 1",
        params![new_kdf.m_kib, new_kdf.t, new_kdf.p, &salt[..], wrapped],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn item_aad(vault_id: &[u8; 16], purpose: Purpose, id: &[u8; 16], revision: u64) -> Vec<u8> {
    Aad { vault_id: *vault_id, purpose, record_id: *id, revision, extra: &[] }.encode()
}

#[allow(clippy::too_many_arguments)]
/// Both blobs carry the item kind inside the authenticated plaintext (first byte here).
pub fn put_item(c: &Connection, dek: &Dek, vault_id: &[u8; 16], id: &[u8; 16], revision: u64, kind: u8, summary: &[u8], payload: &[u8]) -> Result<(), Error> {
    let k = dek.items_key();
    let mut s = vec![kind];
    s.extend_from_slice(summary);
    let mut p = vec![kind];
    p.extend_from_slice(payload);
    let s_env = seal(k.bytes(), &pad(&s), &item_aad(vault_id, Purpose::ItemSummary, id, revision))?;
    let p_env = seal(k.bytes(), &pad(&p), &item_aad(vault_id, Purpose::ItemPayload, id, revision))?;
    c.execute(
        "INSERT INTO items (id, revision, summary, payload) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET revision = excluded.revision, summary = excluded.summary, payload = excluded.payload",
        params![&id[..], revision as i64, s_env, p_env],
    )?;
    Ok(())
}

/// Returns (kind, summary, payload). Fails on any AEAD error or kind mismatch.
pub fn get_item(c: &Connection, dek: &Dek, vault_id: &[u8; 16], id: &[u8; 16]) -> Result<(u8, Vec<u8>, Vec<u8>), Error> {
    let (rev, s_env, p_env): (i64, Vec<u8>, Vec<u8>) =
        c.query_row("SELECT revision, summary, payload FROM items WHERE id = ?1", params![&id[..]], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    let k = dek.items_key();
    let s = open(k.bytes(), &s_env, &item_aad(vault_id, Purpose::ItemSummary, id, rev as u64))?;
    let p = open(k.bytes(), &p_env, &item_aad(vault_id, Purpose::ItemPayload, id, rev as u64))?;
    let (s, p) = (unpad(&s)?, unpad(&p)?);
    if s.is_empty() || p.is_empty() || s[0] != p[0] {
        return Err(Error::Format("summary/payload kind mismatch"));
    }
    Ok((s[0], s[1..].to_vec(), p[1..].to_vec()))
}
