//! Reproducible evidence for docs/CRYPTOGRAPHY.md (D1, AAD, header binding, password change, backup).
//! Test KDF params are deliberately tiny (`allow_test_params = true`) to keep tests fast;
//! `production_params_enforced` proves the production path rejects them.

use rusqlite::{Connection, params};
use std::collections::HashSet;
use std::path::Path;
use vault_crypto_proto::backup::{create_backup, restore_to_new, verify_backup};
use vault_crypto_proto::fsutil::{PARTIAL_MARKER, cleanup_partials};
use vault_crypto_proto::keys::{Dek, KdfParams};
use vault_crypto_proto::store::{change_password, create_vault, get_item, put_item, unlock};
use vault_crypto_proto::{Error, seal};

const T: KdfParams = KdfParams { m_kib: 1024, t: 1, p: 1 };
const PW: &str = "correct horse battery staple";
const CANARY_S: &[u8] = b"VELFORT-CANARY-SUMMARY-7f3a";
const CANARY_P: &[u8] = b"VELFORT-CANARY-PASSWORD-91c2";
const BIG: u64 = 1 << 30;

fn vault(dir: &Path) -> (Connection, Dek, [u8; 16]) {
    create_vault(&dir.join("v.velfort"), PW, T, true).unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn utf16le(s: &[u8]) -> Vec<u8> {
    s.iter().flat_map(|&b| [b, 0]).collect()
}

#[test]
fn production_params_enforced() {
    assert_eq!(T.validate(false), Err(Error::KdfParamsOutOfRange));
    assert!(KdfParams::MIN.validate(false).is_ok());
    let too_big = KdfParams { m_kib: 8 * 1024 * 1024, t: 3, p: 4 };
    assert_eq!(too_big.validate(true), Err(Error::KdfParamsOutOfRange));
}

#[test]
fn subkeys_are_distinct_and_deterministic() {
    let d = Dek::from_bytes([7u8; 32]);
    let ks = [
        *d.items_key().bytes(),
        *d.attach_key().bytes(),
        *d.manifest_key().bytes(),
        *d.settings_key().bytes(),
        *d.local_state_key().bytes(),
    ];
    let set: HashSet<[u8; 32]> = ks.iter().copied().collect();
    assert_eq!(set.len(), 5, "every purpose gets a different key");
    assert!(!ks.contains(&[7u8; 32]), "no subkey equals the DEK");
    assert_eq!(*Dek::from_bytes([7u8; 32]).items_key().bytes(), ks[0]);
    assert_ne!(*Dek::from_bytes([8u8; 32]).items_key().bytes(), ks[0]);
}

#[test]
fn debug_output_redacts_keys() {
    let d = Dek::from_bytes([0xAB; 32]);
    let s = format!("{:?} {:?}", d, d.items_key());
    assert!(s.contains("REDACTED") && !s.contains("171") && !s.to_lowercase().contains("ab, ab"));
}

#[test]
fn roundtrip_and_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let (c, dek, vid) = vault(dir.path());
    put_item(&c, &dek, &vid, &[1; 16], 1, 3, b"title", b"secret").unwrap();
    let (k, s, p) = get_item(&c, &dek, &vid, &[1; 16]).unwrap();
    assert_eq!((k, &s[..], &p[..]), (3, &b"title"[..], &b"secret"[..]));
    assert_eq!(unlock(&c, "wrong", true).err(), Some(Error::Auth));
    assert!(unlock(&c, PW, true).is_ok());
}

/// D1: summary and payload of the SAME row are bound to different purposes.
#[test]
fn d1_swapping_summary_and_payload_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (c, dek, vid) = vault(dir.path());
    put_item(&c, &dek, &vid, &[1; 16], 1, 3, b"same-length", b"same-length").unwrap();
    c.execute("UPDATE items SET summary = payload, payload = summary", []).unwrap();
    assert_eq!(get_item(&c, &dek, &vid, &[1; 16]).err(), Some(Error::Auth));
}

#[test]
fn swapping_blobs_between_rows_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (c, dek, vid) = vault(dir.path());
    put_item(&c, &dek, &vid, &[1; 16], 1, 3, b"a", b"A").unwrap();
    put_item(&c, &dek, &vid, &[2; 16], 1, 3, b"b", b"B").unwrap();
    let p2: Vec<u8> = c.query_row("SELECT payload FROM items WHERE id = ?1", params![&[2u8; 16][..]], |r| r.get(0)).unwrap();
    c.execute("UPDATE items SET payload = ?1 WHERE id = ?2", params![p2, &[1u8; 16][..]]).unwrap();
    assert_eq!(get_item(&c, &dek, &vid, &[1; 16]).err(), Some(Error::Auth));
}

#[test]
fn moving_ciphertext_between_vaults_is_detected() {
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let (c1, k1, v1) = vault(d1.path());
    let (c2, k2, v2) = vault(d2.path());
    put_item(&c1, &k1, &v1, &[1; 16], 1, 3, b"a", b"A").unwrap();
    put_item(&c2, &k2, &v2, &[1; 16], 1, 3, b"b", b"B").unwrap();
    let (s, p): (Vec<u8>, Vec<u8>) = c1.query_row("SELECT summary, payload FROM items", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    c2.execute("UPDATE items SET summary = ?1, payload = ?2", params![s, p]).unwrap();
    assert_eq!(get_item(&c2, &k2, &v2, &[1; 16]).err(), Some(Error::Auth));
}

/// Changing only the plaintext revision column breaks AAD; restoring an OLD consistent
/// (revision, summary, payload) triple is NOT detected by AEAD -> the manifest is required.
#[test]
fn per_row_rollback_needs_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let (c, dek, vid) = vault(dir.path());
    put_item(&c, &dek, &vid, &[1; 16], 1, 3, b"t", b"old-secret").unwrap();
    let old: (i64, Vec<u8>, Vec<u8>) = c.query_row("SELECT revision, summary, payload FROM items", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    put_item(&c, &dek, &vid, &[1; 16], 2, 3, b"t", b"new-secret").unwrap();
    c.execute("UPDATE items SET revision = 1", []).unwrap();
    assert_eq!(get_item(&c, &dek, &vid, &[1; 16]).err(), Some(Error::Auth), "revision column alone");
    c.execute("UPDATE items SET revision = ?1, summary = ?2, payload = ?3", params![old.0, old.1, old.2]).unwrap();
    let (_, _, p) = get_item(&c, &dek, &vid, &[1; 16]).unwrap();
    assert_eq!(p, b"old-secret", "consistent old triple decrypts: AEAD alone cannot detect rollback");
}

#[test]
fn kind_mismatch_between_summary_and_payload_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (c, dek, vid) = vault(dir.path());
    // Same id+revision but different kinds can only be produced by a key holder (bug or forgery);
    // emulate by writing two rows and splicing the summary of a kind-4 item from revision-equal data.
    put_item(&c, &dek, &vid, &[1; 16], 1, 3, b"t", b"p").unwrap();
    let p1: Vec<u8> = c.query_row("SELECT payload FROM items", [], |r| r.get(0)).unwrap();
    put_item(&c, &dek, &vid, &[1; 16], 1, 4, b"t", b"p").unwrap();
    c.execute("UPDATE items SET payload = ?1", params![p1]).unwrap();
    assert_eq!(get_item(&c, &dek, &vid, &[1; 16]).err(), Some(Error::Format("summary/payload kind mismatch")));
}

#[test]
fn header_fields_are_bound_to_wrapped_dek() {
    for stmt in [
        "UPDATE vault_header SET kdf_t = kdf_t + 1",
        "UPDATE vault_header SET kdf_m = kdf_m * 2",
        "UPDATE vault_header SET kdf_p = 2",
        "UPDATE vault_header SET salt = zeroblob(16)",
        "UPDATE vault_header SET vault_id = zeroblob(16)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (c, _, _) = vault(dir.path());
        c.execute(stmt, []).unwrap();
        assert_eq!(unlock(&c, PW, true).err(), Some(Error::Auth), "{stmt}");
    }
    let dir = tempfile::tempdir().unwrap();
    let (c, _, _) = vault(dir.path());
    c.execute("UPDATE vault_header SET kdf_m = 999999999", []).unwrap();
    assert_eq!(unlock(&c, PW, true).err(), Some(Error::KdfParamsOutOfRange), "DoS bound checked before KDF");
}

#[test]
fn change_password_rewraps_without_reencrypting_items() {
    let dir = tempfile::tempdir().unwrap();
    let (mut c, dek, vid) = vault(dir.path());
    put_item(&c, &dek, &vid, &[1; 16], 1, 3, b"t", b"p").unwrap();
    let before: (Vec<u8>, Vec<u8>, Vec<u8>) = c.query_row("SELECT i.payload, h.salt, h.wrapped_dek FROM items i, vault_header h", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(change_password(&mut c, "bad", "new", T, true).err(), Some(Error::Auth));
    change_password(&mut c, PW, "new password", T, true).unwrap();
    let after: (Vec<u8>, Vec<u8>, Vec<u8>) = c.query_row("SELECT i.payload, h.salt, h.wrapped_dek FROM items i, vault_header h", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(before.0, after.0, "item ciphertext untouched");
    assert_ne!(before.1, after.1, "new salt");
    assert_ne!(before.2, after.2, "new wrap");
    assert_eq!(unlock(&c, PW, true).err(), Some(Error::Auth));
    let (d2, _) = unlock(&c, "new password", true).unwrap();
    assert_eq!(get_item(&c, &d2, &vid, &[1; 16]).unwrap().2, b"p");
}

#[test]
fn nonces_are_unique_over_100k_seals() {
    let mut set = HashSet::new();
    for _ in 0..100_000 {
        let e = seal::seal(&[1; 32], b"x", b"aad").unwrap();
        assert!(set.insert(e[2..26].to_vec()));
    }
}

#[test]
fn envelope_bitflips_are_detected() {
    let e = seal::seal(&[1; 32], b"secret", b"aad").unwrap();
    for i in 2..e.len() {
        for bit in 0..8 {
            let mut x = e.clone();
            x[i] ^= 1 << bit;
            assert_eq!(seal::open(&[1; 32], &x, b"aad").err(), Some(Error::Auth), "byte {i} bit {bit}");
        }
    }
    assert!(seal::open(&[1; 32], &e, b"aad!").is_err());
}

fn setup_backup(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let (mut c, dek, vid) = vault(dir);
    for i in 0..50u8 {
        put_item(&c, &dek, &vid, &[i; 16], 1, 3, CANARY_S, CANARY_P).unwrap();
    }
    let b = dir.join("v.velfort-backup");
    let r = create_backup(&mut c, PW, T, true, BIG, &b).unwrap();
    assert!(r.file_bytes > r.snapshot_bytes);
    (dir.join("v.velfort"), b)
}

#[test]
fn backup_roundtrip_restore_to_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let (src, b) = setup_backup(dir.path());
    let target = dir.path().join("restored.velfort");
    restore_to_new(&b, PW, &target, true, BIG).unwrap();
    let c = Connection::open(&target).unwrap();
    let (dek, vid) = unlock(&c, PW, true).unwrap();
    assert_eq!(get_item(&c, &dek, &vid, &[7; 16]).unwrap().2, CANARY_P);
    assert!(src.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().contains(PARTIAL_MARKER)).count(), 0);
}

#[test]
fn backup_uses_separate_salt_and_key_context() {
    let dir = tempfile::tempdir().unwrap();
    let (src, b) = setup_backup(dir.path());
    let raw = std::fs::read(&b).unwrap();
    let c = Connection::open(&src).unwrap();
    let vault_salt: Vec<u8> = c.query_row("SELECT salt FROM vault_header", [], |r| r.get(0)).unwrap();
    let backup_salt = &raw[21 + 52..21 + 68];
    assert_ne!(&vault_salt[..], backup_salt);
    // Two backups of the same vault use different salts and ids.
    let (mut c2, _, _) = (Connection::open(&src).unwrap(), (), ());
    let b2 = dir.path().join("second.velfort-backup");
    create_backup(&mut c2, PW, T, true, BIG, &b2).unwrap();
    let raw2 = std::fs::read(&b2).unwrap();
    assert_ne!(&raw[21..37], &raw2[21..37], "backup_id");
    assert_ne!(backup_salt, &raw2[21 + 52..21 + 68], "salt");
}

#[test]
fn backup_requires_current_master_password() {
    let dir = tempfile::tempdir().unwrap();
    let (mut c, _, _) = vault(dir.path());
    let r = create_backup(&mut c, "wrong", T, true, BIG, &dir.path().join("x.velfort-backup"));
    assert_eq!(r.err(), Some(Error::Auth));
    assert!(!dir.path().join("x.velfort-backup").exists());
}

#[test]
fn backup_wrong_password_and_tampering_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (_, b) = setup_backup(dir.path());
    assert_eq!(verify_backup(&b, "wrong", true, BIG).err(), Some(Error::Auth));
    let raw = std::fs::read(&b).unwrap();
    // Flip one bit in every region: magic, format, header (each field), wrapped key, nonce, ct, tag.
    // layout (format 2): prefix 21 | header 77 (pw_transform at 21+76) | wrapped 74 at 98 | payload env at 172
    let probes = [0usize, 15, 17, 21, 21 + 16, 21 + 24, 21 + 40, 21 + 52, 21 + 68, 21 + 76, 98, 98 + 30, 172 + 2, 172 + 26, raw.len() / 2, raw.len() - 1];
    for &i in &probes {
        let mut x = raw.clone();
        x[i] ^= 0x01;
        let p = dir.path().join(format!("t{i}.bin"));
        std::fs::write(&p, &x).unwrap();
        assert!(verify_backup(&p, PW, true, BIG).is_err(), "flip at {i} accepted");
    }
    let p = dir.path().join("trunc.bin");
    std::fs::write(&p, &raw[..raw.len() - 1]).unwrap();
    assert!(verify_backup(&p, PW, true, BIG).is_err(), "truncated");
    let mut x = raw.clone();
    x.push(0);
    std::fs::write(&p, &x).unwrap();
    assert!(verify_backup(&p, PW, true, BIG).is_err(), "extended");
    std::fs::write(&p, b"not a backup").unwrap();
    assert!(verify_backup(&p, PW, true, BIG).is_err(), "garbage");
}

#[test]
fn restore_refuses_existing_target_and_source() {
    let dir = tempfile::tempdir().unwrap();
    let (src, b) = setup_backup(dir.path());
    let before = std::fs::read(&src).unwrap();
    assert_eq!(restore_to_new(&b, PW, &src, true, BIG).err(), Some(Error::TargetExists));
    assert_eq!(restore_to_new(&b, PW, &b, true, BIG).err(), Some(Error::TargetIsSource));
    assert_eq!(std::fs::read(&src).unwrap(), before, "existing vault untouched");
}

#[test]
fn corrupted_backup_creates_no_target() {
    let dir = tempfile::tempdir().unwrap();
    let (_, b) = setup_backup(dir.path());
    let mut raw = std::fs::read(&b).unwrap();
    let n = raw.len();
    raw[n - 20] ^= 0xFF;
    std::fs::write(&b, &raw).unwrap();
    let target = dir.path().join("restored.velfort");
    assert!(restore_to_new(&b, PW, &target, true, BIG).is_err());
    assert!(!target.exists());
}

#[test]
fn size_limit_is_enforced_before_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let (src, b) = setup_backup(dir.path());
    let mut c = Connection::open(&src).unwrap();
    let out = dir.path().join("small.velfort-backup");
    assert_eq!(create_backup(&mut c, PW, T, true, 1024, &out).err(), Some(Error::TooLarge));
    assert!(!out.exists());
    assert_eq!(verify_backup(&b, PW, true, 1024).err(), Some(Error::TooLarge));
}

#[test]
fn orphan_partial_files_are_cleaned() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(format!("x.velfort{PARTIAL_MARKER}abcd")), b"half").unwrap();
    std::fs::write(dir.path().join("keep.velfort"), b"keep").unwrap();
    assert_eq!(cleanup_partials(dir.path()).unwrap(), 1);
    assert!(dir.path().join("keep.velfort").exists());
}

#[test]
fn no_plaintext_canaries_in_vault_backup_or_restored_files() {
    let dir = tempfile::tempdir().unwrap();
    let (src, b) = setup_backup(dir.path());
    let target = dir.path().join("restored.velfort");
    restore_to_new(&b, PW, &target, true, BIG).unwrap();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let p = entry.unwrap().path();
        let data = std::fs::read(&p).unwrap();
        for canary in [CANARY_S, CANARY_P, PW.as_bytes()] {
            assert!(!contains(&data, canary), "{} contains utf8 canary", p.display());
            assert!(!contains(&data, &utf16le(canary)), "{} contains utf16 canary", p.display());
        }
    }
    // journal_mode=DELETE: no journal file remains after normal close.
    assert!(!dir.path().join("v.velfort-journal").exists());
    assert!(src.exists());
}
