//! Phase 0.6 group A — Master Password Unicode NFC normalization (F-2).
//! Test KDF params are tiny (`allow_test_params = true`) to keep the suite fast.

use rusqlite::Connection;
use std::path::Path;
use vault_crypto_proto::Error;
use vault_crypto_proto::backup::{create_backup, restore_to_new, verify_backup};
use vault_crypto_proto::keys::{KdfParams, MAX_PASSWORD_BYTES, PW_TRANSFORM_NFC_UTF8, normalize_password};
use vault_crypto_proto::store::{change_password, create_vault, unlock};

const T: KdfParams = KdfParams { m_kib: 1024, t: 1, p: 1 };
const BIG: u64 = 1 << 30;

fn nfc(s: &str) -> Vec<u8> {
    normalize_password(s, PW_TRANSFORM_NFC_UTF8).unwrap().as_bytes().to_vec()
}

fn vault_with(dir: &Path, pw: &str) -> Connection {
    create_vault(&dir.join("v.velfort"), pw, T, true).unwrap().0
}

// --- pure normalization --------------------------------------------------------------------

#[test]
fn ascii_is_unchanged() {
    let s = "Correct-Horse_Battery 123!~";
    assert_eq!(nfc(s), s.as_bytes());
}

#[test]
fn cyrillic_short_i_nfd_equals_nfc() {
    let nfc_form = "\u{0439}од"; // й (precomposed) + од
    let nfd_form = "\u{0438}\u{0306}од"; // и + combining breve + од
    assert_ne!(nfc_form.as_bytes(), nfd_form.as_bytes(), "inputs differ as bytes");
    assert_eq!(nfc(nfd_form), nfc(nfc_form));
    assert_eq!(nfc(nfc_form), "йод".as_bytes()); // d0 b9 ...
    assert_eq!(&nfc(nfd_form)[..2], &[0xd0, 0xb9]);
}

#[test]
fn latin_combining_marks_and_canonical_ordering() {
    assert_eq!(nfc("e\u{0301}"), nfc("\u{00e9}"));
    // Canonical reordering: dot below (ccc 220) and circumflex (ccc 230) in either order.
    assert_eq!(nfc("a\u{0323}\u{0302}"), nfc("a\u{0302}\u{0323}"));
    assert_eq!(nfc("a\u{0323}\u{0302}"), nfc("\u{1ead}")); // ậ
}

#[test]
fn supplementary_plane_characters_survive() {
    let s = "🔐\u{1D518}\u{20000}"; // emoji, MATHEMATICAL FRAKTUR CAPITAL U, CJK Ext. B
    assert_eq!(nfc(s), s.as_bytes(), "NFC leaves these unchanged");
}

#[test]
fn nfkc_distinctions_are_preserved() {
    // NFKC would map these together; NFC must not (UAX #15: KC/KD "may remove distinctions").
    assert_ne!(nfc("\u{FB01}"), nfc("fi")); // ﬁ ligature
    assert_ne!(nfc("\u{1D518}"), nfc("U"));
    assert_ne!(nfc("\u{2460}"), nfc("1")); // ①
    assert_ne!(nfc("\u{00BD}"), nfc("1\u{2044}2")); // ½
}

#[test]
fn normalization_is_idempotent() {
    for s in ["й", "\u{0438}\u{0306}", "a\u{0302}\u{0323}", "\u{0958}", "🔐", "Ω\u{2126}", ""] {
        let once = nfc(s);
        let twice = nfc(std::str::from_utf8(&once).unwrap());
        assert_eq!(once, twice, "{s:?}");
    }
}

#[test]
fn singleton_and_composition_exclusion() {
    // U+2126 OHM SIGN is a singleton decomposition -> U+03A9 in NFC.
    assert_eq!(nfc("\u{2126}"), "\u{03A9}".as_bytes());
    // U+0958 DEVANAGARI QA is a composition exclusion: NFC keeps it decomposed (3 -> 6 bytes).
    assert_eq!(nfc("\u{0958}"), "\u{0915}\u{093C}".as_bytes());
}

#[test]
fn empty_string_normalizes_but_cannot_be_a_master_password() {
    assert_eq!(nfc(""), b"");
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(create_vault(&dir.path().join("v.velfort"), "", T, true).err(), Some(Error::Format("empty master password")));
}

#[test]
fn unknown_transform_and_oversized_input_are_rejected() {
    assert_eq!(normalize_password("x", 0).err(), Some(Error::Format("unknown password transform")));
    assert_eq!(normalize_password("x", 2).err(), Some(Error::Format("unknown password transform")));
    let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
    assert_eq!(normalize_password(&long, PW_TRANSFORM_NFC_UTF8).err(), Some(Error::Format("password too long")));
    assert!(normalize_password(&"a".repeat(MAX_PASSWORD_BYTES), PW_TRANSFORM_NFC_UTF8).is_ok());
}

#[test]
fn worst_case_expansion_does_not_reallocate() {
    // Many composition-excluded characters (3 bytes -> 6 bytes each) at the length limit.
    let s: String = std::iter::repeat_n('\u{0958}', MAX_PASSWORD_BYTES / 3).collect();
    let out = normalize_password(&s, PW_TRANSFORM_NFC_UTF8).unwrap();
    assert_eq!(out.len(), (MAX_PASSWORD_BYTES / 3) * 6);
}

// --- protocol-level: create / unlock / change / backup ---------------------------------------

#[test]
fn vault_created_with_nfc_unlocks_with_nfd_and_vice_versa() {
    let d = tempfile::tempdir().unwrap();
    let c = vault_with(d.path(), "пароль-\u{0439}-é");
    assert!(unlock(&c, "пароль-\u{0438}\u{0306}-e\u{0301}", true).is_ok());
    let d2 = tempfile::tempdir().unwrap();
    let c2 = vault_with(d2.path(), "пароль-\u{0438}\u{0306}-e\u{0301}");
    assert!(unlock(&c2, "пароль-\u{0439}-é", true).is_ok());
}

#[test]
fn compatibility_lookalikes_do_not_unlock() {
    let d = tempfile::tempdir().unwrap();
    let c = vault_with(d.path(), "\u{FB01}le");
    assert_eq!(unlock(&c, "file", true).err(), Some(Error::Auth));
}

#[test]
fn change_password_uses_the_same_normalization() {
    let d = tempfile::tempdir().unwrap();
    let mut c = vault_with(d.path(), "старый");
    change_password(&mut c, "старый", "нов\u{0438}\u{0306}", T, true).unwrap();
    assert!(unlock(&c, "нов\u{0439}", true).is_ok());
    assert_eq!(change_password(&mut c, "нов\u{0439}", "", T, true).err(), Some(Error::Format("empty master password")));
}

#[test]
fn backup_and_restore_use_the_same_normalization() {
    let d = tempfile::tempdir().unwrap();
    let mut c = vault_with(d.path(), "ключ-\u{0439}");
    let b = d.path().join("v.velfort-backup");
    create_backup(&mut c, "ключ-\u{0438}\u{0306}", T, true, BIG, &b).unwrap(); // NFD at backup time
    assert!(verify_backup(&b, "ключ-\u{0439}", true, BIG).is_ok()); // NFC at verify time
    let target = d.path().join("restored.velfort");
    restore_to_new(&b, "ключ-\u{0438}\u{0306}", &target, true, BIG).unwrap();
    let r = Connection::open(&target).unwrap();
    assert!(unlock(&r, "ключ-\u{0439}", true).is_ok());
}

#[test]
fn tampered_pw_transform_in_vault_header_is_rejected() {
    for v in [0i64, 2, 255] {
        let d = tempfile::tempdir().unwrap();
        let c = vault_with(d.path(), "pw");
        c.execute("UPDATE vault_header SET pw_transform = ?1", [v]).unwrap();
        assert_eq!(unlock(&c, "pw", true).err(), Some(Error::Format("unknown password transform")), "{v}");
    }
}

#[test]
fn tampered_pw_transform_in_backup_header_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let mut c = vault_with(d.path(), "pw");
    let b = d.path().join("v.velfort-backup");
    create_backup(&mut c, "pw", T, true, BIG, &b).unwrap();
    let mut raw = std::fs::read(&b).unwrap();
    assert_eq!(raw[21 + 76], PW_TRANSFORM_NFC_UTF8, "format 2 layout: pw_transform at offset 97");
    raw[21 + 76] = 0;
    std::fs::write(&b, &raw).unwrap();
    assert!(verify_backup(&b, "pw", true, BIG).is_err());
}
