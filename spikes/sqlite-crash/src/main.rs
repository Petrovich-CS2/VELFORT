//! VELFORT Phase 0.5 / W8 + W12 — SQLite rollback-journal (journal_mode=DELETE) behaviour under crashes.
//! Spike only. Plaintext canaries are used on purpose to make SQLite's page copies observable;
//! in VELFORT every record is AEAD-encrypted before it reaches SQLite.
//!
//! Usage: sqlite-crash run <work-dir> [full-fs-dir]
//! Prints one line per check: `CHECK <name>: PASS|FAIL|INFO <detail>`.

use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};
use std::process::Command;

const CANARY_OLD: &str = "VELFORT-CANARY-OLD-VALUE-4b1d";
const CANARY_NEW: &str = "VELFORT-CANARY-NEW-VALUE-8e2a";
const CANARY_DEL: &str = "VELFORT-CANARY-DELETED-ROW-c0de";
const CANARY_HDR: &str = "VELFORT-CANARY-HEADER-ORIGINAL-77aa";

fn open(p: &Path, secure_delete: bool) -> Connection {
    let c = Connection::open(p).unwrap();
    c.execute_batch(&format!(
        "PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA secure_delete = {}; PRAGMA cache_size = 4;",
        if secure_delete { "ON" } else { "OFF" }
    ))
    .unwrap();
    c
}

fn init(p: &Path, secure_delete: bool) {
    let c = open(p, secure_delete);
    c.execute_batch("CREATE TABLE header(id INTEGER PRIMARY KEY, wrapped BLOB); CREATE TABLE items(id INTEGER PRIMARY KEY, v TEXT, pad BLOB);").unwrap();
    c.execute("INSERT INTO header VALUES (1, ?1)", params![CANARY_HDR]).unwrap();
    c.execute_batch("BEGIN").unwrap();
    for i in 0..200 {
        c.execute("INSERT INTO items VALUES (?1, ?2, zeroblob(2000))", params![i, format!("{CANARY_OLD}-{i}")]).unwrap();
    }
    c.execute_batch("COMMIT").unwrap();
}

fn contains(path: &Path, needle: &str) -> bool {
    std::fs::read(path).map(|d| d.windows(needle.len()).any(|w| w == needle.as_bytes())).unwrap_or(false)
}

fn journal(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}-journal", p.display()))
}

fn report(name: &str, ok: bool, detail: impl AsRef<str>) {
    println!("CHECK {name}: {} {}", if ok { "PASS" } else { "FAIL" }, detail.as_ref());
}
fn info(name: &str, detail: impl AsRef<str>) {
    println!("CHECK {name}: INFO {}", detail.as_ref());
}

/// Child: modify the critical header row and many items in ONE transaction, force pages to be
/// written to the db file (tiny cache => spill), then abort before COMMIT.
fn child_crash_mid_txn(p: &Path) {
    let c = open(p, true);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    c.execute("UPDATE header SET wrapped = ?1 WHERE id = 1", params![CANARY_NEW]).unwrap();
    for i in 0..200 {
        c.execute("UPDATE items SET v = ?1 WHERE id = ?2", params![format!("{CANARY_NEW}-{i}"), i]).unwrap();
    }
    let hot = journal(p).exists();
    eprintln!("child: journal exists before abort = {hot}");
    std::process::abort();
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.get(1).map(String::as_str) == Some("child-crash") {
        child_crash_mid_txn(Path::new(&a[2]));
        return;
    }
    let work = PathBuf::from(&a[2]);
    std::fs::create_dir_all(&work).unwrap();
    println!("sqlite version: {}", rusqlite::version());

    // 1. Journal lifecycle in DELETE mode.
    let p = work.join("lifecycle.db");
    init(&p, true);
    {
        let c = open(&p, true);
        let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
        let sync: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0)).unwrap();
        let sd: i64 = c.query_row("PRAGMA secure_delete", [], |r| r.get(0)).unwrap();
        report("pragmas", mode == "delete" && sync == 2 && sd == 1, format!("journal_mode={mode} synchronous={sync} (2=FULL) secure_delete={sd}"));
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        c.execute("UPDATE header SET wrapped = 'x' WHERE id = 1", []).unwrap();
        let during = journal(&p).exists();
        let during_has_old = contains(&journal(&p), CANARY_HDR);
        c.execute_batch("ROLLBACK").unwrap();
        report("journal_exists_during_write_txn", during, format!("exists={during}"));
        info("journal_contains_original_page_content", format!("old canary in journal during txn = {during_has_old} (rollback journal stores ORIGINAL pages)"));
    }
    report("no_journal_after_normal_close", !journal(&p).exists(), format!("exists={}", journal(&p).exists()));

    // 2. Crash in the middle of a transaction (process abort).
    let p = work.join("crash.db");
    init(&p, true);
    let st = Command::new(&a[0]).args(["child-crash", p.to_str().unwrap()]).status().unwrap();
    info("child_exit", format!("{st:?}"));
    let hot = journal(&p).exists();
    report("hot_journal_left_after_crash", hot, format!("exists={hot}, size={}", std::fs::metadata(journal(&p)).map(|m| m.len()).unwrap_or(0)));
    info("db_file_contains_uncommitted_new_value_before_recovery", format!("{}", contains(&p, CANARY_NEW)));
    {
        let c = open(&p, true);
        let ic: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
        let hdr: String = c.query_row("SELECT wrapped FROM header WHERE id = 1", [], |r| r.get(0)).unwrap();
        let n_new: i64 = c.query_row("SELECT count(*) FROM items WHERE v LIKE ?1", params![format!("{CANARY_NEW}%")], |r| r.get(0)).unwrap();
        report("recovery_integrity_check", ic == "ok", ic);
        report("recovery_header_is_old_value", hdr == CANARY_HDR, "critical row rolled back");
        report("recovery_no_partial_item_updates", n_new == 0, format!("rows with new value = {n_new}"));
    }
    report("journal_removed_after_recovery", !journal(&p).exists(), format!("exists={}", journal(&p).exists()));
    info("db_file_contains_new_value_after_recovery", format!("{} (rolled-back page images may persist in free space only if not overwritten)", contains(&p, CANARY_NEW)));

    // 3. secure_delete effect on deleted rows (ON vs OFF).
    for sd in [true, false] {
        let p = work.join(format!("sd-{sd}.db"));
        init(&p, sd);
        let c = open(&p, sd);
        c.execute("INSERT INTO items VALUES (9999, ?1, zeroblob(10))", params![CANARY_DEL]).unwrap();
        c.execute("DELETE FROM items WHERE id = 9999", []).unwrap();
        c.execute("UPDATE header SET wrapped = ?1 WHERE id = 1", params![CANARY_NEW]).unwrap();
        drop(c);
        let del = contains(&p, CANARY_DEL);
        let old = contains(&p, CANARY_HDR);
        if sd {
            report("secure_delete_on_deleted_row_not_in_file", !del, format!("deleted canary present={del}"));
            info("secure_delete_on_overwritten_header_old_value_in_file", format!("{old}"));
        } else {
            info("secure_delete_off_deleted_row_in_file", format!("deleted canary present={del}"));
            info("secure_delete_off_overwritten_header_old_value_in_file", format!("{old}"));
        }
    }

    // 4. Logical SQLITE_FULL via max_page_count (portable substitute for a full disk).
    let p = work.join("full.db");
    init(&p, true);
    {
        let c = open(&p, true);
        let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        c.execute_batch(&format!("PRAGMA max_page_count = {}", pages + 2)).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        c.execute("UPDATE header SET wrapped = ?1 WHERE id = 1", params![CANARY_NEW]).unwrap();
        let mut err = None;
        for i in 0..1000 {
            if let Err(e) = c.execute("INSERT INTO items VALUES (?1, 'x', zeroblob(4000))", params![10_000 + i]) {
                err = Some(e.to_string());
                break;
            }
        }
        let in_txn = !c.is_autocommit();
        if in_txn {
            c.execute_batch("ROLLBACK").unwrap();
        }
        let hdr: String = c.query_row("SELECT wrapped FROM header WHERE id = 1", [], |r| r.get(0)).unwrap();
        let ic: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
        report("sqlite_full_error_returned", err.is_some(), err.unwrap_or_default());
        report("sqlite_full_rollback_keeps_old_header", hdr == CANARY_HDR && ic == "ok", format!("integrity={ic}"));
    }

    // 5. Real filesystem-full (optional, needs a small filesystem dir, e.g. tmpfs on Linux).
    if let Some(fs) = a.get(3) {
        let p = Path::new(fs).join("realfull.db");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(journal(&p));
        init(&p, true);
        let c = open(&p, true);
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        c.execute("UPDATE header SET wrapped = ?1 WHERE id = 1", params![CANARY_NEW]).unwrap();
        let mut err = None;
        for i in 0..100_000 {
            if let Err(e) = c.execute("INSERT INTO items VALUES (?1, 'x', zeroblob(8000))", params![10_000 + i]) {
                err = Some(e.to_string());
                break;
            }
        }
        let commit = if err.is_none() { c.execute_batch("COMMIT").err().map(|e| e.to_string()) } else { None };
        if !c.is_autocommit() {
            let _ = c.execute_batch("ROLLBACK");
        }
        drop(c);
        let c = open(&p, true);
        let hdr: String = c.query_row("SELECT wrapped FROM header WHERE id = 1", [], |r| r.get(0)).unwrap();
        let ic: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
        report("fs_full_error_returned", err.is_some() || commit.is_some(), format!("{err:?} {commit:?}"));
        report("fs_full_old_header_and_integrity", hdr == CANARY_HDR && ic == "ok", format!("integrity={ic}"));
    } else {
        info("fs_full", "skipped (no small filesystem dir given)");
    }
}
