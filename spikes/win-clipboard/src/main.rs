//! W3 — Windows clipboard behaviour for copied secrets (spike, Windows only).
//! Usage: win-clipboard run | win-clipboard child-write <text> | win-clipboard child-spam <n>
//! Prints `CHECK <name>: PASS|FAIL|INFO <detail>`.

#[cfg(not(windows))]
fn main() {
    println!("CHECK platform: INFO win-clipboard runs only on Windows");
}

#[cfg(windows)]
mod imp {
    use arboard::{Clipboard, SetExtWindows};
    use std::process::Command;
    use std::time::Duration;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, EnumClipboardFormats, GetClipboardFormatNameW, GetClipboardSequenceNumber, OpenClipboard,
    };

    pub const CANARY: &str = "VELFORT-CANARY-CLIPBOARD-SECRET-5e1f";
    pub const CANARY_PLAIN: &str = "VELFORT-CANARY-CLIPBOARD-PLAIN-9d0c";

    fn report(name: &str, ok: bool, d: impl AsRef<str>) {
        println!("CHECK {name}: {} {}", if ok { "PASS" } else { "FAIL" }, d.as_ref());
    }
    fn info(name: &str, d: impl AsRef<str>) {
        println!("CHECK {name}: INFO {}", d.as_ref());
    }

    fn open_retry() -> bool {
        for _ in 0..50 {
            // SAFETY: NULL owner is allowed for reading/emptying.
            if unsafe { OpenClipboard(core::ptr::null_mut()) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn registered_format_names() -> Vec<String> {
        let mut names = Vec::new();
        if !open_retry() {
            return names;
        }
        // SAFETY: clipboard is open; buffer sized.
        unsafe {
            let mut f = EnumClipboardFormats(0);
            while f != 0 {
                let mut buf = [0u16; 256];
                let n = GetClipboardFormatNameW(f, buf.as_mut_ptr(), 256);
                names.push(if n > 0 { String::from_utf16_lossy(&buf[..n as usize]) } else { format!("#{f}") });
                f = EnumClipboardFormats(f);
            }
            CloseClipboard();
        }
        names
    }

    fn seq() -> u32 {
        // SAFETY: no preconditions.
        unsafe { GetClipboardSequenceNumber() }
    }

    fn copy_secret(cb: &mut Clipboard, text: &str) -> u32 {
        cb.set().exclude_from_monitoring().text(text.to_owned()).expect("set");
        seq()
    }

    /// Reads CF_UNICODETEXT while the clipboard is already open.
    unsafe fn text_under_lock() -> Option<String> {
        use windows_sys::Win32::System::DataExchange::GetClipboardData;
        use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
        const CF_UNICODETEXT: u32 = 13;
        // SAFETY: caller holds the clipboard open; handle is locked/unlocked in pairs.
        unsafe {
            let h = GetClipboardData(CF_UNICODETEXT);
            if h.is_null() {
                return None;
            }
            let p = GlobalLock(h as _) as *const u16;
            if p.is_null() {
                return None;
            }
            let mut n = 0usize;
            while *p.add(n) != 0 {
                n += 1;
            }
            let t = String::from_utf16_lossy(core::slice::from_raw_parts(p, n));
            GlobalUnlock(h as _);
            Some(t)
        }
    }

    /// Result of one clear attempt.
    /// v1 = "clear if sequence number unchanged since our copy" (racy, see W3 report);
    /// v2 = "clear only if the CURRENT content (read while the clipboard is open) is our secret".
    /// Only v2 is applied. OpenClipboard "prevents other applications from modifying the clipboard
    /// content" until CloseClipboard, so the v2 check and EmptyClipboard are not interleaved.
    pub struct ClearOutcome {
        pub applied: &'static str,
        pub v1_would_erase_foreign: bool,
    }

    pub fn safe_clear(our_seq: u32, secret: &str) -> ClearOutcome {
        if !open_retry() {
            return ClearOutcome { applied: "busy", v1_would_erase_foreign: false };
        }
        // SAFETY: clipboard is open for the duration.
        unsafe {
            let seq_same = GetClipboardSequenceNumber() == our_seq;
            let current = text_under_lock();
            let ours = current.as_deref() == Some(secret);
            let applied = if !ours {
                "changed-by-other"
            } else if EmptyClipboard() != 0 {
                "cleared"
            } else {
                "empty-failed"
            };
            CloseClipboard();
            ClearOutcome { applied, v1_would_erase_foreign: seq_same && !ours }
        }
    }

    fn history_probe(label: &str) {
        use windows::ApplicationModel::DataTransfer::Clipboard as WinRtClipboard;
        match WinRtClipboard::IsHistoryEnabled() {
            Ok(enabled) => info(&format!("{label}_history_enabled"), format!("{enabled}")),
            Err(e) => info(&format!("{label}_history_enabled"), format!("error {e}")),
        }
        match WinRtClipboard::IsRoamingEnabled() {
            Ok(r) => info(&format!("{label}_roaming_enabled"), format!("{r}")),
            Err(e) => info(&format!("{label}_roaming_enabled"), format!("error {e}")),
        }
        let res = WinRtClipboard::GetHistoryItemsAsync().and_then(|op| op.join());
        match res {
            Ok(r) => {
                let status = r.Status().map(|s| s.0).unwrap_or(-1);
                let mut texts = Vec::new();
                if let Ok(items) = r.Items() {
                    let n = items.Size().unwrap_or(0);
                    for i in 0..n {
                        if let Ok(it) = items.GetAt(i)
                            && let Ok(t) = it.Content().and_then(|c| c.GetTextAsync()).and_then(|op| op.join())
                        {
                            texts.push(t.to_string());
                        }
                    }
                }
                let has_secret = texts.iter().any(|t| t.contains(CANARY));
                let has_plain = texts.iter().any(|t| t.contains(CANARY_PLAIN));
                info(
                    &format!("{label}_history_items"),
                    format!("status={status} (0=Success,1=AccessDenied,2=ClipboardHistoryDisabled) items={} contains_excluded_secret={has_secret} contains_plain_control={has_plain}", texts.len()),
                );
                if has_plain {
                    report(&format!("{label}_excluded_secret_absent_from_history"), !has_secret, "control item present, so history works");
                }
            }
            Err(e) => info(&format!("{label}_history_items"), format!("error {e}")),
        }
    }

    pub fn run(exe: &str) {
        let mut cb = match Clipboard::new() {
            Ok(c) => c,
            Err(e) => {
                info("clipboard_open", format!("FAILED to open clipboard: {e}"));
                return;
            }
        };

        // 1. Exclusion formats present after arboard set().exclude_from_monitoring().
        let s = copy_secret(&mut cb, CANARY);
        let names = registered_format_names();
        report("exclusion_format_present", names.iter().any(|n| n == "ExcludeClipboardContentFromMonitorProcessing"), format!("formats={names:?}"));
        report("secret_readable_by_other_code_while_present", cb.get_text().map(|t| t == CANARY).unwrap_or(false), "any process of the user can read it while it is on the clipboard (expected)");

        // 2. Normal timed clear.
        std::thread::sleep(Duration::from_millis(500));
        let r = safe_clear(s, CANARY).applied;
        let after = cb.get_text().unwrap_or_default();
        report("timed_clear_removes_our_value", r == "cleared" && after != CANARY, format!("result={r} after_len={}", after.len()));

        // 3. Another process overwrote the clipboard -> we must NOT clear the user's content.
        let s = copy_secret(&mut cb, CANARY);
        let st = Command::new(exe).args(["child-write", "USER-COPIED-TEXT"]).status();
        info("child_write_status", format!("{st:?}"));
        let r = safe_clear(s, CANARY).applied;
        let after = cb.get_text().unwrap_or_default();
        report("no_clear_after_foreign_change", r == "changed-by-other" && after == "USER-COPIED-TEXT", format!("result={r} clipboard={after}"));

        // 4. Race: a child spams the clipboard while we copy+clear repeatedly.
        let mut child = Command::new(exe).args(["child-spam", "300"]).spawn().expect("spawn");
        let (mut cleared, mut skipped, mut busy, mut v1_bad) = (0, 0, 0, 0);
        for _ in 0..300 {
            let s = copy_secret(&mut cb, CANARY);
            let o = safe_clear(s, CANARY);
            if o.v1_would_erase_foreign {
                v1_bad += 1;
            }
            match o.applied {
                "cleared" => cleared += 1,
                "changed-by-other" => skipped += 1,
                _ => busy += 1,
            }
        }
        let _ = child.wait();
        info("race_counts", format!("v2: cleared={cleared} skipped_foreign={skipped} busy={busy}"));
        info("race_v1_sequence_rule_would_have_erased_foreign_content", format!("{v1_bad} times out of 300"));

        // 5. Clipboard history: control (plain) item vs excluded secret.
        cb.set().text(CANARY_PLAIN.to_owned()).expect("plain");
        std::thread::sleep(Duration::from_millis(1500));
        let _s = copy_secret(&mut cb, CANARY);
        std::thread::sleep(Duration::from_millis(1500));
        history_probe("history");
        let _ = safe_clear(seq(), CANARY);
    }

    pub fn child_write(text: &str) {
        let mut cb = Clipboard::new().expect("child clipboard");
        cb.set_text(text.to_owned()).expect("child set");
    }

    pub fn child_spam(n: usize) {
        let mut cb = Clipboard::new().expect("child clipboard");
        for i in 0..n {
            let _ = cb.set_text(format!("FOREIGN-{i}"));
            std::thread::sleep(Duration::from_millis(3));
        }
    }
}

#[cfg(windows)]
fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("child-write") => imp::child_write(&a[2]),
        Some("child-spam") => imp::child_spam(a[2].parse().unwrap()),
        _ => imp::run(&a[0]),
    }
}
