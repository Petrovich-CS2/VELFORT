//! win-clipboard spike binary.
//!   run              — Phase 0.6 secret writer checks on the real Windows clipboard
//!   legacy-arboard   — Phase 0.5 arboard research run (kept for comparison)
//!   child-write <t>  — another process writes text (via arboard, as an "other application")
//!   child-spam <n>   — another process writes n times quickly
//!   child-hold <ms>  — another process keeps the clipboard open for <ms>
//! Output: `CHECK <name>: PASS|FAIL|INFO <detail>`.

#[cfg(not(windows))]
fn main() {
    println!("CHECK platform: INFO win-clipboard Win32 checks run only on Windows; writer logic is tested by `cargo test` on any OS");
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod legacy;

#[cfg(windows)]
#[allow(unsafe_code)]
mod v2 {
    use std::process::Command;
    use std::time::Duration;
    use win_clipboard::win32::Win32Backend;
    use win_clipboard::writer::{ALL_FORMATS, Backend, ClearOutcome, CopyError, CopyOutcome, Policy, ProtectFormat, Writer};

    const CANARY: &str = "VELFORT-CANARY-CLIPBOARD-V2-7b3e";

    fn report(name: &str, ok: bool, d: impl AsRef<str>) {
        println!("CHECK {name}: {} {}", if ok { "PASS" } else { "FAIL" }, d.as_ref());
    }
    fn info(name: &str, d: impl AsRef<str>) {
        println!("CHECK {name}: INFO {}", d.as_ref());
    }
    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }
    fn writer() -> Writer<Win32Backend> {
        Writer::new(Win32Backend::new().expect("message-only window"))
    }

    /// Opens with our window and inspects: (our text present?, owner is us?, DWORD per format).
    fn inspect(wr: &mut Writer<Win32Backend>) -> Option<(bool, bool, Vec<Option<u32>>)> {
        for _ in 0..20 {
            if wr.backend.open().is_ok() {
                let text = wr.backend.read_text().ok().flatten().map(|t| t.as_slice() == w(CANARY).as_slice()).unwrap_or(false);
                let owner = wr.backend.is_owner();
                let f = ALL_FORMATS.iter().map(|f| wr.backend.read_format_dword(*f)).collect();
                wr.backend.close();
                return Some((text, owner, f));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    fn other_text() -> Option<String> {
        let mut cb = arboard::Clipboard::new().ok()?;
        cb.get_text().ok()
    }

    pub fn run(exe: &str) {
        // 1. Success: text + three protective formats, one session.
        let mut wr = writer();
        let (o, t) = wr.copy_secret(&w(CANARY), Policy::Strict);
        let st = wr.backend.stats;
        report("v2_copy_protected", o == CopyOutcome::Protected, format!("{o:?}"));
        match inspect(&mut wr) {
            Some((text, owner, f)) => {
                report("v2_text_present_and_owner", text && owner, format!("text={text} owner={owner}"));
                report("v2_formats_dword_zero", f.iter().all(|x| *x == Some(0)), format!("{:?} for {:?}", f, ALL_FORMATS));
            }
            None => info("v2_inspect", "clipboard unavailable"),
        }
        report("v2_global_memory_accounting", st.allocated == 4 && st.transferred_to_system == 4 && st.freed_after_failure == 0, format!("{st:?}"));

        // 2. Clear our own value.
        let c = wr.clear_if_ours(t.as_ref().unwrap());
        let after = inspect(&mut wr).map(|x| x.0);
        report("v2_clear_ours", c == ClearOutcome::Cleared && after == Some(false), format!("{c:?} text_after={after:?}"));

        // 3. Another application overwrote the clipboard: must NOT clear.
        let (_, t) = wr.copy_secret(&w(CANARY), Policy::Strict);
        let s = Command::new(exe).args(["child-write", "USER-COPIED-TEXT-V2"]).status();
        info("v2_child_write_status", format!("{s:?}"));
        let c = wr.clear_if_ours(t.as_ref().unwrap());
        let other = other_text();
        report("v2_no_clear_of_foreign_content", c == ClearOutcome::NotOurs && other.as_deref() == Some("USER-COPIED-TEXT-V2"), format!("{c:?} clipboard={other:?}"));

        // 4. Clipboard held open by another process: bounded attempts, failure, nothing placed.
        let mut child = Command::new(exe).args(["child-hold", "1500"]).spawn().expect("spawn");
        std::thread::sleep(Duration::from_millis(400));
        let mut wb = writer();
        wb.max_open_attempts = 5;
        let t0 = std::time::Instant::now();
        let (o, t) = wb.copy_secret(&w(CANARY), Policy::Strict);
        let ms = t0.elapsed().as_millis();
        let le = wb.backend.last_error();
        let _ = child.wait();
        report("v2_busy_bounded_failure", o == CopyOutcome::Failed(CopyError::Busy) && t.is_none(), format!("{o:?} after {ms} ms, GetLastError={le} (5=ERROR_ACCESS_DENIED)"));
        report("v2_busy_secret_not_placed", other_text().as_deref() != Some(CANARY), "");

        // 5. Each protective format failing (real API error via invalid format id): Strict removes text.
        for f in ALL_FORMATS {
            let mut wf = writer();
            wf.backend.inject_fail_format = Some(f);
            let (o, t) = wf.copy_secret(&w(CANARY), Policy::Strict);
            let st = wf.backend.stats;
            let present = inspect(&mut wf).map(|x| x.0);
            report(
                &format!("v2_strict_protection_failure_{f:?}"),
                o == CopyOutcome::Failed(CopyError::ProtectionFailed(vec![f])) && t.is_none() && present == Some(false) && st.freed_after_failure == 1,
                format!("{o:?} text_present_after={present:?} {st:?}"),
            );
        }

        // 6. Text placement failing: nothing placed, memory freed by us.
        let mut wt = writer();
        wt.backend.inject_fail_text = true;
        let (o, _) = wt.copy_secret(&w(CANARY), Policy::Strict);
        let st = wt.backend.stats;
        report("v2_set_text_failure", o == CopyOutcome::Failed(CopyError::SetText) && st.freed_after_failure == 1 && st.transferred_to_system == 0, format!("{o:?} {st:?}"));

        // 7. AllowUnprotected: never claims protection; missing format really absent.
        let mut wu = writer();
        wu.backend.inject_fail_format = Some(ProtectFormat::NoCloud);
        let (o, t) = wu.copy_secret(&w(CANARY), Policy::AllowUnprotected);
        let ins = inspect(&mut wu);
        report(
            "v2_allow_unprotected_reports_missing",
            o == CopyOutcome::CopiedUnprotected(vec![ProtectFormat::NoCloud]) && ins.as_ref().is_some_and(|x| x.0 && x.2[2].is_none() && x.2[0] == Some(0)),
            format!("{o:?} inspect={ins:?}"),
        );
        if let Some(t) = t {
            let _ = wu.clear_if_ours(&t);
        }

        // 8. Race with a spamming process.
        let mut child = Command::new(exe).args(["child-spam", "300"]).spawn().expect("spawn");
        let mut wr = writer();
        let (mut prot, mut busy, mut other_fail, mut cleared, mut not_ours, mut clear_busy, mut unprotected_seen) = (0, 0, 0, 0, 0, 0, 0);
        for _ in 0..300 {
            let (o, t) = wr.copy_secret(&w(CANARY), Policy::Strict);
            match &o {
                CopyOutcome::Protected => prot += 1,
                CopyOutcome::Failed(CopyError::Busy) => busy += 1,
                _ => other_fail += 1,
            }
            // D-P2 check: whenever our text is on the clipboard and we own it, all formats must be there.
            if let Some((text, owner, f)) = inspect(&mut wr)
                && text
                && owner
                && f.iter().any(|x| x.is_none())
            {
                unprotected_seen += 1;
            }
            if let Some(t) = t {
                match wr.clear_if_ours(&t) {
                    ClearOutcome::Cleared => cleared += 1,
                    ClearOutcome::NotOurs => not_ours += 1,
                    _ => clear_busy += 1,
                }
            }
        }
        let _ = child.wait();
        info("v2_race_counts", format!("copy: protected={prot} busy={busy} other_fail={other_fail}; clear: cleared={cleared} not_ours={not_ours} busy={clear_busy}"));
        report("v2_race_no_unprotected_secret_observed", unprotected_seen == 0, format!("our text without all protective formats observed {unprotected_seen} times"));
    }

    pub fn child_hold(ms: u64) {
        let b = Win32Backend::new().expect("window");
        // SAFETY: own window handle; closed below.
        unsafe { windows_sys::Win32::System::DataExchange::OpenClipboard(b.hwnd()) };
        std::thread::sleep(Duration::from_millis(ms));
        // SAFETY: paired with OpenClipboard.
        unsafe { windows_sys::Win32::System::DataExchange::CloseClipboard() };
    }
}

#[cfg(windows)]
fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("legacy-arboard") => legacy::imp::run(&a[0]),
        Some("child-write") => legacy::imp::child_write(&a[2]),
        Some("child-spam") => legacy::imp::child_spam(a[2].parse().unwrap()),
        Some("child-hold") => v2::child_hold(a[2].parse().unwrap()),
        _ => v2::run(&a[0]),
    }
}
