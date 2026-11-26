//! W9 — Option C prototype: native Win32 window with an ES_PASSWORD edit control (spike, Windows only).
//! Automated experiment (no human input needed):
//!   1. create window + ES_PASSWORD edit; "type" a canary via WM_CHAR;
//!   2. a second process of the same user tries GetWindowTextW and WM_GETTEXT on the control;
//!   3. the second process scans our memory for the canary (UTF-16LE / UTF-8) before and after clearing.
//!
//! Usage: `win-native-prompt run`, `reader <hwnd>`, `scan <pid>`

#[cfg(not(windows))]
fn main() {
    println!("CHECK platform: INFO win-native-prompt runs only on Windows");
}

#[cfg(windows)]
mod imp {
    use std::process::{Command, Stdio};
    use win_memory::scan::{scan_process, utf16le};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    use zeroize::Zeroize;

    pub const CANARY: &str = "VELFORT-CANARY-MASTER-NATIVE-3a7c";

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    unsafe extern "system" fn wndproc(h: HWND, m: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        // SAFETY: default processing.
        unsafe { DefWindowProcW(h, m, wp, lp) }
    }

    /// Pump messages until the child exits, so cross-process SendMessage to our window is served.
    fn run_child_pumping(args: &[String]) -> String {
        let mut child = Command::new(std::env::current_exe().unwrap()).args(args).stdout(Stdio::piped()).spawn().expect("spawn");
        loop {
            // SAFETY: standard message pump.
            unsafe {
                let mut msg: MSG = core::mem::zeroed();
                while PeekMessageW(&mut msg, core::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let out = child.wait_with_output().expect("out");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn scan_self(label: &str) {
        let pid = std::process::id().to_string();
        let r = run_child_pumping(&["scan".into(), pid]);
        println!("CHECK native_memory_scan_{label}: INFO {r}");
    }

    pub fn run() {
        // SAFETY (block): Win32 window creation and messaging with valid arguments.
        unsafe {
            let hinst = GetModuleHandleW(core::ptr::null());
            let class = w("VelfortSpikePrompt");
            let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: hinst, lpszClassName: class.as_ptr(), ..core::mem::zeroed() };
            RegisterClassW(&wc);
            let title = w("VELFORT — spike native prompt");
            let top = CreateWindowExW(0, class.as_ptr(), title.as_ptr(), WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 420, 160, core::ptr::null_mut(), core::ptr::null_mut(), hinst, core::ptr::null());
            let edit_cls = w("EDIT");
            let empty = w("");
            let edit = CreateWindowExW(0, edit_cls.as_ptr(), empty.as_ptr(), (WS_CHILD | WS_VISIBLE | WS_BORDER) | (ES_PASSWORD | ES_AUTOHSCROLL) as u32, 20, 40, 360, 28, top, core::ptr::null_mut(), hinst, core::ptr::null());
            println!("CHECK native_window_created: {} top={top:?} edit={edit:?}", if !top.is_null() && !edit.is_null() { "PASS" } else { "FAIL" });
            SetFocus(edit);
            for ch in CANARY.encode_utf16() {
                SendMessageW(edit, WM_CHAR, ch as WPARAM, 0);
            }
            let pc = SendMessageW(edit, 210 /* EM_GETPASSWORDCHAR */, 0, 0);
            println!("CHECK native_password_char: INFO EM_GETPASSWORDCHAR={pc} (non-zero => masked display)");

            // 2. Other process of the same user tries to read the control.
            let r = run_child_pumping(&["reader".into(), format!("{}", edit as usize)]);
            println!("CHECK native_cross_process_read: INFO {r}");

            // 3. Memory scan while the password is in the control.
            scan_self("while_in_control");

            // 4. Read once into our own buffer, then clear the control and our buffer.
            let mut buf = vec![0u16; 256];
            let n = GetWindowTextW(edit, buf.as_mut_ptr(), 256) as usize;
            let got = String::from_utf16_lossy(&buf[..n]) == CANARY;
            println!("CHECK native_owner_reads_value: {} len={n}", if got { "PASS" } else { "FAIL" });
            // Overwrite with same-length filler first (attempt to reuse the control's buffer), then empty.
            let filler: Vec<u16> = std::iter::repeat_n('x' as u16, n).chain(Some(0)).collect();
            SetWindowTextW(edit, filler.as_ptr());
            SetWindowTextW(edit, empty.as_ptr());
            buf.zeroize();
            scan_self("after_clear_and_zeroize");

            DestroyWindow(top);
            scan_self("after_destroy_window");
        }
    }

    pub fn reader(hwnd: usize) {
        let h = hwnd as HWND;
        // SAFETY: foreign HWND; APIs tolerate invalid handles.
        unsafe {
            let mut b = [0u16; 256];
            let n1 = GetWindowTextW(h, b.as_mut_ptr(), 256) as usize;
            let t1 = String::from_utf16_lossy(&b[..n1]);
            let mut b2 = [0u16; 256];
            let n2 = SendMessageW(h, WM_GETTEXT, 256, b2.as_mut_ptr() as LPARAM) as usize;
            let t2 = String::from_utf16_lossy(&b2[..n2.min(256)]);
            print!(
                "GetWindowTextW_len={n1} GetWindowTextW_equals_secret={} WM_GETTEXT_len={n2} WM_GETTEXT_equals_secret={}",
                t1 == CANARY,
                t2 == CANARY
            );
        }
    }

    pub fn scan(pid: u32) {
        let needles = vec![utf16le(CANARY), CANARY.as_bytes().to_vec()];
        match scan_process(pid, &needles) {
            Some(c) => print!("utf16_occurrences={} utf8_occurrences={}", c[0], c[1]),
            None => print!("open_process_failed"),
        }
    }
}

#[cfg(windows)]
fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("reader") => imp::reader(a[2].parse().unwrap()),
        Some("scan") => imp::scan(a[2].parse().unwrap()),
        _ => imp::run(),
    }
}
