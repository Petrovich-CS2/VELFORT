//! Win32 backend for the secret clipboard writer (Phase 0.6). Spike only.
//!
//! Contracts used (MS Learn):
//! * SetClipboardData: "The window must be the current clipboard owner, and the application must
//!   have called the OpenClipboard function"; with OpenClipboard(NULL) EmptyClipboard sets the
//!   owner to NULL and "this causes SetClipboardData to fail" -> we own a message-only window.
//! * hMem "must have been allocated using the function with the GMEM_MOVEABLE flag"; on success
//!   "the system owns the object"; the failure case does not transfer ownership (the page only
//!   documents success), so on failure we GlobalFree it ourselves.
//! * "The memory must be unlocked before the Clipboard is closed."
//! * Protective formats are registered with RegisterClipboardFormatW; DWORD 0 for
//!   CanIncludeInClipboardHistory / CanUploadToCloudClipboard, any data for
//!   ExcludeClipboardContentFromMonitorProcessing (we use DWORD 0).
//!
//! Limitation: once SetClipboardData succeeds the system owns the text memory; it cannot be
//! wiped by us and is freed by the system when the clipboard is emptied (no zeroing documented).

#![allow(unsafe_code)]

use crate::writer::{Backend, BackendError, ProtectFormat};
use std::cell::Cell;
use windows_sys::Win32::Foundation::{GetLastError, GlobalFree, HWND};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardOwner, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, HWND_MESSAGE};
use zeroize::Zeroizing;

const CF_UNICODETEXT: u32 = 13;

pub fn format_name(f: ProtectFormat) -> &'static str {
    match f {
        ProtectFormat::ExcludeMonitor => "ExcludeClipboardContentFromMonitorProcessing",
        ProtectFormat::NoHistory => "CanIncludeInClipboardHistory",
        ProtectFormat::NoCloud => "CanUploadToCloudClipboard",
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Global-memory accounting so tests can prove that nothing leaks or is double-freed.
#[derive(Default, Debug, Clone, Copy)]
pub struct MemStats {
    pub allocated: u32,
    pub transferred_to_system: u32,
    pub freed_after_failure: u32,
}

pub struct Win32Backend {
    hwnd: HWND,
    open: bool,
    pub stats: MemStats,
    /// Test hooks (spike): force a protective format to fail / force the text call to fail
    /// by using an invalid format id, exercising the real API error path.
    pub inject_fail_format: Option<ProtectFormat>,
    pub inject_fail_text: bool,
    pub retry_sleep_ms: u64,
    last_error: Cell<u32>,
}

impl Win32Backend {
    pub fn new() -> Result<Self, u32> {
        let cls = wide("STATIC");
        let empty = wide("");
        // SAFETY: creating a message-only window of a system class; destroyed in Drop.
        let hwnd = unsafe {
            CreateWindowExW(0, cls.as_ptr(), empty.as_ptr(), 0, 0, 0, 0, 0, HWND_MESSAGE, core::ptr::null_mut(), GetModuleHandleW(core::ptr::null()), core::ptr::null())
        };
        if hwnd.is_null() {
            // SAFETY: no preconditions.
            return Err(unsafe { GetLastError() });
        }
        Ok(Self { hwnd, open: false, stats: MemStats::default(), inject_fail_format: None, inject_fail_text: false, retry_sleep_ms: 15, last_error: Cell::new(0) })
    }

    pub fn hwnd(&self) -> HWND {
        self.hwnd
    }

    pub fn last_error(&self) -> u32 {
        self.last_error.get()
    }

    fn fail(&self) -> BackendError {
        // SAFETY: no preconditions.
        let e = unsafe { GetLastError() };
        self.last_error.set(e);
        BackendError::Failed(e)
    }

    /// Allocates movable global memory, copies `bytes`, unlocks, and hands it to SetClipboardData.
    /// Frees the memory itself if SetClipboardData fails.
    fn put(&mut self, format: u32, bytes: &[u8]) -> Result<(), BackendError> {
        // SAFETY: GlobalAlloc/Lock/Unlock/Free used per their contracts; the copy is bounded.
        unsafe {
            let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1));
            if h.is_null() {
                return Err(self.fail());
            }
            self.stats.allocated += 1;
            let p = GlobalLock(h) as *mut u8;
            if p.is_null() {
                let e = self.fail();
                GlobalFree(h);
                self.stats.freed_after_failure += 1;
                return Err(e);
            }
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
            GlobalUnlock(h);
            if SetClipboardData(format, h).is_null() {
                let e = self.fail();
                GlobalFree(h);
                self.stats.freed_after_failure += 1;
                return Err(e);
            }
            self.stats.transferred_to_system += 1;
            Ok(())
        }
    }

    fn register(&self, f: ProtectFormat) -> Result<u32, BackendError> {
        let n = wide(format_name(f));
        // SAFETY: NUL-terminated UTF-16 name.
        let id = unsafe { RegisterClipboardFormatW(n.as_ptr()) };
        if id == 0 { Err(self.fail()) } else { Ok(id) }
    }

    /// Test helper: while open, read the DWORD stored under a protective format (None if absent).
    pub fn read_format_dword(&self, f: ProtectFormat) -> Option<u32> {
        let id = self.register(f).ok()?;
        // SAFETY: clipboard is open (caller contract); handle locked/unlocked in pairs.
        unsafe {
            let h = GetClipboardData(id);
            if h.is_null() {
                return None;
            }
            let p = GlobalLock(h as _) as *const u8;
            if p.is_null() {
                return None;
            }
            let mut b = [0u8; 4];
            core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 4);
            GlobalUnlock(h as _);
            Some(u32::from_ne_bytes(b))
        }
    }
}

impl Drop for Win32Backend {
    fn drop(&mut self) {
        if self.open {
            self.close();
        }
        // SAFETY: window created in `new`.
        unsafe { DestroyWindow(self.hwnd) };
    }
}

impl Backend for Win32Backend {
    fn open(&mut self) -> Result<(), BackendError> {
        // SAFETY: our own window handle.
        if unsafe { OpenClipboard(self.hwnd) } == 0 {
            self.fail();
            return Err(BackendError::Unavailable);
        }
        self.open = true;
        Ok(())
    }
    fn close(&mut self) {
        // SAFETY: paired with a successful OpenClipboard.
        unsafe { CloseClipboard() };
        self.open = false;
    }
    fn empty(&mut self) -> Result<(), BackendError> {
        // SAFETY: clipboard open with our window -> we become the owner.
        if unsafe { EmptyClipboard() } == 0 { Err(self.fail()) } else { Ok(()) }
    }
    fn set_text(&mut self, utf16: &[u16]) -> Result<(), BackendError> {
        // NUL-terminated UTF-16 in a zeroizing temporary.
        let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(utf16.len() * 2 + 2));
        for u in utf16.iter().chain(std::iter::once(&0u16)) {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let fmt = if self.inject_fail_text { 0 } else { CF_UNICODETEXT };
        self.put(fmt, &bytes)
    }
    fn set_format(&mut self, f: ProtectFormat) -> Result<(), BackendError> {
        let id = if self.inject_fail_format == Some(f) { 0 } else { self.register(f)? };
        self.put(id, &0u32.to_ne_bytes())
    }
    fn is_owner(&self) -> bool {
        // SAFETY: no preconditions.
        unsafe { GetClipboardOwner() == self.hwnd }
    }
    fn read_text(&mut self) -> Result<Option<Zeroizing<Vec<u16>>>, BackendError> {
        // SAFETY: clipboard is open; handle locked/unlocked in pairs; read bounded by NUL.
        unsafe {
            let h = GetClipboardData(CF_UNICODETEXT);
            if h.is_null() {
                return Ok(None);
            }
            let p = GlobalLock(h as _) as *const u16;
            if p.is_null() {
                return Err(self.fail());
            }
            let mut v = Zeroizing::new(Vec::new());
            let mut i = 0usize;
            while *p.add(i) != 0 && i < 1 << 20 {
                v.push(*p.add(i));
                i += 1;
            }
            GlobalUnlock(h as _);
            Ok(Some(v))
        }
    }
    fn pause(&mut self, _attempt: u32) {
        std::thread::sleep(std::time::Duration::from_millis(self.retry_sleep_ms));
    }
}
