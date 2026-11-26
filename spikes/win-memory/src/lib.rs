//! VELFORT Phase 0.5 spike helpers (Windows only): scan another process's committed memory
//! for canary byte patterns. Used to observe residual copies of secrets (W2, W5, W9).
//! A process of the same user and integrity level can do this — that is exactly the threat
//! described in THREAT_MODEL T-10; this tool demonstrates it, it does not defend against it.

#[cfg(windows)]
pub mod scan {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    pub fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Returns, for each needle, the number of occurrences found in committed readable memory.
    /// `None` if the process could not be opened.
    pub fn scan_process(pid: u32, needles: &[Vec<u8>]) -> Option<Vec<usize>> {
        // SAFETY: plain Win32 calls; every handle is closed; buffers are sized from region info.
        unsafe {
            let h: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut counts = vec![0usize; needles.len()];
            let mut addr: usize = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
            let mut buf: Vec<u8> = Vec::new();
            while VirtualQueryEx(h, addr as *const _, &mut mbi, core::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
                let size = mbi.RegionSize;
                if mbi.State == MEM_COMMIT && mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0 && size <= 512 * 1024 * 1024 {
                    buf.resize(size, 0);
                    let mut read = 0usize;
                    if ReadProcessMemory(h, mbi.BaseAddress, buf.as_mut_ptr().cast(), size, &mut read) != 0 || read > 0 {
                        let hay = &buf[..read];
                        for (i, n) in needles.iter().enumerate() {
                            if !n.is_empty() && hay.len() >= n.len() {
                                counts[i] += hay.windows(n.len()).filter(|w| *w == &n[..]).count();
                            }
                        }
                    }
                }
                addr = mbi.BaseAddress as usize + size;
                if size == 0 {
                    break;
                }
            }
            CloseHandle(h);
            Some(counts)
        }
    }

    /// All processes whose executable name matches `exe` (case-insensitive).
    pub fn pids_by_name(exe: &str) -> Vec<u32> {
        let mut v = Vec::new();
        // SAFETY: snapshot handle closed; struct size set as required.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap.is_null() || snap as isize == -1 {
                return v;
            }
            let mut e: PROCESSENTRY32W = core::mem::zeroed();
            e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut e);
            while ok != 0 {
                let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                let name = String::from_utf16_lossy(&e.szExeFile[..len]);
                if name.eq_ignore_ascii_case(exe) {
                    v.push(e.th32ProcessID);
                }
                ok = Process32NextW(snap, &mut e);
            }
            CloseHandle(snap);
        }
        v
    }
}
