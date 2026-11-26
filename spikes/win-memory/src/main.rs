//! W2 — VirtualLock / working set / CryptProtectMemory experiments (Windows only, spike).
//! Prints `CHECK <name>: PASS|FAIL|INFO <detail>` lines.

#[cfg(not(windows))]
fn main() {
    println!("CHECK platform: INFO win-memory runs only on Windows");
}

#[cfg(windows)]
fn main() {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory, CryptUnprotectMemory,
    };
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock,
    };
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize};
    use zeroize::Zeroize;

    // SAFETY (whole block): direct Win32 calls with valid arguments; every allocation is freed.
    unsafe {
        let mut si: SYSTEM_INFO = core::mem::zeroed();
        GetSystemInfo(&mut si);
        let page = si.dwPageSize as usize;
        println!("CHECK page_size: INFO {page} bytes");
        let (mut wmin, mut wmax) = (0usize, 0usize);
        GetProcessWorkingSetSize(GetCurrentProcess(), &mut wmin, &mut wmax);
        println!("CHECK working_set_default: INFO min={wmin} B ({} pages) max={wmax} B", wmin / page);

        // 1. Lock a single page.
        let p = VirtualAlloc(core::ptr::null(), page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        let ok = VirtualLock(p, page) != 0;
        println!("CHECK virtuallock_one_page: {} err={}", if ok { "PASS" } else { "FAIL" }, if ok { 0 } else { GetLastError() });
        // 2. Unlock twice: second must fail with ERROR_NOT_LOCKED (158) per docs.
        let u1 = VirtualUnlock(p, page) != 0;
        let u2 = VirtualUnlock(p, page) != 0;
        let e2 = GetLastError();
        println!("CHECK virtualunlock_semantics: {} first={u1} second={u2} err={e2} (158=ERROR_NOT_LOCKED)", if u1 && !u2 && e2 == 158 { "PASS" } else { "FAIL" });
        VirtualFree(p, 0, MEM_RELEASE);

        // 3. PAGE_NOACCESS cannot be locked (per docs).
        let q = VirtualAlloc(core::ptr::null(), page, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
        let okq = VirtualLock(q, page) != 0;
        println!("CHECK virtuallock_noaccess_rejected: {} err={}", if !okq { "PASS" } else { "FAIL" }, GetLastError());
        VirtualFree(q, 0, MEM_RELEASE);

        // 4. Find the default lock limit: grow the locked region until failure.
        let mut max_ok = 0usize;
        let mut fail_err = 0u32;
        for pages in [1usize, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096] {
            let size = pages * page;
            let r = VirtualAlloc(core::ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if VirtualLock(r, size) != 0 {
                max_ok = pages;
                VirtualUnlock(r, size);
                VirtualFree(r, 0, MEM_RELEASE);
            } else {
                fail_err = GetLastError();
                VirtualFree(r, 0, MEM_RELEASE);
                break;
            }
        }
        println!("CHECK virtuallock_default_limit: INFO largest single lock that succeeded = {max_ok} pages; first failure err={fail_err} (1453=ERROR_WORKING_SET_QUOTA)");

        // 5. Raise the working set minimum, retry a 4096-page (16 MiB) lock.
        let want = 4096 * page;
        let set = SetProcessWorkingSetSize(GetCurrentProcess(), wmin + want + 64 * page, wmax.max(wmin + want + 128 * page)) != 0;
        let se = GetLastError();
        let r = VirtualAlloc(core::ptr::null(), want, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        let ok4096 = VirtualLock(r, want) != 0;
        let e4096 = GetLastError();
        println!("CHECK virtuallock_after_setworkingset: INFO SetProcessWorkingSetSize ok={set} (err={se}); lock 4096 pages ok={ok4096} err={}", if ok4096 { 0 } else { e4096 });
        if ok4096 {
            VirtualUnlock(r, want);
        }
        VirtualFree(r, 0, MEM_RELEASE);

        // 6. Locking a Rust heap buffer (not page aligned): VirtualLock locks all pages touched.
        let mut key = vec![0x5Au8; 32];
        let okv = VirtualLock(key.as_mut_ptr().cast(), key.len()) != 0;
        println!("CHECK virtuallock_rust_vec: {} err={}", if okv { "PASS" } else { "FAIL" }, if okv { 0 } else { GetLastError() });
        key.zeroize();
        let zero = key.iter().all(|&b| b == 0);
        VirtualUnlock(key.as_mut_ptr().cast(), key.len());
        println!("CHECK zeroize_then_unlock: {} buffer all-zero after zeroize = {zero}", if zero { "PASS" } else { "FAIL" });

        // 7. CryptProtectMemory round trip (SAME_PROCESS), size must be a multiple of 16.
        let mut buf = [0x11u8; 32];
        let orig = buf;
        let enc = CryptProtectMemory(buf.as_mut_ptr().cast(), 32, CRYPTPROTECTMEMORY_SAME_PROCESS) != 0;
        let changed = buf != orig;
        let dec = CryptUnprotectMemory(buf.as_mut_ptr().cast(), 32, CRYPTPROTECTMEMORY_SAME_PROCESS) != 0;
        println!("CHECK cryptprotectmemory_roundtrip: {} enc={enc} changed={changed} dec={dec} restored={}", if enc && changed && dec && buf == orig { "PASS" } else { "FAIL" }, buf == orig);
        let mut odd = [0u8; 20];
        let bad = CryptProtectMemory(odd.as_mut_ptr().cast(), 20, CRYPTPROTECTMEMORY_SAME_PROCESS) != 0;
        println!("CHECK cryptprotectmemory_non_multiple_rejected: {} block_size={CRYPTPROTECTMEMORY_BLOCK_SIZE} err={}", if !bad { "PASS" } else { "FAIL" }, GetLastError());
    }
}
