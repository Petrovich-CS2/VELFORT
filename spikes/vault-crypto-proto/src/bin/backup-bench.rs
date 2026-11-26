//! W10 measurement tool (spike). Usage:
//!   backup-bench make   <dir> <target_mib>          create a vault of ~target size (test KDF params)
//!   backup-bench backup <dir>                       create backup, print time + peak memory
//!   backup-bench verify <dir>                       verify+restore into new file, print time + peak memory
//!   backup-bench restore-into <dir> <target>        restore backup from <dir> into <target>
//!   backup-bench crash-restore <dir>                restore with abort injected before the final move
//! Each phase runs in its own process so peak memory is per phase.
use rusqlite::Connection;
use std::path::Path;
use std::time::Instant;
use vault_crypto_proto::backup::{create_backup, restore_to_new};
use vault_crypto_proto::keys::KdfParams;
use vault_crypto_proto::store::{create_vault, put_item};

const T: KdfParams = KdfParams { m_kib: 1024, t: 1, p: 1 };
const PW: &[u8] = b"bench password";

#[cfg(target_os = "linux")]
fn peak_mib() -> String {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()).map(|k| format!("{:.0}", k as f64 / 1024.0)).unwrap_or("n/a".into())
}
#[cfg(windows)]
#[allow(unsafe_code)]
fn peak_mib() -> String {
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut c: PROCESS_MEMORY_COUNTERS = unsafe { core::mem::zeroed() };
    c.cb = core::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: pseudo-handle and correctly sized struct.
    if unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) } != 0 { format!("{:.0}", c.PeakWorkingSetSize as f64 / 1048576.0) } else { "n/a".into() }
}
#[cfg(not(any(windows, target_os = "linux")))]
fn peak_mib() -> String { "n/a".into() }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dir = Path::new(&a[2]);
    let vault = dir.join("bench.velfort");
    let backup = dir.join("bench.velfort-backup");
    match a[1].as_str() {
        "make" => {
            let mib: usize = a[3].parse().unwrap();
            let (c, dek, vid) = create_vault(&vault, PW, T, true).unwrap();
            c.execute_batch("BEGIN").unwrap();
            let chunk = vec![0x5Au8; 64 * 1024];
            for i in 0..(mib * 16) as u32 {
                let mut id = [0u8; 16];
                id[..4].copy_from_slice(&i.to_le_bytes());
                put_item(&c, &dek, &vid, &id, 1, 1, b"t", &chunk).unwrap();
            }
            c.execute_batch("COMMIT").unwrap();
            println!("vault bytes: {}", std::fs::metadata(&vault).unwrap().len());
        }
        "backup" => {
            let mut c = Connection::open(&vault).unwrap();
            let t = Instant::now();
            let r = create_backup(&mut c, PW, T, true, u64::MAX, &backup).unwrap();
            println!("backup: snapshot {} B, file {} B, {:.0} ms (incl. 2x Argon2id test params), peak {} MiB", r.snapshot_bytes, r.file_bytes, t.elapsed().as_secs_f64() * 1000.0, peak_mib());
        }
        "verify" => {
            let target = dir.join(format!("restored-{}.velfort", std::process::id()));
            let t = Instant::now();
            restore_to_new(&backup, PW, &target, true, u64::MAX).unwrap();
            println!("verify+restore: {:.0} ms, peak {} MiB", t.elapsed().as_secs_f64() * 1000.0, peak_mib());
            std::fs::remove_file(target).unwrap();
        }
        "restore-into" => {
            let target = Path::new(&a[3]);
            match restore_to_new(&backup, PW, target, true, u64::MAX) {
                Ok(()) => println!("restore-into: OK"),
                Err(e) => println!("restore-into: ERROR {e:?}"),
            }
        }
        "crash-restore" => {
            let target = dir.join("crash-target.velfort");
            // SAFETY: single-threaded at this point.
            unsafe { std::env::set_var("VELFORT_SPIKE_ABORT_BEFORE_MOVE", "1") };
            let _ = restore_to_new(&backup, PW, &target, true, u64::MAX);
            unreachable!("abort expected");
        }
        _ => panic!("unknown mode"),
    }
}
