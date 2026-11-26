//! VELFORT Phase 0.5 / W1 — Argon2id benchmark (spike, not production code).
//!
//! Usage: argon2-bench <repeats> <profile-index|all> [load-threads] [own-buffer]
//!   load-threads: number of busy-spinning background threads (simulates parallel load)
//!   own-buffer:   use hash_password_into_with_memory with a caller-owned, zeroized buffer
//! Prints a KAT self-check (RFC 9106 §5.3 Argon2id vector), then for each profile:
//! min / median / max wall time over `repeats` runs, and peak process memory.

use argon2::{Algorithm, Argon2, Params, Version};
use std::time::Instant;

const PROFILES: &[(u32, u32, u32)] = &[
    // (m_cost KiB, t_cost, p_cost)
    (64 * 1024, 3, 4),  // = RFC 9106 SECOND RECOMMENDED
    (128 * 1024, 3, 4),
    (256 * 1024, 3, 4),
    (512 * 1024, 3, 4),
    (256 * 1024, 2, 4),
    (1024 * 1024, 1, 4),
    (19 * 1024, 2, 1),  // = OWASP minimum, for reference only
];

fn kat_rfc9106() -> bool {
    // RFC 9106 §5.3 Argon2id test vector: m=32, t=3, p=4, password 32x0x01,
    // salt 16x0x02, secret 8x0x03, associated data 12x0x04, tag length 32.
    let expected: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53,
        0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01,
        0xe6, 0x59,
    ];
    let ad = [4u8; 12];
    let params = argon2::ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(argon2::AssociatedData::new(&ad).expect("ad"))
        .output_len(32)
        .build()
        .expect("params");
    let secret = [3u8; 8];
    let a = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
        .expect("argon2");
    let mut out = [0u8; 32];
    a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out).expect("hash");
    out == expected
}

#[cfg(windows)]
fn peak_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut c: PROCESS_MEMORY_COUNTERS = unsafe { core::mem::zeroed() };
    c.cb = core::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: valid pseudo-handle and correctly sized out-struct.
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
    (ok != 0).then_some(c.PeakWorkingSetSize as u64)
}

#[cfg(target_os = "linux")]
fn peak_memory_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn peak_memory_bytes() -> Option<u64> {
    None
}

fn run_once(m: u32, t: u32, p: u32, own_buffer: bool) -> Result<f64, String> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| e.to_string())?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    let start = Instant::now();
    if own_buffer {
        // Caller-owned memory: allocation failure is reported, and the buffer is wiped after use.
        let n = params.block_count();
        let mut blocks: Vec<argon2::Block> = Vec::new();
        blocks.try_reserve_exact(n).map_err(|e| format!("try_reserve_exact failed: {e}"))?;
        blocks.resize(n, argon2::Block::default());
        let r = a.hash_password_into_with_memory(b"velfort benchmark password", &salt, &mut out, &mut blocks[..]);
        use zeroize::Zeroize;
        for b in blocks.iter_mut() { b.zeroize(); }
        r.map_err(|e| e.to_string())?;
    } else {
        a.hash_password_into(b"velfort benchmark password", &salt, &mut out)
            .map_err(|e| e.to_string())?;
    }
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let repeats: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let only: Option<usize> = args.get(2).and_then(|s| s.parse().ok());
    let load: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let own_buffer = args.get(4).is_some_and(|s| s == "own-buffer");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for _ in 0..load {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut x: u64 = 1;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                std::hint::black_box(x);
            }
        });
    }
    println!("background load threads: {load}, own-buffer: {own_buffer}");

    println!("argon2 crate 0.6.0, parallel feature: {}", cfg!(feature = "parallel"));
    println!("available_parallelism: {:?}", std::thread::available_parallelism().map(|n| n.get()));
    let kat = kat_rfc9106();
    println!("KAT RFC 9106 §5.3 Argon2id: {}", if kat { "OK" } else { "MISMATCH" });
    if !kat {
        std::process::exit(2);
    }
    println!("| m (MiB) | t | p | runs | min ms | median ms | max ms | peak WS/RSS MiB (process, cumulative) |");
    println!("|---|---|---|---|---|---|---|---|");
    for (i, &(m, t, p)) in PROFILES.iter().enumerate() {
        if only.is_some_and(|o| o != i) {
            continue;
        }
        let mut v = Vec::with_capacity(repeats);
        let mut err = None;
        // one warm-up run (not counted)
        if let Err(e) = run_once(m, t, p, own_buffer) {
            err = Some(e);
        }
        for _ in 0..repeats {
            match run_once(m, t, p, own_buffer) {
                Ok(ms) => v.push(ms),
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = err {
            println!("| {} | {t} | {p} | - | ERROR: {e} | | | |", m / 1024);
            continue;
        }
        v.sort_by(|a, b| a.total_cmp(b));
        let med = if v.len() % 2 == 1 { v[v.len() / 2] } else { (v[v.len() / 2 - 1] + v[v.len() / 2]) / 2.0 };
        let peak = peak_memory_bytes().map(|b| format!("{:.0}", b as f64 / 1048576.0)).unwrap_or("n/a".into());
        println!(
            "| {} | {t} | {p} | {} | {:.0} | {:.0} | {:.0} | {peak} |",
            m / 1024,
            v.len(),
            v[0],
            med,
            v[v.len() - 1]
        );
    }
}
