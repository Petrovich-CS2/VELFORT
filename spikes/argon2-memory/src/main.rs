//! F-1 residue meter. Measures how many copies of Argon2id working-memory blocks remain
//! readable in THIS process after a key derivation, for several implementation variants.
//!
//!   argon2-memory reference <file> <m_kib> <t> <p>
//!       (child process) derives once and writes a masked 32-byte fingerprint of every final
//!       block plus the output tag to <file>. Done in a separate process so the reference run
//!       does not leave residue in the measuring process.
//!   argon2-memory probe <variant> <file> <m_kib> <t> <p>
//!       derives with <variant>, drops everything, scans its own readable memory for the
//!       fingerprints and prints one result line.
//!
//! Variants: lib-default | own-nozero | own-zeroizing | own-zeroizing-scrub | thread-zeroizing-scrub | positive-control-leak
//!
//! Coverage limit: only copies of FINAL block values (first 32 bytes) and of the tag are detected;
//! intermediate values (earlier passes, `r`/`q` temporaries) are not fingerprinted.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use argon2_memory::{alloc_work, kdf_into, scrub_stack};
use std::collections::HashSet;
use zeroize::Zeroizing;

const PW: &[u8] = b"velfort F-1 residue probe password";
const SALT: [u8; 16] = *b"velfort-salt-f1!";
const MASK: u8 = 0xA5;

fn params(a: &[String]) -> Params {
    Params::new(a[0].parse().unwrap(), a[1].parse().unwrap(), a[2].parse().unwrap(), Some(32)).unwrap()
}

fn fp_block(b: &Block) -> [u8; 32] {
    let w: &[u64] = b.as_ref();
    let mut f = [0u8; 32];
    for i in 0..4 {
        f[i * 8..i * 8 + 8].copy_from_slice(&w[i].to_le_bytes());
    }
    f
}

fn masked(mut f: [u8; 32]) -> [u8; 32] {
    f.iter_mut().for_each(|x| *x ^= MASK);
    f
}

fn reference(path: &str, p: Params) {
    let mut work = alloc_work(&p).unwrap();
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p).hash_password_into_with_memory(PW, &SALT, &mut out, &mut work[..]).unwrap();
    let mut data = Vec::with_capacity(32 * (work.len() + 1));
    data.extend_from_slice(&masked(out));
    for b in &work {
        data.extend_from_slice(&masked(fp_block(b)));
    }
    std::fs::write(path, data).unwrap();
    println!("reference: {} block fingerprints + tag written", work.len());
}

fn derive(variant: &str, p: Params) {
    let mut out = Zeroizing::new([0u8; 32]);
    match variant {
        "lib-default" => {
            Argon2::new(Algorithm::Argon2id, Version::V0x13, p).hash_password_into(PW, &SALT, &mut out[..]).unwrap();
        }
        "own-nozero" => {
            let mut work = alloc_work(&p).unwrap();
            Argon2::new(Algorithm::Argon2id, Version::V0x13, p).hash_password_into_with_memory(PW, &SALT, &mut out[..], &mut work[..]).unwrap();
            drop(work);
        }
        "own-zeroizing" => {
            let mut work = alloc_work(&p).unwrap();
            kdf_into(PW, &SALT, p, &mut out[..], &mut work).unwrap();
        }
        "own-zeroizing-scrub" => {
            let mut work = alloc_work(&p).unwrap();
            kdf_into(PW, &SALT, p, &mut out[..], &mut work).unwrap();
            scrub_stack();
        }
        "thread-zeroizing-scrub" => {
            std::thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    let mut work = alloc_work(&p).unwrap();
                    let mut o = Zeroizing::new([0u8; 32]);
                    kdf_into(PW, &SALT, p, &mut o[..], &mut work).unwrap();
                    scrub_stack();
                })
                .unwrap()
                .join()
                .unwrap();
        }
        "positive-control-leak" => {
            // Deliberately keeps the working memory alive: the meter MUST find (almost) all blocks.
            let mut work = alloc_work(&p).unwrap();
            Argon2::new(Algorithm::Argon2id, Version::V0x13, p).hash_password_into_with_memory(PW, &SALT, &mut out[..], &mut work[..]).unwrap();
            std::mem::forget(work);
        }
        v => panic!("unknown variant {v}"),
    }
    // `out` (the tag) is a Zeroizing value and is wiped here.
}

#[cfg(target_os = "linux")]
fn visit_self(mut f: impl FnMut(usize, &[u8], (usize, usize))) {
    use std::io::{Read, Seek, SeekFrom};
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut mem = std::fs::File::open("/proc/self/mem").unwrap();
    let mut buf = vec![0u8; 4 << 20];
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let range = it.next().unwrap();
        let perms = it.next().unwrap();
        if !perms.starts_with('r') || line.contains("[vvar") || line.contains("[vsyscall]") {
            continue;
        }
        let (a, b) = range.split_once('-').unwrap();
        let (start, end) = (usize::from_str_radix(a, 16).unwrap(), usize::from_str_radix(b, 16).unwrap());
        let mut pos = start;
        while pos < end {
            let n = (end - pos).min(buf.len());
            let ex = (buf.as_ptr() as usize, buf.as_ptr() as usize + buf.capacity());
            if mem.seek(SeekFrom::Start(pos as u64)).is_err() || mem.read_exact(&mut buf[..n]).is_err() {
                break;
            }
            f(pos, &buf[..n], ex);
            pos += n;
        }
    }
}

#[cfg(windows)]
fn visit_self(f: impl FnMut(usize, &[u8], (usize, usize))) {
    assert!(win_memory::scan::visit_process_memory(std::process::id(), f));
}

fn probe(variant: &str, path: &str, p: Params) {
    let data = std::fs::read(path).unwrap();
    let tag = <[u8; 32]>::try_from(&data[..32]).unwrap();
    let blocks: HashSet<[u8; 32]> = data[32..].chunks_exact(32).map(|c| <[u8; 32]>::try_from(c).unwrap()).collect();
    let prefixes: HashSet<u64> = blocks.iter().map(|f| u64::from_ne_bytes(f[..8].try_into().unwrap())).collect();
    drop(data);

    let t0 = std::time::Instant::now();
    derive(variant, p.clone());
    let kdf_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let (mut hit_addrs, mut tag_hits, mut scanned) = (0usize, 0usize, 0usize);
    let mut found: HashSet<[u8; 32]> = HashSet::new();
    let mut seen_addr: HashSet<usize> = HashSet::new();
    visit_self(|base, bytes, ex| {
        scanned += bytes.len();
        if bytes.len() < 32 {
            return;
        }
        let mut off = 0;
        while off + 32 <= bytes.len() {
            let addr = base + off;
            if addr >= ex.0 && addr < ex.1 {
                off += 8;
                continue;
            }
            let mut pre = [0u8; 8];
            for i in 0..8 {
                pre[i] = bytes[off + i] ^ MASK;
            }
            if prefixes.contains(&u64::from_ne_bytes(pre)) || bytes[off] ^ MASK == tag[0] {
                let mut w = [0u8; 32];
                for i in 0..32 {
                    w[i] = bytes[off + i] ^ MASK;
                }
                if w == tag {
                    tag_hits += 1;
                }
                if blocks.contains(&w) && seen_addr.insert(addr) {
                    hit_addrs += 1;
                    found.insert(w);
                }
            }
            off += 8;
        }
    });
    println!(
        "| {variant} | {} | {} | {hit_addrs} | {} | {tag_hits} | {:.0} | {} |",
        p.m_cost() / 1024,
        blocks.len(),
        found.len(),
        kdf_ms,
        scanned / (1024 * 1024)
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("reference") => reference(&a[2], params(&a[3..6])),
        Some("probe") => probe(&a[2], &a[3], params(&a[4..7])),
        _ => {
            eprintln!("usage: argon2-memory reference <file> <m> <t> <p> | probe <variant> <file> <m> <t> <p>");
            std::process::exit(2);
        }
    }
}
