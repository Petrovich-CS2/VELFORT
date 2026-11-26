//! Recursively scans files under <dir> for each needle (UTF-8 and UTF-16LE). Spike utility.
//! Usage: scan-dir <dir> <needle> [needle...]
use std::path::Path;

fn walk(p: &Path, files: &mut Vec<std::path::PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() { walk(&path, files) } else { files.push(path) }
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dir = Path::new(&a[1]);
    let mut files = Vec::new();
    walk(dir, &mut files);
    println!("SCANDIR {}: {} files", dir.display(), files.len());
    let mut total = 0usize;
    for n in &a[2..] {
        let u8n = n.as_bytes().to_vec();
        let u16n: Vec<u8> = n.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        for f in &files {
            let Ok(d) = std::fs::read(f) else { println!("  unreadable (locked?): {}", f.display()); continue };
            let c8 = d.windows(u8n.len()).filter(|w| *w == &u8n[..]).count();
            let c16 = d.windows(u16n.len()).filter(|w| *w == &u16n[..]).count();
            if c8 + c16 > 0 {
                total += c8 + c16;
                println!("  HIT needle#{} utf8={c8} utf16={c16} file={}", a[2..].iter().position(|x| x == n).unwrap(), f.display());
            }
        }
    }
    println!("SCANDIR total hits: {total}");
}
