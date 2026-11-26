//! File helpers for "restore only into a NEW file".
//!
//! `std::fs::rename` REPLACES an existing destination on both Linux and Windows, so it must not
//! be used for the final step. We use a no-replace move instead:
//! * Windows: `MoveFileExW(src, dst, MOVEFILE_WRITE_THROUGH)` without `MOVEFILE_REPLACE_EXISTING`
//!   (fails if `dst` exists). Microsoft does not document this as atomic (see ARCHITECTURE_REVIEW S13).
//! * Other OS: `hard_link(src, dst)` (fails with AlreadyExists) followed by `remove_file(src)`.

use crate::Error;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const PARTIAL_MARKER: &str = ".velfort-partial-";

/// Writes `data` to a fresh temporary file next to `target`, fsyncs it, then moves it to `target`
/// without ever replacing an existing file. On any error the temporary file is removed.
pub fn write_new_file_no_replace(target: &Path, data: &[u8]) -> Result<(), Error> {
    if target.exists() {
        return Err(Error::TargetExists);
    }
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = target.file_name().ok_or(Error::Format("target name"))?;
    let rnd: [u8; 8] = crate::random()?;
    let tmp: PathBuf = dir.join(format!(
        "{}{}{}",
        name.to_string_lossy(),
        PARTIAL_MARKER,
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let result = (|| -> Result<(), Error> {
        let mut f: File = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?; // FlushFileBuffers on Windows, fsync on Linux
        drop(f);
        // Spike-only fault injection: simulate a crash after the temp file is durable, before the move.
        if std::env::var_os("VELFORT_SPIKE_ABORT_BEFORE_MOVE").is_some() {
            std::process::abort();
        }
        move_no_replace(&tmp, target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Removes orphaned `*.velfort-partial-*` files in `dir` (left after a crash). Returns count.
pub fn cleanup_partials(dir: &Path) -> Result<usize, Error> {
    let mut n = 0;
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_name().to_string_lossy().contains(PARTIAL_MARKER) {
            std::fs::remove_file(e.path())?;
            n += 1;
        }
    }
    Ok(n)
}

/// True if both paths resolve to the same existing file (guards "restore onto the source").
pub fn same_existing_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn move_no_replace(src: &Path, dst: &Path) -> Result<(), Error> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    let w = |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    let (s, d) = (w(src), w(dst));
    // SAFETY: both buffers are NUL-terminated UTF-16 strings that outlive the call.
    let ok = unsafe { MoveFileExW(s.as_ptr(), d.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if ok == 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::AlreadyExists || dst.exists() {
            return Err(Error::TargetExists);
        }
        return Err(e.into());
    }
    Ok(())
}

#[cfg(not(windows))]
fn move_no_replace(src: &Path, dst: &Path) -> Result<(), Error> {
    match std::fs::hard_link(src, dst) {
        Ok(()) => {
            std::fs::remove_file(src)?;
            if let Some(dir) = dst.parent().filter(|p| !p.as_os_str().is_empty())
                && let Ok(d) = File::open(dir)
            {
                let _ = d.sync_all(); // persist the directory entry (POSIX)
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::TargetExists),
        Err(e) => Err(e.into()),
    }
}
