//! VELFORT Phase 0.6 secret clipboard writer (spike). `writer` is platform-independent and
//! tested with a fake backend on any OS; `win32` is the Windows backend.
#![deny(unsafe_code)] // only `win32` (Win32 FFI) is allowed unsafe

pub mod writer;
#[cfg(windows)]
pub mod win32;
