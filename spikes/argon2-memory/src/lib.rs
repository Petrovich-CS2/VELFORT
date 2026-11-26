//! Phase 0.6 / F-1 — candidate mitigation for Argon2id working-memory residue (spike only).
//!
//! What the public API of `argon2` 0.6.0 allows:
//! * `hash_password_into_with_memory` lets the CALLER own the heap working memory (`[Block]`),
//!   so the caller can wipe it (`Block: Zeroize` with feature `zeroize`).
//! * It does NOT give access to stack temporaries inside the crate (e.g. `hash: [u8; 1024]` in
//!   `fill_blocks`, `r`/`q` in `Block::compress`). `scrub_stack` overwrites a large stack window
//!   below the caller's frame as a best-effort measure; its effect is MEASURED by the binary in
//!   `src/main.rs`, not assumed.

#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroize;

/// Wipes the borrowed working memory when dropped — on success, on error and during unwinding.
pub struct WipeOnDrop<'a>(pub &'a mut Vec<Block>);

impl Drop for WipeOnDrop<'_> {
    fn drop(&mut self) {
        // `[Block]` element-wise zeroize (volatile writes + compiler fence inside `zeroize`).
        self.0.iter_mut().for_each(Zeroize::zeroize);
    }
}

/// Allocates the working memory without aborting on OOM.
pub fn alloc_work(params: &Params) -> Result<Vec<Block>, &'static str> {
    let n = params.block_count();
    let mut v: Vec<Block> = Vec::new();
    v.try_reserve_exact(n).map_err(|_| "out of memory")?;
    v.resize(n, Block::default());
    Ok(v)
}

/// Argon2id into `out` using caller-owned `work`; `work` is wiped before this returns,
/// including on the error path and while unwinding.
pub fn kdf_into(pw: &[u8], salt: &[u8], params: Params, out: &mut [u8], work: &mut Vec<Block>) -> Result<(), argon2::Error> {
    let guard = WipeOnDrop(work);
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    a.hash_password_into_with_memory(pw, salt, out, &mut guard.0[..])
}

/// Best-effort overwrite of the stack area that the KDF just used (no `unsafe`).
/// Must be called from the same frame that called the KDF, right after it returns.
#[inline(never)]
pub fn scrub_stack() {
    let mut buf = [0u8; 256 * 1024];
    buf.zeroize();
    std::hint::black_box(&buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Params {
        Params::new(256, 1, 1, Some(32)).unwrap()
    }

    fn all_zero(v: &[Block]) -> bool {
        v.iter().all(|b| b.as_ref().iter().all(|&w| w == 0))
    }

    #[test]
    fn work_is_wiped_after_success() {
        let mut work = alloc_work(&p()).unwrap();
        let mut out = [0u8; 32];
        kdf_into(b"pw", b"saltsaltsaltsalt", p(), &mut out, &mut work).unwrap();
        assert_ne!(out, [0u8; 32]);
        assert!(all_zero(&work), "working memory must be zero after success");
    }

    #[test]
    fn work_is_wiped_after_error() {
        let mut work = alloc_work(&p()).unwrap();
        // Fill with non-zero data to prove the wipe ran on the error path.
        for b in work.iter_mut() {
            *b = Block::default();
            b.as_mut()[0] = 0xDEAD_BEEF;
        }
        let mut out = [0u8; 2]; // OutputTooShort
        assert!(kdf_into(b"pw", b"saltsaltsaltsalt", p(), &mut out, &mut work).is_err());
        assert!(all_zero(&work), "working memory must be zero after an error");
    }

    #[test]
    fn work_is_wiped_during_unwinding() {
        let mut work = alloc_work(&p()).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = WipeOnDrop(&mut work);
            let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p());
            let mut out = [0u8; 32];
            a.hash_password_into_with_memory(b"pw", b"saltsaltsaltsalt", &mut out, &mut guard.0[..]).unwrap();
            assert!(!all_zero(guard.0), "precondition: work holds derived data");
            panic!("simulated panic after KDF");
        }));
        assert!(r.is_err());
        assert!(all_zero(&work), "working memory must be zero after unwinding");
    }

    #[test]
    fn alloc_failure_is_an_error_not_an_abort() {
        // usize::MAX blocks cannot be reserved.
        let mut v: Vec<Block> = Vec::new();
        assert!(v.try_reserve_exact(usize::MAX / 2).is_err());
    }

    #[test]
    fn output_matches_library_default_path() {
        let mut work = alloc_work(&p()).unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        kdf_into(b"pw", b"saltsaltsaltsalt", p(), &mut a, &mut work).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, p()).hash_password_into(b"pw", b"saltsaltsaltsalt", &mut b).unwrap();
        assert_eq!(a, b, "the mitigation must not change the cryptographic result");
    }
}
