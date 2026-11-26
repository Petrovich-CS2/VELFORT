//! Platform-independent secret clipboard writer logic (Phase 0.6, D-P1/D-P2). Spike only.
//!
//! Responsibilities: (1) put ONE secret on the clipboard together with the protective formats in
//! ONE open/close session; (2) report exactly one of three outcomes; (3) later clear it ONLY if
//! the clipboard still holds our data. It does not read arbitrary clipboard content for other
//! purposes and is not a general clipboard framework.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The three protective formats are NOT interchangeable (MS Learn, "Cloud Clipboard and
/// Clipboard History Formats"):
/// * `ExcludeMonitor` (`ExcludeClipboardContentFromMonitorProcessing`, any data): excludes all
///   formats from history AND cross-device sync.
/// * `NoHistory` (`CanIncludeInClipboardHistory` = DWORD 0): history only; "does not affect
///   synchronization to the user's other devices".
/// * `NoCloud` (`CanUploadToCloudClipboard` = DWORD 0): sync only; "does not affect the local
///   device's clipboard history".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectFormat {
    ExcludeMonitor,
    NoHistory,
    NoCloud,
}

pub const ALL_FORMATS: [ProtectFormat; 3] = [ProtectFormat::ExcludeMonitor, ProtectFormat::NoHistory, ProtectFormat::NoCloud];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Default: if any protective format cannot be set, the secret is removed before the
    /// clipboard is closed and the copy fails.
    Strict,
    /// Only after explicit user consent: keep the text even if protection is incomplete.
    AllowUnprotected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyError {
    /// The clipboard stayed unavailable for all bounded attempts.
    Busy,
    /// Emptying (taking ownership) failed; nothing of ours was placed.
    TakeOwnership,
    /// Placing the text failed; nothing of ours remains.
    SetText,
    /// Protection incomplete and the text was removed again before close (Strict).
    ProtectionFailed(Vec<ProtectFormat>),
    /// CRITICAL: protection incomplete AND removing the text failed. The secret may be on the
    /// clipboard without protection; the caller must warn the user and schedule a clear.
    ProtectionFailedRemovalFailed(Vec<ProtectFormat>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyOutcome {
    /// Text and all three protective formats were accepted by the API.
    Protected,
    /// Text placed; listed formats were NOT set (only with `Policy::AllowUnprotected`).
    CopiedUnprotected(Vec<ProtectFormat>),
    Failed(CopyError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearOutcome {
    Cleared,
    /// Ownership or content changed: another application wrote to the clipboard. Not touched.
    NotOurs,
    /// Clipboard unavailable for all bounded attempts; caller may retry later (bounded).
    Busy,
    /// Opened, verified ours, but EmptyClipboard failed.
    EmptyFailed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BackendError {
    Unavailable,
    Failed(u32),
}

/// Minimal clipboard operations. `open` must associate the session with our own window so that
/// `empty` makes us the owner (a NULL window makes SetClipboardData fail — MS Learn).
pub trait Backend {
    fn open(&mut self) -> Result<(), BackendError>;
    fn close(&mut self);
    fn empty(&mut self) -> Result<(), BackendError>;
    fn set_text(&mut self, utf16: &[u16]) -> Result<(), BackendError>;
    fn set_format(&mut self, f: ProtectFormat) -> Result<(), BackendError>;
    /// Only valid while open.
    fn is_owner(&self) -> bool;
    /// Only valid while open. Returns the CF_UNICODETEXT content, if any.
    fn read_text(&mut self) -> Result<Option<Zeroizing<Vec<u16>>>, BackendError>;
    fn pause(&mut self, attempt: u32);
}

/// Proof of a successful copy; holds only a hash of the secret, never the secret.
#[derive(Debug)]
pub struct Ticket {
    digest: [u8; 32],
}

fn digest(utf16: &[u16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"VELFORT/clipboard-ticket/v1");
    for u in utf16 {
        h.update(u.to_le_bytes());
    }
    h.finalize().into()
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub struct Writer<B: Backend> {
    pub backend: B,
    /// Upper bound on OpenClipboard attempts (no infinite retries).
    pub max_open_attempts: u32,
}

impl<B: Backend> Writer<B> {
    pub fn new(backend: B) -> Self {
        Self { backend, max_open_attempts: 10 }
    }

    fn open_bounded(&mut self) -> bool {
        for attempt in 0..self.max_open_attempts {
            if self.backend.open().is_ok() {
                return true;
            }
            self.backend.pause(attempt);
        }
        false
    }

    pub fn copy_secret(&mut self, secret_utf16: &[u16], policy: Policy) -> (CopyOutcome, Option<Ticket>) {
        if !self.open_bounded() {
            return (CopyOutcome::Failed(CopyError::Busy), None);
        }
        if self.backend.empty().is_err() {
            self.backend.close();
            return (CopyOutcome::Failed(CopyError::TakeOwnership), None);
        }
        if self.backend.set_text(secret_utf16).is_err() {
            self.backend.close();
            return (CopyOutcome::Failed(CopyError::SetText), None);
        }
        let missing: Vec<ProtectFormat> = ALL_FORMATS.iter().copied().filter(|f| self.backend.set_format(*f).is_err()).collect();
        let outcome = if missing.is_empty() {
            CopyOutcome::Protected
        } else if policy == Policy::AllowUnprotected {
            CopyOutcome::CopiedUnprotected(missing)
        } else if self.backend.empty().is_ok() {
            // Removed before CloseClipboard: the secret was never published to other apps.
            CopyOutcome::Failed(CopyError::ProtectionFailed(missing))
        } else {
            CopyOutcome::Failed(CopyError::ProtectionFailedRemovalFailed(missing))
        };
        self.backend.close();
        let placed = matches!(outcome, CopyOutcome::Protected | CopyOutcome::CopiedUnprotected(_) | CopyOutcome::Failed(CopyError::ProtectionFailedRemovalFailed(_)));
        let ticket = placed.then(|| Ticket { digest: digest(secret_utf16) });
        (outcome, ticket)
    }

    /// Clears the clipboard only if we are still the owner AND it still holds our secret.
    /// The checks and EmptyClipboard run inside one open session (OpenClipboard "prevents other
    /// applications from modifying the clipboard content").
    pub fn clear_if_ours(&mut self, ticket: &Ticket) -> ClearOutcome {
        if !self.open_bounded() {
            return ClearOutcome::Busy;
        }
        let ours = self.backend.is_owner()
            && matches!(self.backend.read_text(), Ok(Some(t)) if ct_eq(&digest(&t), &ticket.digest));
        let r = if !ours {
            ClearOutcome::NotOurs
        } else if self.backend.empty().is_ok() {
            ClearOutcome::Cleared
        } else {
            ClearOutcome::EmptyFailed
        };
        self.backend.close();
        r
    }
}

/// In-memory fake used by the platform-independent tests.
pub mod fake {
    use super::*;

    #[derive(Default, Clone)]
    pub struct State {
        pub text: Option<Vec<u16>>,
        pub formats: Vec<ProtectFormat>,
        pub owner_is_us: bool,
        pub open_by_us: bool,
        pub open_calls: u32,
        pub empty_calls: u32,
    }

    #[derive(Default)]
    pub struct FakeBackend {
        pub s: State,
        pub fail_open_times: u32,
        pub fail_empty_from_call: Option<u32>,
        pub fail_set_text: bool,
        pub fail_formats: Vec<ProtectFormat>,
        /// Simulates another application writing between our operations.
        pub foreign_write_on_open: Option<Vec<u16>>,
    }

    impl FakeBackend {
        pub fn foreign_write(&mut self, text: &[u16]) {
            self.s.text = Some(text.to_vec());
            self.s.formats.clear();
            self.s.owner_is_us = false;
        }
    }

    impl Backend for FakeBackend {
        fn open(&mut self) -> Result<(), BackendError> {
            self.s.open_calls += 1;
            if self.fail_open_times > 0 {
                self.fail_open_times -= 1;
                return Err(BackendError::Unavailable);
            }
            if let Some(t) = self.foreign_write_on_open.take() {
                self.foreign_write(&t);
            }
            self.s.open_by_us = true;
            Ok(())
        }
        fn close(&mut self) {
            assert!(self.s.open_by_us, "close without open");
            self.s.open_by_us = false;
        }
        fn empty(&mut self) -> Result<(), BackendError> {
            assert!(self.s.open_by_us);
            self.s.empty_calls += 1;
            if self.fail_empty_from_call.is_some_and(|n| self.s.empty_calls >= n) {
                return Err(BackendError::Failed(5));
            }
            self.s.text = None;
            self.s.formats.clear();
            self.s.owner_is_us = true;
            Ok(())
        }
        fn set_text(&mut self, utf16: &[u16]) -> Result<(), BackendError> {
            assert!(self.s.open_by_us);
            if self.fail_set_text || !self.s.owner_is_us {
                return Err(BackendError::Failed(1418));
            }
            self.s.text = Some(utf16.to_vec());
            Ok(())
        }
        fn set_format(&mut self, f: ProtectFormat) -> Result<(), BackendError> {
            assert!(self.s.open_by_us);
            if self.fail_formats.contains(&f) {
                return Err(BackendError::Failed(0));
            }
            self.s.formats.push(f);
            Ok(())
        }
        fn is_owner(&self) -> bool {
            self.s.owner_is_us
        }
        fn read_text(&mut self) -> Result<Option<Zeroizing<Vec<u16>>>, BackendError> {
            Ok(self.s.text.clone().map(Zeroizing::new))
        }
        fn pause(&mut self, _attempt: u32) {}
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeBackend;
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn writer() -> Writer<FakeBackend> {
        Writer::new(FakeBackend::default())
    }

    #[test]
    fn success_sets_text_and_all_three_formats_in_one_session() {
        let mut wr = writer();
        let (o, t) = wr.copy_secret(&w("s3cr3t"), Policy::Strict);
        assert_eq!(o, CopyOutcome::Protected);
        assert!(t.is_some());
        assert_eq!(wr.backend.s.text, Some(w("s3cr3t")));
        assert_eq!(wr.backend.s.formats, ALL_FORMATS.to_vec());
        assert_eq!(wr.backend.s.open_calls, 1, "one open/close session");
        assert!(!wr.backend.s.open_by_us, "closed");
    }

    #[test]
    fn busy_clipboard_is_bounded_and_reports_failure() {
        let mut wr = writer();
        wr.backend.fail_open_times = u32::MAX;
        let (o, t) = wr.copy_secret(&w("x"), Policy::Strict);
        assert_eq!(o, CopyOutcome::Failed(CopyError::Busy));
        assert!(t.is_none());
        assert_eq!(wr.backend.s.open_calls, wr.max_open_attempts, "no infinite retries");
    }

    #[test]
    fn transient_busy_then_success() {
        let mut wr = writer();
        wr.backend.fail_open_times = 3;
        assert_eq!(wr.copy_secret(&w("x"), Policy::Strict).0, CopyOutcome::Protected);
        assert_eq!(wr.backend.s.open_calls, 4);
    }

    #[test]
    fn set_text_failure_reports_failure_and_places_nothing() {
        let mut wr = writer();
        wr.backend.fail_set_text = true;
        let (o, t) = wr.copy_secret(&w("x"), Policy::Strict);
        assert_eq!(o, CopyOutcome::Failed(CopyError::SetText));
        assert!(t.is_none() && wr.backend.s.text.is_none());
    }

    #[test]
    fn strict_protection_failure_removes_secret_before_close() {
        for f in ALL_FORMATS {
            let mut wr = writer();
            wr.backend.fail_formats = vec![f];
            let (o, t) = wr.copy_secret(&w("secret"), Policy::Strict);
            assert_eq!(o, CopyOutcome::Failed(CopyError::ProtectionFailed(vec![f])), "{f:?}");
            assert!(t.is_none());
            assert_eq!(wr.backend.s.text, None, "secret must not remain after protection failure ({f:?})");
        }
    }

    #[test]
    fn strict_protection_failure_with_removal_failure_is_critical() {
        let mut wr = writer();
        wr.backend.fail_formats = vec![ProtectFormat::NoCloud];
        wr.backend.fail_empty_from_call = Some(2); // first empty (take ownership) ok, second fails
        let (o, t) = wr.copy_secret(&w("secret"), Policy::Strict);
        assert_eq!(o, CopyOutcome::Failed(CopyError::ProtectionFailedRemovalFailed(vec![ProtectFormat::NoCloud])));
        assert!(t.is_some(), "caller gets a ticket to clear later");
        assert_eq!(wr.backend.s.text, Some(w("secret")));
    }

    #[test]
    fn allow_unprotected_never_claims_protection() {
        let mut wr = writer();
        wr.backend.fail_formats = vec![ProtectFormat::NoHistory];
        let (o, _) = wr.copy_secret(&w("secret"), Policy::AllowUnprotected);
        assert_eq!(o, CopyOutcome::CopiedUnprotected(vec![ProtectFormat::NoHistory]));
    }

    #[test]
    fn clear_removes_our_value() {
        let mut wr = writer();
        let (_, t) = wr.copy_secret(&w("secret"), Policy::Strict);
        assert_eq!(wr.clear_if_ours(&t.unwrap()), ClearOutcome::Cleared);
        assert_eq!(wr.backend.s.text, None);
    }

    #[test]
    fn clear_never_erases_foreign_content() {
        let mut wr = writer();
        let (_, t) = wr.copy_secret(&w("secret"), Policy::Strict);
        wr.backend.foreign_write(&w("user text"));
        assert_eq!(wr.clear_if_ours(t.as_ref().unwrap()), ClearOutcome::NotOurs);
        assert_eq!(wr.backend.s.text, Some(w("user text")));
    }

    #[test]
    fn clear_refuses_when_other_app_copied_the_same_text() {
        // Same characters, but another owner: not ours by the rule "owner AND content".
        let mut wr = writer();
        let (_, t) = wr.copy_secret(&w("secret"), Policy::Strict);
        wr.backend.foreign_write(&w("secret"));
        assert_eq!(wr.clear_if_ours(t.as_ref().unwrap()), ClearOutcome::NotOurs);
        assert_eq!(wr.backend.s.text, Some(w("secret")));
    }

    #[test]
    fn race_foreign_write_just_before_clear_session() {
        let mut wr = writer();
        let (_, t) = wr.copy_secret(&w("secret"), Policy::Strict);
        wr.backend.foreign_write_on_open = Some(w("racing app"));
        assert_eq!(wr.clear_if_ours(t.as_ref().unwrap()), ClearOutcome::NotOurs);
        assert_eq!(wr.backend.s.text, Some(w("racing app")));
    }

    #[test]
    fn clear_when_busy_is_bounded() {
        let mut wr = writer();
        let (_, t) = wr.copy_secret(&w("secret"), Policy::Strict);
        wr.backend.fail_open_times = u32::MAX;
        let before = wr.backend.s.open_calls;
        assert_eq!(wr.clear_if_ours(t.as_ref().unwrap()), ClearOutcome::Busy);
        assert_eq!(wr.backend.s.open_calls - before, wr.max_open_attempts);
        assert_eq!(wr.backend.s.text, Some(w("secret")), "unchanged; caller must report");
    }

    #[test]
    fn clear_with_empty_failure_is_reported() {
        let mut wr = writer();
        let (_, t) = wr.copy_secret(&w("secret"), Policy::Strict);
        wr.backend.fail_empty_from_call = Some(2);
        assert_eq!(wr.clear_if_ours(t.as_ref().unwrap()), ClearOutcome::EmptyFailed);
    }

    #[test]
    fn ticket_does_not_contain_the_secret() {
        let mut wr = writer();
        let (_, t) = wr.copy_secret(&w("VELFORT-CANARY-TICKET"), Policy::Strict);
        let dbg = format!("{:?}", t.unwrap());
        assert!(!dbg.contains("CANARY"));
    }
}
