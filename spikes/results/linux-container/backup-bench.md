| target MiB | vault bytes | backup | verify+restore |
|---|---|---|---|
| 1 | 1081344 | backup: snapshot 1081344 B, file 1081557 B, 6 ms (incl. 2x Argon2id test params), peak 8 MiB | verify+restore: 8 ms, peak 10 MiB |
| 16 | 17014784 | backup: snapshot 17014784 B, file 17014997 B, 60 ms (incl. 2x Argon2id test params), peak 39 MiB | verify+restore: 77 ms, peak 56 MiB |
| 64 | 67993600 | backup: snapshot 67993600 B, file 67993813 B, 250 ms (incl. 2x Argon2id test params), peak 137 MiB | verify+restore: 251 ms, peak 202 MiB |
| 256 | 271929344 | backup: snapshot 271929344 B, file 271929557 B, 1246 ms (incl. 2x Argon2id test params), peak 526 MiB | verify+restore: 1063 ms, peak 785 MiB |

Peak memory = whole-process VmHWM for that phase (separate process per phase), test KDF params (m=1 MiB, t=1, p=1).

## Fault injection (Linux container, 2026-11-26)
- crash-restore (abort after temp file fsync, before no-replace move): exit 134 (SIGABRT); target `crash-target.velfort` NOT created;
  `crash-target.velfort.velfort-partial-<rand>` left behind; sha256 of source vault and backup unchanged.
- restore-into a 3 MiB tmpfs (4 MiB snapshot): `restore-into: ERROR Io(StorageFull)`; filesystem empty afterwards
  (partial file removed, no target).
