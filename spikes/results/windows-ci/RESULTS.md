# Windows CI results (GitHub-hosted `windows-latest`) — NOT physical Windows 11

Environment (printed by the workflow, run 3):
- OS: Microsoft Windows Server 2025 Datacenter, version 10.0.26100, build 26100
- CPU: AMD EPYC 7763 64-Core Processor, cores=2, logical=4 (VM)
- RAM: 16.0 GiB
- WebView2 Runtime pv: 157.0.4341.46
- rustc 1.97.0 (2d8144b78 2026-07-07); Tauri 2.12.7; @tauri-apps/cli 2.12.6

Runs (https://github.com/Petrovich-CS2/VELFORT/actions):
- run 1 `45789398829` (commit 835a301): spikes-core stopped at W3 (arboard panic, see below); tauri-shell complete (job 139804301642).
- run 2 `45790686305` (commit 63f5ede): spikes-core complete (job 139808626517).
- run 3 `45792012823` (commit 7f91f1e): spikes-core complete (job 139813122038) — values below are from run 3 unless stated.

## Tests
`cargo test --release --locked -p vault-crypto-proto -p aead-stream-audit`: 22 + 11 passed, 0 failed (runs 1, 2, 3).

## W1 Argon2id (5 runs + 1 warm-up each, separate process per profile; ms)
Sequential lanes (argon2 0.6.0 default features), run 3:

| m MiB | t | p | min | median | max | peak WS MiB |
|---|---|---|---|---|---|---|
| 64 | 3 | 4 | 103 | 104 | 105 | 68 |
| 128 | 3 | 4 | 215 | 215 | 223 | 132 |
| 256 | 3 | 4 | 443 | 444 | 446 | 260 |
| 512 | 3 | 4 | 933 | 949 | 971 | 516 |
| 256 | 2 | 4 | 301 | 307 | 308 | 260 |
| 1024 | 1 | 4 | 702 | 703 | 718 | 1028 |
| 19 | 2 | 1 | 19 | 19 | 20 | 23 |
| 64 (4 busy threads) | 3 | 4 | 124 | 170 | 174 | 68 |
| 256 (4 busy threads) | 3 | 4 | 661 | 668 | 774 | 260 |
| 256 own zeroized buffer | 3 | 4 | 477 | 480 | 489 | 260 |

`parallel` feature (rayon), run 3:

| m MiB | t | p | min | median | max | peak WS MiB |
|---|---|---|---|---|---|---|
| 64 | 3 | 4 | 43 | 43 | 55 | 68 |
| 128 | 3 | 4 | 89 | 110 | 121 | 132 |
| 256 | 3 | 4 | 183 | 194 | 208 | 260 |
| 512 | 3 | 4 | 379 | 402 | 415 | 516 |
| 256 | 2 | 4 | 127 | 140 | 150 | 260 |
| 1024 | 1 | 4 | 295 | 317 | 326 | 1028 |
| 64 (4 busy threads) | 3 | 4 | 271 | 283 | 300 | 68 |
| 256 (4 busy threads) | 3 | 4 | 566 | 609 | 657 | 260 |

KAT RFC 9106 §5.3 Argon2id: OK in every run.

## W2 VirtualLock / CryptProtectMemory (runs 1–3 identical)
```
page_size 4096; working_set_default min=204800 B (50 pages) max=1413120 B
virtuallock_one_page: PASS
virtualunlock_semantics: PASS first=true second=false err=158 (ERROR_NOT_LOCKED)
virtuallock_noaccess_rejected: PASS err=998
virtuallock_default_limit: largest single lock that succeeded = 32 pages; next (64 pages) err=1453 (ERROR_WORKING_SET_QUOTA)
virtuallock_after_setworkingset: SetProcessWorkingSetSize ok=true; lock 4096 pages ok=true
virtuallock_rust_vec: PASS; zeroize_then_unlock: PASS
cryptprotectmemory_roundtrip: PASS; cryptprotectmemory_non_multiple_rejected: PASS err=87
```

## W3 Clipboard
Run 3:
```
exclusion_format_present: PASS formats=["#13","ExcludeClipboardContentFromMonitorProcessing","#16","#1","#7"]
timed_clear_removes_our_value: PASS
no_clear_after_foreign_change: PASS result=changed-by-other clipboard=USER-COPIED-TEXT
race_counts: v2 (content rule): cleared=243 skipped_foreign=47 busy=4
race_arboard_set_errors: 6 of 300; after error: secret on clipboard WITHOUT exclusion format = 1, secret absent = 5
race_v1_sequence_rule_would_have_erased_foreign_content: 29 times out of 300
history_enabled: false; roaming_enabled: false; GetHistoryItemsAsync status=2 (ClipboardHistoryDisabled)
```
Run 2: v1 rule would have erased foreign content 39/300; arboard set errors 2/300 (secret absent in both).
Run 1: `arboard` `set()` panicked in the race loop: "Failed to exclude data from clipboard monitoring".
Clipboard history could not be enabled on the runner via `HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory=1` → history behaviour NOT TESTED.

## W9 Native ES_PASSWORD prompt (run 3)
```
EM_GETPASSWORDCHAR=42
cross-process (same user): GetWindowTextW_len=0, WM_GETTEXT_len=0 (secret not returned)
memory scan by second process: utf16 occurrences 0 (in control), 0 (after clear+zeroize), 0 (after DestroyWindow)
utf8 occurrences 1 at every stage = canary literal compiled into the binary (baseline)
```

## W5/W6 Tauri spike (run 1, tauri-shell job)
JS results: forbidden registered command → "Command spike_forbidden not allowed by ACL"; unknown command and
`plugin:fs|read_text_file` → "not allowed by ACL"; external fetch blocked ("TypeError: Failed to fetch");
inline script blocked; eval blocked; `window.__TAURI__` namespaces: app, core, dpi, event, image, menu, mocks, path,
tray, webview, webviewWindow, window; localStorage available.

Memory scan (counts = [master UTF-16, master UTF-8, item UTF-16, item UTF-8]); master password was entered in an
`<input type=password>` via execCommand('insertText'), read once, field cleared, sent through IPC:
- before reload: msedgewebview2 pid 4928 → [2,4,0,3]; pid 6012 → [0,4,0,0]; 5 other msedgewebview2 processes → [0,0,0,0]
- after `location.reload()`: pid 4928 → [1,4,0,1]; others → [0,0,0,0]
- Rust process holds needle copies by design (not meaningful).

UDF: `C:\Users\runneradmin\AppData\Local\app.velfort.spike\EBWebView` (163 files incl. `Crashpad\reports`,
`Default\AutofillStrikeDatabase`, `Default\Cache`) — scan for both canaries (UTF-8/UTF-16): 0 hits.
UDF ACL: SYSTEM (F), Administrators (F), the user (F).

## W7 Installer (run 1, tauri-shell job)
- perMachine + downloadBootstrapper: `VELFORT Spike_0.0.1_x64-setup.exe` = 1,401,145 bytes; silent install → `C:\Program Files\VELFORT Spike`
  (uninstall.exe 79,441 B; velfort-spike-shell.exe 4,580,864 B); ACL inherited: Users (RX), Administrators/SYSTEM/TrustedInstaller (F).
- Silent uninstall: install dir removed = true; `%LOCALAPPDATA%\app.velfort.spike` still present = true.
- currentUser: installed to `%LOCALAPPDATA%\VELFORT Spike`; ACL: SYSTEM (F), Administrators (F), the user (F).
- offlineInstaller: makensis downloaded `https://go.microsoft.com/fwlink/?linkid=2124701`; installer = 299,574,972 bytes (285.70 MiB).
- WebView2 Runtime was already installed on the runner → bootstrapper path, missing-runtime, offline and download-failure scenarios NOT TESTED.

## W8 SQLite (runs 2 and 3 identical; SQLite 3.54.1)
All checks as in Linux: pragmas delete/FULL/secure_delete=1 PASS; journal exists during txn; original page content in journal;
no journal after close; hot journal after abort (child exit 3221226505 = 0xC0000409); recovery integrity ok, header rolled back,
0 partial updates, journal removed; secure_delete ON: deleted canary absent / OFF: present; logical SQLITE_FULL and real
NTFS-full (16 MiB VHDX): error returned, old header kept, integrity ok.

## W10 Backup (run 3; test KDF params)
| vault bytes | backup ms | backup peak MiB | verify+restore ms | peak MiB |
|---|---|---|---|---|
| 1,081,344 | 7 | 8 | 8 | 10 |
| 17,014,784 | 58 | 39 | 58 | 57 |
| 67,993,600 | 288 | 137 | 241 | 203 |
| 271,929,344 | 1094 | 526 | 1071 | 786 |
crash-restore exit -1073740791 (0xC0000409): target not created; `crash-target.velfort.velfort-partial-<rand>` left;
source+backup hashes unchanged. restore-into full 16 MiB NTFS volume: `Io(StorageFull)`; no partial left.

## W12 ACLs
Documents\…\x.velfort, %APPDATA%\…, %LOCALAPPDATA%\…, %TEMP%: SYSTEM (F), Administrators (F), the user (F).
C:\Program Files: Users (RX), Administrators/SYSTEM (M + inherit F), TrustedInstaller (F).
