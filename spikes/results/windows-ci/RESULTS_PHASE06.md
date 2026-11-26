# Phase 0.6 CI results (run 5, `45797145690`, commit 49e3dbf) — Windows CI is NOT physical Windows 11

Jobs: `linux-core` 139830632630 (ubuntu-latest), `spikes-core` 139830632075 and `tauri-shell` 139830632687 (windows-latest).
Windows environment (spikes-core): Windows Server 2025 Datacenter 10.0.26100 build 26100; INTEL(R) XEON(R) PLATINUM 8573C,
cores=2 logical=4; 16.0 GiB; WebView2 Runtime 157.0.4341.60; rustc 1.97.0. (Phase 0.5 runs used an AMD EPYC 7763 runner.)

## Tests
Windows `cargo test --release --locked -p vault-crypto-proto -p aead-stream-audit -p argon2-memory -p win-clipboard`: step success.
Linux job: same packages: step success. Linux container (local): 22 + 16 + 11 + 14 + 5 = 68 passed, 0 failed.

## F-1 Argon2 residue meter (columns: variant | m MiB (0 = 64 KiB) | blocks | residue addresses | distinct blocks | tag hits | KDF ms | scanned MiB)
Windows CI:
```
| positive-control-leak  | 64 | 65536 | 65536 | 65536 | 8 | 115 | 87 |
| lib-default            | 64 | 65536 | 0 | 0 | 8 | 115 | 17 |
| own-nozero             | 64 | 65536 | 0 | 0 | 6 | 115 | 17 |
| own-zeroizing          | 64 | 65536 | 0 | 0 | 8 | 115 | 17 |
| own-zeroizing-scrub    | 64 | 65536 | 0 | 0 | 0 | 125 | 17 |
| thread-zeroizing-scrub | 64 | 65536 | 0 | 0 | 0 | 116 | 17 |
| positive-control-leak  | 0 | 64 | 128 | 64 | 6 | 0 | 12 |
| lib-default            | 0 | 64 | 0 | 0 | 2 | 0 | 12 |
| own-nozero             | 0 | 64 | 0 | 0 | 2 | 0 | 12 |
| own-zeroizing          | 0 | 64 | 0 | 0 | 2 | 0 | 12 |
| own-zeroizing-scrub    | 0 | 64 | 0 | 0 | 0 | 0 | 12 |
| thread-zeroizing-scrub | 0 | 64 | 0 | 0 | 0 | 1 | 12 |
```
Linux container (local, identical commit of argon2-memory): see `../linux-container/argon2-residue.md`
(64 KiB: lib-default 61/64 blocks, own-nozero 61/64, own-zeroizing 0; tag hits 2 without scrub, 0 with scrub).

## W3 v2 secret clipboard writer (Windows CI)
```
v2_copy_protected: PASS Protected
v2_text_present_and_owner: PASS text=true owner=true
v2_formats_dword_zero: PASS [Some(0), Some(0), Some(0)] for [ExcludeMonitor, NoHistory, NoCloud]
v2_global_memory_accounting: PASS allocated 4, transferred_to_system 4, freed_after_failure 0
v2_clear_ours: PASS Cleared text_after=Some(false)
v2_no_clear_of_foreign_content: PASS NotOurs clipboard="USER-COPIED-TEXT-V2"
v2_busy_bounded_failure: PASS Failed(Busy) after 76 ms, GetLastError=5 (ERROR_ACCESS_DENIED)
v2_busy_secret_not_placed: PASS
v2_strict_protection_failure_{ExcludeMonitor,NoHistory,NoCloud}: PASS Failed(ProtectionFailed([f])) text_present_after=false; allocated 4, transferred 3, freed_after_failure 1
v2_set_text_failure: PASS Failed(SetText); allocated 1, transferred 0, freed_after_failure 1
v2_allow_unprotected_reports_missing: PASS CopiedUnprotected([NoCloud]); NoCloud absent, others DWORD 0
v2_race_counts: copy protected=270 busy=30 other_fail=0; clear cleared=268 not_ours=0 busy=2
v2_race_no_unprotected_secret_observed: PASS 0
```
Legacy arboard run (same job): arboard set errors 5/300 (secret absent after each), sequence-number rule would have erased
foreign content 33/300; clipboard history disabled on the runner (status 2).

## Tauri spike (Windows CI)
Config guard + self-test (14 mutations): PASS on Linux and Windows jobs.
JS: global_tauri_namespace_present=false; Object.keys(__TAURI_INTERNALS__)=["plugins"]; forbidden/unknown/plugin:fs → "not allowed by ACL";
CSP: external fetch, inline script, eval blocked.
WebView2 settings (ICoreWebView2Settings4): before explicit set (Tauri config + WebView2 defaults): general_autofill=false,
password_autosave=false; explicit set ok; after: false/false. FailureReportFolderPath = `%LOCALAPPDATA%\app.velfort.spike\EBWebView\Crashpad\reports`.
Memory (master16, master8, item16, item8): before reload renderer pid 9568 [2,4,0,3], pid 9200 [0,4,0,0]; after reload pid 9568 [1,4,0,1].
Crash test (DevTools `Page.crash` after reload): `Crashpad\reports\4e84dde9-39c9-438a-b216-fc861d8c061a.dmp` = 6,136,428 bytes;
canary hits in it (utf8, utf16): master [0,0], item [0,0]. Crashpad also contains `metadata` (114 B), `settings.dat` (288 B),
`throttle_store.dat` (20 B), `watson_metadata` (692 B).
UDF scan after exit: 168 files, 0 canary hits. Present: `Default\Login Data` (43,008 B), `Default\Login Data For Account` (43,008 B),
`Default\Web Data` (227,328 B) + empty `-journal` files.
Installer: perMachine downloadBootstrapper 1,409,250 B → Program Files (Users RX); silent uninstall removes install dir, keeps
`%LOCALAPPDATA%\app.velfort.spike`; offlineInstaller 299,588,161 B (285.71 MiB).
