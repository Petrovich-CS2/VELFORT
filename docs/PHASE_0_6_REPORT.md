# VELFORT — Phase 0.6 Report (Security Remediation)

Дата: 2026-11-26. **Итоговый статус Phase 0.6: PARTIAL.**
Phase 1 не открыта; production-модулей нет; все изменения кода — в `spikes/` (отдельный workspace) и в CI.
Физическая Windows 11 не подключена: **ни одна проверка не выполнялась на физической Windows 11.**

Окружения: [LNX] Linux-контейнер (Intel Xeon 2.30 GHz, 4 CPU, 16 GiB); [LCI] GitHub `ubuntu-latest`;
[WCI] GitHub `windows-latest` — Windows Server 2025 Datacenter 10.0.26100 (run 5: Intel Xeon Platinum 8573C, 4 logical, 16 GiB,
WebView2 157.0.4341.60). Прогон CI: run `45797145690` (commit `49e3dbf`). Сырые данные:
[`spikes/results/windows-ci/RESULTS_PHASE06.md`](../spikes/results/windows-ci/RESULTS_PHASE06.md).

## 1. Краткое резюме

Устранены в прототипе и проверены в Windows CI: D-P1, D-P2 (новый Win32 Secret Clipboard Writer), D-P4 (автозаполнение
и автосохранение паролей фактически выключены), D-P13 (`withGlobalTauri` выключен, CI-проверка конфигурации);
реализована и покрыта тестами F-2 (NFC — часть протокола, `pw_transform` в формате). F-1 — **снижена и измерена**
(0 остатков в пределах охвата измерителя), но не объявлена исправленной. D-P10 — **не исправлен**: документированный
механизм отключения отправки дампов недоступен через Tauri/wry (C-2); определена политика. D-P12 — политика определена,
путь с флажком «удалить данные» не проверен. D-P3 — принятый остаточный риск варианта A.

## 2. Что изменено

* `spikes/vault-crypto-proto`: `normalize_password` (NFC), `pw_transform` в заголовках, формат хранилища 2 и бэкапа 2, 16 новых тестов.
* `spikes/argon2-memory` (новый): затирание рабочей памяти на всех путях, очистка стека, измеритель остатков с позитивным контролем.
* `spikes/win-clipboard`: `writer` (логика + 14 тестов на поддельном backend), `win32` (backend), новый сценарий `run`; исследование Phase 0.5 сохранено как `legacy-arboard`.
* `spikes/win-memory`: обход памяти процесса с исключением буфера сканера.
* `spikes/tauri-shell`: `generalAutofillEnabled: false`, `withGlobalTauri: false`, чтение/установка настроек WebView2, `FailureReportFolderPath`, сбой renderer и поиск дампов; `ci/check_config.py`.
* CI: задание `linux-core`; новые шаги Windows (тесты, измеритель, writer v2, проверка конфигурации, листинги UDF/Crashpad).
* Документы: см. §12.

## 3–4. Проблемы: устранённые и оставшиеся

| ID | Исходное состояние | Действие | Проверка | Фактический результат | Статус | Остаточный риск |
|---|---|---|---|---|---|---|
| **F-2** | Нет NFC: «й» NFC `d0b9` / NFD `d0b8cc86` → разные ключи | Единая `normalize_password` (NFC, `unicode-normalization` 0.1.26) во всех точках KDF; `pw_transform=1` в аутентифицированных заголовках | `tests/nfc.rs` (16) [LNX, LCI, WCI]; мутация `nfc()`→`chars()` | 16/16 PASS; мутация: 7 тестов падают | **FIXED в прототипе протокола** | Неназначенные кодовые точки Unicode 18.0 (UAX #15 §3) |
| **F-1** | `argon2` 0.6.0 освобождает `Blocks` без затирания; стековые временные не затираются | `hash_password_into_with_memory` + `WipeOnDrop` + `scrub_stack`; измеритель остатков | 5 unit-тестов (успех/ошибка/паника/OOM/эквивалентность); измеритель [LNX, WCI] | Воспроизведено: 61/64 блока (64 KiB, LNX) и 2–8 копий tag на стеке; выбранный вариант: **0/0** на обеих ОС; позитивный контроль 65536/65536 | **MITIGATED** (не FIXED) | Промежуточные значения не измеряются; pagefile/гибернация |
| **D-P1** | Очистка по номеру последовательности стирала чужое (29–39/300) | Очистка только при «владелец = наше окно И текст = хэш секрета» под одной блокировкой | логика (LNX, LCI, WCI) + Win32 [WCI] | 0 ошибочных очисток (гонка 300; `NotOurs` для чужой записи); правило по номеру в legacy-прогоне — 33/300 | **FIXED в прототипе (WCI)** | Не проверено на WIN11 |
| **D-P2** | Формат исключения ставился отдельным шагом; 1/300 секрет без защиты | CF_UNICODETEXT + 3 формата в одной сессии; Strict удаляет текст до `CloseClipboard` при любом сбое; 3 исхода | внедрённые отказы каждого формата и текста [WCI]; гонка | Все PASS; «наш текст без всех форматов» — 0 из 300; `GlobalFree` при сбоях подтверждён учётом | **FIXED в прототипе (WCI)** | Эффект форматов на историю/облако **не проверен** (история на раннере отключена) |
| **D-P3** | Master Password в памяти WebView2 после очистки и reload | Решение владельца: вариант A в v1; меры SR-AUTH-1; повторное измерение | [WCI] | Повторилось: renderer до reload [2,4], после [1,4] (UTF-16, UTF-8) | **ACCEPTED RISK** | Без изменений; вариант C — v1.x |
| **D-P4** | `general_autofill_enabled` по умолчанию `true` | `generalAutofillEnabled: false` + явная установка `IsPasswordAutosaveEnabled`/`IsGeneralAutofillEnabled=false` с чтением | спайк [WCI]; guard [LNX, LCI, WCI] | До явной установки (только конфиг + умолчания): false/false; после: false/false | **FIXED (WCI)** | В UDF существуют `Login Data`/`Web Data` (без сигнальных строк) |
| **D-P10** | Crashpad может хранить дампы | Эксперимент: `Page.crash`; политика CRASH_DUMP_POLICY | [WCI] | Создан minidump 6 136 428 Б в `FailureReportFolderPath`; сигнальных строк в нём 0 (один прогон); отправку в Microsoft отключает только `IsCustomCrashReportingEnabled`, недоступный через wry | **NOT FIXED — POLICY, OPEN (C-2)** | Дампы могут отправляться в Microsoft; отсутствие секретов не доказано |
| **D-P12** | После удаления остаётся кэш WebView2 | Политика UNINSTALL_DATA_POLICY по исходнику шаблона NSIS | [WCI] тихое удаление | Данные сохраняются; встроенный флажок делает `RmDir /r` каталогов `<identifier>` | **POLICY, OPEN (C-4/UNI-4)** | Путь с флажком не проверен |
| **D-P13** | `withGlobalTauri` открывал 12 пространств имён | Отключён; API из бандла; CI-guard | [WCI] JS; guard [LNX, LCI, WCI] | `window.__TAURI__` отсутствует; ACL-отказы сохраняются; guard ловит 14/14 мутаций | **FIXED (WCI)** | `__TAURI_INTERNALS__` есть всегда — граница = ACL |

## 5. Принятые решения

NFC (`unicode-normalization`) — утверждено владельцем, реализовано; Argon2 `parallel` — отклонено для v1, не включено;
запись секретов — собственный узкий Win32-писатель вместо `arboard`; поле Master Password — React (вариант A), вариант C
отложен; Phase 1 — не открыта; формат хранилища/бэкапа повышен до версии 2 из-за `pw_transform` (обоснование: C-5).

## 6. Зависимости

| Зависимость | Где | Зачем | Альтернатива без неё | Поддержка / безопасность | Лицензия | Размер |
|---|---|---|---|---|---|---|
| `unicode-normalization` 0.1.26 (+ `tinyvec` 1.13.3) | `spikes/vault-crypto-proto` | NFC (утверждено) | собственные таблицы Unicode — отклонено | выпуск 2026-10-16; `cargo-audit` 0.23.0: 0 уязвимостей в `spikes/Cargo.lock`; 9 `unsafe` вне таблиц | `(MIT OR Apache-2.0) AND Unicode-3.0` | пакет 130 122 Б; влияние на бинарник не измерено |
| `webview2-com` 0.39.1, `windows`/`windows-core` 0.62.2 | `spikes/tauri-shell` | чтение/установка настроек WebView2, сбой renderer | — | уже были в графе через wry (новых crates нет) | MIT / MIT OR Apache-2.0 | 0 новых |
| `sha2`, `zeroize` | `spikes/win-clipboard` | хэш билета, затирание | — | уже в workspace | MIT OR Apache-2.0 | 0 новых |

## 7. Результаты тестирования

| Набор | LNX | LCI | WCI |
|---|---|---|---|
| `vault-crypto-proto` proto (22) | PASS | PASS (шаг) | PASS (шаг) |
| `vault-crypto-proto` nfc (16) | PASS | PASS (шаг) | PASS (шаг) |
| `aead-stream-audit` (11) | PASS | PASS (шаг) | PASS (шаг) |
| `argon2-memory` unit (5) | PASS | PASS (шаг) | PASS (шаг) |
| `win-clipboard` логика (14) | PASS | PASS (шаг) | PASS (шаг) |
| Измеритель остатков Argon2 | 0/0 в выбранном варианте | выполнен (шаг success) | 0/0 в выбранном варианте |
| Writer v2 на реальном буфере (14 проверок PASS) | NOT TESTED (Win32) | NOT TESTED | PASS |
| Tauri guard + самопроверка | PASS | PASS | PASS |
| WebView2 настройки / ACL / CSP / дампы | NOT TESTED | NOT TESTED | PASS / PASS / PASS / результат зафиксирован |
| clippy (Linux; Windows-target для pure-Rust спайков) | 0 предупреждений | — | — |

«PASS (шаг)» — шаг CI завершился успешно; поштучный вывод тестов для LCI не просматривался.

## 8. Linux CI

Задание `linux-core` (run 5): все 4 шага — success (тесты, измеритель, guard + самопроверка).

## 9. Windows CI

Задания `spikes-core` и `tauri-shell` (run 5): все шаги success; содержательные результаты — §3–4 и RESULTS_PHASE06.md.
Шаги с `continue-on-error` оценены по выводу, а не по статусу шага.

## 10. Не проверено на физической Windows 11

Всё. Обязательный минимум для закрытия Phase 0.6 — P-01, P-03, P-04, P-05, P-07, P-08, P-13, P-14, P-16, P-17, P-20
([PHYSICAL_WINDOWS_11_TEST_PLAN.md](PHYSICAL_WINDOWS_11_TEST_PLAN.md)).

## 11. Остаточные риски

Malware с правами пользователя; Master Password в памяти WebView2 (вариант A); отправка дампов WebView2 в Microsoft;
неподтверждённое соблюдение защитных форматов историей/облаком; неполный охват измерителя Argon2; неназначенные кодовые
точки в пароле; физические остатки на SSD; полный откат файла хранилища (без внешнего состояния — без изменений).

## 12. Изменённые файлы

Документы: `README.md`, `docs/ARCHITECTURE.md`, `docs/ARCHITECTURE_REVIEW.md`, `docs/CRYPTOGRAPHY.md`, `docs/DATA_MODEL.md`,
`docs/DEVELOPMENT_ROADMAP.md`, `docs/SECURITY_REQUIREMENTS.md`, `docs/THREAT_MODEL.md`; новые: `docs/PHASE_0_6_IMPLEMENTATION_PLAN.md`,
`docs/SECURE_MEMORY_ANALYSIS.md`, `docs/CRASH_DUMP_POLICY.md`, `docs/UNINSTALL_DATA_POLICY.md`, `docs/PHYSICAL_WINDOWS_11_TEST_PLAN.md`,
`docs/PHASE_0_6_REPORT.md`.
CI: `.github/workflows/phase05-windows.yml`.
Спайки: `spikes/Cargo.toml`, `spikes/Cargo.lock`; `argon2-memory/*` (новый); `vault-crypto-proto/{Cargo.toml, src/aad.rs, src/backup.rs, src/keys.rs, src/store.rs, src/bin/backup-bench.rs, tests/proto.rs, tests/nfc.rs}`;
`win-clipboard/{Cargo.toml, src/lib.rs, src/writer.rs, src/win32.rs, src/main.rs, src/legacy.rs (перенос Phase 0.5)}`; `win-memory/src/lib.rs`;
`tauri-shell/{ci/check_config.py, dist/app.js, src-tauri/{Cargo.toml, Cargo.lock, build.rs, capabilities/main.json, src/main.rs, tauri.conf.json, permissions/autogenerated/spike_crash.toml}}`;
результаты: `spikes/results/linux-container/{argon2-residue.md, nfc-mutation.txt}`, `spikes/results/windows-ci/RESULTS_PHASE06.md`.

## 13. Git-коммиты

`a24edd0` план · `fed55b4` NFC · `b6d479b` F-1 · `0c60e23` clipboard · `a909a63` Tauri · `49e3dbf` CI ·
`2153b37` политика удаления и план WIN11 · `f5df188` анализ памяти и политика дампов · `cd302ee` обновления документов ·
(этот отчёт — следующий коммит).

## 14. Готовность к следующему этапу

**Phase 0.6 — PARTIAL.** Невыполненные обязательные условия: физическая Windows 11; F-1 подтверждена лишь в пределах
охвата измерителя; D-P10 без технического решения (C-2); решения владельца по CDP-5 и UNI-4.
Phase 1 не начинать до отдельного подтверждения владельца.
