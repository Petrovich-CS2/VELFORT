# VELFORT — Phase 0.6 Implementation Plan (Security Remediation)

Дата: 2026-11-26. Статус: **план, этап B**. Phase 1 не открыта; production-модули не создаются; всё
экспериментальное — только в `spikes/`.

## 1. Результаты аудита (этап A)

* Git: ветка `claude/velfort-password-manager-c23d9y`, рабочее дерево чистое, синхронизирована с `origin`
  (последний коммит `039d5ce`).
* Документы Phase 0.5 и `spikes/` изучены. Production-кода и основного `Cargo.toml` нет.

### 1.1. Карта затрагиваемых компонентов

| Проблема | Компонент `spikes/` | Документы |
|---|---|---|
| F-2 NFC | `vault-crypto-proto` (`keys.rs`, `store.rs`, `backup.rs`, тесты) | CRYPTOGRAPHY §1.2/§2/§4, DATA_MODEL §3/§6, SECURITY_REQUIREMENTS SR-KDF-5 |
| F-1 Argon2 | `vault-crypto-proto/keys.rs`; новый `argon2-memory` (измерение остатков) | SECURE_MEMORY_ANALYSIS (новый), CRYPTOGRAPHY §8.3 |
| D-P1/D-P2 Clipboard | `win-clipboard` → библиотека `writer` (логика + Win32 backend) | ARCHITECTURE §6, THREAT_MODEL T-12, SR-CLIP-* |
| D-P4 Autofill | `tauri-shell` (`tauri.conf.json`, `main.rs`) + проверка конфигурации | ARCHITECTURE §4.1/§11, SR-UI-5 |
| D-P13 API | `tauri-shell` (`withGlobalTauri`, `app.js`) + проверка конфигурации | ARCHITECTURE_REVIEW, SR-UI-6 |
| D-P10 Crashpad | `tauri-shell` (принудительный сбой renderer, поиск дампов) | CRASH_DUMP_POLICY (новый), THREAT_MODEL T-18 |
| D-P12 Uninstall | анализ шаблона NSIS | UNINSTALL_DATA_POLICY (новый) |
| CI | `.github/workflows/phase05-windows.yml` (+ Linux-задание) | PHASE_0_6_REPORT (новый) |

### 1.2. Противоречия, выявленные до реализации

| ID | Противоречие | Источник | Последствие для плана |
|---|---|---|---|
| **C-1** | Публичный API `argon2` 0.6.0 позволяет управлять только **кучей** рабочей памяти (`hash_password_into_with_memory`). Временные значения на **стеке** не затираются: `let mut hash = [0u8; Block::SIZE]` (`src/lib.rs:383`), `r`/`q` в `Block::compress` (`src/block.rs:80-114`). Итоговые `blockhash`/`blockhash_bytes` и `initial_hash` затираются при feature `zeroize` (`lib.rs:389-390, 570-574`) | исходник | F-1 нельзя объявить исправленной одной заменой буфера; нужен измеритель остатков и оценка очистки стека (без `unsafe`) |
| **C-2** | Отправку дампов WebView2 в Microsoft отключает только `IsCustomCrashReportingEnabled` (`ICoreWebView2EnvironmentOptions3`, MS Learn «Data and privacy»); `wry` 0.57.4 создаёт окружение сам и эту опцию **не выставляет** (в `src/webview2/mod.rs` нет упоминаний; доступны только `additional_browser_args`) | исходник wry, MS Learn | D-P10 нельзя исправить конфигурацией Tauri 2.12; требуется решение владельца (принять и задокументировать / запрос в upstream / форк — форк запрещён правилами без крайней необходимости) |
| **C-3** | `@tauri-apps/api` 2.12.5 `core.js:341` вызывает `window.__TAURI_INTERNALS__.invoke`; `__TAURI_INTERNALS__` внедряется всегда. Отключение `withGlobalTauri` убирает удобные пространства имён, но **не** IPC | исходник npm-пакета | D-P13 — уменьшение поверхности «удобства», граница безопасности по-прежнему ACL; так и документировать |
| **C-4** | Встроенный в шаблон NSIS (tauri-bundler 2.10.6 `installer.nsi:915-929`) флажок «удалить данные приложения» выполняет `RmDir /r "$APPDATA\${BUNDLEID}"` и `RmDir /r "$LOCALAPPDATA\${BUNDLEID}"` — широкое рекурсивное удаление | исходник | Противоречит требованию «не использовать широкие рекурсивные операции» → политика: хранилища/бэкапы запрещено размещать в этих каталогах; альтернатива — собственный шаблон/хук (решение владельца) |
| **C-5** | Нормализация пароля меняет байты, подаваемые в Argon2id. Формат заголовка не содержит идентификатора преобразования пароля → нет способа отличить хранилища без нормализации от хранилищ с NFC и зафиксировать правило | DATA_MODEL §3, CRYPTOGRAPHY §2 | Обоснованное изменение формата: поле `pw_transform` (1 = UTF-8 NFC) в заголовке хранилища и бэкапа, включено в AAD обёртки ключа |
| **C-6** | `SetClipboardData` требует, чтобы окно было владельцем буфера; при `OpenClipboard(NULL)` `EmptyClipboard` делает владельца NULL и `SetClipboardData` завершается ошибкой (MS Learn SetClipboardData/OpenClipboard) | MS Learn | Writer требует собственного (message-only) окна, живущего до очистки, иначе невозможна проверка владельца при очистке |

## 2. Порядок исправлений

1. **F-2 NFC** — нужна для единого протокола до остальных изменений `vault-crypto-proto`.
   Зависимость: `unicode-normalization` (решение владельца; обоснование — §4).
2. **F-1** — `Zeroizing<Vec<Block>>` (затирание и при ошибке, и при раскрутке паники) + очистка стека
   неинлайнящейся функцией + отдельный поток; **измеритель остатков** (`spikes/argon2-memory`): эталонные блоки
   вычисляются в дочернем процессе, родитель после KDF сканирует собственную память на отпечатки блоков.
3. **D-P1/D-P2** — `win-clipboard`: платформенно-независимая логика (политика, результат, решение об очистке) за
   трейтом backend + Win32 backend (`OpenClipboard(hwnd)`, `EmptyClipboard`, `GlobalAlloc(GMEM_MOVEABLE)`,
   `SetClipboardData` для CF_UNICODETEXT и трёх защитных форматов в **одной** сессии; при ошибке защиты —
   `EmptyClipboard` до `CloseClipboard`). Логика тестируется на Linux поддельным backend, Win32 — в Windows CI.
4. **D-P4** — `generalAutofillEnabled: false`; явная установка и чтение `IsPasswordAutosaveEnabled`/
   `IsGeneralAutofillEnabled` через `with_webview` в спайке (проверка фактического значения); проверка UDF на
   хранилища учётных данных.
5. **D-P13** — `withGlobalTauri: false`; JS спайка через `__TAURI_INTERNALS__.invoke` (эквивалент `core.invoke`);
   проверка конфигурации (скрипт) в CI.
6. **D-P10** — эксперимент: принудительный сбой renderer (CDP `Page.crash`), фиксация `FailureReportFolderPath`,
   поиск minidump и сигнальных строк; политика.
7. **D-P12** — политика удаления по фактам шаблона NSIS и Phase 0.5.
8. Физическая Windows 11 — план тестов.
9. Документация и отчёт.

## 3. Тесты и критерии завершения

| Группа | Тесты | Среда | Критерий |
|---|---|---|---|
| A NFC | NFC/NFD, ASCII, кириллица, комбинируемые, supplementary, идемпотентность, пустая строка, бэкап, неверный `pw_transform` | LNX, CI | все проходят; мутационная проверка (без нормализации тест NFD падает) |
| B Argon2 | успех/ошибка/паника — буфер затёрт; измеритель остатков для 5 вариантов | LNX, CI | измерены фактические остатки; F-1 «FIXED» только при 0 остатков в выбранном варианте на обеих ОС |
| C Clipboard | логика: успех, отказ доступа, конкуренция, ошибка формата, очистка, чужое содержимое (fake backend); Win32: то же на реальном буфере | LNX (логика), CI (Win32) | все проходят; ни одного стирания чужого содержимого |
| D WebView2 | проверка конфигурации; фактические значения настроек WebView2; UDF без хранилищ паролей с секретами | CI | значения `false`; секретов нет |
| E Crashpad | сбой renderer → наличие/отсутствие дампа, сигнальные строки | CI | результат зафиксирован как есть |

Существующие тесты (22 + 11) не изменяются ради прохождения; при изменении API — адаптируются с сохранением проверяемого свойства.

## 4. Зависимости

| Зависимость | Зачем | Почему нельзя без неё | Поддержка | Безопасность | Лицензия | Размер |
|---|---|---|---|---|---|---|
| `unicode-normalization` 0.1.26 (+ `tinyvec`) | NFC пароля (F-2), **решение владельца** | Реализация таблиц Unicode вручную — собственный код в критическом пути | репозиторий unicode-rs; выпуск 2026-10-16; ~710 млн загрузок (crates.io) | проверяется `cargo-audit`; 9 вхождений `unsafe` вне таблиц (grep) | `(MIT OR Apache-2.0) AND Unicode-3.0` | пакет 130 122 Б; влияние на бинарник измерить |
| `windows-sys` (уже в spikes) | Win32 Clipboard | — | — | — | MIT OR Apache-2.0 | — |
| `webview2-com` 0.39 (уже транзитивно через wry) | чтение настроек WebView2 и `FailureReportFolderPath` в **спайке** | Tauri не даёт этих значений | tauri-apps | — | MIT | транзитивная, новый код не тянет |

Новые зависимости production не добавляются (production нет).

## 5. Риски плана

* Измеритель остатков ловит только копии **итоговых** блоков (отпечаток 32 байта), а не промежуточные значения `r`/`q`;
  это частичное покрытие — будет указано.
* Windows CI не равен Windows 11; история буфера обмена на раннере отключена.
* Принудительный сбой renderer может не создать дамп («a minidump file might not be generated at all», MS Learn).
