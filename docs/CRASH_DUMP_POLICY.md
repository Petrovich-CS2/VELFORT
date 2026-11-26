# VELFORT — Crash Dump Policy (D-P10)

Дата: 2026-11-26. Статус: **политика определена; механизм отключения отправки дампов WebView2 в Tauri 2.12
недоступен (ограничение C-2) — D-P10 не исправлен, только ограничен и задокументирован.**

## 1. Факты

| Факт | Источник / окружение |
|---|---|
| При сбое процесса WebView2 создаются minidump-файлы в каталоге `FailureReportFolderPath`; «for unexpected crashes, a minidump file might not be generated at all»; каталог может содержать старые дампы | MS Learn, ICoreWebView2Environment11 [DOC] |
| Дампы находятся в user data folder, в каталоге `FailureReportFolderPath` | MS Learn, «Process-related events» [DOC] |
| «If any WebView2 process crashes, one or more minidump files are created and sent to Microsoft for diagnosis» (Watson) | MS Learn, «Data and privacy» [DOC] |
| Отправку отключает только `IsCustomCrashReportingEnabled = true` (ICoreWebView2EnvironmentOptions3): «Windows won't send crash data to the Microsoft endpoint»; пользователь управляет сбором через Windows «Diagnostic data», но обязательные данные собираются независимо от настройки | MS Learn, «Data and privacy» [DOC] |
| `wry` 0.57.4 / Tauri 2.12.7 создают окружение WebView2 сами и **не** выставляют `IsCustomCrashReportingEnabled`; доступны только `additional_browser_args` | исходник `wry` `src/webview2/mod.rs` [DOC] |
| Флагов браузера для crash reporting в списке WebView2 нет; «Apps in production shouldn't use WebView2 browser flags» | MS Learn, «WebView2 browser flags» [DOC] |
| `FailureReportFolderPath` = `%LOCALAPPDATA%\<identifier>\EBWebView\Crashpad\reports` | **[CI]** (ICoreWebView2Environment11 из спайка) |
| Принудительный сбой renderer (DevTools `Page.crash`) создал `…\Crashpad\reports\<uuid>.dmp` размером **6 136 428 байт**; рядом `watson_metadata` (692 Б) | **[CI]** |
| В этом дампе сигнальных строк Master Password и секрета записи **нет** (UTF-8 и UTF-16), хотя в памяти renderer в это время пароль присутствовал (1 UTF-16 + 4 UTF-8 после reload) | **[CI]**, один прогон |
| Отправлялся ли дамп в Microsoft на раннере — **неизвестно** (сетевой трафик не анализировался) | — |

**Нельзя утверждать, что дампы не содержат секретов**: один дамп одного типа сбоя не содержал сигнальных строк;
другие сбои (браузерный процесс, иные типы дампов, иные версии Runtime) могут содержать иное.

## 2. Политика VELFORT

| ID | Правило | Обоснование | Проверка | Статус |
|---|---|---|---|---|
| CDP-1 (MUST) | VELFORT не содержит собственного crash-reporter, не отправляет диагностические данные; `panic = "abort"`; паника без данных | Privacy-first (SR-LOG-3/4) | ревью `Cargo.toml`, тест конфигурации | Прототип: соблюдается |
| CDP-2 (MUST) | Документация и UI сообщают: дампы WebView2 при сбое могут создаваться и **отправляться в Microsoft** через механизм Windows; управлять этим можно настройкой Windows «Диагностические данные» (обязательные данные собираются всегда) | Честность ограничений; C-2 | ревью текстов | Не реализовано (Phase 1) |
| CDP-3 (MUST) | При запуске и при блокировке хранилища VELFORT удаляет файлы `*.dmp` в `FailureReportFolderPath` своего профиля (адресно, без рекурсии за пределы каталога, только расширение `.dmp`), и сообщает пользователю, если удаление не удалось | Сократить время хранения дампов с возможной памятью процесса | интеграционный тест на Windows: сбой → перезапуск → дампа нет | Не реализовано |
| CDP-4 (MUST) | Секреты записей и Master Password не хранить в WebView дольше необходимого (снижает вероятность попадания в дамп renderer) | T-11 | e2e | См. SR-AUTH-1 |
| CDP-5 (SHOULD, решение владельца) | Запросить в upstream (tauri/wry) параметр `IsCustomCrashReportingEnabled`; до этого — не форкать wry | Единственный документированный механизм отключения отправки | — | Открыт |
| CDP-6 (MUST) | Не использовать недокументированные флаги браузера для отключения Crashpad | MS Learn запрещает использовать флаги в production | ревью конфигурации (guard проверяет отсутствие `additionalBrowserArgs` — добавить в Phase 1) | — |

## 3. Остаточные риски

* Дамп может уйти в Microsoft до того, как VELFORT его удалит (CDP-3 не предотвращает отправку).
* Удаление файла не затирает данные на диске (SSD).
* Сбой процесса VELFORT (Rust) под Windows Error Reporting — отдельный механизм (WER LocalDumps), не исследовался.
* Проверка на физической Windows 11 с включёнными «дополнительными» диагностическими данными — P-16/P-17.
