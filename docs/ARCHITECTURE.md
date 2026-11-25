# VELFORT — Architecture

Статус: **черновик, ожидает утверждения**. Связанные документы: [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md),
[DATA_MODEL.md](DATA_MODEL.md), [THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Общая схема

```
┌───────────────────────── VELFORT.exe (один процесс Rust) ─────────────────────────┐
│                                                                                   │
│  ┌──────────── WebView2 (недоверенная зона отображения) ────────────┐             │
│  │ React + TypeScript UI · без доступа к ФС, сети, ключам           │             │
│  │ CSP: default-src 'self'; connect-src ipc: http://ipc.localhost    │             │
│  └──────────────┬──────────────────────────────────────────────────┘             │
│                 │ Tauri IPC (invoke) · Isolation hook · allow-list команд         │
│  ┌──────────────▼──────────────────────────────────────────────────┐             │
│  │ commands  — тонкий слой: валидация DTO, проверка состояния, маппинг ошибок      │
│  └──────────────┬──────────────────────────────────────────────────┘             │
│  ┌──────────────▼────────────── velfort-core (библиотека, без Tauri) ──────────┐  │
│  │ auth ── vault ── models ── password_generator ── backup ── import/export    │  │
│  │   │       │                                                                 │  │
│  │ crypto  storage(SQLite)          security (lock timer, clipboard, memory)   │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────┘
```

Ключевое решение: **вся бизнес-логика и безопасность — в crate `velfort-core`, не зависящем от Tauri.**
Это позволяет тестировать ядро обычными `cargo test` (в том числе на Linux CI), а Tauri-слой оставить тонким.

## 2. Модули

| Модуль | Ответственность | Не делает |
|---|---|---|
| `crypto` | Обёртки над Argon2id, XChaCha20-Poly1305, HKDF, CSPRNG; типы ключей (`Dek`, `Kek`, `SubKey`) без `Clone`/`Debug`-утечек; envelope encode/decode; AAD-конструктор | Не знает о SQLite и о записях |
| `models` | Типы записей, сводки, payload, DTO, валидация длин и форматов; версионирование схем payload | Не шифрует, не хранит |
| `storage` | SQLite через `rusqlite` (bundled SQLite), транзакции, миграции, только blob'ы и id | Не видит открытых данных |
| `vault` | `VaultSession`: открытое состояние, CRUD, поиск по сводкам, история, манифест, корзина | Не работает с IPC |
| `auth` | Создание хранилища, unlock, смена пароля, rekey, backoff | Не хранит пароль |
| `password_generator` | Генерация паролей и парольных фраз, оценка энтропии | Без сетевых словарей |
| `backup` | Экспорт/проверка/восстановление `.velfort-backup` | Не перезаписывает текущее хранилище без подтверждения |
| `security` | Таймер автоблокировки, события ОС (lock/sleep), буфер обмена, `VirtualLock`/`CryptProtectMemory`, redaction | — |
| `import_export` (этап 5) | Строгие парсеры форматов других менеджеров с лимитами | Не исполняет содержимое |
| `commands` (в `velfort-app`) | `#[tauri::command]`-функции; DTO ↔ core | Никакой логики, кроме маппинга |
| `frontend` (`ui/`) | Отображение, ввод, состояние UI | Нет крипто, нет хранения секретов дольше показа |

Правило зависимостей (проверяется `cargo` workspace-структурой): `crypto` ← `storage` ← `vault` ← `auth`,
`backup`; `commands` зависит только от публичного API `velfort-core`. Циклические зависимости запрещены.

## 3. Предлагаемая структура репозитория

```
VELFORT/
├── Cargo.toml                 # workspace
├── crates/
│   └── velfort-core/          # вся логика; #![forbid(unsafe_code)] везде, кроме security::memory (обоснованный unsafe FFI)
│       └── src/{crypto,models,storage,vault,auth,password_generator,backup,security,import_export}/
├── src-tauri/                 # velfort-app: Tauri-оболочка
│   ├── capabilities/main.json # единственная capability для окна "main"
│   ├── build.rs               # AppManifest::commands — явный allow-list
│   ├── tauri.conf.json        # productName = VELFORT, CSP, без devtools в release
│   └── src/{main.rs,commands/}
├── ui/                        # React + TypeScript + Vite
│   └── src/{app,screens(lock,vault,item,generator,settings),components,ipc(типизированный клиент),styles(tokens.css)}
├── tests/fixtures/            # эталонные файлы хранилищ и бэкапов всех версий формата
├── docs/
├── deny.toml                  # cargo-deny: лицензии, advisories, запрет дубликатов/источников
└── .github/workflows/         # CI: Linux (core tests) + Windows (app, e2e, сборка установщика)
```

## 4. Граница frontend / backend

### 4.1. Правила

1. Frontend **не имеет доступа к базе данных и к файловой системе**: плагины `fs`, `shell`, `http`, `sql`,
   `updater`, `opener` не подключаются. Выбор файла — через `tauri-plugin-dialog` (только диалог,
   путь возвращается в Rust, а не читается JS).
2. Все команды перечислены в `AppManifest::commands`; по умолчанию Tauri разрешает все зарегистрированные
   команды всем окнам (https://v2.tauri.app/security/capabilities/), поэтому allow-list обязателен.
3. Одно окно с меткой `main`; удалённые URL не загружаются; навигация за пределы бандла блокируется.
4. Isolation pattern включается; скрипт изоляции пишется без ES-модулей (ограничение Windows, указанное в
   https://v2.tauri.app/concept/inter-process-communication/isolation/). Хук проверяет имя команды
   по списку и форму аргументов — это **дополнительный** уровень; основная валидация — в Rust.
5. Каждая команда: строго типизированный DTO (`serde`, `deny_unknown_fields`), лимиты длины, проверка
   состояния сессии (Locked/Unlocked), единый тип ошибки `AppError { code, message_key }` без внутренних деталей.

### 4.2. Каталог команд (этапы 1–4)

| Команда | Состояние | Возвращает в JS | Примечание |
|---|---|---|---|
| `vault_list_recent` | любое | пути и имена файлов | |
| `vault_create(path, password)` | Locked | `Ok` | калибровка KDF, прогресс событием |
| `vault_unlock(path, password)` | Locked | `VaultInfo` | backoff |
| `vault_lock()` | любое | `Ok` | идемпотентна |
| `vault_status()` | любое | `Locked/Unlocked` + таймер | |
| `items_list(filter)` / `items_search(query)` | Unlocked | `ItemSummaryDto[]` (без секретов) | поиск в Rust по сводкам |
| `item_get(id)` | Unlocked | поля **без** секретов (`password: Masked`) | |
| `item_reveal_field(id, field)` | Unlocked | значение секрета | событие аудита в памяти; UI скрывает через N с |
| `item_copy_field(id, field)` | Unlocked | `Ok` | **значение не покидает Rust** |
| `item_create/update(dto)` | Unlocked | `id, revision` | секреты приходят из JS при вводе (неизбежно) |
| `item_delete(id)` / `item_restore(id)` / `item_purge(id)` | Unlocked | `Ok` | корзина |
| `item_history(id)` | Unlocked | список ревизий (без секретов) | |
| `folders_*`, `item_set_favorite` | Unlocked | | |
| `generator_generate(options)` | любое | сгенерированное значение | генерация в Rust; значение неизбежно отображается |
| `generator_copy(options)` | любое | оценка энтропии | генерирует и копирует, не возвращая значение |
| `auth_change_password(old, new)` | Unlocked | `Ok` | |
| `backup_create(path)` / `backup_verify(path)` / `backup_restore(path, target)` | разные | отчёт | |
| `settings_get/update` | разные | | |
| `activity_ping()` | Unlocked | — | продление таймера от активности в окне |

## 5. Жизненный цикл сессии и блокировка

```
           create/unlock (успех)
  Locked ───────────────────────────► Unlocked
    ▲                                    │
    │  vault_lock / таймер бездействия / │
    │  блокировка сеанса Windows /       │
    │  сон или гибернация / закрытие окна│
    └────────────────────────────────────┘
```

Источники блокировки (реализация в `security::lock`):

1. **Ручная**: кнопка, `Ctrl+L`, пункт трея.
2. **Бездействие**: таймер в Rust (по умолчанию 5 мин, настраивается 1–60 мин; «никогда» — не предлагается
   либо только с предупреждением — вопрос на согласование). Активность = `activity_ping` из окна VELFORT
   (дебаунс), а также опционально системное бездействие (`GetLastInputInfo`).
3. **События ОС**: блокировка сеанса (`WTSRegisterSessionNotification` → `WTS_SESSION_LOCK`),
   переход в сон (`WM_POWERBROADCAST`/`PBT_APMSUSPEND`) — блокировка **до** засыпания.
4. **Минимизация/свёртывание в трей** — опционально.

Действия при блокировке (в Rust, синхронно, до ответа):

1. `VaultSession` удаляется: DEK, подключи, сводки, поисковый индекс — затираются (`Drop` + `zeroize`).
2. Запланированная очистка буфера обмена выполняется немедленно (если там ещё наше значение).
3. В WebView отправляется событие `vault://locked`; frontend сбрасывает store и **перезагружает документ**
   (`location.reload`) — это освобождает JS-объекты для GC, но не гарантирует затирание памяти.
4. Любая команда, требующая Unlocked, после этого возвращает `VaultLocked`.

## 6. Буфер обмена

* Запись выполняется в Rust через `arboard` (3.7.0). В исходном коде `arboard` 3.7.0
  (`src/platform/windows.rs`) есть `exclude_from_monitoring`, `exclude_from_cloud`, `exclude_from_history`,
  регистрирующие форматы `ExcludeClipboardContentFromMonitorProcessing`, `CanUploadToCloudClipboard`,
  `CanIncludeInClipboardHistory`. По документации Microsoft
  (https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats) первый формат исключает
  содержимое из истории буфера обмена и синхронизации на другие устройства.
* Автоочистка через N секунд (по умолчанию 30 с): очищаем **только если буфер всё ещё содержит наше значение**
  (сравнение хеша, вычисленного при копировании, в постоянном времени; хеш затирается после очистки).
* Ограничения, явно показываемые пользователю: любое приложение пользователя может прочитать буфер, пока
  значение в нём; сторонние менеджеры буфера обмена могут игнорировать флаги исключения; гарантии удаления
  нет.

## 7. Сборка, зависимости, поставка

* Rust: `edition 2024`, `#![deny(warnings)]` в CI, `clippy -D warnings`, `cargo-deny` (лицензии,
  advisories RustSec, запрет git-зависимостей), `cargo-audit`. В release: `panic = "abort"`, `lto`,
  `strip`, отключение devtools.
* Frontend: зафиксированный `package-lock.json`, `npm ci`, минимальный набор (React, React DOM,
  `@tauri-apps/api`, Vite, TypeScript, тестовые инструменты); никаких CDN.
* Установщик: Tauri bundler (NSIS и/или MSI), `VELFORT_<ver>_x64-setup.exe`. Подпись Authenticode — требует
  сертификата (вопрос на согласование). WebView2 — системный Evergreen Runtime (на Windows 11 предустановлен —
  подтвердить по документации Microsoft при подготовке установщика).
* Автообновление по сети **отключено** (offline/privacy-first). Обновление — загрузкой нового установщика
  вручную; вопрос о подписанном опциональном updater — на согласование.

## 8. Наблюдаемость без утечек

* Логи: только `event_code`, уровень, время, версия; никаких путей к хранилищу (опционально), заголовков записей,
  значений. Реализация: `tracing` с собственным форматтером и типами-обёртками `Redacted<T>`.
* Нет телеметрии, crash-reporting SDK, сетевых вызовов. Проверяется тестом: сборка не содержит HTTP-клиента
  (`cargo tree` без `reqwest`/`hyper`/`ureq`) и e2e-тестом без сетевой активности.
