# VELFORT — Data Model

Статус: **ревизия 2, ожидает утверждения**. Изменения: AAD с `purpose`, формат бэкапа, режим журнала, локальное состояние (см. [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md)).

## 1. Файлы на диске

| Файл | Расположение (по умолчанию) | Содержимое | Шифрование |
|---|---|---|---|
| `<имя>.velfort` | выбирает пользователь; по умолчанию `%USERPROFILE%\Documents\VELFORT\` | SQLite-база хранилища | Все секреты и метаданные — AEAD на уровне полей; открыт только заголовок |
| `<имя>.velfort-journal` | рядом, только во время транзакции | rollback-журнал SQLite (`journal_mode=DELETE`) | Содержит только зашифрованные страницы |
| WebView2 user data folder | путь задаётся Tauri — уточнить в W6 | кэш/хранилища WebView2 | Данные записей туда не пишутся; проверяется сканером |
| `config.json` | `%APPDATA%\VELFORT\` | список недавних хранилищ, тема, язык, размер окна, `{vault_id, last_seen_generation, mac}` | Не секретно; `mac = HMAC-SHA-256(K_local, vault_id ‖ generation)` (CRYPTOGRAPHY §5.3) |
| `<имя>_<дата>.velfort-backup` | выбирает пользователь | резервная копия | Полностью зашифрована (см. §6) |
| Логи | `%LOCALAPPDATA%\VELFORT\logs\` | коды событий, без данных | Секретов не содержат по построению (SR-LOG) |

Решение: **шифрование на уровне полей (application-level AEAD)**, а не SQLCipher, потому что:

* ключ и вся криптография остаются в нашем коде на RustCrypto, с AAD-привязкой к id/ревизии записи;
* не требуется сборка SQLCipher/OpenSSL (меньше нативных зависимостей);
* бэкап = копия файла, остающаяся зашифрованной без дополнительных шагов.

Компромисс: SQLite видит структуру (число строк, размеры blob'ов, таблицы). Меры: padding до 256 байт,
отсутствие открытых метаданных записей, `PRAGMA secure_delete = ON`.

## 2. Классификация данных

| Данные | Хранение | Обоснование |
|---|---|---|
| Пароли, PIN, CVV, номера карт, TOTP-секреты, API-ключи, recovery-коды, ключи Wi-Fi, лицензионные ключи | **Зашифровано** (payload, K_items) | ТЗ 4.3 |
| Логины, e-mail, URL, домены | **Зашифровано** | раскрывают, какими сервисами пользуется человек |
| Название записи, заметки, теги, папки, избранное, иконка | **Зашифровано** | названия часто содержат персональные сведения («Сбер — карта мамы») |
| Тип записи | **Зашифровано** (внутри сводки) | раскрывает, например, наличие банковских карт |
| Даты создания/изменения записи | **Зашифровано** | раскрывают паттерны активности |
| Идентификатор записи (UUID v4, случайный) | Открыто | нужен для адресации и AAD; случайный, информации не несёт |
| `revision` (u64) | Открыто | нужен для AAD и манифеста; раскрывает число правок — принимаемая утечка |
| Размер шифротекста | Открыто (неизбежно) | сглажено padding |
| Параметры KDF, соль, wrapped DEK, версия формата, vault_id | Открыто | необходимы для разблокировки; защищены AAD |
| Имя хранилища | **Зашифровано** (в `vault_settings`); в списке недавних — имя файла | имя файла видно и так |
| Число записей | Открыто (число строк) | неизбежно без фиктивных записей; принимается |

## 3. Схема SQLite (версия схемы 1)

```sql
PRAGMA application_id = 0x56454C46;  -- 'VELF', идентификация файла
PRAGMA user_version  = 1;            -- версия схемы для миграций
PRAGMA foreign_keys  = ON;
PRAGMA secure_delete = ON;
PRAGMA journal_mode  = DELETE;       -- ревизия 2: один файл, без остатков WAL (ARCHITECTURE §9); требует решения
PRAGMA synchronous   = FULL;

CREATE TABLE vault_header (           -- ровно одна строка
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  magic           BLOB    NOT NULL,   -- 'VELFORT\0'
  format_version  INTEGER NOT NULL,
  vault_id        BLOB    NOT NULL CHECK (length(vault_id) = 16),
  kdf_alg         INTEGER NOT NULL,   -- 1 = Argon2id v0x13
  kdf_m_kib       INTEGER NOT NULL,
  kdf_t           INTEGER NOT NULL,
  kdf_p           INTEGER NOT NULL,
  kdf_salt        BLOB    NOT NULL CHECK (length(kdf_salt) = 16),
  aead_alg        INTEGER NOT NULL,   -- 1 = XChaCha20-Poly1305
  wrap_nonce      BLOB    NOT NULL CHECK (length(wrap_nonce) = 24),
  wrapped_dek     BLOB    NOT NULL CHECK (length(wrapped_dek) = 48),  -- 32 + тег 16
  header_created  INTEGER NOT NULL    -- unix-время смены заголовка (входит в AAD)
);

CREATE TABLE items (
  id          BLOB    PRIMARY KEY CHECK (length(id) = 16),
  revision    INTEGER NOT NULL CHECK (revision >= 1),
  summary     BLOB    NOT NULL,   -- envelope, AAD purpose = ITEM_SUMMARY (0x10)
  payload     BLOB    NOT NULL    -- envelope, AAD purpose = ITEM_PAYLOAD (0x11)
);

CREATE TABLE item_history (
  item_id     BLOB    NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  revision    INTEGER NOT NULL,
  payload     BLOB    NOT NULL,   -- envelope снимка предыдущей версии
  PRIMARY KEY (item_id, revision)
);

CREATE TABLE folders (
  id          BLOB    PRIMARY KEY CHECK (length(id) = 16),
  revision    INTEGER NOT NULL,
  data        BLOB    NOT NULL    -- envelope: имя, parent_id, порядок, иконка
);

CREATE TABLE attachments (          -- этап 5
  id          BLOB    PRIMARY KEY CHECK (length(id) = 16),
  item_id     BLOB    NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  revision    INTEGER NOT NULL,
  meta        BLOB    NOT NULL,   -- envelope: имя файла, MIME, размер, хеш
  chunk_count INTEGER NOT NULL
);
CREATE TABLE attachment_chunks (
  attachment_id BLOB    NOT NULL REFERENCES attachments(id) ON DELETE CASCADE,
  idx           INTEGER NOT NULL,
  data          BLOB    NOT NULL, -- envelope; AAD += idx || is_last
  PRIMARY KEY (attachment_id, idx)
);

CREATE TABLE vault_settings (       -- одна строка, envelope под K_settings
  id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL, data BLOB NOT NULL
);
CREATE TABLE manifest (             -- одна строка, envelope под K_manifest
  id INTEGER PRIMARY KEY CHECK (id = 1), generation INTEGER NOT NULL, data BLOB NOT NULL
);
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL
);
```

Отказ от `AUTOINCREMENT`/`INTEGER PRIMARY KEY` для записей: последовательные id раскрывают порядок создания.

## 4. Сводка и payload записи

Разделение нужно, чтобы держать в памяти открытого хранилища **только сводки**, а секреты расшифровывать
по требованию (CRYPTOGRAPHY §4, шаг 8).

```rust
// Иллюстрация модели (не реализация)
struct ItemSummary {          // -> items.summary
    schema: u16,
    kind: ItemKind,
    title: String,
    subtitle: Option<String>, // логин/последние 4 цифры карты/SSID — для списка
    folder_id: Option<Uuid>,
    tags: Vec<String>,
    favorite: bool,
    domains: Vec<String>,     // для поиска; полные URL — в payload
    created_at: i64, updated_at: i64, password_changed_at: Option<i64>,
    trashed_at: Option<i64>,  // корзина
}
struct ItemPayload {          // -> items.payload
    schema: u16,
    fields: ItemFields,       // по типу, ниже
    notes: Option<String>,
    custom_fields: Vec<CustomField>, // {label, value, kind: Text|Hidden|Url|Totp}
}
```

### Типы записей (`ItemFields`)

| Тип | Поля (секретные помечены *) |
|---|---|
| **Login** | username, password*, urls[], totp_secret* (этап 5), password_history* |
| **Secure Note** | body* (весь текст считается секретным) |
| **Credit Card** | cardholder, number*, expiry, cvv*, pin*, brand, issuer |
| **Identity** | first/last name, birth_date, document_type, document_number*, address, phone, email |
| **API Key** | service, key_id, secret*, scopes, expires_at, environment |
| **Wi-Fi** | ssid, security (WPA2/WPA3/…), passphrase*, hidden |
| **Software License** | product, version, licensee, email, license_key*, order_number, purchase_date |

`*` означает, что поле передаётся во frontend **только** по явной команде «показать» (`item_reveal_field`)
и никогда — в составе обычного `item_get`. Копирование выполняется командой `item_copy_field`
без возврата значения в JS.

## 5. История изменений

* При каждом изменении `payload` прошлая версия перешифровывается в `item_history` с AAD
  `record_kind = HISTORY, record_id = item_id, revision = старая ревизия`.
* Ограничение хранения (настройка в `vault_settings`): по умолчанию 20 версий или 365 дней.
* Удаление записи: сначала корзина (`trashed_at`), окончательное удаление — `DELETE` + `secure_delete`
  + обновление манифеста. **Ограничение:** `secure_delete` затирает страницы внутри файла, но не гарантирует
  удаление копий на уровне файловой системы/SSD (wear leveling, теневые копии тома).

## 6. Формат резервной копии `.velfort-backup`

Полное описание — [CRYPTOGRAPHY.md §7](CRYPTOGRAPHY.md) (ревизия 2): отдельная соль и Argon2id от Master Password,
случайный ключ бэкапа `BK`, потоковое шифрование `aead-stream` `StreamBE32` + XChaCha20-Poly1305, снимок БД
через `Connection::serialize` в память без временного файла, восстановление только в новый файл.

## 7. Миграции

1. Перед миграцией — защитная копия файла (CRYPTOGRAPHY §7.5; не требует пароля, файл зашифрован на уровне полей).
2. Миграция выполняется в одной транзакции; `user_version` обновляется в той же транзакции.
3. Неизвестная (более новая) версия формата/схемы → отказ открытия с сообщением «создано более новой версией
   VELFORT», **без попытки чтения**.
4. Миграции payload (`schema` внутри сводки/payload) — ленивые при чтении + полная при следующей записи; код
   чтения поддерживает все предыдущие версии.
5. Каждая миграция покрывается тестом: фикстура файла предыдущей версии (в репозитории) → миграция →
   проверка всех записей и манифеста.

## 8. Валидация

* Длины всех полей ограничены (title ≤ 512 символов, note ≤ 1 МиБ, вложение ≤ 64 МиБ — уточнить).
* UUID-строки из IPC парсятся строго; неизвестные поля JSON → ошибка (`#[serde(deny_unknown_fields)]`).
* SQL — только параметризованные запросы.
