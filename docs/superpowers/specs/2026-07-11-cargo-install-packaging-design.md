# Дизайн: установка через `cargo install`

Дата: 2026-07-11
Статус: утверждён

## Цель

Сделать `check_inet` устанавливаемым через `cargo install` и готовым к публикации
на crates.io.

## Решения

- **Дистрибуция:** публикация на crates.io (полный набор метаданных). Также
  работают `cargo install --path .` и `cargo install --git <url>`.
- **Имя команды:** `check-inet` (дефис, конвенция CLI) через секцию `[[bin]]`;
  имя крейта остаётся `check_inet`.
- **Лицензия:** `MIT OR Apache-2.0` (двойная, стандарт Rust-экосистемы) + файлы
  `LICENSE-MIT` и `LICENSE-APACHE` (канонический текст Apache скачан с apache.org).
- **`authors`:** не добавляем (опционально, deprecated в современном Cargo; не
  светим email публично).
- **`description`/`keywords`/README:** на английском — конвенция crates.io
  (keywords обязаны быть ASCII).

## Изменения

- `Cargo.toml` `[package]`: `description`, `license`, `repository`
  (`https://github.com/geibos/check_inet`), `readme`, `keywords`
  (`network`, `diagnostics`, `connectivity`, `cli`, `dns`), `categories`
  (`command-line-utilities`, `network-programming`), `exclude = ["/docs"]`.
- `Cargo.toml` `[[bin]]`: `name = "check-inet"`, `path = "src/main.rs"`.
- Новые файлы: `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`.

## Верификация

- `cargo build --release` — сборка бинаря `check-inet`.
- `cargo install --path .` + запуск `check-inet` — end-to-end проверка установки.
- `cargo publish --dry-run` — валидация метаданных и упаковки без публикации.

## Вне области

- Сам `cargo publish` — действие пользователя (нужен аккаунт/токен crates.io).
- Настройка git remote и push.
