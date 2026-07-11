# Дизайн: порт `check_inet` с Python на Rust

Дата: 2026-07-11
Статус: утверждён (ожидает финального ревью спеки)

## Цель

Переписать утилиту проверки интернет-связности `check_inet.py` в самодостаточный
Rust-бинарник. Поведение оригинала сохраняется; единственное намеренное отличие —
ненулевой exit code при неуспехе.

## Что делает оригинал (`check_inet.py`)

Три проверки связности выполняются **параллельно**, каждая с таймаутом 3 секунды:

1. **Router** — парсит вывод `ip r`, находит `default via <IP>`, делает TCP-connect к `<IP>:80`.
2. **TCP** — TCP-connect к `8.8.8.8:443`.
3. **HTTP** — HTTPS GET к `https://ya.ru` (через `httpx`).

Результаты печатаются построчно:

```
{name:<13} | {sigil} | {time:.4f}[ | {error}]
```

где `sigil` = 🟢 (успех) / 🛑 (провал), `error` добавляется только при провале
(текст ошибки либо `Timeout`).

Retry-логика (`main`): аргументы `--times/-t` (int, default 1) и `--delay/-d`
(float секунд, default 1). Цикл до `times` попыток; строка `try i / times`
печатается только при `times > 1`; ранний выход при успехе; `sleep(delay)` между
попытками. Exit code оригинала — всегда 0.

## Решения по дизайну

- **Платформа:** Linux + macOS (кроссплатформенное определение шлюза).
- **Стек:** минимальный — `std::thread` + `std::net::TcpStream` + `ureq` (blocking, rustls)
  для HTTPS. Без tokio/reqwest/regex.
- **Exit code:** `0`, если последняя попытка успешна; иначе `1`. При `times = 0`
  (как в Python — цикл не выполняется) — exit `0`.
- **(A) Модель:** функциональная (struct `CheckOutcome` + три функции), без
  trait-иерархии — проще и идиоматичнее для утилиты этого размера.
- **(B) Таймауты:** нативные, на самой блокирующей операции (`connect_timeout`,
  таймаут `ureq`), а не через отмену потоков (потоки в std не отменяются чисто).
- **(B) Семантика HTTP:** любой полученный HTTP-ответ = успех (как `httpx`, который
  не бросает на 4xx/5xx). В `ureq` статус-ошибки (не-2xx) маплю в **успех**; в провал —
  только транспортные ошибки (DNS/TLS/connect/timeout).
- **(C) CLI:** `clap` (derive) — даёт `--help`, валидацию и сообщения об ошибках,
  аналогично argparse.

## Архитектура

```
src/
├── main.rs      — CLI (clap), retry-цикл, оркестрация потоков, exit code
├── check.rs     — struct CheckOutcome + форматирование строки результата
├── checks.rs    — check_router(), check_tcp(), check_http()
└── gateway.rs   — кроссплатформенное определение default-шлюза (#[cfg] per-OS)
```

### `check.rs`

```rust
pub struct CheckOutcome {
    pub name: String,
    pub success: bool,
    pub elapsed: Duration,
    pub error: Option<String>,
}
```

- `CheckOutcome::row(&self) -> String` — формирует строку вывода в точном формате
  оригинала: имя с левым выравниванием по ширине 13, sigil, время с 4 знаками после
  запятой, опциональный ` | {error}` при провале (`error` либо `Timeout`).
- Хелпер маппинга ошибок в строку: `io::ErrorKind::TimedOut` и таймаут `ureq` → `"Timeout"`;
  прочие → `Display` ошибки. (Точная строка Python `"{ClassName} {msg}"` не
  воспроизводится — сохраняется смысл: показать причину.)

### `checks.rs`

Три функции, каждая возвращает `CheckOutcome`, сама измеряет своё время
(`Instant::now()` → `elapsed`) и применяет таймаут 3с:

- `check_router()` — вызывает `gateway::detect()`; при отсутствии шлюза → `CheckOutcome`
  с именем `<no route>`, `success = false`, `error = Some("No route")`. Иначе имя = IP
  шлюза, `TcpStream::connect_timeout(<gw>:80, 3s)`.
- `check_tcp()` — имя `8.8.8.8`, `TcpStream::connect_timeout(8.8.8.8:443, 3s)`.
- `check_http()` — имя `ya.ru`, `ureq` GET `https://ya.ru` с таймаутом 3с; статус-ошибки
  → успех, транспортные → провал.

Константа `TIMEOUT: Duration = Duration::from_secs(3)`.

### `gateway.rs`

`detect() -> Option<Ipv4Addr>` — определяет default-шлюз, ручной парсинг (без `regex`):

- **Linux** (`#[cfg(target_os = "linux")]`): `ip route`, строка `default via <IP> ...` —
  берётся токен после `via`.
- **macOS** (`#[cfg(target_os = "macos")]`): `route -n get default`, строка `gateway: <IP>` —
  берётся последний токен.

Парсинг выделен в чистые функции `parse_linux(&str)` и `parse_macos(&str)` для
юнит-тестирования на фикстурах.

### `main.rs`

- Парсинг аргументов через `clap` derive: `times: u32` (default 1), `delay: f64` (default 1.0).
- Оркестрация: `std::thread::scope` — три потока (`check_router`, `check_tcp`, `check_http`),
  результаты собираются **в исходном порядке** и печатаются.
- Retry-цикл повторяет семантику оригинала (строка `try i / times` при `times > 1`,
  ранний выход при успехе, `sleep(Duration::from_secs_f64(delay))` между попытками).
- Exit code через `std::process::exit` (или возврат из `main`): `0` при успехе последней
  попытки, иначе `1`.

## Обработка ошибок

- Внешние команды (`ip route`, `route`): при ошибке запуска/ненулевом коде — шлюз
  считается не найденным (`None`), проверка router → `No route`.
- Все сетевые ошибки не паникуют — конвертируются в `CheckOutcome { success: false, error }`.
- `unwrap()`/`expect()` — только в тестах и на действительно недостижимых состояниях.

## Тестирование

Тестируется чистая логика без сети (там вся нетривиальная часть):

- `gateway::parse_linux` / `parse_macos` — фикстуры вывода → ожидаемый IP (включая
  случаи «нет default», мусор, несколько маршрутов).
- Маппинг ошибок в строку, включая ветку `Timeout`.
- `CheckOutcome::row()` — форматирование для успеха и провала (паддинг, `.4f`, ` | error`).
- Маппинг статус-ошибки `ureq` в успех.

Сетевые проверки (`check_tcp` и т.п.) не мокаются — они интеграционные и зависят от
окружения; логика в них минимальна.

## Зависимости

- `ureq` — blocking HTTPS (rustls).
- `clap` (derive) — CLI.

## Явно вне области (YAGNI)

- Никакого async-рантайма.
- Конфигурируемые хосты/порты/таймаут не добавляются (в оригинале захардкожены).
- Без логирования/цветного вывода сверх исходного формата.
