# Adaptive Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Расширить `check_inet` до адаптивной диагностики: один бинарь при неполадках определяет, на каком этапе (локальный IP → шлюз → интернет → DNS → приложение → captive portal) ломается связность, с быстрым early-return когда всё здорово.

**Architecture:** Фаза 1 (быстрая, как сейчас) гоняет параллельно шлюз + интернет-по-IP + приложение; если всё зелёное — exit 0. При провале — эскалация: параллельный прогон дополнительных проб, интерпретация результатов как лесенки зависимостей (корень = первый упавший этап снизу вверх), печать вердикта, exit = номер этапа. Все пробы синхронные (std threads), без async.

**Tech Stack:** Rust (edition 2024), std::net (TcpStream/UdpSocket), ureq 3.3 (blocking HTTPS, rustls), clap 4.6 (derive). Никаких новых зависимостей.

## Global Constraints

- rustc ≥ 1.85 (edition 2024); в окружении 1.96.1.
- Зависимости: только уже присутствующие — `ureq 3.3.0`, `clap 4.6.1`. **Новые крейты не добавлять** (спека: стек минимальный, без async/regex/hickory).
- Платформы: Linux + macOS. Платформо-зависимый код — под `#[cfg(target_os = ...)]`, парсеры доступны в тестах через `#[cfg(any(target_os = "...", test))]`.
- `TIMEOUT: Duration = Duration::from_secs(3)` — единая константа для всех проб (уже есть в `checks.rs`).
- Стиль: `cargo fmt` перед каждым коммитом. Production-код без `unwrap()` (в тестах — можно); в проде — `.expect("...")` с обоснованием только на действительно недостижимых состояниях.
- **Гейт clippy (важно для bottom-up TDD):** `pub fn` в binary-крейте, используемая пока только своими тестами, ловится линтом `dead_code`. Поэтому: на **чисто-логических** задачах (1, 3, 4, 5, 7, 8, 9) гейт — `cargo test` (функции покрыты тестами) + `cargo clippy --all-targets` **информационно** (транзиентный `dead_code` для ещё-не-подключённых функций ожидаем). На задачах-**обвязках** (2, 6, 10, 11, 12) и в **финале** (13) — жёсткий `cargo clippy --all-targets -- -D warnings` должен быть чист (к этому моменту всё подключено). Каждая `pub`-функция обязана быть использована в non-test коде к концу плана.
- Rust-дисциплина: при написании кода держать активным skill `rust-intel` (§B2/B3 неприменимы — async нет; §C2 error handling, §C5 reflexive clone, §A1 API — применимы).
- **Коммиты — ТОЛЬКО по явной просьбе пользователя** (правило git.md, переопределяет дефолт). Шаги «Commit» в задачах выполнять лишь после явного разрешения; иначе останавливаться на зелёных тестах и ждать. Сообщения коммитов — conventional commits, **без упоминания AI/Claude** в любом виде.
- Комментарии и пользовательский вывод — на русском.

**Итоговые типы (ссылка для всех задач):**

```rust
// check.rs (существует)
pub struct CheckOutcome { pub name: String, pub success: bool, pub elapsed: Duration, pub error: Option<String> }
impl CheckOutcome { pub fn row(&self) -> String; }
pub fn io_error_text(err: &io::Error) -> Option<String>;

// net.rs (новый)
pub fn kind_is_reachable(kind: io::ErrorKind) -> bool;
pub fn local_ip() -> Option<IpAddr>;
pub fn probe_ipv6() -> CheckOutcome;

// target.rs (новый)
pub enum Target { Host { host: String, port: u16 }, Ip { addr: IpAddr, port: u16 } }
impl Target {
    pub fn parse(input: &str) -> Result<Target, String>;
    pub fn host(&self) -> Option<&str>;      // Some(host) для Host, None для Ip
    pub fn display_name(&self) -> String;   // "ya.ru:443" / "8.8.8.8:443"
    pub fn connect_addr(&self) -> String;    // "ya.ru:443" / "[ipv6]:443"
}
impl Default for Target { /* Host { "ya.ru", 443 } */ }

// checks.rs (эволюция)
pub fn probe_gateway() -> CheckOutcome;                 // reachability до <шлюз>:80
pub fn probe_internet() -> CheckOutcome;                // reachability до 8.8.8.8:443
pub fn probe_application(target: &Target) -> CheckOutcome; // Host→HTTPS, IP→TCP:443
pub fn probe_captive() -> CheckOutcome;                 // generate_204; success=нет портала
pub fn classify_http<T>(result: Result<T, ureq::Error>) -> (bool, Option<String>); // существует

// dns.rs (новый)
pub fn build_query(name: &str, id: u16) -> Vec<u8>;
pub struct DnsAnswer { pub id: u16, pub rcode: u8, pub ancount: u16 }
pub fn parse_response(buf: &[u8]) -> Option<DnsAnswer>;
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr>;
pub fn parse_scutil(text: &str) -> Vec<IpAddr>;
pub enum QueryOutcome { Resolved, NxDomain, NoResponse }
pub enum DnsVerdict { Ok, SystemBrokenPublicWorks, Blocked, Nxdomain }
pub fn classify_dns(system: &[QueryOutcome], public: &[QueryOutcome]) -> DnsVerdict;
pub fn probe_dns(target: &Target) -> (CheckOutcome, bool); // (строка вывода, dns_ok)

// diag.rs (новый)
#[repr(u8)] pub enum Stage { LocalIp=1, Gateway=2, Internet=3, Dns=4, Application=5, CaptivePortal=6 }
pub fn exit_code(stage: Option<Stage>) -> u8;
pub struct DiagReport { pub local_ip: bool, pub gateway: bool, pub internet: bool, pub dns: bool, pub application: bool, pub captive_ok: bool }
pub fn root_cause(r: &DiagReport) -> Option<Stage>;
pub fn verdict_line(stage: Option<Stage>) -> String;
```

---

## Phase 1 — reachability

### Task 1: Reachability-классификация (`net.rs`)

**Files:**
- Create: `src/net.rs`
- Modify: `src/main.rs` (добавить `mod net;`)
- Test: в `src/net.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `pub fn kind_is_reachable(kind: std::io::ErrorKind) -> bool` — true, если исход TCP-connect доказывает, что хост жив (ответил).

- [ ] **Step 1: Написать падающий тест**

Создать `src/net.rs`:

```rust
//! Сетевые пробы: reachability-классификация, локальный IP, IPv6.

use std::io;

/// Доказывает ли исход TCP-connect, что хост жив (ответил на пакет).
///
/// `ConnectionRefused`/`ConnectionReset` = хост ответил RST → достижим.
/// `TimedOut`/`*Unreachable`/прочее → недостижим.
pub fn kind_is_reachable(kind: io::ErrorKind) -> bool {
    let _ = kind;
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_means_reachable() {
        assert!(kind_is_reachable(io::ErrorKind::ConnectionRefused));
        assert!(kind_is_reachable(io::ErrorKind::ConnectionReset));
    }

    #[test]
    fn timeout_and_unreachable_mean_not_reachable() {
        assert!(!kind_is_reachable(io::ErrorKind::TimedOut));
        assert!(!kind_is_reachable(io::ErrorKind::HostUnreachable));
        assert!(!kind_is_reachable(io::ErrorKind::NetworkUnreachable));
    }
}
```

Добавить в начало `src/main.rs` (после `mod check;`): `mod net;`

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test net:: 2>&1 | tail -15`
Expected: FAIL — `refused_means_reachable` (assert!(false)).

- [ ] **Step 3: Реализовать**

```rust
pub fn kind_is_reachable(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
    )
}
```

- [ ] **Step 4: Запустить тест — убедиться, что проходит**

Run: `cargo test net:: 2>&1 | tail -8`
Expected: PASS (2 теста).

- [ ] **Step 5: Commit** (только после явного разрешения пользователя)

```bash
git add src/net.rs src/main.rs
git commit -m "feat: add reachability classification"
```

---

### Task 2: Пробы фазы 1 на reachability (`checks.rs`)

Существующие `check_router`/`check_tcp` дают ложный 🛑 при `Connection refused` (шлюз/хост жив, но не слушает порт). Переводим их на reachability и переименовываем в `probe_gateway`/`probe_internet`; `check_http` → `probe_application` (пока с дефолтным `ya.ru`, target придёт в Task 6).

**Files:**
- Modify: `src/checks.rs` (переписать `check_router`→`probe_gateway`, `check_tcp`→`probe_internet`, `check_http`→`probe_application`; добавить `reachability_probe`)
- Modify: `src/main.rs` (обновить вызовы в `run_checks`)
- Test: в `src/checks.rs`

**Interfaces:**
- Consumes: `crate::net::kind_is_reachable` (Task 1); `CheckOutcome`, `io_error_text` (check.rs); `gateway::detect` (gateway.rs); `classify_http` (существует).
- Produces:
  - `pub fn probe_gateway() -> CheckOutcome`
  - `pub fn probe_internet() -> CheckOutcome`
  - `pub fn probe_application() -> CheckOutcome` (сигнатура без аргумента в этой задаче; получит `&Target` в Task 6)
  - `fn reachability_outcome(name: String, result: io::Result<TcpStream>, start: Instant) -> CheckOutcome` (внутренняя)

- [ ] **Step 1: Написать падающий тест**

В `src/checks.rs` в `mod tests` добавить (проверяем чистую суть reachability-обёртки через хелпер, без сети — вынесем классификацию исхода в тестируемую функцию `reachable_from_result`):

```rust
    #[test]
    fn reachability_counts_refused_as_success() {
        // Ok → success, error None
        let ok: io::Result<()> = Ok(());
        assert_eq!(reachable_from_result(&ok), (true, None));

        // refused → success (хост жив), error None
        let refused: io::Result<()> =
            Err(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert_eq!(reachable_from_result(&refused), (true, None));
    }

    #[test]
    fn reachability_counts_timeout_as_failure() {
        let t: io::Result<()> = Err(io::Error::from(io::ErrorKind::TimedOut));
        let (success, error) = reachable_from_result(&t);
        assert!(!success);
        assert_eq!(error, None); // TimedOut → io_error_text даёт None → строка "Timeout"
    }

    #[test]
    fn reachability_reports_other_errors() {
        let e: io::Result<()> = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let (success, error) = reachable_from_result(&e);
        assert!(!success);
        assert!(error.is_some());
    }
```

Добавить импорты в тест-модуль при необходимости (`use std::io;`).

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test checks:: 2>&1 | tail -15`
Expected: FAIL — `reachable_from_result` не определена (E0425).

- [ ] **Step 3: Реализовать**

Переписать `src/checks.rs` целиком:

```rust
//! Пробы связности фазы 1.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::check::{CheckOutcome, io_error_text};
use crate::gateway;
use crate::net::kind_is_reachable;

/// Таймаут одной пробы (как в оригинале — 3 секунды).
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// Классифицирует исход TCP-connect в терминах reachability.
///
/// `Ok` и «хост ответил» (refused/reset) → успех без ошибки.
/// Таймаут → провал, `None` (в строке станет `Timeout`).
/// Прочее → провал с текстом ошибки.
fn reachable_from_result<T>(result: &io::Result<T>) -> (bool, Option<String>) {
    match result {
        Ok(_) => (true, None),
        Err(err) if kind_is_reachable(err.kind()) => (true, None),
        Err(err) => (false, io_error_text(err)),
    }
}

/// Reachability-проба TCP до `addr`; `start` задаёт начало отсчёта времени.
fn reachability_outcome(name: String, addr: SocketAddr, start: Instant) -> CheckOutcome {
    let result = TcpStream::connect_timeout(&addr, TIMEOUT);
    let (success, error) = reachable_from_result(&result);
    CheckOutcome { name, success, elapsed: start.elapsed(), error }
}

/// Этап «шлюз»: определяет default-шлюз, reachability до `<шлюз>:80`.
pub fn probe_gateway() -> CheckOutcome {
    let start = Instant::now();
    match gateway::detect() {
        Some(gw) => reachability_outcome(gw.to_string(), SocketAddr::from((gw, 80)), start),
        None => CheckOutcome {
            name: "<no route>".to_string(),
            success: false,
            elapsed: start.elapsed(),
            error: Some("No route".to_string()),
        },
    }
}

/// Этап «интернет»: reachability до якорного публичного IP `8.8.8.8:443`.
pub fn probe_internet() -> CheckOutcome {
    let start = Instant::now();
    let addr = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 443));
    reachability_outcome("8.8.8.8".to_string(), addr, start)
}

/// Этап «приложение»: HTTPS GET к `https://ya.ru`.
pub fn probe_application() -> CheckOutcome {
    let start = Instant::now();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let (success, error) = classify_http(agent.get("https://ya.ru").call());
    CheckOutcome { name: "ya.ru".to_string(), success, elapsed: start.elapsed(), error }
}

/// Классифицирует результат HTTP-запроса `ureq` в пару `(success, error)`.
///
/// Любой полученный ответ (в т.ч. 4xx/5xx) — успех, как `httpx` в оригинале.
/// Провал — транспортные ошибки; таймаут даёт `None` (→ `Timeout`).
pub fn classify_http<T>(result: Result<T, ureq::Error>) -> (bool, Option<String>) {
    match result {
        Ok(_) | Err(ureq::Error::StatusCode(_)) => (true, None),
        Err(ureq::Error::Timeout(_)) => (false, None),
        Err(err) => (false, Some(err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ... существующие тесты classify_http (ok/4xx/5xx/transport/timeout) сохранить ...

    #[test]
    fn reachability_counts_refused_as_success() {
        let ok: io::Result<()> = Ok(());
        assert_eq!(reachable_from_result(&ok), (true, None));
        let refused: io::Result<()> = Err(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert_eq!(reachable_from_result(&refused), (true, None));
    }

    #[test]
    fn reachability_counts_timeout_as_failure() {
        let t: io::Result<()> = Err(io::Error::from(io::ErrorKind::TimedOut));
        let (success, error) = reachable_from_result(&t);
        assert!(!success);
        assert_eq!(error, None);
    }

    #[test]
    fn reachability_reports_other_errors() {
        let e: io::Result<()> = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let (success, error) = reachable_from_result(&e);
        assert!(!success);
        assert!(error.is_some());
    }
}
```

> Сохранить пять существующих `classify_http`-тестов из текущего файла (`ok_response_is_success`, `status_4xx_is_success`, `status_5xx_is_success`, `transport_error_is_failure_with_message`, `timeout_is_failure_without_message`) — они не меняются.

Обновить `src/main.rs` `run_checks()`:

```rust
    let outcomes = thread::scope(|scope| {
        let gw = scope.spawn(checks::probe_gateway);
        let net = scope.spawn(checks::probe_internet);
        let app = scope.spawn(checks::probe_application);
        [
            gw.join().expect("поток проверки шлюза паникнул"),
            net.join().expect("поток интернет-пробы паникнул"),
            app.join().expect("поток приложения паникнул"),
        ]
    });
```

- [ ] **Step 4: Запустить тесты + clippy**

Run: `cargo test 2>&1 | grep -E 'test result|error\[' && cargo clippy --all-targets -- -D warnings 2>&1 | tail -3`
Expected: все тесты PASS (8 gateway + 3 check + 5 classify_http + 3 reachability = 19); clippy чист.

- [ ] **Step 5: Реальный прогон**

Run: `cargo build --release 2>&1 | tail -1 && ./target/release/check_inet; echo "exit: $?"`
Expected: три строки; шлюз теперь 🟢 (refused=reachable), 8.8.8.8 🟢, ya.ru 🟢 при рабочей сети → exit 0.

- [ ] **Step 6: Commit** (после явного разрешения)

```bash
git add src/checks.rs src/main.rs
git commit -m "feat: reachability semantics for gateway/internet probes"
```

---

## Phase 2 — target

### Task 3: Разбор аргумента target (`target.rs`)

**Files:**
- Create: `src/target.rs`
- Modify: `src/main.rs` (`mod target;`)
- Test: в `src/target.rs`

**Interfaces:**
- Produces: `Target` enum + `parse`/`is_host`/`host`/`display_name`/`connect_addr` + `Default`.

- [ ] **Step 1: Написать падающий тест**

Создать `src/target.rs`:

```rust
//! Разбор необязательного аргумента цели `host[:port]` / `ip[:port]`.

use std::net::{IpAddr, SocketAddr};

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Host { host: String, port: u16 },
    Ip { addr: IpAddr, port: u16 },
}

impl Default for Target {
    fn default() -> Self {
        Target::Host { host: "ya.ru".to_string(), port: 443 }
    }
}

impl Target {
    /// Разбирает `host`, `host:port`, `ip`, `ip:port`, `[ipv6]:port`.
    /// Порт по умолчанию — 443. Возвращает `Err(описание)` на пустом вводе.
    pub fn parse(input: &str) -> Result<Target, String> {
        let _ = input;
        Err("stub".to_string())
    }

    pub fn host(&self) -> Option<&str> {
        match self {
            Target::Host { host, .. } => Some(host),
            Target::Ip { .. } => None,
        }
    }

    /// Имя для строки вывода: `host:port` / `ip:port`.
    pub fn display_name(&self) -> String {
        match self {
            Target::Host { host, port } => format!("{host}:{port}"),
            Target::Ip { addr, port } => format!("{addr}:{port}"),
        }
    }

    /// Адрес для connect/URL: то же `host:port` (IPv6 — в скобках).
    pub fn connect_addr(&self) -> String {
        match self {
            Target::Host { host, port } => format!("{host}:{port}"),
            Target::Ip { addr: IpAddr::V6(a), port } => format!("[{a}]:{port}"),
            Target::Ip { addr, port } => format!("{addr}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn plain_host_defaults_to_443() {
        assert_eq!(
            Target::parse("example.com").unwrap(),
            Target::Host { host: "example.com".to_string(), port: 443 }
        );
    }

    #[test]
    fn host_with_port() {
        assert_eq!(
            Target::parse("example.com:8443").unwrap(),
            Target::Host { host: "example.com".to_string(), port: 8443 }
        );
    }

    #[test]
    fn ipv4_without_port() {
        assert_eq!(
            Target::parse("1.1.1.1").unwrap(),
            Target::Ip { addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), port: 443 }
        );
    }

    #[test]
    fn ipv4_with_port() {
        assert_eq!(
            Target::parse("1.1.1.1:53").unwrap(),
            Target::Ip { addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), port: 53 }
        );
    }

    #[test]
    fn ipv6_bracketed_with_port() {
        let t = Target::parse("[2001:4860:4860::8888]:443").unwrap();
        assert!(matches!(t, Target::Ip { port: 443, .. }));
        assert_eq!(t.connect_addr(), "[2001:4860:4860::8888]:443");
    }

    #[test]
    fn bare_ipv6_defaults_to_443() {
        let t = Target::parse("2001:4860:4860::8888").unwrap();
        assert!(matches!(t, Target::Ip { port: 443, .. }));
    }

    #[test]
    fn empty_is_error() {
        assert!(Target::parse("").is_err());
    }

    #[test]
    fn host_returns_name_ip_returns_none() {
        assert_eq!(Target::parse("example.com").unwrap().host(), Some("example.com"));
        assert_eq!(Target::parse("1.1.1.1").unwrap().host(), None);
    }
}
```

Добавить `mod target;` в `src/main.rs`.

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test target:: 2>&1 | tail -15`
Expected: FAIL — `parse` возвращает `Err("stub")`, падают все позитивные кейсы.

- [ ] **Step 3: Реализовать `parse`**

```rust
    pub fn parse(input: &str) -> Result<Target, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("пустая цель".to_string());
        }
        // 1) ip:port или [ipv6]:port
        if let Ok(sa) = input.parse::<SocketAddr>() {
            return Ok(Target::Ip { addr: sa.ip(), port: sa.port() });
        }
        // 2) голый IP (v4/v6) → порт 443
        if let Ok(addr) = input.parse::<IpAddr>() {
            return Ok(Target::Ip { addr, port: 443 });
        }
        // 3) host:port — только если суффикс валидный порт и в хосте нет ':'
        if let Some((host, port)) = input.rsplit_once(':') {
            if !host.contains(':') && !host.is_empty() {
                if let Ok(port) = port.parse::<u16>() {
                    return Ok(Target::Host { host: host.to_string(), port });
                }
            }
        }
        // 4) голый host → порт 443
        Ok(Target::Host { host: input.to_string(), port: 443 })
    }
```

- [ ] **Step 4: Запустить тесты + clippy**

Run: `cargo test target:: 2>&1 | tail -12 && cargo clippy --all-targets 2>&1 | tail -4`
Expected: 8 target-тестов PASS. Возможен транзиентный `dead_code` для `host()`/`display_name()`/`connect_addr()` — они подключаются в Task 6/10 (см. гейт clippy в Global Constraints). Иных warnings быть не должно.

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/target.rs src/main.rs
git commit -m "feat: parse optional target argument"
```

---

## Phase 3 — diag ladder + adaptive flow

### Task 4: `Stage` + exit-коды (`diag.rs`)

**Files:**
- Create: `src/diag.rs`
- Modify: `src/main.rs` (`mod diag;`)
- Test: в `src/diag.rs`

**Interfaces:**
- Produces: `pub enum Stage` (repr u8, 1..6), `pub fn exit_code(stage: Option<Stage>) -> u8`.

- [ ] **Step 1: Написать падающий тест**

Создать `src/diag.rs`:

```rust
//! Лесенка диагностики: этапы, интерпретация, вердикт, exit-коды.

/// Этап связности. Номер = exit code при провале на этом этапе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    LocalIp = 1,
    Gateway = 2,
    Internet = 3,
    Dns = 4,
    Application = 5,
    CaptivePortal = 6,
}

/// Exit code: 0 если здорово (`None`), иначе номер этапа-корня.
pub fn exit_code(stage: Option<Stage>) -> u8 {
    let _ = stage;
    255
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_exits_zero() {
        assert_eq!(exit_code(None), 0);
    }

    #[test]
    fn stage_maps_to_its_number() {
        assert_eq!(exit_code(Some(Stage::LocalIp)), 1);
        assert_eq!(exit_code(Some(Stage::Gateway)), 2);
        assert_eq!(exit_code(Some(Stage::Internet)), 3);
        assert_eq!(exit_code(Some(Stage::Dns)), 4);
        assert_eq!(exit_code(Some(Stage::Application)), 5);
        assert_eq!(exit_code(Some(Stage::CaptivePortal)), 6);
    }
}
```

Добавить `mod diag;` в `src/main.rs`.

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test diag:: 2>&1 | tail -12`
Expected: FAIL — `healthy_exits_zero` (255 != 0).

- [ ] **Step 3: Реализовать**

```rust
pub fn exit_code(stage: Option<Stage>) -> u8 {
    stage.map_or(0, |s| s as u8)
}
```

- [ ] **Step 4: Запустить тесты**

Run: `cargo test diag:: 2>&1 | tail -8`
Expected: 2 теста PASS.

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/diag.rs src/main.rs
git commit -m "feat: add diagnostic Stage enum and exit code mapping"
```

---

### Task 5: Интерпретация лесенки `root_cause` + вердикт (`diag.rs`)

**Files:**
- Modify: `src/diag.rs`
- Test: в `src/diag.rs`

**Interfaces:**
- Consumes: `Stage` (Task 4).
- Produces: `pub struct DiagReport { local_ip, gateway, internet, dns, application, captive_ok: bool }`, `pub fn root_cause(&DiagReport) -> Option<Stage>`, `pub fn verdict_line(Option<Stage>) -> String`.

- [ ] **Step 1: Написать падающий тест**

В `src/diag.rs` добавить после enum (перед `mod tests`):

```rust
/// Результаты проб: `true` = этап пройден. `captive_ok = false` → обнаружен портал.
pub struct DiagReport {
    pub local_ip: bool,
    pub gateway: bool,
    pub internet: bool,
    pub dns: bool,
    pub application: bool,
    pub captive_ok: bool,
}

/// Первый упавший этап снизу вверх. CaptivePortal имеет приоритет над Application.
pub fn root_cause(r: &DiagReport) -> Option<Stage> {
    let _ = r;
    Some(Stage::LocalIp)
}

/// Человекочитаемая строка вердикта.
pub fn verdict_line(stage: Option<Stage>) -> String {
    let _ = stage;
    String::new()
}
```

В `mod tests` добавить:

```rust
    fn healthy() -> DiagReport {
        DiagReport { local_ip: true, gateway: true, internet: true, dns: true, application: true, captive_ok: true }
    }

    #[test]
    fn all_pass_no_root() {
        assert_eq!(root_cause(&healthy()), None);
    }

    #[test]
    fn first_failure_bottom_up() {
        let r = DiagReport { local_ip: false, ..healthy() };
        assert_eq!(root_cause(&r), Some(Stage::LocalIp));

        let r = DiagReport { gateway: false, ..healthy() };
        assert_eq!(root_cause(&r), Some(Stage::Gateway));

        let r = DiagReport { internet: false, ..healthy() };
        assert_eq!(root_cause(&r), Some(Stage::Internet));

        let r = DiagReport { dns: false, ..healthy() };
        assert_eq!(root_cause(&r), Some(Stage::Dns));

        let r = DiagReport { application: false, ..healthy() };
        assert_eq!(root_cause(&r), Some(Stage::Application));
    }

    #[test]
    fn lower_stage_wins_over_higher() {
        // и шлюз, и приложение упали → корень = шлюз (ниже)
        let r = DiagReport { gateway: false, application: false, ..healthy() };
        assert_eq!(root_cause(&r), Some(Stage::Gateway));
    }

    #[test]
    fn captive_portal_takes_priority_over_application() {
        // интернет и dns ок, приложение упало, но обнаружен портал → CaptivePortal
        let r = DiagReport { application: false, captive_ok: false, ..healthy() };
        assert_eq!(root_cause(&r), Some(Stage::CaptivePortal));
    }

    #[test]
    fn lower_stage_wins_over_captive() {
        // портал «обнаружен», но реально нет даже интернета → корень Internet, не портал
        let r = DiagReport { internet: false, captive_ok: false, ..healthy() };
        assert_eq!(root_cause(&r), Some(Stage::Internet));
    }

    #[test]
    fn verdict_mentions_stage() {
        assert!(verdict_line(None).contains("здоров") || verdict_line(None).contains("ok"));
        assert!(verdict_line(Some(Stage::Dns)).contains("[4]"));
        assert!(verdict_line(Some(Stage::CaptivePortal)).contains("[6]"));
    }
```

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test diag:: 2>&1 | tail -20`
Expected: FAIL — `all_pass_no_root` (получает `Some(LocalIp)` вместо `None`).

- [ ] **Step 3: Реализовать**

```rust
pub fn root_cause(r: &DiagReport) -> Option<Stage> {
    if !r.local_ip {
        return Some(Stage::LocalIp);
    }
    if !r.gateway {
        return Some(Stage::Gateway);
    }
    if !r.internet {
        return Some(Stage::Internet);
    }
    if !r.dns {
        return Some(Stage::Dns);
    }
    // Портал проверяем после нижних этапов, но раньше Application:
    // он маскируется под сбой приложения (TLS-перехват), являясь актуальной причиной.
    if !r.captive_ok {
        return Some(Stage::CaptivePortal);
    }
    if !r.application {
        return Some(Stage::Application);
    }
    None
}

pub fn verdict_line(stage: Option<Stage>) -> String {
    match stage {
        None => "вердикт: связь здорова".to_string(),
        Some(Stage::LocalIp) => "корень: [1] нет локального IP — линк/DHCP не выдал адрес".to_string(),
        Some(Stage::Gateway) => "корень: [2] шлюз недостижим — проблема в локальной сети/роутере".to_string(),
        Some(Stage::Internet) => "корень: [3] нет выхода в интернет — публичный IP недостижим (маршрут/ISP)".to_string(),
        Some(Stage::Dns) => "корень: [4] DNS не работает — имена не резолвятся".to_string(),
        Some(Stage::Application) => "корень: [5] уровень приложения — TLS/HTTP до цели не отвечает".to_string(),
        Some(Stage::CaptivePortal) => "корень: [6] captive portal — сеть требует авторизации".to_string(),
    }
}
```

- [ ] **Step 4: Запустить тесты + clippy**

Run: `cargo test diag:: 2>&1 | tail -12 && cargo clippy --all-targets 2>&1 | tail -4`
Expected: 8 diag-тестов PASS. Возможен транзиентный `dead_code` для `root_cause`/`verdict_line`/`DiagReport` — подключаются в Task 6. Иных warnings быть не должно.

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/diag.rs
git commit -m "feat: ladder interpretation and verdict lines"
```

---

### Task 6: Адаптивный поток в `main.rs` + target-аргумент

Связывает фазу 1, target и лесенку (пока на пробах фазы 1: local_ip/dns/captive считаются пройденными — их пробы добавятся в фазе 4-5). Даёт рабочий бинарь с новыми exit-кодами и вердиктом.

**Files:**
- Modify: `src/main.rs` (Args + target, `run_phase1`, эскалация, exit code)
- Modify: `src/checks.rs` (`probe_application` принимает `&Target`)
- Test: реальный прогон (main — I/O-оркестрация)

**Interfaces:**
- Consumes: `checks::probe_gateway/probe_internet/probe_application` (Task 2), `target::Target` (Task 3), `diag::{DiagReport, root_cause, exit_code, verdict_line, Stage}` (Task 4-5).
- Produces: обновлённый `probe_application(target: &Target) -> CheckOutcome`.

- [ ] **Step 1: Обновить `probe_application` под `&Target`**

В `src/checks.rs` заменить `probe_application`:

```rust
use crate::target::Target;

/// Этап «приложение»: для Host — HTTPS GET; для IP — TCP-connect к порту цели.
pub fn probe_application(target: &Target) -> CheckOutcome {
    let start = Instant::now();
    match target {
        Target::Host { .. } => {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_global(Some(TIMEOUT))
                .build()
                .into();
            let url = format!("https://{}", target.connect_addr());
            let (success, error) = classify_http(agent.get(&url).call());
            CheckOutcome { name: target.display_name(), success, elapsed: start.elapsed(), error }
        }
        Target::Ip { addr, port } => {
            let saddr = SocketAddr::from((*addr, *port));
            // Реальный connect (не reachability): закрытый порт = сбой приложения.
            let result = TcpStream::connect_timeout(&saddr, TIMEOUT);
            let (success, error) = match &result {
                Ok(_) => (true, None),
                Err(err) => (false, io_error_text(err)),
            };
            CheckOutcome { name: target.display_name(), success, elapsed: start.elapsed(), error }
        }
    }
}
```

Добавить `use std::net::SocketAddr;` если ещё не импортирован (он уже есть в checks.rs). Убедиться, что `Ipv4Addr` всё ещё используется (в `probe_internet`).

- [ ] **Step 2: Переписать `src/main.rs`**

```rust
mod check;
mod checks;
mod diag;
mod gateway;
mod net;
mod target;

use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use clap::Parser;

use crate::check::CheckOutcome;
use crate::diag::{DiagReport, Stage, exit_code, root_cause, verdict_line};
use crate::target::Target;

/// Диагностика интернет-связности: определяет, на каком этапе ломается связь.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Цель для проверки уровня приложения: host[:port] или ip[:port] (по умолчанию ya.ru:443)
    target: Option<String>,

    /// Число попыток фазы 1
    #[arg(short, long, default_value_t = 1)]
    times: u32,

    /// Задержка между попытками, секунд
    #[arg(short, long, default_value_t = 1.0)]
    delay: f64,
}

/// Фаза 1: параллельно шлюз + интернет + приложение. Печатает строки, возвращает исходы.
fn run_phase1(target: &Target) -> [CheckOutcome; 3] {
    let outcomes = thread::scope(|scope| {
        let gw = scope.spawn(checks::probe_gateway);
        let net = scope.spawn(checks::probe_internet);
        let app = scope.spawn(|| checks::probe_application(target));
        [
            gw.join().expect("поток проверки шлюза паникнул"),
            net.join().expect("поток интернет-пробы паникнул"),
            app.join().expect("поток приложения паникнул"),
        ]
    });
    for o in &outcomes {
        println!("{}", o.row());
    }
    outcomes
}

fn main() -> ExitCode {
    let args = Args::parse();
    let target = match args.target.as_deref() {
        Some(s) => match Target::parse(s) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("неверная цель '{s}': {e}");
                return ExitCode::from(2);
            }
        },
        None => Target::default(),
    };

    // Фаза 1 с retry. Семантика оригинала: строка `try i / times` печатается перед
    // каждой попыткой при times > 1; ранний выход при успехе; задержка между попытками.
    // times == 0 → цикл не выполняется, проверок нет, exit 0.
    let mut phase1: Option<[CheckOutcome; 3]> = None;
    for attempt in 1..=args.times {
        if args.times > 1 {
            println!("try {attempt} / {}", args.times);
        }
        let outcomes = run_phase1(&target);
        let ok = outcomes.iter().all(|o| o.success);
        phase1 = Some(outcomes);
        if ok || attempt == args.times {
            break;
        }
        thread::sleep(Duration::from_secs_f64(args.delay));
    }

    // Early-return: нечего проверять (times == 0) или всё зелёное.
    let phase1 = match phase1 {
        Some(p) => p,
        None => return ExitCode::SUCCESS,
    };
    if phase1.iter().all(|o| o.success) {
        return ExitCode::SUCCESS;
    }

    // Эскалация: диагностика. В этой задаче доп-пробы (local_ip/dns/captive)
    // считаются пройденными — они добавятся в фазах 4-5.
    println!("--- диагностика ---");
    let report = DiagReport {
        local_ip: true,
        gateway: phase1[0].success,
        internet: phase1[1].success,
        dns: true,
        application: phase1[2].success,
        captive_ok: true,
    };
    let stage = root_cause(&report);
    println!("{}", verdict_line(stage));
    ExitCode::from(exit_code(stage))
}
```

> Примечание: retry-семантика слегка изменена (early-check в начале итерации), но снаружи эквивалентна оригиналу: строка `try N / M` печатается перед повторной попыткой, между попытками — задержка, ранний выход при успехе.

- [ ] **Step 3: Тесты + clippy**

Run: `cargo test 2>&1 | grep -E 'test result|error\[' && cargo clippy --all-targets -- -D warnings 2>&1 | tail -3`
Expected: все юнит-тесты PASS (19 из фаз 1-2 + 10 diag = без изменений в числе target/diag); clippy чист.

- [ ] **Step 4: Реальный прогон — happy path + target + сбой**

Run:
```bash
cargo build --release 2>&1 | tail -1
echo "--- default ---"; ./target/release/check_inet; echo "exit: $?"
echo "--- target host:port ---"; ./target/release/check_inet example.com:443; echo "exit: $?"
echo "--- target ip ---"; ./target/release/check_inet 1.1.1.1; echo "exit: $?"
echo "--- unreachable target → application stage ---"; ./target/release/check_inet 10.255.255.1:443; echo "exit: $?"
```
Expected: рабочая сеть → default/host/ip дают 3×🟢 и exit 0. Недостижимая цель `10.255.255.1:443` → шлюз/интернет 🟢, приложение 🛑 (timeout) → блок диагностики + «корень: [5] …» + exit 5.

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/main.rs src/checks.rs
git commit -m "feat: adaptive flow with target arg and exit-by-stage"
```

---

## Phase 4 — deep DNS

### Task 7: `build_query` (`dns.rs`)

**Files:**
- Create: `src/dns.rs`
- Modify: `src/main.rs` (`mod dns;`)
- Test: в `src/dns.rs`

**Interfaces:**
- Produces: `pub fn build_query(name: &str, id: u16) -> Vec<u8>`.

- [ ] **Step 1: Написать падающий тест**

Создать `src/dns.rs`:

```rust
//! Глубокая DNS-диагностика: ручной DNS-по-UDP + определение резолверов.

use std::net::IpAddr;

/// Строит DNS-запрос типа A для `name` с transaction id `id`.
///
/// Формат (RFC 1035): 12-байтовый заголовок (id, flags=0x0100 recursion desired,
/// QDCOUNT=1, остальные счётчики 0) + QNAME (label-длина + байты) + 0x00 +
/// QTYPE=1 (A) + QCLASS=1 (IN).
pub fn build_query(name: &str, id: u16) -> Vec<u8> {
    let _ = (name, id);
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_question_layout() {
        let q = build_query("ya.ru", 0x1234);
        // Заголовок
        assert_eq!(&q[0..2], &[0x12, 0x34]); // id
        assert_eq!(&q[2..4], &[0x01, 0x00]); // flags: recursion desired
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT = 1
        assert_eq!(&q[6..12], &[0, 0, 0, 0, 0, 0]); // AN/NS/AR count = 0
        // QNAME: 2 "ya" 2 "ru" 0
        assert_eq!(&q[12..13], &[2]);
        assert_eq!(&q[13..15], b"ya");
        assert_eq!(&q[15..16], &[2]);
        assert_eq!(&q[16..18], b"ru");
        assert_eq!(&q[18..19], &[0]); // терминатор
        // QTYPE=A, QCLASS=IN
        assert_eq!(&q[19..21], &[0x00, 0x01]);
        assert_eq!(&q[21..23], &[0x00, 0x01]);
    }

    #[test]
    fn total_length_is_correct() {
        // 12 (header) + 1+2 + 1+2 + 1 (qname) + 4 (qtype+qclass) = 23
        assert_eq!(build_query("ya.ru", 1).len(), 23);
    }
}
```

Добавить `mod dns;` в `src/main.rs`.

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test dns::tests::header 2>&1 | tail -12`
Expected: FAIL — пустой `Vec`, паника на индексации `q[0..2]`.

- [ ] **Step 3: Реализовать**

```rust
pub fn build_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes()); // id
    q.extend_from_slice(&[0x01, 0x00]);     // flags: recursion desired
    q.extend_from_slice(&[0x00, 0x01]);     // QDCOUNT = 1
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // терминатор QNAME
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    q
}
```

> Заметка (§C4/clippy): `label.len() as u8` — clippy может предложить проверку. Имена доменов имеют метки ≤ 63 байт по стандарту; для диагностики этого достаточно. Если clippy `-D warnings` ругнётся на `cast_possible_truncation` (это `pedantic`, не в дефолтном наборе `-D warnings`), оставить как есть — дефолтный `-D warnings` его не включает.

- [ ] **Step 4: Запустить тесты**

Run: `cargo test dns:: 2>&1 | tail -8`
Expected: 2 теста PASS.

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/dns.rs src/main.rs
git commit -m "feat: build DNS A-query packet"
```

---

### Task 8: `parse_response` (`dns.rs`)

**Files:**
- Modify: `src/dns.rs`
- Test: в `src/dns.rs`

**Interfaces:**
- Produces: `pub struct DnsAnswer { id: u16, rcode: u8, ancount: u16 }`, `pub fn parse_response(buf: &[u8]) -> Option<DnsAnswer>`.

- [ ] **Step 1: Написать падающий тест**

В `src/dns.rs` добавить перед `mod tests`:

```rust
/// Извлечённые поля DNS-ответа.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub id: u16,
    pub rcode: u8,
    pub ancount: u16,
}

/// Парсит заголовок DNS-ответа. `None`, если буфер короче 12 байт или это не ответ (QR=0).
pub fn parse_response(buf: &[u8]) -> Option<DnsAnswer> {
    let _ = buf;
    None
}
```

В `mod tests`:

```rust
    #[test]
    fn parses_successful_answer() {
        // id=0x1234, flags=0x8180 (QR=1, RD, RA, RCODE=0), QD=1, AN=2
        let buf = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0, 0, 0, 0];
        assert_eq!(
            parse_response(&buf),
            Some(DnsAnswer { id: 0x1234, rcode: 0, ancount: 2 })
        );
    }

    #[test]
    fn parses_nxdomain() {
        // flags=0x8183 → RCODE=3 (NXDOMAIN), AN=0
        let buf = [0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0];
        assert_eq!(
            parse_response(&buf),
            Some(DnsAnswer { id: 1, rcode: 3, ancount: 0 })
        );
    }

    #[test]
    fn rejects_query_flag_qr0() {
        // QR=0 (это запрос, не ответ) → None
        let buf = [0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0];
        assert_eq!(parse_response(&buf), None);
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(parse_response(&[0x00, 0x01, 0x81]), None);
    }
```

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test dns::tests::parses 2>&1 | tail -12`
Expected: FAIL — `parses_successful_answer` (None вместо Some).

- [ ] **Step 3: Реализовать**

```rust
pub fn parse_response(buf: &[u8]) -> Option<DnsAnswer> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return None; // QR=0: не ответ
    }
    Some(DnsAnswer {
        id: u16::from_be_bytes([buf[0], buf[1]]),
        rcode: (flags & 0x000F) as u8,
        ancount: u16::from_be_bytes([buf[6], buf[7]]),
    })
}
```

- [ ] **Step 4: Запустить тесты**

Run: `cargo test dns:: 2>&1 | tail -10`
Expected: 6 dns-тестов PASS (2 build + 4 parse).

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/dns.rs
git commit -m "feat: parse DNS response header"
```

---

### Task 9: Определение резолверов (`dns.rs`)

**Files:**
- Modify: `src/dns.rs`
- Test: в `src/dns.rs`

**Interfaces:**
- Produces: `pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr>`, `pub fn parse_scutil(text: &str) -> Vec<IpAddr>`.

- [ ] **Step 1: Написать падающий тест**

В `src/dns.rs` перед `mod tests`:

```rust
/// Извлекает `nameserver <IP>` из содержимого `/etc/resolv.conf` (Linux).
#[cfg(any(target_os = "linux", test))]
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let _ = text;
    Vec::new()
}

/// Извлекает `nameserver[N] : <IP>` из вывода `scutil --dns` (macOS).
#[cfg(any(target_os = "macos", test))]
pub fn parse_scutil(text: &str) -> Vec<IpAddr> {
    let _ = text;
    Vec::new()
}
```

В `mod tests`:

```rust
    use std::net::Ipv4Addr;

    #[test]
    fn resolv_conf_extracts_nameservers() {
        let text = "# comment\nnameserver 192.168.1.1\nnameserver 8.8.8.8\noptions edns0\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ]
        );
    }

    #[test]
    fn resolv_conf_empty_when_none() {
        assert!(parse_resolv_conf("options edns0\n").is_empty());
    }

    #[test]
    fn scutil_extracts_nameservers() {
        let text = "resolver #1\n  nameserver[0] : 192.168.0.1\n  nameserver[1] : 1.1.1.1\n  flags  : Request A records\n";
        assert_eq!(
            parse_scutil(text),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ]
        );
    }

    #[test]
    fn scutil_ignores_non_ip() {
        let text = "  nameserver[0] : garbage\n  flags : x\n";
        assert!(parse_scutil(text).is_empty());
    }
```

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test dns::tests::resolv 2>&1 | tail -12`
Expected: FAIL — пустой `Vec` вместо двух адресов.

- [ ] **Step 3: Реализовать**

```rust
#[cfg(any(target_os = "linux", test))]
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("nameserver")?;
            rest.trim().parse().ok()
        })
        .collect()
}

#[cfg(any(target_os = "macos", test))]
pub fn parse_scutil(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("nameserver[") {
                return None;
            }
            let (_, ip) = line.rsplit_once(':')?;
            ip.trim().parse().ok()
        })
        .collect()
}
```

- [ ] **Step 4: Запустить тесты + clippy**

Run: `cargo test dns:: 2>&1 | tail -12 && cargo clippy --all-targets 2>&1 | tail -4`
Expected: 10 dns-тестов PASS. Возможен транзиентный `dead_code` для `parse_resolv_conf`/`parse_scutil` — подключаются в Task 10 через `detect_resolvers`. Иных warnings быть не должно.

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/dns.rs
git commit -m "feat: parse system resolver configuration"
```

---

### Task 10: DNS-классификация + I/O-проба + подключение в лесенку

**Files:**
- Modify: `src/dns.rs` (classify + I/O: `detect_resolvers`, `query_server`, `probe_dns`)
- Modify: `src/main.rs` (вызвать `probe_dns` в эскалации, обновить `report.dns`)
- Test: `classify_dns` — юнит; проба — реальный прогон.

**Interfaces:**
- Consumes: `build_query`, `parse_response`, `parse_resolv_conf`/`parse_scutil`, `target::Target`, `check::CheckOutcome`, `checks::TIMEOUT`.
- Produces: `pub enum QueryOutcome { Resolved, NxDomain, NoResponse }`, `pub enum DnsVerdict {...}`, `pub fn classify_dns(&[QueryOutcome], &[QueryOutcome]) -> DnsVerdict`, `pub fn probe_dns(target: &Target) -> (CheckOutcome, bool)`.

- [ ] **Step 1: Написать падающий тест (classify_dns)**

В `src/dns.rs` перед `mod tests`:

```rust
/// Исход одного DNS-запроса к одному серверу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOutcome {
    Resolved,   // RCODE=0, ANCOUNT>0
    NxDomain,   // RCODE=3
    NoResponse, // таймаут / ошибка / прочий RCODE
}

/// Вердикт этапа DNS.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsVerdict {
    Ok,
    SystemBrokenPublicWorks,
    Blocked,
    Nxdomain,
}

impl DnsVerdict {
    /// Пройден ли этап DNS для целей лесенки (только `Ok`).
    pub fn is_ok(&self) -> bool {
        matches!(self, DnsVerdict::Ok)
    }
}

/// Интерпретирует исходы запросов к системным и публичным серверам.
pub fn classify_dns(system: &[QueryOutcome], public: &[QueryOutcome]) -> DnsVerdict {
    let _ = (system, public);
    DnsVerdict::Blocked
}
```

В `mod tests`:

```rust
    #[test]
    fn dns_ok_when_system_resolves() {
        assert_eq!(
            classify_dns(&[QueryOutcome::Resolved], &[QueryOutcome::NoResponse]),
            DnsVerdict::Ok
        );
    }

    #[test]
    fn dns_system_broken_when_only_public_resolves() {
        assert_eq!(
            classify_dns(&[QueryOutcome::NoResponse], &[QueryOutcome::Resolved]),
            DnsVerdict::SystemBrokenPublicWorks
        );
    }

    #[test]
    fn dns_blocked_when_all_silent() {
        assert_eq!(
            classify_dns(&[QueryOutcome::NoResponse], &[QueryOutcome::NoResponse]),
            DnsVerdict::Blocked
        );
    }

    #[test]
    fn dns_nxdomain_when_resolvers_answer_nxdomain() {
        assert_eq!(
            classify_dns(&[QueryOutcome::NxDomain], &[QueryOutcome::NxDomain]),
            DnsVerdict::Nxdomain
        );
    }
```

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cargo test dns::tests::dns_ok 2>&1 | tail -10`
Expected: FAIL — `Blocked` вместо `Ok`.

- [ ] **Step 3: Реализовать classify_dns + I/O**

```rust
pub fn classify_dns(system: &[QueryOutcome], public: &[QueryOutcome]) -> DnsVerdict {
    let resolved = |s: &[QueryOutcome]| s.iter().any(|o| *o == QueryOutcome::Resolved);
    if resolved(system) {
        return DnsVerdict::Ok;
    }
    if resolved(public) {
        return DnsVerdict::SystemBrokenPublicWorks;
    }
    let all = system.iter().chain(public);
    if all.clone().all(|o| *o == QueryOutcome::NoResponse) {
        return DnsVerdict::Blocked;
    }
    if all.clone().any(|o| *o == QueryOutcome::NxDomain) {
        return DnsVerdict::Nxdomain;
    }
    DnsVerdict::Blocked
}
```

Добавить I/O (после classify_dns):

```rust
use std::net::{SocketAddr, UdpSocket};
use crate::check::CheckOutcome;
use crate::checks::TIMEOUT;
use crate::target::Target;
use std::time::Instant;

/// Публичные DNS для фолбэка.
const PUBLIC_DNS: [IpAddr; 2] = [
    IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
];

/// Фиксированный transaction id: для диагностики достаточно (не защита от спуфинга).
const DNS_QUERY_ID: u16 = 0x7A7A;

/// Определяет системные DNS-серверы (платформо-зависимо).
fn detect_resolvers() -> Vec<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|t| parse_resolv_conf(&t))
            .unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("scutil")
            .arg("--dns")
            .output()
            .ok()
            .map(|o| parse_scutil(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Один DNS-запрос типа A к серверу; исход по таймауту/ответу.
fn query_server(server: IpAddr, name: &str) -> QueryOutcome {
    let socket = match UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => return QueryOutcome::NoResponse,
    };
    if socket.set_read_timeout(Some(TIMEOUT)).is_err() {
        return QueryOutcome::NoResponse;
    }
    let query = build_query(name, DNS_QUERY_ID);
    if socket.send_to(&query, SocketAddr::from((server, 53))).is_err() {
        return QueryOutcome::NoResponse;
    }
    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) => match parse_response(&buf[..n]) {
            Some(a) if a.id == DNS_QUERY_ID && a.rcode == 0 && a.ancount > 0 => QueryOutcome::Resolved,
            Some(a) if a.rcode == 3 => QueryOutcome::NxDomain,
            _ => QueryOutcome::NoResponse,
        },
        Err(_) => QueryOutcome::NoResponse,
    }
}

/// Этап «DNS»: резолвит имя цели (или `ya.ru`) через системные и публичные серверы.
/// Возвращает строку вывода и `dns_ok` для лесенки.
pub fn probe_dns(target: &Target) -> (CheckOutcome, bool) {
    let start = Instant::now();
    let name = target.host().unwrap_or("ya.ru");
    let resolvers = detect_resolvers();
    let system: Vec<QueryOutcome> = resolvers.iter().map(|s| query_server(*s, name)).collect();
    let public: Vec<QueryOutcome> = PUBLIC_DNS.iter().map(|s| query_server(*s, name)).collect();
    let verdict = classify_dns(&system, &public);
    let ok = verdict.is_ok();
    let error = if ok {
        None
    } else {
        Some(match verdict {
            DnsVerdict::SystemBrokenPublicWorks => "системный DNS не отвечает, публичные работают".to_string(),
            DnsVerdict::Blocked => "DNS недоступен (:53 заблокирован?)".to_string(),
            DnsVerdict::Nxdomain => format!("имя '{name}' не существует (NXDOMAIN)"),
            DnsVerdict::Ok => unreachable!(),
        })
    };
    let outcome = CheckOutcome { name: "dns".to_string(), success: ok, elapsed: start.elapsed(), error };
    (outcome, ok)
}
```

> §A1: `UdpSocket::bind/send_to/recv_from/set_read_timeout` — стабильные std API. `Ipv4Addr::UNSPECIFIED` = `0.0.0.0`.

Обновить `src/main.rs` — в блоке эскалации заменить `dns: true`:

```rust
    println!("--- диагностика ---");
    let (dns_outcome, dns_ok) = dns::probe_dns(&target);
    println!("{}", dns_outcome.row());
    let report = DiagReport {
        local_ip: true,
        gateway: phase1[0].success,
        internet: phase1[1].success,
        dns: dns_ok,
        application: phase1[2].success,
        captive_ok: true,
    };
```

- [ ] **Step 4: Тесты + clippy + реальный прогон**

Run:
```bash
cargo test 2>&1 | grep -E 'test result|error\['
cargo clippy --all-targets -- -D warnings 2>&1 | tail -3
cargo build --release 2>&1 | tail -1
echo "--- nxdomain host → dns/app fail ---"
./target/release/check_inet nonexistent-abcxyz.invalid; echo "exit: $?"
```
Expected: юнит-тесты PASS (14 dns), clippy чист. Прогон с несуществующим именем: DNS-строка покажет NXDOMAIN; корень — [4] DNS или [5] Application в зависимости от того, что упало (для `.invalid` DNS вернёт NXDOMAIN → dns_ok=false → корень [4]).

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/dns.rs src/main.rs
git commit -m "feat: deep DNS probing with system/public resolver fallback"
```

---

## Phase 5 — captive portal, local IP, IPv6

### Task 11: Локальный IP + этап LocalIp (`net.rs`)

**Files:**
- Modify: `src/net.rs` (`local_ip`), `src/checks.rs` (`probe_local_ip`), `src/main.rs` (wire LocalIp)
- Test: реальный прогон (I/O; чистой логики нет — только сокет-трюк).

**Interfaces:**
- Produces: `pub fn local_ip() -> Option<IpAddr>` (net.rs), `pub fn probe_local_ip() -> CheckOutcome` (checks.rs).

- [ ] **Step 1: Реализовать `local_ip` в `net.rs`**

Добавить в `src/net.rs`:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// Определяет локальный IP через UDP-connect к публичному адресу (пакеты не шлются —
/// connect лишь выбирает исходящий интерфейс по таблице маршрутизации).
/// `None`, если сокет не создан/не привязан или адрес неопределён (нет линка).
pub fn local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 80))).ok()?;
    let addr = socket.local_addr().ok()?.ip();
    if addr.is_unspecified() { None } else { Some(addr) }
}
```

- [ ] **Step 2: Добавить `probe_local_ip` в `checks.rs`**

```rust
use std::time::Instant;
use crate::net::local_ip;

/// Этап «локальный IP»: есть ли рабочий исходящий адрес.
pub fn probe_local_ip() -> CheckOutcome {
    let start = Instant::now();
    match local_ip() {
        Some(ip) => CheckOutcome { name: ip.to_string(), success: true, elapsed: start.elapsed(), error: None },
        None => CheckOutcome {
            name: "<no local ip>".to_string(),
            success: false,
            elapsed: start.elapsed(),
            error: Some("нет локального адреса (линк/DHCP)".to_string()),
        },
    }
}
```

(`Instant` уже импортирован в checks.rs — не дублировать `use`.)

- [ ] **Step 3: Подключить в `main.rs` эскалацию**

В блоке диагностики, до печати dns, добавить local ip и параллелить с dns:

```rust
    println!("--- диагностика ---");
    let (local, dns_res) = thread::scope(|scope| {
        let l = scope.spawn(checks::probe_local_ip);
        let d = scope.spawn(|| dns::probe_dns(&target));
        (l.join().expect("поток local-ip паникнул"), d.join().expect("поток dns паникнул"))
    });
    let (dns_outcome, dns_ok) = dns_res;
    println!("{}", local.row());
    println!("{}", dns_outcome.row());
    let report = DiagReport {
        local_ip: local.success,
        gateway: phase1[0].success,
        internet: phase1[1].success,
        dns: dns_ok,
        application: phase1[2].success,
        captive_ok: true,
    };
```

- [ ] **Step 4: Тесты + clippy + прогон**

Run:
```bash
cargo test 2>&1 | grep -E 'test result|error\['
cargo clippy --all-targets -- -D warnings 2>&1 | tail -3
cargo build --release 2>&1 | tail -1
./target/release/check_inet 10.255.255.1:443; echo "exit: $?"
```
Expected: тесты PASS без изменений; при сбое до цели блок диагностики показывает строку локального IP (🟢 при наличии сети).

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/net.rs src/checks.rs src/main.rs
git commit -m "feat: local IP detection as bottom ladder rung"
```

---

### Task 12: Captive portal (`checks.rs`)

**Files:**
- Modify: `src/checks.rs` (`probe_captive`), `src/main.rs` (wire captive_ok)
- Test: `classify_captive` — юнит; проба — реальный прогон.

**Interfaces:**
- Produces: `pub fn probe_captive() -> CheckOutcome` (success=нет портала), внутренняя `fn classify_captive(status: Option<u16>) -> bool`.

- [ ] **Step 1: Написать падающий тест (classify_captive)**

В `src/checks.rs` `mod tests`:

```rust
    #[test]
    fn captive_204_means_no_portal() {
        assert!(classify_captive(Some(204))); // ok=нет портала
    }

    #[test]
    fn captive_non_204_means_portal() {
        assert!(!classify_captive(Some(200))); // портал перехватил
        assert!(!classify_captive(Some(302)));
    }

    #[test]
    fn captive_no_response_is_inconclusive_ok() {
        // нет ответа (сети нет) → не наша забота, считаем «портала нет»
        assert!(classify_captive(None));
    }
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cargo test checks::tests::captive 2>&1 | tail -10`
Expected: FAIL — `classify_captive` не определена.

- [ ] **Step 3: Реализовать**

В `src/checks.rs`:

```rust
/// Портал отсутствует, если ответ — ровно 204, либо ответа нет (неинформативно).
/// Любой иной статус (200 с телом, редирект) → портал перехватил запрос.
fn classify_captive(status: Option<u16>) -> bool {
    match status {
        Some(204) => true,
        Some(_) => false,
        None => true,
    }
}

/// Этап «captive portal»: GET к generate_204 по plain HTTP без редиректов.
pub fn probe_captive() -> CheckOutcome {
    let start = Instant::now();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let status = agent
        .get("http://connectivitycheck.gstatic.com/generate_204")
        .call()
        .ok()
        .map(|r| r.status().as_u16());
    let no_portal = classify_captive(status);
    let error = if no_portal { None } else { Some("сеть требует авторизации (captive portal)".to_string()) };
    CheckOutcome { name: "captive-portal".to_string(), success: no_portal, elapsed: start.elapsed(), error }
}
```

> §A1: `r.status().as_u16()` — в ureq 3.x `status()` возвращает `http::StatusCode`; `.as_u16()` даёт число. Если сигнатура иная — проверить `cargo doc -p ureq --open` перед фиксом; ожидаемо `StatusCode::as_u16(&self) -> u16`.

- [ ] **Step 4: Подключить в `main.rs`**

Добавить captive в параллельный блок диагностики:

```rust
    let (local, dns_res, captive) = thread::scope(|scope| {
        let l = scope.spawn(checks::probe_local_ip);
        let d = scope.spawn(|| dns::probe_dns(&target));
        let c = scope.spawn(checks::probe_captive);
        (
            l.join().expect("поток local-ip паникнул"),
            d.join().expect("поток dns паникнул"),
            c.join().expect("поток captive паникнул"),
        )
    });
    let (dns_outcome, dns_ok) = dns_res;
    println!("{}", local.row());
    println!("{}", dns_outcome.row());
    println!("{}", captive.row());
    let report = DiagReport {
        local_ip: local.success,
        gateway: phase1[0].success,
        internet: phase1[1].success,
        dns: dns_ok,
        application: phase1[2].success,
        captive_ok: captive.success,
    };
```

- [ ] **Step 5: Тесты + clippy + прогон**

Run:
```bash
cargo test 2>&1 | grep -E 'test result|error\['
cargo clippy --all-targets -- -D warnings 2>&1 | tail -3
cargo build --release 2>&1 | tail -1
./target/release/check_inet 10.255.255.1:443; echo "exit: $?"
```
Expected: тесты PASS (+3 captive); при рабочей сети без портала строка captive-portal 🟢.

- [ ] **Step 6: Commit** (после явного разрешения)

```bash
git add src/checks.rs src/main.rs
git commit -m "feat: captive portal detection via generate_204"
```

---

### Task 13: IPv6-проба (информационно) + финальная верификация

**Files:**
- Modify: `src/net.rs` (`probe_ipv6`), `src/main.rs` (печать ipv6-строки в диагностике)
- Test: реальный прогон.

**Interfaces:**
- Produces: `pub fn probe_ipv6() -> CheckOutcome` (информационно, на вердикт не влияет).

- [ ] **Step 1: Реализовать `probe_ipv6` в `net.rs`**

```rust
use std::net::{Ipv6Addr, TcpStream};
use std::time::{Duration, Instant};
use crate::check::{CheckOutcome, io_error_text};

const IPV6_TIMEOUT: Duration = Duration::from_secs(3);

/// Информационная проба IPv6: TCP до [2001:4860:4860::8888]:443.
/// На вердикт/exit не влияет — многие сети без IPv6 это норма.
pub fn probe_ipv6() -> CheckOutcome {
    let start = Instant::now();
    let addr = SocketAddr::from((Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), 443));
    let result = TcpStream::connect_timeout(&addr, IPV6_TIMEOUT);
    let (success, error) = match &result {
        Ok(_) => (true, None),
        Err(err) => (false, io_error_text(err)),
    };
    CheckOutcome { name: "ipv6".to_string(), success, elapsed: start.elapsed(), error }
}
```

> `SocketAddr`, `Ipv4Addr`, `UdpSocket` уже импортированы в net.rs (Task 11); добавить только недостающие `Ipv6Addr, TcpStream`, `Duration, Instant`, `CheckOutcome, io_error_text`.

- [ ] **Step 2: Подключить в `main.rs`**

Добавить ipv6 в параллельный блок и напечатать строку (после captive, до вердикта); в `DiagReport` НЕ включать:

```rust
    let (local, dns_res, captive, ipv6) = thread::scope(|scope| {
        let l = scope.spawn(checks::probe_local_ip);
        let d = scope.spawn(|| dns::probe_dns(&target));
        let c = scope.spawn(checks::probe_captive);
        let v = scope.spawn(net::probe_ipv6);
        (
            l.join().expect("поток local-ip паникнул"),
            d.join().expect("поток dns паникнул"),
            c.join().expect("поток captive паникнул"),
            v.join().expect("поток ipv6 паникнул"),
        )
    });
    let (dns_outcome, dns_ok) = dns_res;
    println!("{}", local.row());
    println!("{}", dns_outcome.row());
    println!("{}", captive.row());
    println!("{} (информационно)", ipv6.row());
```

- [ ] **Step 3: Полный прогон всех сценариев**

Run:
```bash
cargo test 2>&1 | grep -E 'test result|error\['
cargo clippy --all-targets -- -D warnings 2>&1 | tail -3
cargo build --release 2>&1 | tail -1
echo "=== 1. healthy default ==="; ./target/release/check_inet; echo "exit: $?"
echo "=== 2. healthy target ==="; ./target/release/check_inet cloudflare.com; echo "exit: $?"
echo "=== 3. app-layer fail (unreachable target) ==="; ./target/release/check_inet 10.255.255.1:443; echo "exit: $?"
echo "=== 4. nxdomain ==="; ./target/release/check_inet nonexistent-abcxyz.invalid; echo "exit: $?"
echo "=== 5. help ==="; ./target/release/check_inet --help
```
Expected:
- (1),(2) здоровая сеть: фаза 1 = 3×🟢, exit 0, без блока диагностики.
- (3) шлюз/интернет 🟢, приложение 🛑 → блок диагностики (local-ip 🟢, dns 🟢, captive 🟢, ipv6 инфо), «корень: [5] …», exit 5.
- (4) dns NXDOMAIN → «корень: [4] …», exit 4.
- (5) help показывает `target`, `--times`, `--delay`.

- [ ] **Step 4: Итоговая проверка числа тестов**

Run: `cargo test 2>&1 | grep 'test result'`
Expected суммарно: gateway 8 + check 5 (row 3 / io 2) + checks 11 (classify_http 5 + reachability 3 + captive 3) + target 8 + diag 8 (exit 2 + ladder/verdict 6) + dns 14 (build 2 + parse 4 + resolv/scutil 4 + classify 4) = **54 теста**, все PASS.

- [ ] **Step 5: Commit** (после явного разрешения)

```bash
git add src/net.rs src/main.rs
git commit -m "feat: informational IPv6 probe; complete diagnostics"
```

---

## Заметки по верификации

- Не все ветки лесенки воспроизводимы в произвольной сети (например, «нет локального IP» требует отключённого интерфейса; «captive portal» — реального портала). Такие ветки покрыты юнит-тестами на чистой логике (`root_cause`, `classify_dns`, `classify_captive`, `kind_is_reachable`); I/O-пробы проверяются в доступных сценариях реальным прогоном. Об этом честно сообщать в финальном отчёте.
- Ветка `parse_resolv_conf`/`detect_resolvers` для Linux компилируется только под Linux; парсеры покрыты юнит-тестами кроссплатформенно.
- `cargo fmt` прогнать перед каждым коммитом.
```
