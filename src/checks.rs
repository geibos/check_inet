//! Пробы связности фазы 1.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::check::{CheckOutcome, io_error_text};
use crate::gateway;
use crate::net::{kind_is_reachable, local_ip};
use crate::target::Target;

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
    CheckOutcome {
        name,
        success,
        elapsed: start.elapsed(),
        error,
    }
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
            CheckOutcome {
                name: target.display_name(),
                success,
                elapsed: start.elapsed(),
                error,
            }
        }
        Target::Ip { addr, port } => {
            let saddr = SocketAddr::from((*addr, *port));
            // Реальный connect (не reachability): закрытый порт = сбой приложения.
            let (success, error) = match TcpStream::connect_timeout(&saddr, TIMEOUT) {
                Ok(_) => (true, None),
                Err(err) => (false, io_error_text(&err)),
            };
            CheckOutcome {
                name: target.display_name(),
                success,
                elapsed: start.elapsed(),
                error,
            }
        }
    }
}

/// Этап «локальный IP»: есть ли рабочий исходящий адрес.
pub fn probe_local_ip() -> CheckOutcome {
    let start = Instant::now();
    match local_ip() {
        Some(ip) => CheckOutcome {
            name: ip.to_string(),
            success: true,
            elapsed: start.elapsed(),
            error: None,
        },
        None => CheckOutcome {
            name: "<no local ip>".to_string(),
            success: false,
            elapsed: start.elapsed(),
            error: Some("нет локального адреса (линк/DHCP)".to_string()),
        },
    }
}

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
    let error = if no_portal {
        None
    } else {
        Some("сеть требует авторизации (captive portal)".to_string())
    };
    CheckOutcome {
        name: "captive-portal".to_string(),
        success: no_portal,
        elapsed: start.elapsed(),
        error,
    }
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

    #[test]
    fn ok_response_is_success() {
        assert_eq!(classify_http(Ok::<(), ureq::Error>(())), (true, None));
    }

    #[test]
    fn status_4xx_is_success() {
        let result: Result<(), _> = Err(ureq::Error::StatusCode(404));
        assert_eq!(classify_http(result), (true, None));
    }

    #[test]
    fn status_5xx_is_success() {
        let result: Result<(), _> = Err(ureq::Error::StatusCode(503));
        assert_eq!(classify_http(result), (true, None));
    }

    #[test]
    fn transport_error_is_failure_with_message() {
        let result: Result<(), _> = Err(ureq::Error::HostNotFound);
        let (success, error) = classify_http(result);
        assert!(!success);
        assert!(error.is_some());
        assert!(!error.unwrap().is_empty());
    }

    #[test]
    fn timeout_is_failure_without_message() {
        let result: Result<(), _> = Err(ureq::Error::Timeout(ureq::Timeout::Global));
        assert_eq!(classify_http(result), (false, None));
    }

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
}
