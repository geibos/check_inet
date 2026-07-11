//! Сетевые пробы: reachability-классификация, локальный IP, IPv6.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::check::{CheckOutcome, io_error_text};

/// Таймаут IPv6-пробы (как у прочих проб — 3 секунды).
const IPV6_TIMEOUT: Duration = Duration::from_secs(3);

/// Доказывает ли исход TCP-connect, что хост жив (ответил на пакет).
///
/// `ConnectionRefused`/`ConnectionReset` = хост ответил RST → достижим.
/// `TimedOut`/`*Unreachable`/прочее → недостижим.
pub fn kind_is_reachable(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
    )
}

/// Определяет локальный IP через UDP-connect к публичному адресу (пакеты не шлются —
/// connect лишь выбирает исходящий интерфейс по таблице маршрутизации).
/// `None`, если сокет не создан/не привязан или адрес неопределён (нет линка).
pub fn local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket
        .connect(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 80)))
        .ok()?;
    let addr = socket.local_addr().ok()?.ip();
    if addr.is_unspecified() {
        None
    } else {
        Some(addr)
    }
}

/// Информационная проба IPv6: TCP до `[2001:4860:4860::8888]:443`.
/// На вердикт/exit не влияет — многие сети без IPv6 это норма.
pub fn probe_ipv6() -> CheckOutcome {
    let start = Instant::now();
    let addr = SocketAddr::from((
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        443,
    ));
    let (success, error) = match TcpStream::connect_timeout(&addr, IPV6_TIMEOUT) {
        Ok(_) => (true, None),
        Err(err) => (false, io_error_text(&err)),
    };
    CheckOutcome {
        name: "ipv6".to_string(),
        success,
        elapsed: start.elapsed(),
        error,
    }
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
