//! Глубокая DNS-диагностика: ручной DNS-по-UDP + определение резолверов.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Instant;

use crate::check::CheckOutcome;
use crate::checks::TIMEOUT;
use crate::target::Target;

/// Строит DNS-запрос типа A для `name` с transaction id `id`.
///
/// Формат (RFC 1035): 12-байтовый заголовок (id, flags=0x0100 recursion desired,
/// QDCOUNT=1, остальные счётчики 0) + QNAME (label-длина + байты) + 0x00 +
/// QTYPE=1 (A) + QCLASS=1 (IN).
pub fn build_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes()); // id
    q.extend_from_slice(&[0x01, 0x00]); // flags: recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
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

/// Извлечённые поля DNS-ответа.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub id: u16,
    pub rcode: u8,
    pub ancount: u16,
}

/// Парсит заголовок DNS-ответа. `None`, если буфер короче 12 байт или это не ответ (QR=0).
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

/// Извлекает `nameserver <IP>` из содержимого `/etc/resolv.conf` (Linux).
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

/// Извлекает `nameserver[N] : <IP>` из вывода `scutil --dns` (macOS).
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
    let resolved = |s: &[QueryOutcome]| s.contains(&QueryOutcome::Resolved);
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

/// Публичные DNS для фолбэка.
const PUBLIC_DNS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
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
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => return QueryOutcome::NoResponse,
    };
    if socket.set_read_timeout(Some(TIMEOUT)).is_err() {
        return QueryOutcome::NoResponse;
    }
    let query = build_query(name, DNS_QUERY_ID);
    if socket
        .send_to(&query, SocketAddr::from((server, 53)))
        .is_err()
    {
        return QueryOutcome::NoResponse;
    }
    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) => match parse_response(&buf[..n]) {
            Some(a) if a.id == DNS_QUERY_ID && a.rcode == 0 && a.ancount > 0 => {
                QueryOutcome::Resolved
            }
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
            DnsVerdict::SystemBrokenPublicWorks => {
                "системный DNS не отвечает, публичные работают".to_string()
            }
            DnsVerdict::Blocked => "DNS недоступен (:53 заблокирован?)".to_string(),
            DnsVerdict::Nxdomain => format!("имя '{name}' не существует (NXDOMAIN)"),
            DnsVerdict::Ok => unreachable!(),
        })
    };
    let outcome = CheckOutcome {
        name: "dns".to_string(),
        success: ok,
        elapsed: start.elapsed(),
        error,
    };
    (outcome, ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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

    #[test]
    fn parses_successful_answer() {
        // id=0x1234, flags=0x8180 (QR=1, RD, RA, RCODE=0), QD=1, AN=2
        let buf = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0, 0, 0, 0];
        assert_eq!(
            parse_response(&buf),
            Some(DnsAnswer {
                id: 0x1234,
                rcode: 0,
                ancount: 2
            })
        );
    }

    #[test]
    fn parses_nxdomain() {
        // flags=0x8183 → RCODE=3 (NXDOMAIN), AN=0
        let buf = [0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0];
        assert_eq!(
            parse_response(&buf),
            Some(DnsAnswer {
                id: 1,
                rcode: 3,
                ancount: 0
            })
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
}
