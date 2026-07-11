//! Разбор необязательного аргумента цели `host[:port]` / `ip[:port]`.

use std::net::{IpAddr, SocketAddr};

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Host { host: String, port: u16 },
    Ip { addr: IpAddr, port: u16 },
}

impl Default for Target {
    fn default() -> Self {
        Target::Host {
            host: "ya.ru".to_string(),
            port: 443,
        }
    }
}

impl Target {
    /// Разбирает `host`, `host:port`, `ip`, `ip:port`, `[ipv6]:port`.
    /// Порт по умолчанию — 443. Возвращает `Err(описание)` на пустом вводе.
    pub fn parse(input: &str) -> Result<Target, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("пустая цель".to_string());
        }
        // 1) ip:port или [ipv6]:port
        if let Ok(sa) = input.parse::<SocketAddr>() {
            return Ok(Target::Ip {
                addr: sa.ip(),
                port: sa.port(),
            });
        }
        // 2) голый IP (v4/v6) → порт 443
        if let Ok(addr) = input.parse::<IpAddr>() {
            return Ok(Target::Ip { addr, port: 443 });
        }
        // 3) host:port — только если суффикс валидный порт и в хосте нет ':'
        if let Some((host, port)) = input.rsplit_once(':')
            && !host.contains(':')
            && !host.is_empty()
            && let Ok(port) = port.parse::<u16>()
        {
            return Ok(Target::Host {
                host: host.to_string(),
                port,
            });
        }
        // 4) голый host → порт 443
        Ok(Target::Host {
            host: input.to_string(),
            port: 443,
        })
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
            Target::Ip {
                addr: IpAddr::V6(a),
                port,
            } => format!("[{a}]:{port}"),
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
            Target::Host {
                host: "example.com".to_string(),
                port: 443
            }
        );
    }

    #[test]
    fn host_with_port() {
        assert_eq!(
            Target::parse("example.com:8443").unwrap(),
            Target::Host {
                host: "example.com".to_string(),
                port: 8443
            }
        );
    }

    #[test]
    fn ipv4_without_port() {
        assert_eq!(
            Target::parse("1.1.1.1").unwrap(),
            Target::Ip {
                addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 443
            }
        );
    }

    #[test]
    fn ipv4_with_port() {
        assert_eq!(
            Target::parse("1.1.1.1:53").unwrap(),
            Target::Ip {
                addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 53
            }
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
        assert_eq!(
            Target::parse("example.com").unwrap().host(),
            Some("example.com")
        );
        assert_eq!(Target::parse("1.1.1.1").unwrap().host(), None);
    }
}
