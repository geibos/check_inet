//! Кроссплатформенное определение адреса default-шлюза.

use std::net::Ipv4Addr;

/// Парсит вывод `ip route` (Linux) и возвращает IPv4 default-шлюза.
///
/// Ищет первую строку вида `default via <IP> ...` и извлекает `<IP>`.
#[cfg(any(target_os = "linux", test))]
pub fn parse_linux(output: &str) -> Option<Ipv4Addr> {
    output.lines().find_map(|line| {
        let mut tokens = line.split_whitespace();
        if tokens.next()? != "default" {
            return None;
        }
        // Пропускаем токены до "via" и берём следующий за ним.
        tokens.skip_while(|&t| t != "via").nth(1)?.parse().ok()
    })
}

/// Парсит вывод `route -n get default` (macOS) и возвращает IPv4 default-шлюза.
///
/// Ищет строку `gateway: <IP>` и извлекает `<IP>`.
#[cfg(any(target_os = "macos", test))]
pub fn parse_macos(output: &str) -> Option<Ipv4Addr> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("gateway:")?;
        rest.trim().parse().ok()
    })
}

/// Определяет default-шлюз, вызывая системную утилиту маршрутизации.
///
/// Возвращает `None`, если команда не запустилась, завершилась с ошибкой или
/// шлюз не найден в её выводе.
#[cfg(target_os = "linux")]
pub fn detect() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .arg("route")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_linux(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "macos")]
pub fn detect() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_macos(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn detect() -> Option<Ipv4Addr> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_extracts_gateway_from_default_route() {
        let output = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n\
                      192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.42 metric 600\n";
        assert_eq!(parse_linux(output), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn linux_returns_none_when_no_default_route() {
        let output = "192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.42\n";
        assert_eq!(parse_linux(output), None);
    }

    #[test]
    fn linux_returns_first_default_when_multiple() {
        let output = "default via 10.0.0.1 dev eth0 metric 100\n\
                      default via 10.0.0.2 dev eth1 metric 200\n";
        assert_eq!(parse_linux(output), Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn linux_ignores_ipv6_default_route() {
        let output = "default via fe80::1 dev eth0 proto ra metric 1024\n";
        assert_eq!(parse_linux(output), None);
    }

    #[test]
    fn linux_returns_none_on_garbage() {
        assert_eq!(parse_linux(""), None);
        assert_eq!(parse_linux("default via not-an-ip dev eth0\n"), None);
    }

    #[test]
    fn macos_extracts_gateway() {
        let output = "   route to: default\n\
                      destination: default\n\
                             mask: default\n\
                          gateway: 192.168.0.1\n\
                        interface: en0\n";
        assert_eq!(parse_macos(output), Some(Ipv4Addr::new(192, 168, 0, 1)));
    }

    #[test]
    fn macos_returns_none_when_no_gateway_line() {
        let output = "   route to: default\n        interface: en0\n";
        assert_eq!(parse_macos(output), None);
    }

    #[test]
    fn macos_returns_none_for_link_gateway() {
        // Для некоторых интерфейсов шлюз указывается как `link#N`, а не IPv4.
        let output = "          gateway: link#5\n        interface: en0\n";
        assert_eq!(parse_macos(output), None);
    }
}
