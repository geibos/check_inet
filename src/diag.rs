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
    stage.map_or(0, |s| s as u8)
}

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

/// Человекочитаемая строка вердикта.
pub fn verdict_line(stage: Option<Stage>) -> String {
    match stage {
        None => "вердикт: связь здорова".to_string(),
        Some(Stage::LocalIp) => {
            "корень: [1] нет локального IP — линк/DHCP не выдал адрес".to_string()
        }
        Some(Stage::Gateway) => {
            "корень: [2] шлюз недостижим — проблема в локальной сети/роутере".to_string()
        }
        Some(Stage::Internet) => {
            "корень: [3] нет выхода в интернет — публичный IP недостижим (маршрут/ISP)".to_string()
        }
        Some(Stage::Dns) => "корень: [4] DNS не работает — имена не резолвятся".to_string(),
        Some(Stage::Application) => {
            "корень: [5] уровень приложения — TLS/HTTP до цели не отвечает".to_string()
        }
        Some(Stage::CaptivePortal) => {
            "корень: [6] captive portal — сеть требует авторизации".to_string()
        }
    }
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

    fn healthy() -> DiagReport {
        DiagReport {
            local_ip: true,
            gateway: true,
            internet: true,
            dns: true,
            application: true,
            captive_ok: true,
        }
    }

    #[test]
    fn all_pass_no_root() {
        assert_eq!(root_cause(&healthy()), None);
    }

    #[test]
    fn first_failure_bottom_up() {
        let r = DiagReport {
            local_ip: false,
            ..healthy()
        };
        assert_eq!(root_cause(&r), Some(Stage::LocalIp));

        let r = DiagReport {
            gateway: false,
            ..healthy()
        };
        assert_eq!(root_cause(&r), Some(Stage::Gateway));

        let r = DiagReport {
            internet: false,
            ..healthy()
        };
        assert_eq!(root_cause(&r), Some(Stage::Internet));

        let r = DiagReport {
            dns: false,
            ..healthy()
        };
        assert_eq!(root_cause(&r), Some(Stage::Dns));

        let r = DiagReport {
            application: false,
            ..healthy()
        };
        assert_eq!(root_cause(&r), Some(Stage::Application));
    }

    #[test]
    fn lower_stage_wins_over_higher() {
        // и шлюз, и приложение упали → корень = шлюз (ниже)
        let r = DiagReport {
            gateway: false,
            application: false,
            ..healthy()
        };
        assert_eq!(root_cause(&r), Some(Stage::Gateway));
    }

    #[test]
    fn captive_portal_takes_priority_over_application() {
        // интернет и dns ок, приложение упало, но обнаружен портал → CaptivePortal
        let r = DiagReport {
            application: false,
            captive_ok: false,
            ..healthy()
        };
        assert_eq!(root_cause(&r), Some(Stage::CaptivePortal));
    }

    #[test]
    fn lower_stage_wins_over_captive() {
        // портал «обнаружен», но реально нет даже интернета → корень Internet, не портал
        let r = DiagReport {
            internet: false,
            captive_ok: false,
            ..healthy()
        };
        assert_eq!(root_cause(&r), Some(Stage::Internet));
    }

    #[test]
    fn verdict_mentions_stage() {
        assert!(verdict_line(None).contains("здоров") || verdict_line(None).contains("ok"));
        assert!(verdict_line(Some(Stage::Dns)).contains("[4]"));
        assert!(verdict_line(Some(Stage::CaptivePortal)).contains("[6]"));
    }
}
