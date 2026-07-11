//! Результат одной проверки и его форматирование.

use std::io;
use std::time::Duration;

/// Итог одной проверки связности.
pub struct CheckOutcome {
    /// Отображаемое имя (IP шлюза, `8.8.8.8`, `ya.ru`, либо `<no route>`).
    pub name: String,
    pub success: bool,
    pub elapsed: Duration,
    /// Текст ошибки при провале. `None` при провале означает таймаут
    /// (в строке результата отображается как `Timeout`).
    pub error: Option<String>,
}

impl CheckOutcome {
    /// Форматирует строку результата в формате оригинала:
    /// `{name:<13} | {sigil} | {seconds:.4}[ | {error|Timeout}]`.
    pub fn row(&self) -> String {
        let sigil = if self.success { "🟢" } else { "🛑" };
        let mut row = format!(
            "{:<13} | {} | {:.4}",
            self.name,
            sigil,
            self.elapsed.as_secs_f64()
        );
        if !self.success {
            row.push_str(" | ");
            row.push_str(self.error.as_deref().unwrap_or("Timeout"));
        }
        row
    }
}

/// Преобразует сетевую io-ошибку в текст для вывода.
///
/// Таймаут → `None` (в строке результата станет `Timeout`), прочее → `Some(Display)`.
pub fn io_error_text(err: &io::Error) -> Option<String> {
    if err.kind() == io::ErrorKind::TimedOut {
        None
    } else {
        Some(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_formats_successful_check() {
        let name = "8.8.8.8";
        let outcome = CheckOutcome {
            name: name.to_string(),
            success: true,
            elapsed: Duration::from_secs_f64(0.0032),
            error: None,
        };
        let pad = " ".repeat(13 - name.len());
        assert_eq!(outcome.row(), format!("{name}{pad} | 🟢 | 0.0032"));
    }

    #[test]
    fn row_formats_failed_check_with_error() {
        let name = "8.8.8.8";
        let outcome = CheckOutcome {
            name: name.to_string(),
            success: false,
            elapsed: Duration::from_secs_f64(0.5),
            error: Some("connection refused".to_string()),
        };
        let pad = " ".repeat(13 - name.len());
        assert_eq!(
            outcome.row(),
            format!("{name}{pad} | 🛑 | 0.5000 | connection refused")
        );
    }

    #[test]
    fn row_uses_timeout_label_when_error_is_none_on_failure() {
        let outcome = CheckOutcome {
            name: "ya.ru".to_string(),
            success: false,
            elapsed: Duration::from_secs_f64(3.0),
            error: None,
        };
        assert!(outcome.row().ends_with(" | 🛑 | 3.0000 | Timeout"));
    }

    #[test]
    fn io_error_text_returns_none_on_timeout() {
        let err = io::Error::from(io::ErrorKind::TimedOut);
        assert_eq!(io_error_text(&err), None);
    }

    #[test]
    fn io_error_text_returns_nonempty_message_otherwise() {
        let err = io::Error::from(io::ErrorKind::ConnectionRefused);
        let text = io_error_text(&err);
        assert!(text.is_some());
        assert!(!text.unwrap().is_empty());
    }
}
