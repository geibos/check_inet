mod check;
mod checks;
mod diag;
mod dns;
mod gateway;
mod net;
mod target;

use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use clap::Parser;

use crate::check::CheckOutcome;
use crate::diag::{DiagReport, exit_code, root_cause, verdict_line};
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

    // Эскалация: диагностика. Доп-проба captive добавится в фазе 5.
    println!("--- диагностика ---");
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
    let report = DiagReport {
        local_ip: local.success,
        gateway: phase1[0].success,
        internet: phase1[1].success,
        dns: dns_ok,
        application: phase1[2].success,
        captive_ok: captive.success,
    };
    let stage = root_cause(&report);
    println!("{}", verdict_line(stage));
    ExitCode::from(exit_code(stage))
}
