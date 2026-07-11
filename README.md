# check-inet

Adaptive internet connectivity diagnostics. Run one binary when something is
wrong and it pinpoints **which layer** is broken — from the local interface all
the way up to the application and captive portals.

Fast when healthy (parallel probes with early-return), thorough when not: on
failure it escalates to a dependency-ladder diagnosis and exits with the number
of the first failing stage.

## Install

From crates.io (once published):

```sh
cargo install check_inet
```

From a local checkout:

```sh
cargo install --path .
```

From git:

```sh
cargo install --git https://github.com/geibos/check_inet
```

All of these install a binary named `check-inet`.

## Usage

```sh
check-inet [TARGET] [-t <TIMES>] [-d <DELAY>]
```

- `TARGET` — optional `host[:port]` or `ip[:port]` to check at the application
  layer (default `ya.ru:443`). A hostname also exercises the DNS stage; an IP
  skips per-target DNS.
- `-t, --times` — number of phase-1 attempts (default 1).
- `-d, --delay` — delay between attempts, in seconds (default 1.0).

### How it works

Phase 1 runs three probes in parallel — default gateway, public internet
(`8.8.8.8`), and the application target. If all pass, it prints the results and
exits `0`.

If any fail, it escalates into a full diagnosis: local IP, deep DNS (raw UDP to
the system resolvers with public fallback), captive-portal detection, and an
informational IPv6 check — then prints a verdict naming the root-cause stage.

### Exit codes

The exit code is the number of the first broken stage (bottom-up), or `0` when
healthy:

| Code | Stage | Meaning |
|-----:|-------|---------|
| 0 | — | everything healthy |
| 1 | local IP | no local address (link/DHCP) |
| 2 | gateway | default gateway unreachable |
| 3 | internet | no route to the public internet (ISP/routing) |
| 4 | DNS | name resolution broken |
| 5 | application | TLS/HTTP to the target fails |
| 6 | captive portal | network requires sign-in |

A `Connection refused`/`reset` counts as *reachable* for the gateway and
internet stages: the host answered, so that layer is up. IPv6 is informational
only and never changes the verdict.

### Example

```text
$ check-inet 10.255.255.1:443
172.20.10.1   | 🟢 | 1.0553
8.8.8.8       | 🟢 | 0.0708
10.255.255.1:443 | 🛑 | 0.0754 | Connection refused (os error 61)
--- диагностика ---
10.216.1.4    | 🟢 | 0.0003
dns           | 🟢 | 0.4868
captive-portal | 🟢 | 0.3114
ipv6          | 🛑 | 1.0012 | No route to host (informational)
корень: [5] уровень приложения — TLS/HTTP до цели не отвечает
$ echo $?
5
```

## Platform support

Linux and macOS. Gateway detection uses `ip route` (Linux) / `route -n get
default` (macOS); resolver discovery uses `/etc/resolv.conf` (Linux) /
`scutil --dns` (macOS).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
