# Unreleased

# 0.5.5 (2022-09-19)

- Add colors to the tui view #64

# 0.5.4 (2022-08-27)

- Support Ipv6 host #181
- Print min, max, average and pXX for Requests per second in JSON output like bombardier #177
- Add JSON Output #169
- Fix QPS control to send with correct rate for first 1 sec
- Make histogram compatible to hey
    - closes #161

# 0.5.3 (2022-07-16)

- Add support for bracketed IPv6 syntax in connect-to

# 0.5.2 (2022-04-28)

- Add `rustls` feature flag to build against `rustls` instead of `native-tls`.

# 0.5.1 (2022-03-29)

- Fix histogram to show correct response time
    - closes #157

# 0.5.0 (2022-01-01)

- Use clap 3.0.0 instead of structopt
    - closes #131

# 0.4.6 (2021-07-05)

- Add `--latency-correction` to avoid Coordinated Omission Problem.

# 0.4.5 (2021-05-04)

- Set '--no-tui' automatically when stdout isn't TTY

# 0.4.4 (2020-11-18)

- Bump `resolv-conf` to support `options edns0 trust-ad` on `/etc/resolv.conf`

# 0.4.3 (2020-11-12)

- Add --connect-to option to override DNS for a given host+port, similar to curl

# 0.4.2 (2020-10-06)

- Speed up on WSL Ubuntu 20.4

# 0.4.1 (2020-07-28)

- Support -q 0 option for unlimited qps
- Fix performance on limiting query/second
