# Unreleased

# 1.11.0 (2025-11-01)

- feat:support decimal when using n_requests,such as 2.6k or 0.001m #808 
- connect-to now doing tcp connect instead of dns caching #807 
- feat: make connect timeout configurable #805 
- feat: support k/m suffixes for n-requests #800 
- feat: Add option to read request body line-by-line from file. #729 #789

# 1.10.0 (2025-09-06)

- fix dns lookup on http2/http3 #771 
- feat: add curl-compatible multipart form data support (-F option) #755

# 1.9.0 (2025-06-21)

- Implement experimental HTTP3 support #746 
- Allow appending to database if oha table has already been created #742 
- Add -u/--time-unit option #741 
- Add RequestResult.first_byte field for measuring first body byte latency #727 
- Add support for results in csv format #725 
- Add support for fractional QPS values #724 

# 1.8.0 (2025-02-15)

- Support mtls #687 
- Support Proxy headers #688 
- Randomize --connect-to if multiple matching options #695 

# 1.7.0 (2025-02-01)

- Impl support for calling AWS APIs with sigv4 #666 
- support -o #669 

# 1.6.0 (2025-01-11)

- Feature: Reading Urls from file #639
- Add some optimized workers to `--no-tui` mode #646

# 1.5.0 (2024-12-07)

- Add `--debug` option to check actual request/response
- Switch colors to justified latency thresholds (fixes #609) #610 
- Fix Running with -q hangs #603 
- Support HTTP proxy #614 

# 1.4.7 (2024-10-26)

- [rustls] Cache HTTPS certs

# 1.4.6 (2024-08-17)

- Add `--wait-ongoing-requests-after-deadline` option
- Add `--db-url` option to save results to SQLite database
- Add `--dump-urls` option to debug random URL generation

# 1.4.5 (2024-05-29)

- Some performance improvements

# 1.4.4 (2024-04-20)

- support Termux #464

# 1.4.3 (2024-04-06)

- fix rustls error #452

# 1.4.2 (2024-04-06)

- Fix printing of Size/request #447 

# 1.4.1 (2024-03-16)

- Enable: Profile-Guided Optimization (PGO) #268

# 1.4.0 (2024-03-09)

- No DNS lookup when unix socket or vsock #418
- Add HTTP over VSOCK support #416

# 1.3.0 (2024-02-04)

- Optimize timeout #403 
- Compact error #402 
- fix tui layout #401 

# 1.2.0 (2024-02-03)

- Print help message when no argument is given #378
- Lookup DNS at beginning and cache it #391
- Report deadlined requests #392 
- Fix MacOS Crash issues #384

# 1.1.0 (2024-01-16)

-  [HTTP2] Reconnect TCP connection when it fails #369 

# 1.0.0 (2023-11-16)

- Update hyper dependency to 1.0.0

# 1.0.0-rc.4.a8dcd7ca5df49c0701893c4d9d81ec8c1342f141 (2023-10-14)

This is a RC release for 1.0.0. Please test it and report any issues.
The version is named as same as `hyper`'s version and it's commit hash.

Since this version depends on unreleased `hyper`'s version, we can't release on crates.io. Only on binary releases.

- Support HTTP/2 #224 #201
- Make `rustls` as a default TLS backend #331
- Added `-p` option to set number of HTTP/2 parallel requests

# 0.6.5 (2023-10-09)

- Fix Apple Silicon's binary release #323

# 0.6.4 (2023-09-24)

- Fix -H option to overwrite default value #309
- feat: display 99.90- and 99.99-percentile latency #315 

# 0.6.3 (2023-09-05)

- Add style and colors to the summary view #64
- Added a stats-success-breakdown flag for more detailed status code specific response statistics #212

# 0.6.2 (2023-08-12)

- Support Burst feature #276

# 0.6.1 (2023-07-12)

- Fix sending HTTP uri #255
- Add default user agent header #257

# 0.6.0 (2023-06-24)

- Support IDNA #236
- Support randomly generated URL using rand_regex crate

# 0.5.9 (2023-06-12)

- Fix -H Header parser
-  Update printer #229
    -  Use percentage for Success rate summary value #228 
    - Latency distribution -> Response time distribution

# 0.5.8 (2023-03-25)

- Add `--unix-socket` on `unix` profiles for HTTP. #220
- Fix tui to not requiring True Color. #209

# 0.5.7 (2023-02-25)

- Fix `--latency-correction` adds the time of DNS. #211
- Fix `-z` behaviour to cancel workers at the dead line. #211
- Fix align of histogram #210

# 0.5.6 (2023-02-02)

- Update `clap` to version 4
- Release `musl` binaries #206
- Support [Ipv6] format requested_host in --connect-to #197

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
