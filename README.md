# oha (おはよう)

[![GitHub Actions](https://github.com/hatoo/oha/workflows/CI/badge.svg)](https://github.com/hatoo/oha/actions?query=workflow%3ACI)
[![Crates.io](https://img.shields.io/crates/v/oha.svg)](https://crates.io/crates/oha)
[![Arch Linux](https://img.shields.io/archlinux/v/community/x86_64/oha)](https://archlinux.org/packages/community/x86_64/oha/)
[![Homebrew](https://img.shields.io/homebrew/v/oha)](https://formulae.brew.sh/formula/oha)

oha is a tiny program that sends some load to a web application and show realtime tui inspired by [rakyll/hey](https://github.com/rakyll/hey).

This program is written in Rust and powered by [tokio](https://github.com/tokio-rs/tokio) and beautiful tui by [tui-rs](https://github.com/fdehau/tui-rs).

![demo](demo.gif)

# Installation

This program is built on stable Rust.

    cargo install oha

## On Arch Linux

    pacman -S oha

## On macOS (Homebrew)

    brew install oha

## On Debian ([Azlux's repository](http://packages.azlux.fr/))

    echo "deb http://packages.azlux.fr/debian/ buster main" | sudo tee /etc/apt/sources.list.d/azlux.list
    wget -qO - https://azlux.fr/repo.gpg.key | sudo apt-key add -
    apt update
    apt install oha

# Platform

- Linux - Tested on Ubuntu 18.04 gnome-terminal
- Windows 10 - Tested on Windows Powershell
- MacOS - Tested on iTerm2

# Usage

`-q` option works different from [rakyll/hey](https://github.com/rakyll/hey). It's set overall query per second instead of for each workers.

```
oha 0.4.7
hatoo <hato2000@gmail.com>
Ohayou(おはよう), HTTP load generator, inspired by rakyll/hey with tui animation.

USAGE:
    oha [FLAGS] [OPTIONS] <url>

FLAGS:
        --latency-correction     Correct latency to avoid coordinated omission problem. It's ignored if -q is not set.
        --no-tui                 No realtime tui
        --disable-compression    Disable compression.
        --disable-keepalive      Disable keep-alive, prevents re-use of TCP connections between different HTTP requests.
        --ipv6                   Lookup only ipv6.
        --ipv4                   Lookup only ipv4.
        --insecure               Accept invalid certs.
    -h, --help                   Prints help information
    -V, --version                Prints version information

OPTIONS:
    -n <n-requests>                      Number of requests to run. [default: 200]
    -c <n-workers>                       Number of workers to run concurrently. You may should increase limit to number
                                         of open files for larger `-c`. [default: 50]
    -z <duration>                        Duration of application to send requests. If duration is specified, n is
                                         ignored.
                                         Examples: -z 10s -z 3m.
    -q <query-per-second>                Rate limit for all, in queries per second (QPS)
        --fps <fps>                      Frame per second for tui. [default: 16]
    -m, --method <method>                HTTP method [default: GET]
    -H <headers>...                      Custom HTTP header. Examples: -H "foo: bar"
    -t <timeout>                         Timeout for each request. Default to infinite.
    -A <accept-header>                   HTTP Accept Header.
    -d <body-string>                     HTTP request body.
    -D <body-path>                       HTTP request body from file.
    -T <content-type>                    Content-Type.
    -a <basic-auth>                      Basic authentication, username:password
        --http-version <http-version>    HTTP version. Available values 0.9, 1.0, 1.1, 2.
        --host <host>                    HTTP Host header
    -r, --redirect <redirect>            Limit for number of Redirect. Set 0 for no redirection. [default: 10]
        --connect-to <connect-to>...     Override DNS resolution and default port numbers with strings like
                                         'example.org:443:localhost:8443'

ARGS:
    <url>    Target URL.
```

# Tips

## Stress test in more realistic conditon

`oha` uses default options inherited from [rakyll/hey](https://github.com/rakyll/hey) but you may need to change options to stress test in more realistic condition.

I suggest to run `oha` with following options.
```
oha <-z or -n> -c <number of concurrent connections> -q <query per seconds> --latency-correction --disable-keepalive <target-address>
```

- --disable-keepalive

    In real, user doesn't query same URL using [Keep-Alive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive). You may want to run without `Keep-Alive`.
- --latency-correction

    You can avoid `Coordinated Omission Problem` by using `--latency-correction`.


# Contribution

Feel free to help us!

Here are some issues to improving.

- Write tests
- Improve tui design.
  - Show more information?
  - There are no color in realtime tui now. I want help from someone who has some color sense.
- Improve speed
  - I'm new to tokio. I think there are some space to optimize query scheduling.
- Output like CSV or JSON format.
- Improve histogram in summary output
  - It uses very simple algorithm now.
