# oha (おはよう)

[![GitHub Actions](https://github.com/hatoo/oha/workflows/CI/badge.svg)](https://github.com/hatoo/oha/actions?query=workflow%3ACI)
[![Crates.io](https://img.shields.io/crates/v/oha.svg)](https://crates.io/crates/oha)
[![Arch Linux](https://img.shields.io/archlinux/v/extra/x86_64/oha)](https://archlinux.org/packages/extra/x86_64/oha/)
[![Homebrew](https://img.shields.io/homebrew/v/oha)](https://formulae.brew.sh/formula/oha)
[![Gitter](https://img.shields.io/gitter/room/hatoo/oha)](https://gitter.im/hatoo-oha/community#)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/hatoo)

oha is a tiny program that sends some load to a web application and show realtime tui inspired by [rakyll/hey](https://github.com/rakyll/hey).

This program is written in Rust and powered by [tokio](https://github.com/tokio-rs/tokio) and beautiful tui by [ratatui](https://github.com/ratatui-org/ratatui).

![demo](demo.gif)

# Installation

This program is built on stable Rust, with both `make` and `cmake` prerequisites to install via cargo.

    cargo install oha

You can optionally build oha against [native-tls](https://github.com/sfackler/rust-native-tls) instead of [rustls](https://github.com/rustls/rustls).

    cargo install --no-default-features --features rustls oha

You can enable VSOCK support by enabling `vsock` feature.

    cargo install --features vsock oha

## On Arch Linux

    pacman -S oha

## On macOS (Homebrew)

    brew install oha

## On Windows (winget)

    winget install hatoo.oha

## On Debian ([Azlux's repository](http://packages.azlux.fr/))

    echo "deb [signed-by=/usr/share/keyrings/azlux-archive-keyring.gpg] http://packages.azlux.fr/debian/ stable main" | sudo tee /etc/apt/sources.list.d/azlux.list
    sudo wget -O /usr/share/keyrings/azlux-archive-keyring.gpg https://azlux.fr/repo.gpg
    apt update
    apt install oha

## X-CMD (Linux, macOS, Windows WSL/GitBash)

You can install with [x-cmd](https://www.x-cmd.com).

```sh
x env use oha
```

## Containerized

You can also build and create a container image including oha

```sh
docker build . -t example.com/hatoo/oha:latest
```

Then you can use oha directly through the container

```sh
docker run -it example.com/hatoo/oha:latest https://example.com:3000
```

## Profile-Guided Optimization (PGO)

You can build `oha` with PGO by using the following commands:

```sh
bun run pgo.js
```

And the binary will be available at `target/[target-triple]/pgo/oha`.

# Platform

- Linux - Tested on Ubuntu 18.04 gnome-terminal
- Windows 10 - Tested on Windows Powershell
- MacOS - Tested on iTerm2

# Usage

`-q` option works different from [rakyll/hey](https://github.com/rakyll/hey). It's set overall query per second instead of for each workers.

```sh
Ohayou(おはよう), HTTP load generator, inspired by rakyll/hey with tui animation.

Usage: oha [OPTIONS] <URL>

Arguments:
  <URL>  Target URL or file with multiple URLs.

Options:
  -n <N_REQUESTS>
          Number of requests to run. [default: 200]
  -c <N_CONNECTIONS>
          Number of connections to run concurrently. You may should increase limit to number of open files for larger `-c`. [default: 50]
  -p <N_HTTP2_PARALLEL>
          Number of parallel requests to send on HTTP/2. `oha` will run c * p concurrent workers in total. [default: 1]
  -z <DURATION>
          Duration of application to send requests. If duration is specified, n is ignored.
          On HTTP/1, When the duration is reached, ongoing requests are aborted and counted as "aborted due to deadline"
          You can change this behavior with `-w` option.
          Currently, on HTTP/2, When the duration is reached, ongoing requests are waited. `-w` option is ignored.
          Examples: -z 10s -z 3m.
  -w, --wait-ongoing-requests-after-deadline
          When the duration is reached, ongoing requests are waited
  -q <QUERY_PER_SECOND>
          Rate limit for all, in queries per second (QPS)
      --burst-delay <BURST_DURATION>
          Introduce delay between a predefined number of requests.
          Note: If qps is specified, burst will be ignored
      --burst-rate <BURST_REQUESTS>
          Rates of requests for burst. Default is 1
          Note: If qps is specified, burst will be ignored
      --rand-regex-url
          Generate URL by rand_regex crate but dot is disabled for each query e.g. http://127.0.0.1/[a-z][a-z][0-9]. Currently dynamic scheme, host and port with keep-alive do not work well. See https://docs.rs/rand_regex/latest/rand_regex/struct.Regex.html for details of syntax.
      --urls-from-file
          Read the URLs to query from a file
      --max-repeat <MAX_REPEAT>
          A parameter for the '--rand-regex-url'. The max_repeat parameter gives the maximum extra repeat counts the x*, x+ and x{n,} operators will become. [default: 4]
      --dump-urls <DUMP_URLS>
          Dump target Urls <DUMP_URLS> times to debug --rand-regex-url
      --latency-correction
          Correct latency to avoid coordinated omission problem. It's ignored if -q is not set.
      --no-tui
          No realtime tui
  -j, --json
          Print results as JSON
      --fps <FPS>
          Frame per second for tui. [default: 16]
  -m, --method <METHOD>
          HTTP method [default: GET]
  -H <HEADERS>
          Custom HTTP header. Examples: -H "foo: bar"
  -t <TIMEOUT>
          Timeout for each request. Default to infinite.
  -A <ACCEPT_HEADER>
          HTTP Accept Header.
  -d <BODY_STRING>
          HTTP request body.
  -D <BODY_PATH>
          HTTP request body from file.
  -T <CONTENT_TYPE>
          Content-Type.
  -a <BASIC_AUTH>
          Basic authentication, username:password
  -x <PROXY>
          HTTP proxy
      --proxy-http-version <PROXY_HTTP_VERSION>
          HTTP version to connect to proxy. Available values 0.9, 1.0, 1.1, 2.
      --proxy-http2
          Use HTTP/2 to connect to proxy. Shorthand for --proxy-http-version=2
      --http-version <HTTP_VERSION>
          HTTP version. Available values 0.9, 1.0, 1.1, 2.
      --http2
          Use HTTP/2. Shorthand for --http-version=2
      --host <HOST>
          HTTP Host header
      --disable-compression
          Disable compression.
  -r, --redirect <REDIRECT>
          Limit for number of Redirect. Set 0 for no redirection. Redirection isn't supported for HTTP/2. [default: 10]
      --disable-keepalive
          Disable keep-alive, prevents re-use of TCP connections between different HTTP requests. This isn't supported for HTTP/2.
      --no-pre-lookup
          *Not* perform a DNS lookup at beginning to cache it
      --ipv6
          Lookup only ipv6.
      --ipv4
          Lookup only ipv4.
      --insecure
          Accept invalid certs.
      --connect-to <CONNECT_TO>
          Override DNS resolution and default port numbers with strings like 'example.org:443:localhost:8443'
      --disable-color
          Disable the color scheme.
      --unix-socket <UNIX_SOCKET>
          Connect to a unix socket instead of the domain in the URL. Only for non-HTTPS URLs.
      --stats-success-breakdown
          Include a response status code successful or not successful breakdown for the time histogram and distribution statistics
      --db-url <DB_URL>
          Write succeeded requests to sqlite database url E.G test.db
      --debug
          Perform a single request and dump the request and response
  -h, --help
          Print help
  -V, --version
          Print version
```

# JSON output

`oha` prints JSON output when `-j` option is set.
The schema of JSON output is defined in [schema.json](./schema.json).

# Benchmark

## Performance Comparison

We used `hyperfine` for benchmarking `oha` against `rakyll/hey` on a local server. The server was coded using node. You can start the server by copy pasting this file and then running it via node. After copy-pasting the file, you can run the benchmark via `hyperfine`.

1. Copy-paste the contents into a new javascript file called app.js

```js
const http = require("http");

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });

  res.end("Hello World\n");
});

server.listen(3000, () => {
  console.log("Server running at http://localhost:3000/");
});
```

2. Run `node app.js`
3. Run `hyperfine 'oha --no-tui http://localhost:3000' 'hey http://localhost:3000'` in a different terminal tab

### Benchmark Results

Benchmark 1: oha --no-tui http://localhost:3000

- Time (mean ± σ): 10.8 ms ± 1.8 ms [User: 5.7 ms, System: 11.7 ms]
- Range (min … max): 8.7 ms … 24.8 ms (107 runs)

Benchmark 2: hey http://localhost:3000

- Time (mean ± σ): 14.3 ms ± 4.6 ms [User: 12.2 ms, System: 19.4 ms]
- Range (min … max): 11.1 ms … 48.3 ms (88 runs)

### Summary

In this benchmark, `oha --no-tui http://localhost:3000` was found to be faster, running approximately 1.32 ± 0.48 times faster than `hey http://localhost:3000`.

# Tips

## Stress test in more realistic condition

`oha` uses default options inherited from [rakyll/hey](https://github.com/rakyll/hey) but you may need to change options to stress test in more realistic condition.

I suggest to run `oha` with following options.

```sh
oha <-z or -n> -c <number of concurrent connections> -q <query per seconds> --latency-correction --disable-keepalive <target-address>
```

- --disable-keepalive

    In real, user doesn't query same URL using [Keep-Alive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive). You may want to run without `Keep-Alive`.
- --latency-correction

    You can avoid `Coordinated Omission Problem` by using `--latency-correction`.

## Burst feature

You can use `--burst-delay` along with `--burst-rate` option to introduce delay between a defined number of requests.

```sh
oha -n 10 --burst-delay 2s --burst-rate 4
```

In this particular scenario, every 2 seconds, 4 requests will be processed, and after 6s the total of 10 requests will be processed.
*NOTE: If you don't set `--burst-rate` option, the amount is default to 1*

## Dynamic url feature

You can use `--rand-regex-url` option to generate random url for each connection.

```sh
oha --rand-regex-url http://127.0.0.1/[a-z][a-z][0-9]
```

Each Urls are generated by [rand_regex](https://github.com/kennytm/rand_regex) crate but regex's dot is disabled since it's not useful for this purpose and it's very inconvenient if url's dots are interpreted as regex's dot.

Optionally you can set `--max-repeat` option to limit max repeat count for each regex. e.g http://127.0.0.1/[a-z]* with `--max-repeat 4` will generate url like http://127.0.0.1/[a-z]{0,4}

Currently dynamic scheme, host and port with keep-alive are not works well.

## URLs from file feature

You can use `--urls-from-file` to read the target URLs from a file. Each line of this file needs to contain one valid URL as in the example below.

```
http://domain.tld/foo/bar
http://domain.tld/assets/vendors-node_modules_highlight_js_lib_index_js-node_modules_tanstack_react-query_build_modern-3fdf40-591fb51c8a6e.js
http://domain.tld/images/test.png
http://domain.tld/foo/bar?q=test
http://domain.tld/foo
```

Such a file can for example be created from an access log to generate a more realistic load distribution over the different pages of a server. 

When this type of URL specification is used, every request goes to a random URL given in the file.

# Contribution

Feel free to help us!

Here are some areas which need improving.

- Write tests
- Improve tui design.
  - Show more information?
- Improve speed
  - I'm new to tokio. I think there are some space to optimize query scheduling.
