
# oha

oha is a tiny program that sends some load to a web application and show realtime tui inspired by [rakyll/hey](https://github.com/rakyll/hey).

This program is wirtten in Rust and powered by tokio.

![demo](demo.gif)

```bash
oha 0.1.0
hatoo <hato2000@gmail.com>
Ohayou(おはよう), HTTP load generator, inspired by rakyll/hey with tui animation.

USAGE:
    oha [FLAGS] [OPTIONS] <url>

ARGS:
    <url>    Target URL.

FLAGS:
        --disable-compression    Disable compression.
    -h, --help                   Prints help information
        --no-tui                 No realtime tui
        --http2                  Only HTTP2
    -V, --version                Prints version information

OPTIONS:
    -A <accept-header>           HTTP Accept Header.
    -a <basic-auth>              Basic authentication, username:password
    -D <body-path>               HTTP request body from file.
    -d <body-string>             HTTP request body.
    -T <content-type>            Content-Type.
    -z <duration>                Duration of application to send requests. If duration is specified, n is ignored.
                                 Examples: -z 10s -z 3m.
        --fps <fps>              Frame per second for tui. [default: 16]
    -H <headers>...              Custom HTTP header.
        --host <host>            HTTP Host header
    -m, --method <method>        HTTP method [default: GET]
    -n <n-requests>              Number of requests to run. [default: 200]
    -c <n-workers>               Number of workers to run concurrently. [default: 50]
    -x <proxy>                   HTTP proxy
    -q <query-per-second>        Rate limit, in queries per second (QPS)
        --redirect <redirect>    Limit for number of Redirect. Set 0 for no redirection. [default: 10]
    -t <timeout>                 Timeout for each request. Default to infinite.
```