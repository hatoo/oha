![demo](demo.gif)

```bash
oha 0.1.0
hatoo <hato2000@gmail.com>
HTTP load generator, inspired by rakyll/hey with tui animation

USAGE:
    oha [FLAGS] [OPTIONS] <url>

ARGS:
    <url>    Target URL.

FLAGS:
    -h, --help       Prints help information
        --no-tui     No realtime tui
        --http2      Only HTTP2
    -V, --version    Prints version information

OPTIONS:
    -A <accept-header>           HTTP Accept Header.
    -a <basic-auth>              Basic authentication, username:password
    -D <body-path>               HTTP request body from file.
    -d <body-string>             HTTP request body.
    -T <content-type>            Content-Type.
    -z <duration>                Duration.
                                 Examples: -z 10s -z 3m.
        --fps <fps>              Frame per second for tui. [default: 16]
    -H <headers>...              HTTP header
        --host <host>            HTTP Host header
    -m, --method <method>        HTTP method [default: GET]
    -n <n-requests>              Number of requests. [default: 200]
    -c <n-workers>               Number of workers. [default: 50]
    -x <proxy>                   HTTP proxy
    -q <query-per-second>        Query per second limit.
    -t <timeout>                 Timeout for each request. Default to infinite.
```