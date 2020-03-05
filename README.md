![demo](demo.gif)

```bash
oha 0.1.0
hatoo <hato2000@gmail.com>

USAGE:
    oha [FLAGS] [OPTIONS] <url>

ARGS:
    <url>    Target URL.

FLAGS:
    -h, --help       Prints help information
        --no-tui     No realtime tui
    -V, --version    Prints version information

OPTIONS:
    -z <duration>                Duration.
                                 Examples: -z 10s -z 3m.
        --fps <fps>              Frame per second for tui. [default: 16]
    -n <n-requests>              Number of requests. [default: 200]
    -c <n-workers>               Number of workers. [default: 50]
    -q <query-per-second>        Query per second limit.
```