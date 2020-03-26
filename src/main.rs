use anyhow::Context;
use futures::prelude::*;
use http::header::{HeaderName, HeaderValue};
use std::io::Read;
use structopt::StructOpt;
use url::Url;

mod client;
mod monitor;
mod printer;

struct ParseDuration(std::time::Duration);

impl std::str::FromStr for ParseDuration {
    type Err = parse_duration::parse::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_duration::parse(s).map(ParseDuration)
    }
}

#[derive(StructOpt)]
#[structopt(version = clap::crate_version!(), author = clap::crate_authors!(), about = "Ohayou(おはよう), HTTP load generator, inspired by rakyll/hey with tui animation.", global_setting = clap::AppSettings::DeriveDisplayOrder)]
struct Opts {
    #[structopt(help = "Target URL.")]
    url: Url,
    #[structopt(
        help = "Number of requests to run.",
        short = "n",
        default_value = "200"
    )]
    n_requests: usize,
    #[structopt(
        help = "Number of workers to run concurrently. You may should increase limit to number of open files for larger `-c`.",
        short = "c",
        default_value = "50"
    )]
    n_workers: usize,
    #[structopt(
        help = "Duration of application to send requests. If duration is specified, n is ignored.
Examples: -z 10s -z 3m.",
        short = "z"
    )]
    duration: Option<ParseDuration>,
    #[structopt(help = "Rate limit for all, in queries per second (QPS)", short = "q")]
    query_per_second: Option<usize>,
    #[structopt(help = "No realtime tui", long = "no-tui")]
    no_tui: bool,
    #[structopt(help = "Frame per second for tui.", default_value = "16", long = "fps")]
    fps: usize,
    #[structopt(
        help = "HTTP method",
        short = "m",
        long = "method",
        default_value = "GET"
    )]
    method: http::Method,
    #[structopt(help = "Custom HTTP header. Examples: -H \"foo: bar\"", short = "H")]
    headers: Vec<String>,
    #[structopt(help = "Timeout for each request. Default to infinite.", short = "t")]
    timeout: Option<ParseDuration>,
    #[structopt(help = "HTTP Accept Header.", short = "A")]
    accept_header: Option<String>,
    #[structopt(help = "HTTP request body.", short = "d")]
    body_string: Option<String>,
    #[structopt(help = "HTTP request body from file.", short = "D")]
    body_path: Option<std::path::PathBuf>,
    #[structopt(help = "Content-Type.", short = "T")]
    content_type: Option<String>,
    #[structopt(help = "Basic authentication, username:password", short = "a")]
    basic_auth: Option<String>,
    /*
    #[structopt(help = "HTTP proxy", short = "x")]
    proxy: Option<String>,
    #[structopt(help = "Only HTTP2", long = "http2")]
    only_http2: bool,
    */
    #[structopt(help = "HTTP Host header", long = "host")]
    host: Option<String>,
    #[structopt(help = "Disable compression.", long = "disable-compression")]
    disable_compression: bool,
    /*
    #[structopt(
        help = "Limit for number of Redirect. Set 0 for no redirection.",
        default_value = "10",
        long = "redirect"
    )]
    redirect: usize,
    */
    #[structopt(help = "Set that all scokets have TCP_NODELAY", long = "tcp-nodelay")]
    tcp_nodelay: bool,
}

#[derive(Debug, Clone)]
/// a result for a request
pub struct RequestResult {
    /// When the query started
    start: std::time::Instant,
    /// When the query ends
    end: std::time::Instant,
    /// HTTP status
    status: http::StatusCode,
    /// Length of body
    len_bytes: usize,
}

impl RequestResult {
    /// Dusration the request takes.
    pub fn duration(&self) -> std::time::Duration {
        self.end - self.start
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut opts: Opts = Opts::from_args();

    let headers = {
        let mut headers: http::header::HeaderMap = Default::default();

        // default headers
        headers.insert(
            http::header::ACCEPT,
            http::header::HeaderValue::from_static("*/*"),
        );
        if !opts.disable_compression {
            headers.insert(
                http::header::ACCEPT_ENCODING,
                http::header::HeaderValue::from_static("gzip, br"),
            );
        }

        let host = if let Some(port) = opts.url.port() {
            format!("{}:{}", opts.url.host_str().context("get host")?, port)
        } else {
            opts.url.host_str().context("get host")?.to_string()
        };

        headers.insert(
            http::header::HOST,
            http::header::HeaderValue::from_str(host.as_str())?,
        );

        headers.extend(
            opts.headers
                .into_iter()
                .map(|s| {
                    let header = s.splitn(2, ": ").collect::<Vec<_>>();
                    anyhow::ensure!(header.len() == 2, anyhow::anyhow!("Parse header"));
                    let name = HeaderName::from_bytes(header[0].as_bytes())?;
                    let value = HeaderValue::from_str(header[1])?;
                    Ok::<(HeaderName, HeaderValue), anyhow::Error>((name, value))
                })
                .collect::<anyhow::Result<Vec<_>>>()?
                .into_iter(),
        );

        if let Some(h) = opts.accept_header {
            headers.insert(http::header::ACCEPT, HeaderValue::from_bytes(h.as_bytes())?);
        }

        if let Some(h) = opts.content_type {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_bytes(h.as_bytes())?,
            );
        }

        if let Some(h) = opts.host {
            headers.insert(http::header::HOST, HeaderValue::from_bytes(h.as_bytes())?);
        }

        if let Some(auth) = opts.basic_auth {
            let u_p = auth.splitn(2, ':').collect::<Vec<_>>();
            anyhow::ensure!(u_p.len() == 2, anyhow::anyhow!("Parse auth"));
            let mut header_value = b"Basic ".to_vec();
            {
                use std::io::Write;
                let username = u_p[0];
                let password = if u_p[1].is_empty() {
                    None
                } else {
                    Some(u_p[1])
                };
                let mut encoder =
                    base64::write::EncoderWriter::new(&mut header_value, base64::STANDARD);
                // The unwraps here are fine because Vec::write* is infallible.
                write!(encoder, "{}:", username).unwrap();
                if let Some(password) = password {
                    write!(encoder, "{}", password).unwrap();
                }
            }

            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_bytes(&header_value)?,
            );
        }

        headers
    };

    let body: Option<&'static _> = match (opts.body_string, opts.body_path) {
        (Some(body), _) => Some(Box::leak(body.into_boxed_str().into_boxed_bytes())),
        (_, Some(path)) => {
            let mut buf = Vec::new();
            std::fs::File::open(path)?.read_to_end(&mut buf)?;
            Some(Box::leak(buf.into_boxed_slice()))
        }
        _ => None,
    };

    let (result_tx, mut result_rx) = flume::unbounded();

    let start = std::time::Instant::now();

    let data_collector = if opts.no_tui {
        // When `--no-tui` is enabled, just collect all data.
        tokio::spawn(
            async move {
                let (ctrl_c_tx, mut ctrl_c_rx) = flume::unbounded();

                tokio::spawn(async move {
                    if let Ok(())  = tokio::signal::ctrl_c().await {
                        let _ = ctrl_c_tx.send(());
                    }
                });

                let mut all: Vec<anyhow::Result<RequestResult>> = Vec::new();
                loop {
                    tokio::select! {
                        report = result_rx.recv_async() => {
                            if let Ok(report) = report {
                                all.push(report);
                            } else {
                                break;
                            }
                        }
                        _ = ctrl_c_rx.recv_async() => {
                            // User pressed ctrl-c.
                            let _ = printer::print_summary(&mut std::io::stdout(),&all, start.elapsed());
                            std::process::exit(libc::EXIT_SUCCESS);
                        }
                    }
                }
                all
            }
            .map(Ok),
        )
        .boxed()
    } else {
        tokio::spawn(
            monitor::Monitor {
                end_line: opts
                    .duration
                    .as_ref()
                    .map(|d| monitor::EndLine::Duration(d.0))
                    .unwrap_or(monitor::EndLine::NumQuery(opts.n_requests)),
                report_receiver: result_rx,
                start,
                fps: opts.fps,
            }
            .monitor(),
        )
        .boxed()
    };

    // On mac, tokio runtime crashes when too many files are opend.
    // Then reset terminal mode and exit immediately.
    std::panic::set_hook(Box::new(|info| {
        use crossterm::ExecutableCommand;
        let _ = std::io::stdout().execute(crossterm::terminal::LeaveAlternateScreen);
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = std::io::stdout().execute(crossterm::cursor::Show);
        eprintln!("{}", info);
        std::process::exit(libc::EXIT_FAILURE);
    }));

    let client_builder = client::ClientBuilder {
        url: opts.url,
        method: opts.method,
        headers,
        body,
        tcp_nodelay: opts.tcp_nodelay,
        timeout: opts.timeout.map(|d| d.0),
    };
    if let Some(ParseDuration(duration)) = opts.duration.take() {
        if let Some(qps) = opts.query_per_second {
            client::work_until_with_qps(
                client_builder,
                result_tx,
                qps,
                start,
                start + duration,
                opts.n_workers,
            )
            .await;
        } else {
            client::work_until(client_builder, result_tx, start + duration, opts.n_workers).await;
        }
    } else if let Some(qps) = opts.query_per_second {
        client::work_with_qps(
            client_builder,
            result_tx,
            qps,
            opts.n_requests,
            opts.n_workers,
        )
        .await;
    } else {
        client::work(client_builder, result_tx, opts.n_requests, opts.n_workers).await;
    }

    let duration = start.elapsed();

    let res: Vec<anyhow::Result<RequestResult>> = data_collector.await??;

    printer::print_summary(&mut std::io::stdout(), &res, duration)?;

    if cfg!(target_os = "macos") {
        // On macos, it takes too long time in end of execution for many `-c`.
        // So call exit to quit immediately.
        std::process::exit(libc::EXIT_SUCCESS);
    } else {
        Ok(())
    }
}
