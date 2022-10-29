use anyhow::Context;
use clap::{AppSettings, Parser};
use crossterm::tty::IsTty;
use futures::prelude::*;
use http::header::{HeaderName, HeaderValue};
use printer::PrintMode;
use std::sync::Arc;
use std::{io::Read, str::FromStr};

mod client;
mod histogram;
mod http_wrapper;
mod monitor;
mod printer;
mod timescale;

use client::{ClientError, RequestResult};

#[derive(Parser)]
#[clap(
    author,
    about,
    version,
    global_setting = AppSettings::DeriveDisplayOrder,
    override_usage = "oha [FLAGS] [OPTIONS] <url>"
)]
struct Opts {
    #[clap(help = "Target URL.")]
    url: http::Uri,
    #[structopt(
        help = "Number of requests to run.",
        short = 'n',
        default_value = "200"
    )]
    n_requests: usize,
    #[clap(
        help = "Number of workers to run concurrently. You may should increase limit to number of open files for larger `-c`.",
        short = 'c',
        default_value = "50"
    )]
    n_workers: usize,
    #[clap(
        help = "Duration of application to send requests. If duration is specified, n is ignored.
Examples: -z 10s -z 3m.",
        short = 'z'
    )]
    duration: Option<humantime::Duration>,
    #[clap(help = "Rate limit for all, in queries per second (QPS)", short = 'q')]
    query_per_second: Option<usize>,
    #[clap(
        help = "Correct latency to avoid coordinated omission problem. It's ignored if -q is not set.",
        long = "latency-correction"
    )]
    latency_correction: bool,
    #[clap(help = "No realtime tui", long = "no-tui")]
    no_tui: bool,
    #[clap(help = "Print results as JSON", short, long)]
    json: bool,
    #[clap(help = "Frame per second for tui.", default_value = "16", long = "fps")]
    fps: usize,
    #[clap(
        help = "HTTP method",
        short = 'm',
        long = "method",
        default_value = "GET"
    )]
    method: http::Method,
    #[clap(help = "Custom HTTP header. Examples: -H \"foo: bar\"", short = 'H')]
    headers: Vec<String>,
    #[clap(help = "Timeout for each request. Default to infinite.", short = 't')]
    timeout: Option<humantime::Duration>,
    #[clap(help = "HTTP Accept Header.", short = 'A')]
    accept_header: Option<String>,
    #[clap(help = "HTTP request body.", short = 'd')]
    body_string: Option<String>,
    #[clap(help = "HTTP request body from file.", short = 'D')]
    body_path: Option<std::path::PathBuf>,
    #[clap(help = "Content-Type.", short = 'T')]
    content_type: Option<String>,
    #[clap(help = "Basic authentication, username:password", short = 'a')]
    basic_auth: Option<String>,
    /*
    #[structopt(help = "HTTP proxy", short = "x")]
    proxy: Option<String>,
    */
    #[clap(
        help = "HTTP version. Available values 0.9, 1.0, 1.1, 2.",
        long = "http-version"
    )]
    http_version: Option<String>,
    #[clap(help = "HTTP Host header", long = "host")]
    host: Option<String>,
    #[clap(help = "Disable compression.", long = "disable-compression")]
    disable_compression: bool,
    #[clap(
        help = "Limit for number of Redirect. Set 0 for no redirection.",
        default_value = "10",
        short = 'r',
        long = "redirect"
    )]
    redirect: usize,
    #[clap(
        help = "Disable keep-alive, prevents re-use of TCP connections between different HTTP requests.",
        long = "disable-keepalive"
    )]
    disable_keepalive: bool,
    #[clap(help = "Lookup only ipv6.", long = "ipv6")]
    ipv6: bool,
    #[clap(help = "Lookup only ipv4.", long = "ipv4")]
    ipv4: bool,
    #[clap(help = "Accept invalid certs.", long = "insecure")]
    insecure: bool,
    #[clap(
        help = "Override DNS resolution and default port numbers with strings like 'example.org:443:localhost:8443'",
        long = "connect-to"
    )]
    connect_to: Vec<ConnectToEntry>,
    #[clap(help = "Disable the color scheme.", long = "disable-color")]
    disable_color: bool,
}

/// An entry specified by `connect-to` to override DNS resolution and default
/// port numbers. For example, `example.org:80:localhost:5000` will connect to
/// `localhost:5000` whenever `http://example.org` is requested.
#[derive(Clone, Debug)]
pub struct ConnectToEntry {
    pub requested_host: String,
    pub requested_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl FromStr for ConnectToEntry {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expected_syntax: &str = "syntax for --connect-to is host:port:target_host:target_port";

        let (s, target_port) = s.rsplit_once(':').ok_or(expected_syntax)?;
        let (s, target_host) = if s.ends_with(']') {
            // ipv6
            let i = s.rfind(":[").ok_or(expected_syntax)?;
            (&s[..i], &s[i + 1..])
        } else {
            s.rsplit_once(':').ok_or(expected_syntax)?
        };
        let (requested_host, requested_port) = s.rsplit_once(':').ok_or(expected_syntax)?;

        Ok(ConnectToEntry {
            requested_host: requested_host.into(),
            requested_port: requested_port.parse().map_err(|err| {
                format!("requested port must be an u16, but got {requested_port}: {err}")
            })?,
            target_host: target_host.into(),
            target_port: target_port.parse().map_err(|err| {
                format!("target port must be an u16, but got {target_port}: {err}")
            })?,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut opts: Opts = Opts::parse();

    let http_version: http::Version = if let Some(http_version) = opts.http_version {
        match http_version.as_str() {
            "0.9" => http::Version::HTTP_09,
            "1.0" => http::Version::HTTP_10,
            "1.1" => http::Version::HTTP_11,
            "2.0" | "2" => http::Version::HTTP_2,
            "3.0" | "3" => http::Version::HTTP_3,
            _ => anyhow::bail!("Unknown HTTP version. Valid versions are 0.9, 1.0, 1.1, 2, 3"),
        }
    } else {
        http::Version::HTTP_11
    };

    let headers = {
        let mut headers: http::header::HeaderMap = Default::default();

        // Accept all
        headers.insert(
            http::header::ACCEPT,
            http::header::HeaderValue::from_static("*/*"),
        );

        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding
        if !opts.disable_compression {
            headers.insert(
                http::header::ACCEPT_ENCODING,
                http::header::HeaderValue::from_static("gzip, compress, deflate, br"),
            );
        }

        headers.insert(
            http::header::HOST,
            http::header::HeaderValue::from_str(
                opts.url.authority().context("get authority")?.as_str(),
            )?,
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

        if opts.disable_keepalive && http_version == http::Version::HTTP_11 {
            headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        }

        headers
    };

    let body: Option<&'static [u8]> = match (opts.body_string, opts.body_path) {
        (Some(body), _) => Some(Box::leak(body.into_boxed_str().into_boxed_bytes())),
        (_, Some(path)) => {
            let mut buf = Vec::new();
            std::fs::File::open(path)?.read_to_end(&mut buf)?;
            Some(Box::leak(buf.into_boxed_slice()))
        }
        _ => None,
    };

    let print_mode = if opts.json {
        PrintMode::Json
    } else {
        PrintMode::Text
    };

    let (result_tx, result_rx) = flume::unbounded();

    let start = std::time::Instant::now();

    let data_collector = if opts.no_tui || !std::io::stdout().is_tty() {
        // When `--no-tui` is enabled, just collect all data.
        tokio::spawn(
            async move {
                let (ctrl_c_tx, ctrl_c_rx) = flume::unbounded();

                tokio::spawn(async move {
                    if let Ok(())  = tokio::signal::ctrl_c().await {
                        let _ = ctrl_c_tx.send(());
                    }
                });

                let mut all: Vec<Result<RequestResult, ClientError>> = Vec::new();
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
                            let _ = printer::print_result(&mut std::io::stdout(),print_mode,start, &all, start.elapsed());
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
        // Spawn monitor future which draws realtime tui
        tokio::spawn(
            monitor::Monitor {
                print_mode,
                end_line: opts
                    .duration
                    .map(|d| monitor::EndLine::Duration(d.into()))
                    .unwrap_or(monitor::EndLine::NumQuery(opts.n_requests)),
                report_receiver: result_rx,
                start,
                fps: opts.fps,
                disable_color: opts.disable_color,
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

    let ip_strategy = match (opts.ipv4, opts.ipv6) {
        (false, false) => Default::default(),
        (true, false) => trust_dns_resolver::config::LookupIpStrategy::Ipv4Only,
        (false, true) => trust_dns_resolver::config::LookupIpStrategy::Ipv6Only,
        (true, true) => trust_dns_resolver::config::LookupIpStrategy::Ipv4AndIpv6,
    };
    let (config, _) = trust_dns_resolver::system_conf::read_system_conf()?;
    let mut resolver_opts = trust_dns_resolver::config::ResolverOpts::default();
    resolver_opts.ip_strategy = ip_strategy;
    let resolver = trust_dns_resolver::AsyncResolver::tokio(config, resolver_opts)?;

    // client_builder builds client for each workers
    let client_builder = client::ClientBuilder {
        http_version,
        url: opts.url,
        method: opts.method,
        headers,
        body,
        resolver: Arc::new(resolver),
        timeout: opts.timeout.map(|d| d.into()),
        redirect_limit: opts.redirect,
        disable_keepalive: opts.disable_keepalive,
        insecure: opts.insecure,
        connect_to: Arc::new(opts.connect_to),
    };
    if let Some(duration) = opts.duration.take() {
        match opts.query_per_second {
            Some(0) | None => {
                client::work_until(
                    client_builder,
                    result_tx,
                    start + duration.into(),
                    opts.n_workers,
                )
                .await
            }
            Some(qps) => {
                if opts.latency_correction {
                    client::work_until_with_qps_latency_correction(
                        client_builder,
                        result_tx,
                        qps,
                        start,
                        start + duration.into(),
                        opts.n_workers,
                    )
                    .await
                } else {
                    client::work_until_with_qps(
                        client_builder,
                        result_tx,
                        qps,
                        start,
                        start + duration.into(),
                        opts.n_workers,
                    )
                    .await
                }
            }
        }
    } else {
        match opts.query_per_second {
            Some(0) | None => {
                client::work(client_builder, result_tx, opts.n_requests, opts.n_workers).await
            }
            Some(qps) => {
                if opts.latency_correction {
                    client::work_with_qps_latency_correction(
                        client_builder,
                        result_tx,
                        qps,
                        opts.n_requests,
                        opts.n_workers,
                    )
                    .await
                } else {
                    client::work_with_qps(
                        client_builder,
                        result_tx,
                        qps,
                        opts.n_requests,
                        opts.n_workers,
                    )
                    .await
                }
            }
        }
    }

    let duration = start.elapsed();

    let res: Vec<Result<RequestResult, ClientError>> = data_collector.await??;

    printer::print_result(&mut std::io::stdout(), print_mode, start, &res, duration)?;

    Ok(())
}
