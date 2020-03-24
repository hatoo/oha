use futures::prelude::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::io::Read;
use structopt::StructOpt;
use url::Url;

mod monitor;
mod printer;
mod work;

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
    url: String,
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
    method: reqwest::Method,
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
    #[structopt(help = "HTTP proxy", short = "x")]
    proxy: Option<String>,
    #[structopt(help = "Only HTTP2", long = "http2")]
    only_http2: bool,
    #[structopt(help = "HTTP Host header", long = "host")]
    host: Option<String>,
    #[structopt(help = "Disable compression.", long = "disable-compression")]
    disable_compression: bool,
    #[structopt(
        help = "Limit for number of Redirect. Set 0 for no redirection.",
        default_value = "10",
        long = "redirect"
    )]
    redirect: usize,
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
    status: reqwest::StatusCode,
    /// Length of body
    len_bytes: usize,
}

impl RequestResult {
    /// Dusration the request takes.
    pub fn duration(&self) -> std::time::Duration {
        self.end - self.start
    }
}

#[derive(Clone)]
/// All data to send a request
struct Request {
    /// reqwest client. We can clone this freely.
    client: reqwest::Client,
    /// HTTP method
    method: reqwest::Method,
    /// Target URL
    url: Url,
    /// Custom body to send
    body: Option<&'static [u8]>,
    /// Basic auth info. (username, password)
    basic_auth: Option<(String, Option<String>)>,
}

impl Request {
    async fn request(self) -> anyhow::Result<RequestResult> {
        let start = std::time::Instant::now();
        let mut req = self.client.request(self.method, self.url);
        if let Some(body) = self.body {
            req = req.body(body);
        }
        if let Some((user, pass)) = self.basic_auth {
            req = req.basic_auth(user, pass);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let len_bytes = resp.bytes().await?.len();
        let end = std::time::Instant::now();
        Ok::<_, anyhow::Error>(RequestResult {
            start,
            end,
            status,
            len_bytes,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut opts: Opts = Opts::from_args();
    let url = Url::parse(opts.url.as_str())?;
    let client = {
        // Various settings for client here.
        let mut client_builder = reqwest::ClientBuilder::new();
        if let Some(proxy) = opts.proxy {
            client_builder = client_builder.proxy(reqwest::Proxy::all(proxy.as_str())?);
        }
        if opts.only_http2 {
            client_builder = client_builder.http2_prior_knowledge();
        }
        if let Some(ParseDuration(d)) = opts.timeout {
            client_builder = client_builder.timeout(d);
        }
        let mut headers: HeaderMap = opts
            .headers
            .into_iter()
            .map(|s| {
                let header = s.splitn(2, ": ").collect::<Vec<_>>();
                anyhow::ensure!(header.len() == 2, anyhow::anyhow!("Parse header"));
                let name = HeaderName::from_bytes(header[0].as_bytes())?;
                let value = HeaderValue::from_str(header[1])?;
                Ok::<(HeaderName, HeaderValue), anyhow::Error>((name, value))
            })
            .collect::<anyhow::Result<HeaderMap>>()?;

        if let Some(h) = opts.accept_header {
            headers.insert(
                reqwest::header::ACCEPT,
                HeaderValue::from_bytes(h.as_bytes())?,
            );
        }
        if let Some(h) = opts.content_type {
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                HeaderValue::from_bytes(h.as_bytes())?,
            );
        }
        if let Some(h) = opts.host {
            headers.insert(
                reqwest::header::HOST,
                HeaderValue::from_bytes(h.as_bytes())?,
            );
        }
        if opts.disable_compression {
            client_builder = client_builder.no_gzip().no_brotli();
        }

        client_builder = client_builder.redirect(if opts.redirect == 0 {
            reqwest::redirect::Policy::none()
        } else {
            reqwest::redirect::Policy::limited(opts.redirect)
        });

        if opts.tcp_nodelay {
            client_builder = client_builder.tcp_nodelay();
        }

        client_builder.default_headers(headers).build()?
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

    let basic_auth = if let Some(auth) = opts.basic_auth {
        let u_p = auth.splitn(2, ':').collect::<Vec<_>>();
        anyhow::ensure!(u_p.len() == 2, anyhow::anyhow!("Parse auth"));
        Some((
            u_p[0].to_string(),
            if u_p[1].is_empty() {
                None
            } else {
                Some(u_p[1].to_string())
            },
        ))
    } else {
        None
    };

    let (result_tx, result_rx) = crossbeam::channel::unbounded();

    let start = std::time::Instant::now();

    let data_collector = if opts.no_tui {
        // When `--no-tui` is enabled, just collect all data.
        tokio::spawn(
            async move {
                let (proxy_tx, mut proxy_rx) = tokio::sync::mpsc::unbounded_channel();
                let (mut ctrl_c_tx, mut ctrl_c_rx) = tokio::sync::mpsc::unbounded_channel();

                tokio::spawn(async move {
                    while let Ok(v) = result_rx.recv() {
                        proxy_tx.send(v).unwrap();
                    }
                    ()
                });

                tokio::spawn(async move {
                    if let Ok(())  = tokio::signal::ctrl_c().await {
                        let _ = ctrl_c_tx.send(());
                    }
                });

                let mut all: Vec<anyhow::Result<RequestResult>> = Vec::new();
                loop {
                    tokio::select! {
                        report = proxy_rx.recv() => {
                            if let Some(report) = report {
                                all.push(report);
                            } else {
                                break;
                            }
                        }
                        _ = ctrl_c_rx.recv() => {
                            // User pressed ctrl-c.
                            let _ = printer::print_summary(&mut std::io::stdout(),&all, start.elapsed());
                            std::process::exit(libc::EXIT_SUCCESS);
                        }
                        _ = tokio::task::yield_now() => {}
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

    let req = Request {
        method: opts.method,
        url,
        client: client.clone(),
        body,
        basic_auth,
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

    let task_generator = || async { result_tx.send(req.clone().request().await) };

    // Start sending requests here
    if let Some(ParseDuration(duration)) = opts.duration.take() {
        if let Some(qps) = opts.query_per_second.take() {
            work::work_until_with_qps(task_generator, qps, start, start + duration, opts.n_workers)
                .await
        } else {
            work::work_until(task_generator, start + duration, opts.n_workers).await
        }
    } else if let Some(qps) = opts.query_per_second.take() {
        work::work_with_qps(task_generator, qps, opts.n_requests, opts.n_workers).await
    } else {
        work::work(task_generator, opts.n_requests, opts.n_workers).await
    };

    let duration = start.elapsed();
    std::mem::drop(result_tx);

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
