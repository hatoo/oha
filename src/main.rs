use anyhow::Context;
use clap::Clap;
use futures::prelude::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
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

#[derive(Clap)]
#[clap(version = clap::crate_version!(), author = clap::crate_authors!(), about = "HTTP load generator, inspired by rakyll/hey with tui animation")]
struct Opts {
    #[clap(help = "Target URL.")]
    url: String,
    #[clap(help = "Number of requests.", short = "n", default_value = "200")]
    n_requests: usize,
    #[clap(help = "Number of workers.", short = "c", default_value = "50")]
    n_workers: usize,
    #[clap(help = "Duration.\nExamples: -z 10s -z 3m.", short = "z")]
    duration: Option<ParseDuration>,
    #[clap(help = "Query per second limit.", short = "q")]
    query_per_second: Option<usize>,
    #[clap(help = "No realtime tui", long = "no-tui")]
    no_tui: bool,
    #[clap(help = "Frame per second for tui.", default_value = "16", long = "fps")]
    fps: usize,
    #[clap(
        help = "HTTP method",
        short = "m",
        long = "method",
        default_value = "GET"
    )]
    method: reqwest::Method,
    #[clap(help = "HTTP header", short = "H")]
    headers: Vec<String>,
    #[clap(help = "Timeout for each request. Default to infinite.", short = "t")]
    timeout: Option<ParseDuration>,
}

#[derive(Debug, Clone)]
pub struct RequestResult {
    start: std::time::Instant,
    end: std::time::Instant,
    status: reqwest::StatusCode,
    len_bytes: usize,
}

impl RequestResult {
    pub fn duration(&self) -> std::time::Duration {
        self.end - self.start
    }
}

#[derive(Clone)]
struct Request {
    client: reqwest::Client,
    method: reqwest::Method,
    url: Url,
    headers: HeaderMap,
    timeout: Option<std::time::Duration>,
}

impl Request {
    async fn request(self) -> anyhow::Result<RequestResult> {
        let start = std::time::Instant::now();
        let mut req = self
            .client
            .request(self.method, self.url)
            .headers(self.headers);
        if let Some(timeout) = self.timeout {
            req = req.timeout(timeout);
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
    let mut opts: Opts = Opts::parse();
    let url = Url::parse(opts.url.as_str())?;
    let client = reqwest::Client::new();
    let headers: HeaderMap = opts
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

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let start = std::time::Instant::now();

    let data_collector = if opts.no_tui {
        tokio::spawn(async move {
            let mut all: Vec<anyhow::Result<RequestResult>> = Vec::new();
            loop {
                tokio::select! {
                    report = rx.recv() => {
                        if let Some(report) = report {
                            all.push(report);
                        } else {
                            break;
                        }
                    }
                    Ok(()) = tokio::signal::ctrl_c() => {
                        printer::print(&all, start.elapsed());
                        std::process::exit(0);
                    }
                }
            }
            all
        })
        .boxed()
    } else {
        use std::io;

        use termion::input::MouseTerminal;
        use termion::raw::IntoRawMode;
        use termion::screen::AlternateScreen;
        use tui::backend::TermionBackend;
        use tui::Terminal;

        let stdout = io::stdout().into_raw_mode().context(
            "Failed to make STDOUT into raw mode. You can use `--no-tui` to disable realtime tui.",
        )?;
        let stdout = MouseTerminal::from(stdout);
        let stdout = AlternateScreen::from(stdout);
        let backend = TermionBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.hide_cursor()?;

        tokio::spawn(
            monitor::Monitor {
                terminal,
                end_line: opts
                    .duration
                    .as_ref()
                    .map(|d| monitor::EndLine::Duration(d.0))
                    .unwrap_or(monitor::EndLine::NumQuery(opts.n_requests)),
                report_receiver: rx,
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
        headers,
        timeout: opts.timeout.map(|t| t.0),
    };

    let task_generator = || async { tx.send(req.clone().request().await) };
    if let Some(ParseDuration(duration)) = opts.duration.take() {
        if let Some(qps) = opts.query_per_second.take() {
            work::work_duration_with_qps(task_generator, qps, duration, opts.n_workers).await
        } else {
            work::work_duration(task_generator, duration, opts.n_workers).await
        }
    } else {
        if let Some(qps) = opts.query_per_second.take() {
            work::work_with_qps(task_generator, qps, opts.n_requests, opts.n_workers).await
        } else {
            work::work(task_generator, opts.n_requests, opts.n_workers).await
        }
    };
    let duration = start.elapsed();
    std::mem::drop(tx);

    let res: Vec<_> = data_collector.await?;

    printer::print(&res, duration);

    Ok(())
}
