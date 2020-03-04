use clap::Clap;
use futures::prelude::*;
use url::Url;

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
#[clap(version = clap::crate_version!(), author = clap::crate_authors!())]
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

async fn request(
    client: reqwest::Client,
    url: Url,
    reporter: tokio::sync::mpsc::UnboundedSender<anyhow::Result<RequestResult>>,
) -> Result<(), tokio::sync::mpsc::error::SendError<anyhow::Result<RequestResult>>> {
    let result = async move {
        let start = std::time::Instant::now();
        let resp = client.get(url.clone()).send().await?;
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
    .await;
    reporter.send(result)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut opts: Opts = Opts::parse();
    let url = Url::parse(opts.url.as_str())?;
    let client = reqwest::Client::new();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let data_collector = if opts.no_tui {
        tokio::spawn(async move {
            let mut all = Vec::new();
            while let Some(report) = rx.recv().await {
                all.push(report);
            }
            all
        })
        .boxed()
    } else {
        use std::io;

        use termion::event::{Event, Key};
        use termion::input::MouseTerminal;
        use termion::input::TermRead;
        use termion::raw::IntoRawMode;
        use termion::screen::AlternateScreen;
        use tui::backend::TermionBackend;
        use tui::layout::{Constraint, Direction, Layout};
        use tui::style::{Color, Modifier, Style};
        use tui::widgets::{BarChart, Block, Borders, Gauge};
        use tui::Terminal;

        let stdout = io::stdout().into_raw_mode()?;
        let stdout = MouseTerminal::from(stdout);
        let stdout = AlternateScreen::from(stdout);
        let backend = TermionBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.hide_cursor()?;

        let stdin = io::stdin();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();

        std::thread::spawn(move || {
            for c in stdin.events() {
                if let Ok(evt) = c {
                    event_tx.send(evt).unwrap();
                }
            }
        });

        let start = std::time::Instant::now();
        let duration = opts.duration.as_ref().map(|d| d.0.clone());
        let n_requests = opts.n_requests;

        tokio::spawn(async move {
            use tokio::sync::mpsc::error::TryRecvError;
            let mut all: Vec<anyhow::Result<RequestResult>> = Vec::new();
            'outer: loop {
                loop {
                    match rx.try_recv() {
                        Ok(report) => {
                            all.push(report);
                        }
                        Err(TryRecvError::Empty) => {
                            break;
                        }
                        Err(TryRecvError::Closed) => {
                            break 'outer;
                        }
                    }
                }

                let progress = if let Some(d) = duration {
                    ((std::time::Instant::now() - start).as_secs_f64() / d.as_secs_f64())
                        .max(0.0)
                        .min(1.0)
                } else {
                    (all.len() as f64 / n_requests as f64).max(0.0).min(1.0)
                };

                let now = std::time::Instant::now();

                let resolution = 12.0_f64.min(duration.map(|d| d.as_secs_f64()).unwrap_or(12.0));
                let count = 12;

                let bin = resolution / count as f64;

                let mut bar_num_req = vec![0u64; count];
                for r in all.iter().rev() {
                    if let Ok(r) = r.as_ref() {
                        let past = now - r.end;
                        let i = (past.as_secs_f64() / bin) as usize;
                        if i >= bar_num_req.len() {
                            break;
                        }
                        bar_num_req[i] += 1;
                    }
                }

                let bar_num_req: Vec<(String, u64)> = bar_num_req
                    .into_iter()
                    .enumerate()
                    .map(|(i, n)| (format!("{:.1}s", bin * i as f64), n))
                    .collect();

                let bar_num_req_str: Vec<(&str, u64)> =
                    bar_num_req.iter().map(|(a, b)| (a.as_str(), *b)).collect();

                // Some tui here
                terminal
                    .draw(|mut f| {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Max(3), Constraint::Length(16)].as_ref())
                            .split(f.size());

                        let mut gauge = Gauge::default()
                            .block(Block::default().title("Progress").borders(Borders::ALL))
                            .style(Style::default().fg(Color::White))
                            .ratio(progress);
                        f.render(&mut gauge, chunks[0]);

                        let mut barchart = BarChart::default()
                            .block(
                                Block::default()
                                    .title("Requests - number of requests / past seconds")
                                    .borders(Borders::ALL),
                            )
                            .data(bar_num_req_str.as_slice())
                            .bar_width(
                                bar_num_req
                                    .iter()
                                    .map(|(s, _)| s.chars().count())
                                    .max()
                                    .map(|w| w + 2)
                                    .unwrap_or(1) as u16,
                            );
                        f.render(&mut barchart, chunks[1]);
                    })
                    .unwrap();

                while let Ok(event) = event_rx.try_recv() {
                    match event {
                        Event::Key(Key::Ctrl('c')) | Event::Key(Key::Char('q')) => {
                            std::mem::drop(terminal);
                            printer::print(&all, std::time::Instant::now() - start);
                            std::process::exit(0);
                        }

                        _ => (),
                    }
                }

                // 60fps
                tokio::time::delay_for(std::time::Duration::from_secs(1) / 60).await;
            }
            all
        })
        .boxed()
    };

    let start = std::time::Instant::now();
    if let Some(ParseDuration(duration)) = opts.duration.take() {
        if let Some(qps) = opts.query_per_second.take() {
            work::work_duration_with_qps(
                || request(client.clone(), url.clone(), tx.clone()),
                qps,
                duration,
                opts.n_workers,
            )
            .await
        } else {
            work::work_duration(
                || request(client.clone(), url.clone(), tx.clone()),
                duration,
                opts.n_workers,
            )
            .await
        }
    } else {
        if let Some(qps) = opts.query_per_second.take() {
            work::work_with_qps(
                || request(client.clone(), url.clone(), tx.clone()),
                qps,
                opts.n_requests,
                opts.n_workers,
            )
            .await
        } else {
            work::work(
                || request(client.clone(), url.clone(), tx.clone()),
                opts.n_requests,
                opts.n_workers,
            )
            .await
        }
    };
    std::mem::drop(tx);

    let res: Vec<_> = data_collector.await?;
    let duration = std::time::Instant::now() - start;

    printer::print(&res, duration);

    Ok(())
}
