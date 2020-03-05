use std::collections::HashMap;
use std::io;
use termion::event::{Event, Key};
use termion::input::TermRead;
use tokio::sync::mpsc::error::TryRecvError;
use tui::layout::{Constraint, Direction, Layout};
use tui::style::{Color, Style};
use tui::widgets::{BarChart, Block, Borders, Gauge, Paragraph, Text};
use tui::Terminal;

use crate::RequestResult;

pub enum EndLine {
    Duration(std::time::Duration),
    NumQuery(usize),
}

pub struct Monitor<B: tui::backend::Backend> {
    pub terminal: Terminal<B>,
    pub end_line: EndLine,
    pub report_receiver: tokio::sync::mpsc::UnboundedReceiver<anyhow::Result<RequestResult>>,
    pub start: std::time::Instant,
    pub fps: usize,
}

impl<B: tui::backend::Backend> Monitor<B> {
    pub async fn monitor(mut self) -> Vec<anyhow::Result<RequestResult>> {
        let stdin = io::stdin();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();

        tokio::spawn(async move {
            for c in stdin.events() {
                if let Ok(evt) = c {
                    if event_tx.send(evt).is_err() {
                        break;
                    }
                }
            }
        });

        let mut all: Vec<anyhow::Result<RequestResult>> = Vec::new();
        let mut status_dist: HashMap<reqwest::StatusCode, usize> = HashMap::new();
        'outer: loop {
            loop {
                match self.report_receiver.try_recv() {
                    Ok(report) => {
                        if let Ok(report) = report.as_ref() {
                            *status_dist.entry(report.status).or_default() += 1;
                        }
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

            let now = std::time::Instant::now();
            let progress = match &self.end_line {
                EndLine::Duration(d) => ((now - self.start).as_secs_f64() / d.as_secs_f64())
                    .max(0.0)
                    .min(1.0),
                EndLine::NumQuery(n) => (all.len() as f64 / *n as f64).max(0.0).min(1.0),
            };

            let count = 32;
            let bin = 1.0;

            let mut bar_num_req = vec![0u64; count];
            let short_bin = (now - self.start).as_secs_f64() % bin;
            for r in all.iter().rev() {
                if let Ok(r) = r.as_ref() {
                    let past = (now - r.end).as_secs_f64();
                    let i = if past <= short_bin {
                        0
                    } else {
                        1 + ((past - short_bin) / bin) as usize
                    };
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

            self.terminal
                .draw(|mut f| {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(
                            [
                                Constraint::Length(3),
                                Constraint::Length(6),
                                Constraint::Percentage(40),
                            ]
                            .as_ref(),
                        )
                        .split(f.size());

                    let chunks2 = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(
                            [Constraint::Percentage(50), Constraint::Percentage(50)].as_ref(),
                        )
                        .split(chunks[1]);

                    let mut gauge = Gauge::default()
                        .block(Block::default().title("Progress").borders(Borders::ALL))
                        .style(Style::default().fg(Color::White))
                        .ratio(progress);
                    f.render(&mut gauge, chunks[0]);

                    let last_1_sec = all
                        .iter()
                        .rev()
                        .filter_map(|r| r.as_ref().ok())
                        .take_while(|r| (now - r.start).as_secs_f64() <= 1.0)
                        .collect::<Vec<_>>();
                    let statics_text = [
                        Text::raw(format!("Query per second: {}\n", last_1_sec.len())),
                        Text::raw(format!(
                            "Slowest: {:.4} secs\n",
                            last_1_sec
                                .iter()
                                .map(|r| r.duration())
                                .max()
                                .map(|d| d.as_secs_f64())
                                .unwrap_or(std::f64::NAN)
                        )),
                        Text::raw(format!(
                            "Fastest: {:.4} secs\n",
                            last_1_sec
                                .iter()
                                .map(|r| r.duration())
                                .min()
                                .map(|d| d.as_secs_f64())
                                .unwrap_or(std::f64::NAN)
                        )),
                        Text::raw(format!(
                            "Average: {:.4} secs\n",
                            last_1_sec
                                .iter()
                                .map(|r| r.duration())
                                .sum::<std::time::Duration>()
                                .as_secs_f64()
                                / last_1_sec.len() as f64
                        )),
                    ];
                    let mut statics = Paragraph::new(statics_text.iter()).block(
                        Block::default()
                            .title("statics for last 1 second")
                            .borders(Borders::ALL),
                    );
                    f.render(&mut statics, chunks2[0]);

                    let mut status_v: Vec<(reqwest::StatusCode, usize)> =
                        status_dist.clone().into_iter().collect();
                    status_v.sort_by_key(|t| std::cmp::Reverse(t.1));

                    let mut statics2_string = String::new();
                    for (status, count) in status_v {
                        statics2_string +=
                            format!("[{}] {} responses", status.as_str(), count).as_str();
                    }
                    let statics2_text = [Text::raw(statics2_string)];
                    let mut statics2 = Paragraph::new(statics2_text.iter()).block(
                        Block::default()
                            .title("Status code distribution")
                            .borders(Borders::ALL),
                    );
                    f.render(&mut statics2, chunks2[1]);

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
                    f.render(&mut barchart, chunks[2]);
                })
                .unwrap();
            while let Ok(event) = event_rx.try_recv() {
                match event {
                    Event::Key(Key::Ctrl('c')) | Event::Key(Key::Char('q')) => {
                        std::mem::drop(self.terminal);
                        crate::printer::print(&all, now - self.start);
                        std::process::exit(0);
                    }
                    _ => (),
                }
            }

            // 60fps
            tokio::time::delay_for(std::time::Duration::from_secs(1) / self.fps as u32).await;
        }

        all
    }
}
