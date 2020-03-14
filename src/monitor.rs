use byte_unit::Byte;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::ExecutableCommand;
use std::collections::HashMap;
use std::io;
use tokio::sync::mpsc::error::TryRecvError;
use tui::backend::CrosstermBackend;
use tui::layout::{Constraint, Direction, Layout};
use tui::style::{Color, Style};
use tui::widgets::{BarChart, Block, Borders, Gauge, Paragraph, Text};
use tui::Terminal;

use crate::RequestResult;

/// When the monitor ends
pub enum EndLine {
    /// After a duration
    Duration(std::time::Duration),
    /// After n query done
    NumQuery(usize),
}

pub struct Monitor {
    pub end_line: EndLine,
    /// All workers sends each result to this channel
    pub report_receiver: tokio::sync::mpsc::UnboundedReceiver<anyhow::Result<RequestResult>>,
    pub start: std::time::Instant,
    pub fps: usize,
}

impl Monitor {
    pub async fn monitor(
        mut self,
    ) -> Result<Vec<anyhow::Result<RequestResult>>, crossterm::ErrorKind> {
        crossterm::terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(crossterm::terminal::EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.hide_cursor()?;

        // Return this when ends to application print summary
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

            terminal
                .draw(|mut f| {
                    let top_mid_bot = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(
                            [
                                Constraint::Length(3),
                                Constraint::Length(7),
                                Constraint::Percentage(40),
                            ]
                            .as_ref(),
                        )
                        .split(f.size());

                    let mid = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(
                            [Constraint::Percentage(50), Constraint::Percentage(50)].as_ref(),
                        )
                        .split(top_mid_bot[1]);

                    let mut gauge = Gauge::default()
                        .block(Block::default().title("Progress").borders(Borders::ALL))
                        .style(Style::default().fg(Color::White))
                        .ratio(progress);
                    f.render(&mut gauge, top_mid_bot[0]);

                    let last_1_sec = all
                        .iter()
                        .rev()
                        .filter_map(|r| r.as_ref().ok())
                        .take_while(|r| (now - r.end).as_secs_f64() <= 1.0)
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
                        Text::raw(format!(
                            "Data: {}\n",
                            Byte::from_bytes(
                                last_1_sec.iter().map(|r| r.len_bytes as u128).sum::<u128>()
                            )
                            .get_appropriate_unit(true)
                        )),
                    ];
                    let mut statics = Paragraph::new(statics_text.iter()).block(
                        Block::default()
                            .title("statics for last 1 second")
                            .borders(Borders::ALL),
                    );
                    f.render(&mut statics, mid[0]);

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
                    f.render(&mut statics2, mid[1]);

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
                    f.render(&mut barchart, top_mid_bot[2]);
                })
                .unwrap();
            while crossterm::event::poll(std::time::Duration::from_secs(0))? {
                match crossterm::event::read()? {
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('q'),
                        ..
                    })
                    | Event::Key(KeyEvent {
                        code: KeyCode::Char('c'),
                        modifiers: KeyModifiers::CONTROL,
                    }) => {
                        std::io::stdout().execute(crossterm::terminal::LeaveAlternateScreen)?;
                        crossterm::terminal::disable_raw_mode()?;
                        terminal.show_cursor()?;
                        crate::printer::print(&all, now - self.start);
                        std::process::exit(0);
                    }
                    _ => (),
                }
            }

            tokio::time::delay_for(std::time::Duration::from_secs(1) / self.fps as u32).await;
        }

        std::io::stdout().execute(crossterm::terminal::LeaveAlternateScreen)?;
        crossterm::terminal::disable_raw_mode()?;
        terminal.show_cursor()?;
        Ok(all)
    }
}
