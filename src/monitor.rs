use byte_unit::Byte;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::ExecutableCommand;
use flume::TryRecvError;
use std::collections::BTreeMap;
use std::io;
#[cfg(unix)]
use tokio::stream::StreamExt;
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
    pub report_receiver: flume::Receiver<anyhow::Result<RequestResult>>,
    // When started
    pub start: std::time::Instant,
    // Frame per scond of TUI
    pub fps: usize,
}

impl Monitor {
    pub async fn monitor(self) -> Result<Vec<anyhow::Result<RequestResult>>, crossterm::ErrorKind> {
        crossterm::terminal::enable_raw_mode()?;
        io::stdout().execute(crossterm::terminal::EnterAlternateScreen)?;
        io::stdout().execute(crossterm::cursor::Hide)?;

        let mut terminal = {
            let backend = CrosstermBackend::new(io::stdout());
            Terminal::new(backend)?
        };

        // Return this when ends to application print summary
        // We must not read all data from this due to computational cost.
        let mut all: Vec<anyhow::Result<RequestResult>> = Vec::new();
        // statics for HTTP status
        let mut status_dist: BTreeMap<http::StatusCode, usize> = Default::default();
        // statics for Error
        let mut error_dist: BTreeMap<String, usize> = Default::default();

        #[cfg(unix)]
        // Limit for number open files. eg. ulimit -n
        let nofile_limit = rlimit::getrlimit(rlimit::Resource::NOFILE);

        'outer: loop {
            let frame_start = std::time::Instant::now();
            loop {
                match self.report_receiver.try_recv() {
                    Ok(report) => {
                        match report.as_ref() {
                            Ok(report) => *status_dist.entry(report.status).or_default() += 1,
                            Err(e) => *error_dist.entry(e.to_string()).or_default() += 1,
                        }
                        all.push(report);
                    }
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Disconnected) => {
                        // Application ends.
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

            #[cfg(unix)]
            let nofile = match tokio::fs::read_dir("/dev/fd").await {
                Ok(dir) => Ok(dir.fold(0, |c, _| c + 1).await),
                Err(e) => Err(e),
            };

            terminal.draw(|mut f| {
                let top_mid2_bot = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints(
                        [
                            Constraint::Length(3),
                            Constraint::Length(8),
                            Constraint::Length(error_dist.len() as u16 + 2),
                            Constraint::Percentage(40),
                        ]
                        .as_ref(),
                    )
                    .split(f.size());

                let mid = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                    .split(top_mid2_bot[1]);

                let mut gauge = Gauge::default()
                    .block(Block::default().title("Progress").borders(Borders::ALL))
                    .style(Style::default().fg(Color::White))
                    .ratio(progress);
                f.render(&mut gauge, top_mid2_bot[0]);

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
                    #[cfg(unix)]
                    // Note: Windows can open 255 * 255 * 255 files. So not showing on windows is OK.
                    Text::raw(format!(
                        "Number of open files: {} / {}",
                        nofile
                            .map(|c| c.to_string())
                            .unwrap_or_else(|_| "Error".to_string()),
                        nofile_limit
                            .as_ref()
                            .map(|(s, _h)| s.to_string())
                            .unwrap_or_else(|_| "Unknown".to_string())
                    )),
                ];
                let mut statics = Paragraph::new(statics_text.iter()).block(
                    Block::default()
                        .title("statics for last 1 second")
                        .borders(Borders::ALL),
                );
                f.render(&mut statics, mid[0]);

                let mut status_v: Vec<(http::StatusCode, usize)> =
                    status_dist.clone().into_iter().collect();
                status_v.sort_by_key(|t| std::cmp::Reverse(t.1));

                let mut statics2_string = String::new();
                for (status, count) in status_v {
                    statics2_string +=
                        format!("[{}] {} responses\n", status.as_str(), count).as_str();
                }
                let statics2_text = [Text::raw(statics2_string)];
                let mut statics2 = Paragraph::new(statics2_text.iter()).block(
                    Block::default()
                        .title("Status code distribution")
                        .borders(Borders::ALL),
                );
                f.render(&mut statics2, mid[1]);

                let mut error_v: Vec<(String, usize)> = error_dist.clone().into_iter().collect();
                error_v.sort_by_key(|t| std::cmp::Reverse(t.1));
                let mut errors_string = String::new();
                for (e, count) in error_v {
                    errors_string += format!("[{}] {}\n", count, e).as_str();
                }
                let errors_text = [Text::raw(errors_string)];
                let mut errors = Paragraph::new(errors_text.iter()).block(
                    Block::default()
                        .title("Error distribution")
                        .borders(Borders::ALL),
                );
                f.render(&mut errors, top_mid2_bot[2]);

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
                f.render(&mut barchart, top_mid2_bot[3]);
            })?;
            while crossterm::event::poll(std::time::Duration::from_secs(0))? {
                match crossterm::event::read()? {
                    // User pressed q or ctrl-c
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
                        std::io::stdout().execute(crossterm::cursor::Show)?;
                        let _ = crate::printer::print_summary(
                            &mut std::io::stdout(),
                            &all,
                            now - self.start,
                        );
                        std::process::exit(libc::EXIT_SUCCESS);
                    }
                    _ => (),
                }
            }

            let per_frame = std::time::Duration::from_secs(1) / self.fps as u32;
            let elapsed = frame_start.elapsed();
            if per_frame > elapsed {
                tokio::time::delay_for(per_frame - elapsed).await;
            }
        }

        std::io::stdout().execute(crossterm::terminal::LeaveAlternateScreen)?;
        crossterm::terminal::disable_raw_mode()?;
        std::io::stdout().execute(crossterm::cursor::Show)?;
        Ok(all)
    }
}
