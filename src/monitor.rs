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
use tui::text::{Span, Spans};
use tui::widgets::{BarChart, Block, Borders, Gauge, Paragraph};
use tui::Terminal;

use crate::client::RequestResult;
use crate::timescale::{TimeLabel, TimeScale};

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

        // None means auto timescale which depends on how long it takes
        let mut timescale_auto = None;

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

            let timescale = if let Some(timescale) = timescale_auto {
                timescale
            } else {
                TimeScale::from_elapsed(self.start.elapsed())
            };

            let bin = timescale.as_secs_f64();

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

            let cols = bar_num_req
                .iter()
                .map(|x| x.to_string().chars().count())
                .max()
                .unwrap_or(0);

            let bar_num_req: Vec<(String, u64)> = bar_num_req
                .into_iter()
                .enumerate()
                .map(|(i, n)| {
                    (
                        {
                            let mut s = TimeLabel { x: i, timescale }.to_string();
                            if cols > s.len() {
                                for _ in 0..cols - s.len() {
                                    s.push(' ');
                                }
                            }
                            s
                        },
                        n,
                    )
                })
                .collect();

            let bar_num_req_str: Vec<(&str, u64)> =
                bar_num_req.iter().map(|(a, b)| (a.as_str(), *b)).collect();

            #[cfg(unix)]
            let nofile = match tokio::fs::read_dir("/dev/fd").await {
                Ok(dir) => Ok(dir.fold(0, |c, _| c + 1).await),
                Err(e) => Err(e),
            };

            terminal.draw(|f| {
                let row4 = Layout::default()
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
                    .split(row4[1]);

                let bottom = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                    .split(row4[3]);

                let gauge_label = match &self.end_line {
                    EndLine::Duration(d) => format!(
                        "{} / {}",
                        humantime::Duration::from(std::time::Duration::from_secs(
                            (now - self.start).as_secs_f64() as u64
                        )),
                        humantime::Duration::from(*d)
                    ),
                    EndLine::NumQuery(n) => format!("{} / {}", all.len(), n),
                };
                let gauge = Gauge::default()
                    .block(Block::default().title("Progress").borders(Borders::ALL))
                    .style(Style::default().fg(Color::White))
                    .gauge_style(Style::default().fg(Color::White))
                    .label(Span::raw(gauge_label))
                    .ratio(progress);
                f.render_widget(gauge, row4[0]);

                let last_1_timescale = all
                    .iter()
                    .rev()
                    .filter_map(|r| r.as_ref().ok())
                    .take_while(|r| (now - r.end).as_secs_f64() <= timescale.as_secs_f64())
                    .collect::<Vec<_>>();

                let statics_text = vec![
                    Spans::from(format!("Requests : {}", last_1_timescale.len())),
                    Spans::from(format!(
                        "Slowest: {:.4} secs",
                        last_1_timescale
                            .iter()
                            .map(|r| r.duration())
                            .max()
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(std::f64::NAN)
                    )),
                    Spans::from(format!(
                        "Fastest: {:.4} secs",
                        last_1_timescale
                            .iter()
                            .map(|r| r.duration())
                            .min()
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(std::f64::NAN)
                    )),
                    Spans::from(format!(
                        "Average: {:.4} secs",
                        last_1_timescale
                            .iter()
                            .map(|r| r.duration())
                            .sum::<std::time::Duration>()
                            .as_secs_f64()
                            / last_1_timescale.len() as f64
                    )),
                    Spans::from(format!(
                        "Data: {}",
                        Byte::from_bytes(
                            last_1_timescale
                                .iter()
                                .map(|r| r.len_bytes as u128)
                                .sum::<u128>()
                        )
                        .get_appropriate_unit(true)
                    )),
                    #[cfg(unix)]
                    // Note: Windows can open 255 * 255 * 255 files. So not showing on windows is OK.
                    Spans::from(format!(
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
                let statics_title = format!("statics for last {}", timescale);
                let statics = Paragraph::new(statics_text).block(
                    Block::default()
                        .title(Span::raw(statics_title))
                        .borders(Borders::ALL),
                );
                f.render_widget(statics, mid[0]);

                let mut status_v: Vec<(http::StatusCode, usize)> =
                    status_dist.clone().into_iter().collect();
                status_v.sort_by_key(|t| std::cmp::Reverse(t.1));

                let statics2_text = status_v
                    .into_iter()
                    .map(|(status, count)| {
                        Spans::from(format!("[{}] {} responses", status.as_str(), count))
                    })
                    .collect::<Vec<_>>();
                let statics2 = Paragraph::new(statics2_text).block(
                    Block::default()
                        .title("Status code distribution")
                        .borders(Borders::ALL),
                );
                f.render_widget(statics2, mid[1]);

                let mut error_v: Vec<(String, usize)> = error_dist.clone().into_iter().collect();
                error_v.sort_by_key(|t| std::cmp::Reverse(t.1));
                let errors_text = error_v
                    .into_iter()
                    .map(|(e, count)| Spans::from(format!("[{}] {}", count, e)))
                    .collect::<Vec<_>>();
                let errors = Paragraph::new(errors_text).block(
                    Block::default()
                        .title("Error distribution")
                        .borders(Borders::ALL),
                );
                f.render_widget(errors, row4[2]);

                let title = format!(
                    "Requests / past {}{}. press -/+/a to change",
                    timescale,
                    if timescale_auto.is_none() {
                        " (auto)"
                    } else {
                        ""
                    }
                );

                let barchart = BarChart::default()
                    .block(
                        Block::default()
                            .title(Span::raw(title))
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
                f.render_widget(barchart, bottom[0]);

                let resp_histo_width = 7;
                let resp_histo_data: Vec<(String, u64)> = {
                    let bins = if bottom[1].width < 2 {
                        0
                    } else {
                        (bottom[1].width as usize - 2) / (resp_histo_width + 1)
                    };
                    let values = all
                        .iter()
                        .rev()
                        .filter_map(|r| r.as_ref().ok())
                        .take_while(|r| (now - r.end).as_secs_f64() < timescale.as_secs_f64())
                        .map(|r| r.duration().as_secs_f64())
                        .collect::<Vec<_>>();

                    let histo = crate::histogram::histogram(&values, bins);
                    histo
                        .into_iter()
                        .map(|(label, v)| (format!("{:.4}", label), v as u64))
                        .collect()
                };

                let resp_histo_data_str: Vec<(&str, u64)> = resp_histo_data
                    .iter()
                    .map(|(l, v)| (l.as_str(), *v))
                    .collect();

                let resp_histo = BarChart::default()
                    .block(
                        Block::default()
                            .title("Response time histogram")
                            .borders(Borders::ALL),
                    )
                    .data(resp_histo_data_str.as_slice())
                    .bar_width(resp_histo_width as u16);
                f.render_widget(resp_histo, bottom[1]);
            })?;

            while crossterm::event::poll(std::time::Duration::from_secs(0))? {
                match crossterm::event::read()? {
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('+'),
                        ..
                    }) => timescale_auto = Some(timescale.dec()),
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('-'),
                        ..
                    }) => timescale_auto = Some(timescale.inc()),
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('a'),
                        ..
                    }) => {
                        if timescale_auto.is_some() {
                            timescale_auto = None;
                        } else {
                            timescale_auto = Some(timescale)
                        }
                    }
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
