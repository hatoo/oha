use crate::client::ConnectionTime;
use crate::client::RequestResult;
use crate::histogram::histogram;
use average::Max;
use average::Variance;
use byte_unit::Byte;
use crossterm::style::{StyledContent, Stylize};
use http::StatusCode;
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;
use std::time::Instant;

#[derive(Clone, Copy)]
struct StyleScheme {
    color_enabled: bool,
}
impl StyleScheme {
    fn no_color(self, text: &str) -> StyledContent<&str> {
        text.reset()
    }
    fn heading(self, text: &str) -> StyledContent<&str> {
        text.bold().underlined()
    }
    fn success_rate(self, text: &str, success_rate: f64) -> StyledContent<&str> {
        if self.color_enabled {
            if success_rate >= 100.0 {
                text.green().bold()
            } else if success_rate >= 99.0 {
                text.yellow().bold()
            } else {
                text.red().bold()
            }
        } else {
            self.no_color(text).bold()
        }
    }
    fn fastest(self, text: &str) -> StyledContent<&str> {
        if self.color_enabled {
            text.green()
        } else {
            self.no_color(text)
        }
    }
    fn slowest(self, text: &str) -> StyledContent<&str> {
        if self.color_enabled {
            text.yellow()
        } else {
            self.no_color(text)
        }
    }
    fn average(self, text: &str) -> StyledContent<&str> {
        if self.color_enabled {
            text.cyan()
        } else {
            self.no_color(text)
        }
    }

    fn latency_distribution(self, text: &str, label: f64) -> StyledContent<&str> {
        if self.color_enabled {
            if label <= 0.3 {
                text.green()
            } else if label <= 0.8 {
                text.yellow()
            } else {
                text.red()
            }
        } else {
            self.no_color(text)
        }
    }

    fn status_distribution(self, text: &str, status: StatusCode) -> StyledContent<&str> {
        if self.color_enabled {
            if status.is_success() {
                text.green()
            } else if status.is_client_error() {
                text.yellow()
            } else if status.is_server_error() {
                text.red()
            } else {
                text.white()
            }
        } else {
            self.no_color(text)
        }
    }
}

#[derive(Clone, Copy)]
pub enum PrintMode {
    Text,
    Json,
}

pub fn print_result<W: Write, E: std::fmt::Display>(
    w: &mut W,
    mode: PrintMode,
    start: Instant,
    res: &[Result<RequestResult, E>],
    total_duration: Duration,
    disable_color: bool,
    stats_success_breakdown: bool,
) -> anyhow::Result<()> {
    match mode {
        PrintMode::Text => print_summary(
            w,
            res,
            total_duration,
            disable_color,
            stats_success_breakdown,
        )?,
        PrintMode::Json => print_json(w, start, res, total_duration, stats_success_breakdown)?,
    }
    Ok(())
}

/// Print all summary as JSON
fn print_json<W: Write, E: std::fmt::Display>(
    w: &mut W,
    start: Instant,
    res: &[Result<RequestResult, E>],
    total_duration: Duration,
    stats_success_breakdown: bool,
) -> serde_json::Result<()> {
    use serde::Serialize;
    #[derive(Serialize)]
    struct Summary {
        #[serde(rename = "successRate")]
        success_rate: f64,
        total: f64,
        slowest: f64,
        fastest: f64,
        average: f64,
        #[serde(rename = "requestsPerSec")]
        requests_per_sec: f64,
        #[serde(rename = "totalData")]
        total_data: u128,
        #[serde(rename = "sizePerRequest")]
        size_per_request: f64,
        #[serde(rename = "sizePerSec")]
        size_per_sec: f64,
    }

    #[derive(Serialize)]
    struct Triple {
        average: f64,
        fastest: f64,
        slowest: f64,
    }

    #[derive(Serialize)]
    struct Details {
        #[serde(rename = "DNSDialup")]
        dns_dialup: Triple,
        #[serde(rename = "DNSLookup")]
        dns_lookup: Triple,
    }

    #[derive(Serialize)]
    struct Rps {
        mean: f64,
        stddev: f64,
        max: f64,
        percentiles: BTreeMap<String, f64>,
    }

    #[derive(Serialize)]
    struct Result {
        summary: Summary,
        #[serde(rename = "responseTimeHistogram")]
        response_time_histogram: BTreeMap<String, usize>,
        #[serde(rename = "latencyPercentiles")]
        latency_percentiles: BTreeMap<String, f64>,
        #[serde(
            rename = "responseTimeHistogramSuccessful",
            skip_serializing_if = "Option::is_none"
        )]
        response_time_histogram_successful: Option<BTreeMap<String, usize>>,
        #[serde(
            rename = "latencyPercentilesSuccessful",
            skip_serializing_if = "Option::is_none"
        )]
        latency_percentiles_successful: Option<BTreeMap<String, f64>>,
        #[serde(
            rename = "responseTimeHistogramNotSuccessful",
            skip_serializing_if = "Option::is_none"
        )]
        response_time_histogram_not_successful: Option<BTreeMap<String, usize>>,
        #[serde(
            rename = "latencyPercentilesNotSuccessful",
            skip_serializing_if = "Option::is_none"
        )]
        latency_percentiles_not_successful: Option<BTreeMap<String, f64>>,
        #[serde(rename = "rps")]
        rps: Rps,
        details: Details,
        #[serde(rename = "statusCodeDistribution")]
        status_code_distribution: BTreeMap<String, usize>,
        #[serde(rename = "errorDistribution")]
        error_distribution: BTreeMap<String, usize>,
    }

    let summary = Summary {
        success_rate: res.iter().filter(|r| r.is_ok()).count() as f64 / res.len() as f64,
        total: total_duration.as_secs_f64(),
        slowest: res
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration().as_secs_f64())
            .collect::<average::Max>()
            .max(),
        fastest: res
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration().as_secs_f64())
            .collect::<average::Min>()
            .min(),
        average: {
            let mean = res
                .iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.duration().as_secs_f64())
                .collect::<average::Mean>();
            if mean.is_empty() {
                f64::NAN
            } else {
                mean.mean()
            }
        },
        requests_per_sec: res.len() as f64 / total_duration.as_secs_f64(),
        total_data: res
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.len_bytes as u128)
            .sum::<u128>(),
        size_per_request: res
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.len_bytes as u128)
            .sum::<u128>() as f64
            / res.iter().filter(|r| r.is_ok()).count() as f64,
        size_per_sec: (res
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.len_bytes as u128)
            .sum::<u128>() as f64
            / total_duration.as_secs_f64()),
    };
    let durations_base = res.iter().filter_map(|r| r.as_ref().ok());

    let mut durations = durations_base
        .clone()
        .map(|r| r.duration().as_secs_f64())
        .collect::<Vec<_>>();
    float_ord::sort(&mut durations);

    let response_time_histogram = histogram(&durations, 11)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let latency_percentile_buckets = &[10, 25, 50, 75, 90, 95, 99];
    let latency_percentiles = percentiles(&durations, latency_percentile_buckets);

    let mut response_time_histogram_successful: Option<BTreeMap<String, usize>> = None;
    let mut latency_percentiles_successful: Option<BTreeMap<String, f64>> = None;
    let mut response_time_histogram_not_successful: Option<BTreeMap<String, usize>> = None;
    let mut latency_percentiles_not_successful: Option<BTreeMap<String, f64>> = None;

    if stats_success_breakdown {
        let mut durations_successful = durations_base
            .clone()
            .filter(|r| r.status.is_success())
            .map(|r| r.duration().as_secs_f64())
            .collect::<Vec<_>>();
        float_ord::sort(&mut durations_successful);

        response_time_histogram_successful = Some(
            histogram(&durations_successful, 11)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        );

        latency_percentiles_successful = Some(percentiles(
            &durations_successful,
            latency_percentile_buckets,
        ));

        let mut durations_not_successful = durations_base
            .filter(|r| r.status.is_client_error() || r.status.is_server_error())
            .map(|r| r.duration().as_secs_f64())
            .collect::<Vec<_>>();
        float_ord::sort(&mut durations_not_successful);

        response_time_histogram_not_successful = Some(
            histogram(&durations_not_successful, 11)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        );

        latency_percentiles_not_successful = Some(percentiles(
            &durations_not_successful,
            latency_percentile_buckets,
        ));
    }

    let mut ends = res
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| (r.end - start).as_secs_f64())
        .collect::<Vec<_>>();
    ends.push(0.0);
    float_ord::sort(&mut ends);

    let mut rps: Vec<f64> = Vec::new();
    // 10ms
    const INTERVAL: f64 = 0.01;
    let mut r = 0;
    loop {
        let prev_r = r;

        // increment at least 1
        if r + 1 < ends.len() {
            r += 1;
        }

        while r + 1 < ends.len() && ends[prev_r] + INTERVAL > ends[r + 1] {
            r += 1;
        }

        if r == prev_r {
            break;
        }

        let n = r - prev_r;
        let t = ends[r] - ends[prev_r];
        rps.push(n as f64 / t);
    }

    float_ord::sort(&mut rps);
    let rps_percentiles = percentiles(&rps, &[10, 25, 50, 75, 90, 95, 99]);

    let variance = rps.iter().collect::<Variance>();
    let rps = Rps {
        mean: variance.mean(),
        stddev: variance.sample_variance().sqrt(),
        max: rps.iter().collect::<Max>().max(),
        percentiles: rps_percentiles,
    };

    let mut status_code_distribution: BTreeMap<http::StatusCode, usize> = Default::default();

    for s in res.iter().filter_map(|r| r.as_ref().ok()).map(|r| r.status) {
        *status_code_distribution.entry(s).or_default() += 1;
    }

    let mut error_distribution: BTreeMap<String, usize> = Default::default();
    for e in res.iter().filter_map(|r| r.as_ref().err()) {
        *error_distribution.entry(e.to_string()).or_default() += 1;
    }

    let connection_times: Vec<(std::time::Instant, ConnectionTime)> = res
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .filter_map(|r| r.connection_time.clone().map(|c| (r.start, c)))
        .collect();
    let details = Details {
        dns_dialup: Triple {
            average: connection_times
                .iter()
                .map(|(s, c)| (c.dialup - *s).as_secs_f64())
                .collect::<average::Mean>()
                .mean(),

            fastest: connection_times
                .iter()
                .map(|(s, c)| (c.dialup - *s).as_secs_f64())
                .collect::<average::Min>()
                .min(),
            slowest: connection_times
                .iter()
                .map(|(s, c)| (c.dialup - *s).as_secs_f64())
                .collect::<average::Max>()
                .max(),
        },
        dns_lookup: Triple {
            average: connection_times
                .iter()
                .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
                .collect::<average::Mean>()
                .mean(),
            fastest: connection_times
                .iter()
                .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
                .collect::<average::Min>()
                .min(),
            slowest: connection_times
                .iter()
                .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
                .collect::<average::Max>()
                .max(),
        },
    };

    serde_json::to_writer_pretty(
        w,
        &Result {
            summary,
            response_time_histogram,
            latency_percentiles,
            response_time_histogram_successful,
            latency_percentiles_successful,
            response_time_histogram_not_successful,
            latency_percentiles_not_successful,
            rps,
            details,
            status_code_distribution: status_code_distribution
                .into_iter()
                .map(|(k, v)| (k.as_u16().to_string(), v))
                .collect(),
            error_distribution,
        },
    )
}

/// Print all summary as Text
fn print_summary<W: Write, E: std::fmt::Display>(
    w: &mut W,
    res: &[Result<RequestResult, E>],
    total_duration: Duration,
    disable_color: bool,
    stats_success_breakdown: bool,
) -> std::io::Result<()> {
    let style = StyleScheme {
        color_enabled: !disable_color,
    };
    writeln!(w, "{}", style.heading("Summary:"))?;
    let success_rate = 100.0 * res.iter().filter(|r| r.is_ok()).count() as f64 / res.len() as f64;
    writeln!(
        w,
        "{}",
        style.success_rate(
            &format!("  Success rate:\t{:.2}%", success_rate),
            success_rate
        )
    )?;
    writeln!(w, "  Total:\t{:.4} secs", total_duration.as_secs_f64())?;
    writeln!(
        w,
        "{}",
        style.slowest(&format!(
            "  Slowest:\t{:.4} secs",
            res.iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.duration().as_secs_f64())
                .collect::<average::Max>()
                .max()
        ))
    )?;
    writeln!(
        w,
        "{}",
        style.fastest(&format!(
            "  Fastest:\t{:.4} secs",
            res.iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.duration().as_secs_f64())
                .collect::<average::Min>()
                .min()
        ))
    )?;
    writeln!(
        w,
        "{}",
        style.average(&format!(
            "  Average:\t{:.4} secs",
            res.iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.duration().as_secs_f64())
                .collect::<average::Mean>()
                .mean()
        ))
    )?;
    writeln!(
        w,
        "  Requests/sec:\t{:.4}",
        res.len() as f64 / total_duration.as_secs_f64()
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "  Total data:\t{}",
        Byte::from_bytes(
            res.iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.len_bytes as u128)
                .sum::<u128>()
        )
        .get_appropriate_unit(true)
    )?;
    writeln!(
        w,
        "  Size/request:\t{}",
        (res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.len_bytes as u128)
            .sum::<u128>()
            .checked_div(res.iter().filter(|r| r.is_ok()).count() as u128))
        .map(|n| Byte::from_bytes(n).get_appropriate_unit(true).to_string())
        .unwrap_or_else(|| "NaN".to_string())
    )?;
    writeln!(
        w,
        "  Size/sec:\t{}",
        Byte::from_bytes(
            (res.iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.len_bytes as u128)
                .sum::<u128>() as f64
                / total_duration.as_secs_f64()) as u128
        )
        .get_appropriate_unit(true)
    )?;
    writeln!(w)?;

    let durations_base = res.iter().filter_map(|r| r.as_ref().ok());
    let durations = durations_base
        .clone()
        .map(|r| r.duration().as_secs_f64())
        .collect::<Vec<_>>();

    writeln!(w, "{}", style.heading("Response time histogram:"))?;
    print_histogram(w, &durations, style)?;
    writeln!(w)?;

    writeln!(w, "{}", style.heading("Response time distribution:"))?;
    print_distribution(w, &durations, style)?;
    writeln!(w)?;

    if stats_success_breakdown {
        let mut durations_successful = durations_base
            .clone()
            .filter(|r| r.status.is_success())
            .map(|r| r.duration().as_secs_f64())
            .collect::<Vec<_>>();
        float_ord::sort(&mut durations_successful);

        writeln!(
            w,
            "{}",
            style.heading("Response time histogram (2xx only):")
        )?;
        print_histogram(w, &durations_successful, style)?;
        writeln!(w)?;

        writeln!(
            w,
            "{}",
            style.heading("Response time distribution (2xx only):")
        )?;
        print_distribution(w, &durations_successful, style)?;
        writeln!(w)?;

        let mut durations_not_successful = durations_base
            .filter(|r| r.status.is_client_error() || r.status.is_server_error())
            .map(|r| r.duration().as_secs_f64())
            .collect::<Vec<_>>();
        float_ord::sort(&mut durations_not_successful);

        writeln!(
            w,
            "{}",
            style.heading("Response time histogram (4xx + 5xx only):")
        )?;
        print_histogram(w, &durations_not_successful, style)?;
        writeln!(w)?;

        writeln!(
            w,
            "{}",
            style.heading("Response time distribution (4xx + 5xx only):")
        )?;
        print_distribution(w, &durations_not_successful, style)?;
        writeln!(w)?;
    }
    writeln!(w)?;

    let connection_times: Vec<(std::time::Instant, ConnectionTime)> = res
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .filter_map(|r| r.connection_time.clone().map(|c| (r.start, c)))
        .collect();
    writeln!(
        w,
        "{}",
        style.heading("Details (average, fastest, slowest):")
    )?;

    writeln!(
        w,
        "  DNS+dialup:\t{:.4} secs, {:.4} secs, {:.4} secs",
        connection_times
            .iter()
            .map(|(s, c)| (c.dialup - *s).as_secs_f64())
            .collect::<average::Mean>()
            .mean(),
        connection_times
            .iter()
            .map(|(s, c)| (c.dialup - *s).as_secs_f64())
            .collect::<average::Min>()
            .min(),
        connection_times
            .iter()
            .map(|(s, c)| (c.dialup - *s).as_secs_f64())
            .collect::<average::Max>()
            .max()
    )?;
    writeln!(
        w,
        "  DNS-lookup:\t{:.4} secs, {:.4} secs, {:.4} secs",
        connection_times
            .iter()
            .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
            .collect::<average::Mean>()
            .mean(),
        connection_times
            .iter()
            .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
            .collect::<average::Min>()
            .min(),
        connection_times
            .iter()
            .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
            .collect::<average::Max>()
            .max()
    )?;
    writeln!(w)?;

    let mut status_dist: BTreeMap<http::StatusCode, usize> = Default::default();

    for s in res.iter().filter_map(|r| r.as_ref().ok()).map(|r| r.status) {
        *status_dist.entry(s).or_default() += 1;
    }

    let mut status_v: Vec<(http::StatusCode, usize)> = status_dist.into_iter().collect();
    status_v.sort_by_key(|t| std::cmp::Reverse(t.1));

    writeln!(w, "{}", style.heading("Status code distribution:"))?;

    for (status, count) in status_v {
        writeln!(
            w,
            "{}",
            style.status_distribution(
                &format!("  [{}] {} responses", status.as_str(), count),
                status
            )
        )?;
    }

    let mut error_dist: BTreeMap<String, usize> = Default::default();
    for e in res.iter().filter_map(|r| r.as_ref().err()) {
        *error_dist.entry(e.to_string()).or_default() += 1;
    }

    let mut error_v: Vec<(String, usize)> = error_dist.into_iter().collect();
    error_v.sort_by_key(|t| std::cmp::Reverse(t.1));

    if !error_v.is_empty() {
        writeln!(w)?;
        writeln!(w, "Error distribution:")?;
        for (error, count) in error_v {
            writeln!(w, "  [{count}] {error}")?;
        }
    }

    Ok(())
}

/// Print histogram of series of f64 data.
/// This is used to print histogram of response time.
fn print_histogram<W: Write>(w: &mut W, values: &[f64], style: StyleScheme) -> std::io::Result<()> {
    // TODO: Use better algorithm.
    // Is there any common and good algorithm?
    if values.is_empty() {
        return Ok(());
    }
    let lines = 11;
    let data = crate::histogram::histogram(values, lines);

    let max_bar = data.iter().map(|t| t.1).max().unwrap();
    let str_len_max = max_bar.to_string().len();
    let width = data
        .iter()
        .map(|t| (t.0 as u64).to_string().len())
        .max()
        .unwrap()
        + 4;

    for (label, b) in data.iter() {
        let indent = str_len_max - b.to_string().len();
        write!(
            w,
            "{}",
            style.latency_distribution(
                &format!(
                    "  {:>width$.3} [{}]{} |",
                    label,
                    b,
                    " ".repeat(indent),
                    width = width
                ),
                *label
            )
        )?;
        bar(w, *b as f64 / max_bar as f64, style, *label)?;
        writeln!(w)?;
    }
    Ok(())
}

// Print Bar like ■■■■■■■■■
fn bar<W: Write>(w: &mut W, ratio: f64, style: StyleScheme, label: f64) -> std::io::Result<()> {
    // TODO: Use more block element code to show more precise bar
    let width = 32;
    for _ in 0..(width as f64 * ratio) as usize {
        write!(w, "{}", style.latency_distribution("■", label))?;
    }
    Ok(())
}

/// Print distribution of collection of f64
fn print_distribution<W: Write>(
    w: &mut W,
    values: &[f64],
    style: StyleScheme,
) -> std::io::Result<()> {
    let mut buf = values.to_vec();
    float_ord::sort(&mut buf);

    for &p in &[10, 25, 50, 75, 90, 95, 99] {
        let i = (f64::from(p) / 100.0 * buf.len() as f64) as usize;
        writeln!(
            w,
            "{}",
            style.latency_distribution(
                &format!(
                    "  {}% in {:.4} secs",
                    p,
                    buf.get(i).unwrap_or(&std::f64::NAN)
                ),
                *buf.get(i).unwrap_or(&std::f64::NAN)
            )
        )?;
    }

    Ok(())
}

fn percentiles(values: &[f64], percents: &[i32]) -> BTreeMap<String, f64> {
    percents
        .iter()
        .map(|&p| {
            let i = (f64::from(p) / 100.0 * values.len() as f64) as usize;
            (format!("p{p}"), *values.get(i).unwrap_or(&std::f64::NAN))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_percentiles() {
        let values: [f64; 40] = [
            5.0, 5.0, 5.0, 5.0, 5.0, 10.0, 10.0, 10.0, 10.0, 10.0, 11.0, 11.0, 11.0, 11.0, 11.0,
            11.0, 11.0, 11.0, 11.0, 11.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0,
            12.0, 15.0, 15.0, 15.0, 15.0, 15.0, 20.0, 20.0, 20.0, 25.0, 30.0,
        ];
        let percents: [i32; 7] = [10, 25, 50, 75, 90, 95, 99];
        let result = percentiles(&values, &percents);
        assert_eq!(result["p10"], 5 as f64);
        assert_eq!(result["p25"], 11 as f64);
        assert_eq!(result["p50"], 12 as f64);
        assert_eq!(result["p75"], 15 as f64);
        assert_eq!(result["p90"], 20 as f64);
        assert_eq!(result["p95"], 25 as f64);
        assert_eq!(result["p99"], 30 as f64);
    }
}
