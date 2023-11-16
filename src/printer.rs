use crate::client::ConnectionTime;
use crate::client::RequestResult;
use crate::histogram::histogram;
use average::Max;
use average::Variance;
use byte_unit::Byte;
use crossterm::style::{StyledContent, Stylize};
use hyper::http::{self, StatusCode};
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
        size_per_request: Option<u128>,
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
        success_rate: calculate_success_rate(res),
        total: total_duration.as_secs_f64(),
        slowest: calculate_slowest_request(res),
        fastest: calculate_fastest_request(res),
        average: calculate_average_request(res),
        requests_per_sec: calculate_requests_per_sec(res, total_duration),
        total_data: calculate_total_data(res),
        size_per_request: calculate_size_per_request(res),
        size_per_sec: (calculate_size_per_sec(res, total_duration)),
    };

    let mut durations = get_durations_all(res);

    let response_time_histogram = histogram(&durations, 11)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let latency_percentiles = percentiles(&mut durations);

    let mut response_time_histogram_successful: Option<BTreeMap<String, usize>> = None;
    let mut latency_percentiles_successful: Option<BTreeMap<String, f64>> = None;
    let mut response_time_histogram_not_successful: Option<BTreeMap<String, usize>> = None;
    let mut latency_percentiles_not_successful: Option<BTreeMap<String, f64>> = None;

    if stats_success_breakdown {
        let mut durations_successful = get_durations_successful(res);

        response_time_histogram_successful = Some(
            histogram(&durations_successful, 11)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        );

        latency_percentiles_successful = Some(percentiles(&mut durations_successful));

        let mut durations_not_successful = get_durations_not_successful(res);

        response_time_histogram_not_successful = Some(
            histogram(&durations_not_successful, 11)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        );

        latency_percentiles_not_successful = Some(percentiles(&mut durations_not_successful));
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

    let rps_percentiles = percentiles(&mut rps);

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

    let connection_times: Vec<(std::time::Instant, ConnectionTime)> =
        calcuate_connection_times_base(res);
    let details = Details {
        dns_dialup: Triple {
            average: calculate_connection_times_dns_dialup_average(&connection_times),
            fastest: calculate_connection_times_dns_dialup_fastest(&connection_times),
            slowest: calculate_connection_times_dns_dialup_slowest(&connection_times),
        },
        dns_lookup: Triple {
            average: calculate_connection_times_dns_lookup_average(&connection_times),
            fastest: calculate_connection_times_dns_lookup_fastest(&connection_times),
            slowest: calculate_connection_times_dns_lookup_slowest(&connection_times),
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
    let success_rate = 100.0 * calculate_success_rate(res);
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
            calculate_slowest_request(res)
        ))
    )?;
    writeln!(
        w,
        "{}",
        style.fastest(&format!(
            "  Fastest:\t{:.4} secs",
            calculate_fastest_request(res)
        ))
    )?;
    writeln!(
        w,
        "{}",
        style.average(&format!(
            "  Average:\t{:.4} secs",
            calculate_average_request(res)
        ))
    )?;
    writeln!(
        w,
        "  Requests/sec:\t{:.4}",
        calculate_requests_per_sec(res, total_duration)
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "  Total data:\t{}",
        Byte::from_bytes(calculate_total_data(res)).get_appropriate_unit(true)
    )?;
    writeln!(
        w,
        "  Size/request:\t{}",
        (calculate_size_per_request(res))
            .map(|n| Byte::from_bytes(n).get_appropriate_unit(true).to_string())
            .unwrap_or_else(|| "NaN".to_string())
    )?;
    writeln!(
        w,
        "  Size/sec:\t{}",
        Byte::from_bytes((calculate_size_per_sec(res, total_duration)) as u128)
            .get_appropriate_unit(true)
    )?;
    writeln!(w)?;

    let mut durations = get_durations_all(res);

    writeln!(w, "{}", style.heading("Response time histogram:"))?;
    print_histogram(w, &durations, style)?;
    writeln!(w)?;

    writeln!(w, "{}", style.heading("Response time distribution:"))?;
    print_distribution(w, &mut durations, style)?;
    writeln!(w)?;

    if stats_success_breakdown {
        let mut durations_successful = get_durations_successful(res);

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
        print_distribution(w, &mut durations_successful, style)?;
        writeln!(w)?;

        let mut durations_not_successful = get_durations_not_successful(res);

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
        print_distribution(w, &mut durations_not_successful, style)?;
        writeln!(w)?;
    }
    writeln!(w)?;

    let connection_times: Vec<(std::time::Instant, ConnectionTime)> =
        calcuate_connection_times_base(res);
    writeln!(
        w,
        "{}",
        style.heading("Details (average, fastest, slowest):")
    )?;

    writeln!(
        w,
        "  DNS+dialup:\t{:.4} secs, {:.4} secs, {:.4} secs",
        calculate_connection_times_dns_dialup_average(&connection_times),
        calculate_connection_times_dns_dialup_fastest(&connection_times),
        calculate_connection_times_dns_dialup_slowest(&connection_times),
    )?;
    writeln!(
        w,
        "  DNS-lookup:\t{:.4} secs, {:.4} secs, {:.4} secs",
        calculate_connection_times_dns_lookup_average(&connection_times),
        calculate_connection_times_dns_lookup_fastest(&connection_times),
        calculate_connection_times_dns_lookup_slowest(&connection_times),
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

fn percentile_iter(values: &mut [f64]) -> impl Iterator<Item = (f64, f64)> + '_ {
    float_ord::sort(values);

    [10.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0, 99.9, 99.99]
        .iter()
        .map(move |&p| {
            let i = (p / 100.0 * values.len() as f64) as usize;
            (p, *values.get(i).unwrap_or(&std::f64::NAN))
        })
}

/// Print distribution of collection of f64
fn print_distribution<W: Write>(
    w: &mut W,
    values: &mut [f64],
    style: StyleScheme,
) -> std::io::Result<()> {
    for (p, v) in percentile_iter(values) {
        writeln!(
            w,
            "{}",
            style.latency_distribution(&format!("  {:.2}% in {:.4} secs", p, v), v)
        )?;
    }

    Ok(())
}

fn percentiles(values: &mut [f64]) -> BTreeMap<String, f64> {
    percentile_iter(values)
        .map(|(p, v)| (format!("p{p}"), v))
        .collect()
}

fn calculate_success_rate<E>(res: &[Result<RequestResult, E>]) -> f64 {
    res.iter().filter(|r| r.is_ok()).count() as f64 / res.len() as f64
}

fn calculate_slowest_request<E>(res: &[Result<RequestResult, E>]) -> f64 {
    res.iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| r.duration().as_secs_f64())
        .collect::<average::Max>()
        .max()
}

fn calculate_fastest_request<E>(res: &[Result<RequestResult, E>]) -> f64 {
    res.iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| r.duration().as_secs_f64())
        .collect::<average::Min>()
        .min()
}

fn calculate_average_request<E>(res: &[Result<RequestResult, E>]) -> f64 {
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
}

fn calculate_requests_per_sec<E>(
    res: &[Result<RequestResult, E>],
    total_duration: Duration,
) -> f64 {
    res.len() as f64 / total_duration.as_secs_f64()
}

fn calculate_total_data<E>(res: &[Result<RequestResult, E>]) -> u128 {
    res.iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| r.len_bytes as u128)
        .sum::<u128>()
}

fn calculate_size_per_request<E>(res: &[Result<RequestResult, E>]) -> Option<u128> {
    res.iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| r.len_bytes as u128)
        .sum::<u128>()
        .checked_div(res.iter().filter(|r| r.is_ok()).count() as u128)
}

fn calculate_size_per_sec<E>(res: &[Result<RequestResult, E>], total_duration: Duration) -> f64 {
    res.iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| r.len_bytes as u128)
        .sum::<u128>() as f64
        / total_duration.as_secs_f64()
}

fn calcuate_connection_times_base<E>(
    res: &[Result<RequestResult, E>],
) -> Vec<(Instant, ConnectionTime)> {
    res.iter()
        .filter_map(|r| r.as_ref().ok())
        .filter_map(|r| r.connection_time.map(|c| (r.start, c)))
        .collect()
}

fn calculate_connection_times_dns_dialup_average(
    connection_times: &[(Instant, ConnectionTime)],
) -> f64 {
    connection_times
        .iter()
        .map(|(s, c)| (c.dialup - *s).as_secs_f64())
        .collect::<average::Mean>()
        .mean()
}

fn calculate_connection_times_dns_dialup_fastest(
    connection_times: &[(Instant, ConnectionTime)],
) -> f64 {
    connection_times
        .iter()
        .map(|(s, c)| (c.dialup - *s).as_secs_f64())
        .collect::<average::Min>()
        .min()
}

fn calculate_connection_times_dns_dialup_slowest(
    connection_times: &[(Instant, ConnectionTime)],
) -> f64 {
    connection_times
        .iter()
        .map(|(s, c)| (c.dialup - *s).as_secs_f64())
        .collect::<average::Max>()
        .max()
}

fn calculate_connection_times_dns_lookup_average(
    connection_times: &[(Instant, ConnectionTime)],
) -> f64 {
    connection_times
        .iter()
        .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
        .collect::<average::Mean>()
        .mean()
}

fn calculate_connection_times_dns_lookup_fastest(
    connection_times: &[(Instant, ConnectionTime)],
) -> f64 {
    connection_times
        .iter()
        .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
        .collect::<average::Min>()
        .min()
}

fn calculate_connection_times_dns_lookup_slowest(
    connection_times: &[(Instant, ConnectionTime)],
) -> f64 {
    connection_times
        .iter()
        .map(|(s, c)| (c.dns_lookup - *s).as_secs_f64())
        .collect::<average::Max>()
        .max()
}

fn get_durations_all<E>(res: &[Result<RequestResult, E>]) -> Vec<f64> {
    res.iter()
        .filter_map(|r: &Result<RequestResult, E>| r.as_ref().ok())
        .map(|r| r.duration().as_secs_f64())
        .collect::<Vec<_>>()
}

fn get_durations_successful<E>(res: &[Result<RequestResult, E>]) -> Vec<f64> {
    res.iter()
        .filter_map(|r: &Result<RequestResult, E>| r.as_ref().ok())
        .filter(|r| r.status.is_success())
        .map(|r| r.duration().as_secs_f64())
        .collect::<Vec<_>>()
}

fn get_durations_not_successful<E>(res: &[Result<RequestResult, E>]) -> Vec<f64> {
    res.iter()
        .filter_map(|r: &Result<RequestResult, E>| r.as_ref().ok())
        .filter(|r| r.status.is_client_error() || r.status.is_server_error())
        .map(|r| r.duration().as_secs_f64())
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientError, RequestResult};
    use std::time::Duration;

    fn build_mock_request_result(
        status: StatusCode,
        request_time: u64,
        connection_time_dns_lookup: u64,
        connection_time_dialup: u64,
        size: usize,
    ) -> Result<RequestResult, ClientError> {
        let now = Instant::now();
        Ok(RequestResult {
            start_latency_correction: None,
            start: now,
            connection_time: Some(ConnectionTime {
                dns_lookup: Instant::now()
                    .checked_add(Duration::from_millis(connection_time_dns_lookup))
                    .unwrap(),
                dialup: Instant::now()
                    .checked_add(Duration::from_millis(connection_time_dialup))
                    .unwrap(),
            }),
            end: Instant::now()
                .checked_add(Duration::from_millis(request_time))
                .unwrap(),
            status,
            len_bytes: size,
        })
    }

    fn build_mock_request_result_vec() -> Vec<Result<RequestResult, ClientError>> {
        vec![
            build_mock_request_result(StatusCode::OK, 1000, 200, 50, 100),
            build_mock_request_result(StatusCode::BAD_REQUEST, 100000, 250, 100, 200),
            build_mock_request_result(StatusCode::INTERNAL_SERVER_ERROR, 1000000, 300, 150, 300),
        ]
    }

    fn fp_round(value: f64, places: f64) -> f64 {
        let base: f64 = 10.0;
        let multiplier = base.powf(places);
        (value * multiplier).round() / multiplier
    }

    #[test]
    fn test_percentile_iter() {
        let mut values: [f64; 40] = [
            5.0, 5.0, 5.0, 5.0, 5.0, 10.0, 10.0, 10.0, 10.0, 10.0, 11.0, 11.0, 11.0, 11.0, 11.0,
            11.0, 11.0, 11.0, 11.0, 11.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0,
            12.0, 15.0, 15.0, 15.0, 15.0, 15.0, 20.0, 20.0, 20.0, 25.0, 30.0,
        ];
        let result: Vec<(f64, f64)> = percentile_iter(&mut values).collect();
        assert_eq!(result[0], (10.0, 5_f64));
        assert_eq!(result[1], (25.0, 11_f64));
        assert_eq!(result[2], (50.0, 12_f64));
        assert_eq!(result[3], (75.0, 15_f64));
        assert_eq!(result[4], (90.0, 20_f64));
        assert_eq!(result[5], (95.0, 25_f64));
        assert_eq!(result[6], (99.0, 30_f64));
        assert_eq!(result[7], (99.9, 30_f64));
        assert_eq!(result[8], (99.99, 30_f64));
    }

    #[test]
    fn test_calculate_success_rate() {
        let res = build_mock_request_result_vec();
        assert_eq!(calculate_success_rate(&res), 1.0);
    }

    #[test]
    fn test_calculate_slowest_request() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_slowest_request(&build_mock_request_result_vec()),
                4.0
            ),
            1000_f64
        );
    }

    #[test]
    fn test_calculate_fastest_request() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_fastest_request(&build_mock_request_result_vec()),
                4.0
            ),
            1_f64
        );
    }

    #[test]
    fn test_calculate_average_request() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_average_request(&build_mock_request_result_vec()),
                4.0
            ),
            367_f64
        );
    }

    #[test]
    fn test_calculate_requests_per_sec() {
        assert_eq!(
            calculate_requests_per_sec(&build_mock_request_result_vec(), Duration::from_secs(1)),
            3.0
        );
    }

    #[test]
    fn test_calculate_total_data() {
        assert_eq!(calculate_total_data(&build_mock_request_result_vec()), 600);
    }

    #[test]
    fn test_calculate_size_per_request() {
        assert_eq!(
            calculate_size_per_request(&build_mock_request_result_vec()).unwrap(),
            200
        );
    }

    #[test]
    fn test_calculate_size_per_sec() {
        assert_eq!(
            (calculate_size_per_sec(&build_mock_request_result_vec(), Duration::from_secs(1))),
            600.0
        );
    }

    #[test]
    fn test_calcuate_connection_times_base() {
        assert_eq!(
            calcuate_connection_times_base(&build_mock_request_result_vec()).len(),
            3
        );
    }

    #[test]
    fn test_calculate_connection_times_dns_dialup_average() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_connection_times_dns_dialup_average(&calcuate_connection_times_base(
                    &build_mock_request_result_vec()
                )),
                4.0
            ),
            0.1
        );
    }

    #[test]
    fn test_calculate_connection_times_dns_dialup_fastest() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_connection_times_dns_dialup_fastest(&calcuate_connection_times_base(
                    &build_mock_request_result_vec()
                )),
                4.0
            ),
            0.05
        );
    }

    #[test]
    fn test_calculate_connection_times_dns_dialup_slowest() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_connection_times_dns_dialup_slowest(&calcuate_connection_times_base(
                    &build_mock_request_result_vec()
                )),
                4.0
            ),
            0.15
        );
    }

    #[test]
    fn test_calculate_connection_times_dns_lookup_average() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_connection_times_dns_lookup_average(&calcuate_connection_times_base(
                    &build_mock_request_result_vec()
                )),
                4.0
            ),
            0.25
        );
    }

    #[test]
    fn test_calculate_connection_times_dns_lookup_fastest() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_connection_times_dns_lookup_fastest(&calcuate_connection_times_base(
                    &build_mock_request_result_vec()
                )),
                4.0
            ),
            0.2
        );
    }

    #[test]
    fn test_calculate_connection_times_dns_lookup_slowest() {
        assert_eq!(
            // Round the calculation to 4 decimal places to remove imprecision
            fp_round(
                calculate_connection_times_dns_lookup_slowest(&calcuate_connection_times_base(
                    &build_mock_request_result_vec()
                )),
                4.0
            ),
            0.3
        );
    }

    #[test]
    fn test_get_durations_all() {
        let durations = get_durations_all(&build_mock_request_result_vec());
        // Round the calculations to 4 decimal places to remove imprecision
        assert_eq!(fp_round(durations[0], 4.0), 1.0);
        assert_eq!(fp_round(durations[1], 4.0), 100.0);
        assert_eq!(fp_round(durations[2], 4.0), 1000.0);
    }

    #[test]
    fn test_get_durations_successful() {
        let durations = get_durations_successful(&build_mock_request_result_vec());
        // Round the calculations to 4 decimal places to remove imprecision
        assert_eq!(fp_round(durations[0], 4.0), 1.0);
        assert_eq!(durations.get(1), None);
    }

    #[test]
    fn test_get_durations_not_successful() {
        let durations = get_durations_not_successful(&build_mock_request_result_vec());
        // Round the calculations to 4 decimal places to remove imprecision
        assert_eq!(fp_round(durations[0], 4.0), 100.0);
        assert_eq!(fp_round(durations[1], 4.0), 1000.0);
        assert_eq!(durations.get(2), None);
    }
}
