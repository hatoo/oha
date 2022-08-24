use crate::client::ConnectionTime;
use crate::client::RequestResult;
use crate::histogram::histogram;
use average::Max;
use average::Variance;
use byte_unit::Byte;
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;
use std::time::Instant;

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
) -> anyhow::Result<()> {
    match mode {
        PrintMode::Text => print_summary(w, res, total_duration)?,
        PrintMode::Json => print_json(w, start, res, total_duration)?,
    }
    Ok(())
}

/// Print all summary as JSON
fn print_json<W: Write, E: std::fmt::Display>(
    w: &mut W,
    start: Instant,
    res: &[Result<RequestResult, E>],
    total_duration: Duration,
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
        #[serde(rename = "reaponseTimeHistogram")]
        response_time_histogram: BTreeMap<String, usize>,
        #[serde(rename = "latencyPercentiles")]
        latency_percentiles: BTreeMap<String, f64>,
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

    let mut durations = res
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| r.duration().as_secs_f64())
        .collect::<Vec<_>>();
    float_ord::sort(&mut durations);

    let response_time_histogram = histogram(&durations, 11)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let latency_percentiles = percentiles(&durations, &[10, 25, 50, 75, 90, 95, 99]);

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
) -> std::io::Result<()> {
    writeln!(w, "Summary:")?;
    writeln!(
        w,
        "  Success rate:\t{:.4}",
        res.iter().filter(|r| r.is_ok()).count() as f64 / res.len() as f64
    )?;
    writeln!(w, "  Total:\t{:.4} secs", total_duration.as_secs_f64())?;
    writeln!(
        w,
        "  Slowest:\t{:.4} secs",
        res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration().as_secs_f64())
            .collect::<average::Max>()
            .max()
    )?;
    writeln!(
        w,
        "  Fastest:\t{:.4} secs",
        res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration().as_secs_f64())
            .collect::<average::Min>()
            .min()
    )?;
    writeln!(
        w,
        "  Average:\t{:.4} secs",
        res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration().as_secs_f64())
            .collect::<average::Mean>()
            .mean()
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
    let durations = res
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| r.duration().as_secs_f64())
        .collect::<Vec<_>>();

    writeln!(w, "Response time histogram:")?;
    print_histogram(w, &durations)?;
    writeln!(w)?;
    writeln!(w, "Latency distribution:")?;
    print_distribution(w, &durations)?;
    writeln!(w)?;

    let connection_times: Vec<(std::time::Instant, ConnectionTime)> = res
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .filter_map(|r| r.connection_time.clone().map(|c| (r.start, c)))
        .collect();
    writeln!(w, "Details (average, fastest, slowest):")?;
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

    writeln!(w, "Status code distribution:")?;
    for (status, count) in status_v {
        writeln!(w, "  [{}] {} responses", status.as_str(), count)?;
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
            writeln!(w, "  [{}] {}", count, error)?;
        }
    }

    Ok(())
}

/// Print histogram of series of f64 data.
/// This is used to print histogram of response time.
fn print_histogram<W: Write>(w: &mut W, values: &[f64]) -> std::io::Result<()> {
    // TODO: Use better algorithm.
    // Is there any common and good algorithm?
    if values.is_empty() {
        return Ok(());
    }
    let lines = 11;
    let data = crate::histogram::histogram(values, lines);

    let max_bar = data.iter().map(|t| t.1).max().unwrap();
    let str_len_max = max_bar.to_string().len();

    for (label, b) in data.iter() {
        let indent = str_len_max - b.to_string().len();
        write!(w, "  {:.3} [{}]{} |", label, b, " ".repeat(indent))?;
        bar(w, *b as f64 / max_bar as f64)?;
        writeln!(w)?;
    }
    Ok(())
}

// Print Bar like ■■■■■■■■■
fn bar<W: Write>(w: &mut W, ratio: f64) -> std::io::Result<()> {
    // TODO: Use more block element code to show more precise bar
    let width = 32;
    for _ in 0..(width as f64 * ratio) as usize {
        write!(w, "■")?;
    }
    Ok(())
}

/// Print distribution of collection of f64
fn print_distribution<W: Write>(w: &mut W, values: &[f64]) -> std::io::Result<()> {
    let mut buf = values.to_vec();
    float_ord::sort(&mut buf);

    for &p in &[10, 25, 50, 75, 90, 95, 99] {
        let i = (f64::from(p) / 100.0 * buf.len() as f64) as usize;
        writeln!(
            w,
            "  {}% in {:.4} secs",
            p,
            buf.get(i).unwrap_or(&std::f64::NAN)
        )?;
    }

    Ok(())
}

fn percentiles(values: &[f64], pecents: &[i32]) -> BTreeMap<String, f64> {
    pecents
        .iter()
        .map(|&p| {
            let i = (f64::from(p) / 100.0 * values.len() as f64) as usize;
            (format!("p{}", p), *values.get(i).unwrap_or(&std::f64::NAN))
        })
        .collect()
}
