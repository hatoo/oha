use crate::result_data::ResultData;
use average::{Max, Min, Variance};
use byte_unit::Byte;
use crossterm::style::{StyledContent, Stylize};
use hyper::http::{self, StatusCode};
use ratatui::crossterm;
use std::{
    collections::BTreeMap,
    io::Write,
    time::{Duration, Instant},
};

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
        // See #609 for justification of these thresholds
        const LATENCY_YELLOW_THRESHOLD: f64 = 0.1;
        const LATENCY_RED_THRESHOLD: f64 = 0.4;

        if self.color_enabled {
            if label <= LATENCY_YELLOW_THRESHOLD {
                text.green()
            } else if label <= LATENCY_RED_THRESHOLD {
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

pub fn print_result<W: Write>(
    w: &mut W,
    mode: PrintMode,
    start: Instant,
    res: &ResultData,
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
fn print_json<W: Write>(
    w: &mut W,
    start: Instant,
    res: &ResultData,
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
        total_data: u64,
        #[serde(rename = "sizePerRequest")]
        size_per_request: Option<u64>,
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
        min: f64,
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

    let latency_stat = res.latency_stat();

    let summary = Summary {
        success_rate: res.success_rate(),
        total: total_duration.as_secs_f64(),
        slowest: latency_stat.max(),
        fastest: latency_stat.min(),
        average: latency_stat.mean(),
        requests_per_sec: res.len() as f64 / total_duration.as_secs_f64(),
        total_data: res.total_data() as u64,
        size_per_request: res.size_per_request(),
        size_per_sec: res.total_data() as f64 / total_duration.as_secs_f64(),
    };

    let durations_statistics = res.duration_all_statistics();

    let response_time_histogram = durations_statistics
        .histogram
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let latency_percentiles = durations_statistics
        .percentiles
        .into_iter()
        .map(|(p, v)| (format!("p{p}"), v))
        .collect();

    let mut response_time_histogram_successful: Option<BTreeMap<String, usize>> = None;
    let mut latency_percentiles_successful: Option<BTreeMap<String, f64>> = None;
    let mut response_time_histogram_not_successful: Option<BTreeMap<String, usize>> = None;
    let mut latency_percentiles_not_successful: Option<BTreeMap<String, f64>> = None;

    if stats_success_breakdown {
        let durations_successful_statistics = res.duration_successful_statistics();

        response_time_histogram_successful = Some(
            durations_successful_statistics
                .histogram
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        );

        latency_percentiles_successful = Some(
            durations_successful_statistics
                .percentiles
                .into_iter()
                .map(|(p, v)| (format!("p{p}"), v))
                .collect(),
        );

        let durations_not_successful_statistics = res.duration_not_successful_statistics();

        response_time_histogram_not_successful = Some(
            durations_not_successful_statistics
                .histogram
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        );

        latency_percentiles_not_successful = Some(
            durations_not_successful_statistics
                .percentiles
                .into_iter()
                .map(|(p, v)| (format!("p{p}"), v))
                .collect(),
        );
    }

    let mut ends = res
        .end_times_from_start(start)
        .map(|d| d.as_secs_f64())
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
        min: rps.iter().collect::<Min>().min(),
        percentiles: rps_percentiles,
    };

    let status_code_distribution = res.status_code_distribution();

    let dns_dialup_stat = res.dns_dialup_stat();
    let dns_lookup_stat = res.dns_lookup_stat();

    let details = Details {
        dns_dialup: Triple {
            average: dns_dialup_stat.mean(),
            fastest: dns_dialup_stat.min(),
            slowest: dns_dialup_stat.max(),
        },
        dns_lookup: Triple {
            average: dns_lookup_stat.mean(),
            fastest: dns_lookup_stat.min(),
            slowest: dns_lookup_stat.max(),
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
            error_distribution: res.error_distribution().clone(),
        },
    )
}

/// Print all summary as Text
fn print_summary<W: Write>(
    w: &mut W,
    res: &ResultData,
    total_duration: Duration,
    disable_color: bool,
    stats_success_breakdown: bool,
) -> std::io::Result<()> {
    let style = StyleScheme {
        color_enabled: !disable_color,
    };
    writeln!(w, "{}", style.heading("Summary:"))?;
    let success_rate = 100.0 * res.success_rate();
    writeln!(
        w,
        "{}",
        style.success_rate(
            &format!("  Success rate:\t{success_rate:.2}%"),
            success_rate
        )
    )?;
    writeln!(w, "  Total:\t{:.4} secs", total_duration.as_secs_f64())?;
    let latency_stat = res.latency_stat();
    writeln!(
        w,
        "{}",
        style.slowest(&format!("  Slowest:\t{:.4} secs", latency_stat.max()))
    )?;
    writeln!(
        w,
        "{}",
        style.fastest(&format!("  Fastest:\t{:.4} secs", latency_stat.min()))
    )?;
    writeln!(
        w,
        "{}",
        style.average(&format!("  Average:\t{:.4} secs", latency_stat.mean()))
    )?;
    writeln!(
        w,
        "  Requests/sec:\t{:.4}",
        res.len() as f64 / total_duration.as_secs_f64()
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "  Total data:\t{:.2}",
        Byte::from_u64(res.total_data() as u64).get_appropriate_unit(byte_unit::UnitType::Binary)
    )?;
    if let Some(size) = res
        .size_per_request()
        .map(|n| Byte::from_u64(n).get_appropriate_unit(byte_unit::UnitType::Binary))
    {
        writeln!(w, "  Size/request:\t{size:.2}")?;
    } else {
        writeln!(w, "  Size/request:\tNaN")?;
    }
    writeln!(
        w,
        "  Size/sec:\t{:.2}",
        Byte::from_u64((res.total_data() as f64 / total_duration.as_secs_f64()) as u64)
            .get_appropriate_unit(byte_unit::UnitType::Binary)
    )?;
    writeln!(w)?;

    let duration_all_statistics = res.duration_all_statistics();

    writeln!(w, "{}", style.heading("Response time histogram:"))?;
    print_histogram(w, &duration_all_statistics.histogram, style)?;
    writeln!(w)?;

    writeln!(w, "{}", style.heading("Response time distribution:"))?;
    print_distribution(w, &duration_all_statistics.percentiles, style)?;
    writeln!(w)?;

    if stats_success_breakdown {
        let durations_successful_statics = res.duration_successful_statistics();

        writeln!(
            w,
            "{}",
            style.heading("Response time histogram (2xx only):")
        )?;
        print_histogram(w, &durations_successful_statics.histogram, style)?;
        writeln!(w)?;

        writeln!(
            w,
            "{}",
            style.heading("Response time distribution (2xx only):")
        )?;
        print_distribution(w, &durations_successful_statics.percentiles, style)?;
        writeln!(w)?;

        let durations_not_successful = res.duration_not_successful_statistics();

        writeln!(
            w,
            "{}",
            style.heading("Response time histogram (4xx + 5xx only):")
        )?;
        print_histogram(w, &durations_not_successful.histogram, style)?;
        writeln!(w)?;

        writeln!(
            w,
            "{}",
            style.heading("Response time distribution (4xx + 5xx only):")
        )?;
        print_distribution(w, &durations_not_successful.percentiles, style)?;
        writeln!(w)?;
    }
    writeln!(w)?;

    let dns_dialup_stat = res.dns_dialup_stat();
    let dns_lookup_stat = res.dns_lookup_stat();

    writeln!(
        w,
        "{}",
        style.heading("Details (average, fastest, slowest):")
    )?;

    writeln!(
        w,
        "  DNS+dialup:\t{:.4} secs, {:.4} secs, {:.4} secs",
        dns_dialup_stat.mean(),
        dns_dialup_stat.min(),
        dns_dialup_stat.max()
    )?;
    writeln!(
        w,
        "  DNS-lookup:\t{:.4} secs, {:.4} secs, {:.4} secs",
        dns_lookup_stat.mean(),
        dns_lookup_stat.min(),
        dns_lookup_stat.max()
    )?;
    writeln!(w)?;

    let status_dist: BTreeMap<http::StatusCode, usize> = res.status_code_distribution();

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

    let mut error_v: Vec<(String, usize)> = res
        .error_distribution()
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
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

/// This is used to print histogram of response time.
fn print_histogram<W: Write>(
    w: &mut W,
    data: &[(f64, usize)],
    style: StyleScheme,
) -> std::io::Result<()> {
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
            (p, *values.get(i).unwrap_or(&f64::NAN))
        })
}

/// Print distribution of collection of f64
fn print_distribution<W: Write>(
    w: &mut W,
    percentiles: &[(f64, f64)],
    style: StyleScheme,
) -> std::io::Result<()> {
    for (p, v) in percentiles {
        writeln!(
            w,
            "{}",
            style.latency_distribution(&format!("  {p:.2}% in {v:.4} secs"), *v)
        )?;
    }

    Ok(())
}

fn percentiles(values: &mut [f64]) -> BTreeMap<String, f64> {
    percentile_iter(values)
        .map(|(p, v)| (format!("p{p}"), v))
        .collect()
}

#[cfg(test)]
mod tests {
    use float_cmp::assert_approx_eq;

    use super::*;

    #[test]
    fn test_percentile_iter() {
        let mut values: [f64; 40] = [
            5.0, 5.0, 5.0, 5.0, 5.0, 10.0, 10.0, 10.0, 10.0, 10.0, 11.0, 11.0, 11.0, 11.0, 11.0,
            11.0, 11.0, 11.0, 11.0, 11.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0, 12.0,
            12.0, 15.0, 15.0, 15.0, 15.0, 15.0, 20.0, 20.0, 20.0, 25.0, 30.0,
        ];
        let result: Vec<(f64, f64)> = percentile_iter(&mut values).collect();
        assert_approx_eq!(&[f64], &[result[0].0, result[0].1], &[10.0, 5_f64]);
        assert_approx_eq!(&[f64], &[result[1].0, result[1].1], &[25.0, 11_f64]);
        assert_approx_eq!(&[f64], &[result[2].0, result[2].1], &[50.0, 12_f64]);
        assert_approx_eq!(&[f64], &[result[3].0, result[3].1], &[75.0, 15_f64]);
        assert_approx_eq!(&[f64], &[result[4].0, result[4].1], &[90.0, 20_f64]);
        assert_approx_eq!(&[f64], &[result[5].0, result[5].1], &[95.0, 25_f64]);
        assert_approx_eq!(&[f64], &[result[6].0, result[6].1], &[99.0, 30_f64]);
        assert_approx_eq!(&[f64], &[result[7].0, result[7].1], &[99.9, 30_f64]);
        assert_approx_eq!(&[f64], &[result[8].0, result[8].1], &[99.99, 30_f64]);
    }
}
