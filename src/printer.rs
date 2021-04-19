use crate::client::ConnectionTime;
use crate::client::RequestResult;
use byte_unit::Byte;
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

/// Print all summary
pub fn print_summary<W: Write, E: std::fmt::Display>(
    w: &mut W,
    res: &[Result<Box<RequestResult>, E>],
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
                .map(|r| r.len_bytes)
                .sum::<usize>() as f64
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
