use super::RequestResult;
use byte_unit::Byte;
use std::collections::HashMap;
use std::time::Duration;

/// Print all summary to stdout
pub fn print<E: std::fmt::Display>(res: &[Result<RequestResult, E>], total_duration: Duration) {
    println!("Summary:");
    println!(
        "  Success rate:\t{:.4}",
        res.iter().filter(|r| r.is_ok()).count() as f64 / res.len() as f64
    );
    println!("  Total:\t{:.4} secs", total_duration.as_secs_f64());
    println!(
        "  Slowest:\t{:.4} secs",
        res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration().as_secs_f64())
            .collect::<average::Max>()
            .max()
    );
    println!(
        "  Fastest:\t{:.4} secs",
        res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration().as_secs_f64())
            .collect::<average::Min>()
            .min()
    );
    println!(
        "  Average:\t{:.4} secs",
        res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration().as_secs_f64())
            .collect::<average::Mean>()
            .mean()
    );
    println!(
        "  Requests/sec:\t{:.4}",
        res.len() as f64 / total_duration.as_secs_f64()
    );
    println!();
    println!(
        "  Total data:\t{}",
        Byte::from_bytes(
            res.iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.len_bytes as u128)
                .sum::<u128>()
        )
        .get_appropriate_unit(true)
    );
    println!(
        "  Size/request:\t{}",
        (res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.len_bytes)
            .sum::<usize>()
            .checked_div(res.iter().filter(|r| r.is_ok()).count()))
        .map(|n| Byte::from_bytes(n as u128)
            .get_appropriate_unit(true)
            .to_string())
        .unwrap_or("NaN".to_string())
    );
    println!(
        "  Size/sec:\t{}",
        Byte::from_bytes(
            (res.iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.len_bytes)
                .sum::<usize>() as f64
                / total_duration.as_secs_f64()) as u128
        )
        .get_appropriate_unit(true)
    );
    println!();
    let durations = res
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|r| r.duration().as_secs_f64())
        .collect::<Vec<_>>();

    println!("Response time histogram:");
    print_histogram(&durations);
    println!();
    println!("Latency distribution:");
    print_distribution(&durations);
    println!();

    let mut status_dist: HashMap<reqwest::StatusCode, usize> = HashMap::new();

    for s in res.iter().filter_map(|r| r.as_ref().ok()).map(|r| r.status) {
        *status_dist.entry(s).or_default() += 1;
    }

    let mut status_v: Vec<(reqwest::StatusCode, usize)> = status_dist.into_iter().collect();
    status_v.sort_by_key(|t| std::cmp::Reverse(t.1));

    println!("Status code distribution:");
    for (status, count) in status_v {
        println!("  [{}] {} responses", status.as_str(), count);
    }

    let mut error_dist: HashMap<String, usize> = HashMap::new();
    for e in res.iter().filter_map(|r| r.as_ref().err()) {
        *error_dist.entry(e.to_string()).or_default() += 1;
    }

    let mut error_v: Vec<(String, usize)> = error_dist.into_iter().collect();
    error_v.sort_by_key(|t| std::cmp::Reverse(t.1));

    if !error_v.is_empty() {
        println!();
        println!("Error distribution:");
        for (error, count) in error_v {
            println!("  [{}] {}", count, error);
        }
    }
}

/// Print histogram of series of f64 data.
/// This is used to print histogram of response time.
fn print_histogram(values: &[f64]) {
    // TODO: Use better algorithm.
    // Is there any common and good algorithm?
    if values.is_empty() {
        return;
    }
    let lines = 11;
    let mut bucket: Vec<u64> = vec![0; lines];
    let average = values.iter().collect::<average::Mean>().mean();
    let min = values.iter().collect::<average::Min>().min();
    let max = values
        .iter()
        .collect::<average::Max>()
        .max()
        .min(average * 3.0);
    let step = (max - min) / lines as f64;

    for &v in values {
        let i = std::cmp::min(((v - min) / step) as usize, lines - 1);
        bucket[i] += 1;
    }

    let max_bar = *bucket.iter().max().unwrap();

    for (i, &b) in bucket.iter().enumerate() {
        let t = min + i as f64 * step;
        print!("  {:.3} [{}]\t|", t, b);
        bar(b as f64 / max_bar as f64);
        println!();
    }
}

// Print Bar like ■■■■■■■■■
fn bar(ratio: f64) {
    // TODO: Use more block element code to show more precise bar
    let width = 32;
    for _ in 0..(width as f64 * ratio) as usize {
        print!("■");
    }
}

/// Print distribution of collection of f64
fn print_distribution(values: &[f64]) {
    let mut buf = values.to_vec();
    float_ord::sort(&mut buf);

    for &p in &[10, 25, 50, 75, 90, 95, 99] {
        let i = (f64::from(p) / 100.0 * buf.len() as f64) as usize;
        println!(
            "  {}% in {:.4} secs",
            p,
            buf.get(i).unwrap_or(&std::f64::NAN)
        );
    }
}
