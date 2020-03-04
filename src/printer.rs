use super::RequestResult;
use byte_unit::Byte;
use std::collections::HashMap;
use std::time::Duration;

pub fn print<E>(res: &[Result<RequestResult, E>], total_duration: Duration) {
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
            .map(|r| r.duration.as_secs_f64())
            .collect::<average::Max>()
            .max()
    );
    println!(
        "  Fastest:\t{:.4} secs",
        res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration.as_secs_f64())
            .collect::<average::Min>()
            .min()
    );
    println!(
        "  Average:\t{:.4} secs",
        res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration.as_secs_f64())
            .collect::<average::Mean>()
            .mean()
    );
    println!(
        "  Requests/sec:\t{:.4} secs",
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
        Byte::from_bytes(
            (res.iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|r| r.len_bytes)
                .sum::<usize>()
                / res.iter().filter(|r| r.is_ok()).count()) as u128
        )
        .get_appropriate_unit(true)
    );
    println!();
    println!("Latency distribution:");
    print_distribution(
        &res.iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| r.duration.as_secs_f64())
            .collect::<Vec<_>>(),
    );
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
}

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
