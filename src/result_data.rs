use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use average::{concatenate, Estimate, Max, Mean, Min};
use hyper::StatusCode;

use crate::client::{ClientError, ConnectionTime, RequestResult};

/// Data container for the results of the all requests
/// When a request is successful, the result is pushed to the `success` vector and the memory consumption will not be a problem because the number of successful requests is limited by network overhead.
/// When a request fails, the error message is pushed to the `error` map because the number of error messages may huge.
#[derive(Debug, Default)]
pub struct ResultData {
    success: Vec<RequestResult>,
    error_distribution: BTreeMap<String, usize>,
}

// https://github.com/vks/average/issues/19
// can't define pub struct for now.
concatenate!(MinMaxMeanInner, [Min, min], [Max, max], [Mean, mean]);
pub struct MinMaxMean(MinMaxMeanInner);

impl MinMaxMean {
    pub fn min(&self) -> f64 {
        self.0.min()
    }

    pub fn max(&self) -> f64 {
        self.0.max()
    }

    pub fn mean(&self) -> f64 {
        self.0.mean()
    }
}

impl ResultData {
    #[inline]
    pub fn push(&mut self, result: Result<RequestResult, ClientError>) {
        match result {
            Ok(result) => self.success.push(result),
            Err(err) => {
                let count = self.error_distribution.entry(err.to_string()).or_insert(0);
                *count += 1;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.success.len() + self.error_distribution.values().sum::<usize>()
    }

    // An existence of this method doesn't prevent us to using hdrhistogram.
    // Because this is only called from `monitor` and `monitor` can collect own data.
    pub fn success(&self) -> &[RequestResult] {
        &self.success
    }

    // It's very happy if you can provide all below methods without array (= non liner memory consumption) and fast `push` runtime.

    pub fn success_rate(&self) -> f64 {
        let dead_line = ClientError::Deadline.to_string();
        // We ignore deadline errors which are because of `-z` option, not because of the server
        let denominator = self.success.len()
            + self
                .error_distribution
                .iter()
                .filter_map(|(k, v)| if k == &dead_line { None } else { Some(v) })
                .sum::<usize>();
        let numerator = self.success.len();

        numerator as f64 / denominator as f64
    }

    pub fn latency_stat(&self) -> MinMaxMean {
        let latencies = self
            .success
            .iter()
            .map(|result| result.duration().as_secs_f64())
            .collect::<MinMaxMeanInner>();
        MinMaxMean(latencies)
    }

    pub fn error_distribution(&self) -> &BTreeMap<String, usize> {
        &self.error_distribution
    }

    pub fn end_times_from_start(&self) -> impl Iterator<Item = Duration> + '_ {
        self.success.iter().map(|result| result.end - result.start)
    }

    pub fn status_code_distribution(&self) -> BTreeMap<StatusCode, usize> {
        let mut dist = BTreeMap::new();
        for result in &self.success {
            let count = dist.entry(result.status).or_insert(0);
            *count += 1;
        }
        dist
    }

    pub fn connection_times_base(&self) -> impl Iterator<Item = (Instant, ConnectionTime)> + '_ {
        self.success
            .iter()
            .filter_map(|r| r.connection_time.map(|ct| (r.start, ct)))
    }

    pub fn total_data(&self) -> usize {
        self.success.iter().map(|r| r.len_bytes).sum()
    }

    pub fn size_per_request(&self) -> Option<u64> {
        self.success
            .iter()
            .map(|r| r.len_bytes as u64)
            .sum::<u64>()
            .checked_div(self.success.len() as u64)
    }

    pub fn duration_all(&self) -> impl Iterator<Item = Duration> + '_ {
        self.success.iter().map(|r| r.duration())
    }

    pub fn duration_successful(&self) -> impl Iterator<Item = Duration> + '_ {
        self.success
            .iter()
            .filter(|r| r.status.is_success())
            .map(|r| r.duration())
    }

    pub fn duration_not_successful(&self) -> impl Iterator<Item = Duration> + '_ {
        self.success
            .iter()
            .filter(|r| !r.status.is_success())
            .map(|r| r.duration())
    }
}
