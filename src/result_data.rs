use std::collections::BTreeMap;

use crate::client::{ClientError, RequestResult};

/// Data container for the results of the all requests
/// When a request is successful, the result is pushed to the `success` vector and the memory consumption will not be a problem because the number of successful requests is limited by network overhead.
/// When a request fails, the error message is pushed to the `error` map because the number of error messages may huge.
#[derive(Debug, Default)]
pub struct ResultData {
    pub success: Vec<RequestResult>,
    pub error: BTreeMap<String, usize>,
}

impl ResultData {
    pub fn push(&mut self, result: Result<RequestResult, ClientError>) {
        match result {
            Ok(result) => self.success.push(result),
            Err(err) => {
                let count = self.error.entry(err.to_string()).or_insert(0);
                *count += 1;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.success.len() + self.error.values().sum::<usize>()
    }
}
