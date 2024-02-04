use std::collections::BTreeMap;

use crate::client::{ClientError, RequestResult};

#[derive(Debug, Default)]
pub struct Results {
    pub results: Vec<RequestResult>,
    pub errors: BTreeMap<String, usize>,
}

impl Results {
    pub fn add_result(&mut self, result: Result<RequestResult, ClientError>) {
        match result {
            Ok(result) => self.results.push(result),
            Err(err) => {
                let count = self.errors.entry(err.to_string()).or_insert(0);
                *count += 1;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.results.len() + self.errors.values().sum::<usize>()
    }
}
