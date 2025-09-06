use bytes::Bytes;
use http_body_util::Full;
use hyper::http;
use hyper::{HeaderMap, Method, Version};
use rand::Rng;
use std::sync::{Arc, Mutex};
use thiserror::Error;

use crate::aws_auth::{self, AwsSignatureConfig};
use crate::line_reader::LineReader;
use crate::url_generator;

pub struct Proxy {
    pub headers: HeaderMap,
    pub version: Version,
}

pub struct RequestGenerator {
    pub url_generator: url_generator::UrlGenerator,
    // Only if http with proxy
    pub http_proxy: Option<Proxy>,
    pub method: Method,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
    pub body_lines_reader: Option<Arc<Mutex<LineReader>>>,
    pub aws_config: Option<AwsSignatureConfig>,
}

#[derive(Error, Debug)]
pub enum RequestGenerationError {
    #[error("URL generation error: {0}")]
    UrlGeneration(#[from] url_generator::UrlGeneratorError),
    #[error("Request building error: {0}")]
    RequestBuild(#[from] http::Error),
    #[error("AWS Signature error: {0}")]
    AwsSignature(#[from] aws_auth::AwsSignatureError),
}

impl RequestGenerator {
    #[inline]
    fn is_http1(&self) -> bool {
        self.version <= Version::HTTP_11
    }

    pub fn generate<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<hyper::Request<Full<Bytes>>, RequestGenerationError> {
        let url = self.url_generator.generate(rng)?;

        let mut builder = hyper::Request::builder()
            .uri(if !self.is_http1() || self.http_proxy.is_some() {
                &url[..]
            } else {
                &url[url::Position::BeforePath..]
            })
            .method(self.method.clone())
            .version(
                self.http_proxy
                    .as_ref()
                    .map(|p| p.version)
                    .unwrap_or(self.version),
            );

        let mut headers = self.headers.clone();

        let body = if let Some(reader) = &self.body_lines_reader {
            let mut guard = reader.lock().unwrap();
            match guard.next_line() {
                Ok(Some(line)) => line,
                _ => Bytes::new(),
            }
        } else if let Some(body) = &self.body {
            body.clone()
        } else {
            Bytes::new()
        };

        // Apply AWS SigV4 if configured
        if let Some(aws_config) = &self.aws_config {
            aws_config.sign_request(self.method.as_str(), &mut headers, &url, &body.clone())?;
        }

        if let Some(proxy) = &self.http_proxy {
            for (key, value) in proxy.headers.iter() {
                headers.insert(key, value.clone());
            }
        }

        *builder.headers_mut().unwrap() = headers;

        let req = builder.body(Full::new(body))?;
        Ok(req)
    }
}
