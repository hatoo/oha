use anyhow::Result;

use bytes::Bytes;
use hyper::{
    HeaderMap,
    header::{self, HeaderName},
};
use thiserror::Error;
use url::Url;

pub struct AwsSignatureConfig {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub service: String,
    pub region: String,
}

#[derive(Error, Debug)]
pub enum AwsSignatureError {
    #[error("URL must contain a host")]
    NoHost,
    #[error("Invalid host header name")]
    InvalidHost,
    #[error("Invalid authorization header name")]
    InvalidAuthorization,
}

// Initialize unsignable headers as a static constant
static UNSIGNABLE_HEADERS: [HeaderName; 8] = [
    header::ACCEPT,
    header::ACCEPT_ENCODING,
    header::USER_AGENT,
    header::EXPECT,
    header::RANGE,
    header::CONNECTION,
    HeaderName::from_static("presigned-expires"),
    HeaderName::from_static("x-amzn-trace-id"),
];

impl AwsSignatureConfig {
    pub fn sign_request(
        &self,
        method: &str,
        headers: &mut HeaderMap,
        url: &Url,
        body: &Bytes,
    ) -> Result<(), AwsSignatureError> {
        let datetime = chrono::Utc::now();

        let header_amz_date = datetime
            .format("%Y%m%dT%H%M%SZ")
            .to_string()
            .parse()
            .unwrap();

        if !headers.contains_key(header::HOST) {
            let host = url.host_str().ok_or(AwsSignatureError::NoHost)?;
            headers.insert(
                header::HOST,
                host.parse().map_err(|_| AwsSignatureError::InvalidHost)?,
            );
        }
        headers.insert("x-amz-date", header_amz_date);

        if let Some(session_token) = &self.session_token {
            headers.insert("x-amz-security-token", session_token.parse().unwrap());
        }

        headers.remove(header::AUTHORIZATION);

        //remove and store headers in a vec from unsignable_headers
        let removed_headers: Vec<(header::HeaderName, header::HeaderValue)> = UNSIGNABLE_HEADERS
            .iter()
            .filter_map(|k| headers.remove(k).map(|v| (k.clone(), v)))
            .collect();

        headers.insert(
            header::CONTENT_LENGTH,
            body.len().to_string().parse().unwrap(),
        );

        let aws_sign = aws_sign_v4::AwsSign::new(
            method,
            url.as_str(),
            &datetime,
            headers,
            &self.region,
            &self.access_key,
            &self.secret_key,
            &self.service,
            body,
        );

        let signature = aws_sign.sign();

        //insert headers
        for (key, value) in removed_headers {
            headers.insert(key, value);
        }

        headers.insert(
            header::AUTHORIZATION,
            signature
                .parse()
                .map_err(|_| AwsSignatureError::InvalidAuthorization)?,
        );

        Ok(())
    }

    pub fn new(
        access_key: &str,
        secret_key: &str,
        signing_params: &str,
        session_token: Option<String>,
    ) -> Result<Self, anyhow::Error> {
        let parts: Vec<&str> = signing_params
            .strip_prefix("aws:amz:")
            .unwrap_or_default()
            .split(':')
            .collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid AWS signing params format. Expected aws:amz:region:service");
        }

        Ok(Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            session_token,
            region: parts[0].to_string(),
            service: parts[1].to_string(),
        })
    }
}
