use anyhow::Context;
use futures::future::FutureExt;
use futures::stream::FuturesUnordered;
use rand::prelude::*;
use std::sync::Arc;
use thiserror::Error;
use tokio::stream::StreamExt;

#[derive(Debug, Clone)]
pub struct ConnectionTime {
    pub dns_lookup: std::time::Instant,
    pub dialup: std::time::Instant,
}

#[derive(Debug, Clone)]
/// a result for a request
pub struct RequestResult {
    /// When the query started
    pub start: std::time::Instant,
    /// DNS + dialup
    /// None when reuse connection
    pub connection_time: Option<ConnectionTime>,
    /// When the query ends
    pub end: std::time::Instant,
    /// HTTP status
    pub status: http::StatusCode,
    /// Length of body
    pub len_bytes: usize,
}

impl RequestResult {
    /// Duration the request takes.
    pub fn duration(&self) -> std::time::Duration {
        self.end - self.start
    }
}

pub struct ClientBuilder {
    pub http_version: http::Version,
    pub url: http::Uri,
    pub method: http::Method,
    pub headers: http::header::HeaderMap,
    pub body: Option<&'static [u8]>,
    pub timeout: Option<std::time::Duration>,
    pub redirect_limit: usize,
    /// always discard when used a connection.
    pub disable_keepalive: bool,
    pub resolver: Arc<
        trust_dns_resolver::AsyncResolver<
            trust_dns_resolver::name_server::GenericConnection,
            trust_dns_resolver::name_server::GenericConnectionProvider<
                trust_dns_resolver::name_server::TokioRuntime,
            >,
        >,
    >,
    pub insecure: bool,
}

impl ClientBuilder {
    pub fn build(&self) -> Client {
        Client {
            url: self.url.clone(),
            method: self.method.clone(),
            headers: self.headers.clone(),
            body: self.body,
            resolver: self.resolver.clone(),
            rng: rand::rngs::StdRng::from_entropy(),
            client: None,
            timeout: self.timeout,
            http_version: self.http_version,
            redirect_limit: self.redirect_limit,
            disable_keepalive: self.disable_keepalive,
            insecure: self.insecure,
        }
    }
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("failed to get port from URL")]
    PortNotFound,
    #[error("failed to get host from URL")]
    HostNotFound,
    #[error("failed to get path and query from URL")]
    PathAndQueryNotFound,
    #[error("No record returned from DNS")]
    DNSNoRecord,
    #[error("Redirection limit has reached")]
    TooManyRedirect,
}

pub struct Client {
    http_version: http::Version,
    url: http::Uri,
    method: http::Method,
    headers: http::header::HeaderMap,
    body: Option<&'static [u8]>,
    // To pick a random address from DNS.
    rng: rand::rngs::StdRng,
    resolver: Arc<
        trust_dns_resolver::AsyncResolver<
            trust_dns_resolver::name_server::GenericConnection,
            trust_dns_resolver::name_server::GenericConnectionProvider<
                trust_dns_resolver::name_server::TokioRuntime,
            >,
        >,
    >,
    client: Option<hyper::client::conn::SendRequest<hyper::Body>>,
    timeout: Option<std::time::Duration>,
    redirect_limit: usize,
    disable_keepalive: bool,
    insecure: bool,
}

impl Client {
    async fn lookup_ip(&mut self) -> anyhow::Result<std::net::IpAddr> {
        let addrs = self
            .resolver
            .lookup_ip(self.url.host().ok_or_else(|| ClientError::HostNotFound)?)
            .await?
            .iter()
            .collect::<Vec<_>>();

        let addr = *addrs
            .choose(&mut self.rng)
            .ok_or_else(|| ClientError::DNSNoRecord)?;

        Ok(addr)
    }

    async fn lookup_ip_url(&mut self, url: &http::Uri) -> anyhow::Result<std::net::IpAddr> {
        let addrs = self
            .resolver
            .lookup_ip(url.host().ok_or_else(|| ClientError::HostNotFound)?)
            .await?
            .iter()
            .collect::<Vec<_>>();

        let addr = *addrs
            .choose(&mut self.rng)
            .ok_or_else(|| ClientError::DNSNoRecord)?;

        Ok(addr)
    }

    async fn client(
        &mut self,
        addr: (std::net::IpAddr, u16),
    ) -> anyhow::Result<hyper::client::conn::SendRequest<hyper::Body>> {
        if self.url.scheme() == Some(&http::uri::Scheme::HTTPS) {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            stream.set_keepalive(std::time::Duration::from_secs(1).into())?;
            let connector = if self.insecure {
                native_tls::TlsConnector::builder()
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true)
                    .build()?
            } else {
                native_tls::TlsConnector::new()?
            };
            let connector = tokio_native_tls::TlsConnector::from(connector);
            let stream = connector
                .connect(
                    self.url.host().ok_or_else(|| ClientError::HostNotFound)?,
                    stream,
                )
                .await?;
            let (send, conn) = hyper::client::conn::handshake(stream).await?;
            tokio::spawn(conn);
            Ok(send)
        } else {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            stream.set_keepalive(std::time::Duration::from_secs(1).into())?;
            let (send, conn) = hyper::client::conn::handshake(stream).await?;
            tokio::spawn(conn);
            Ok(send)
        }
    }

    fn request(&self, url: &http::Uri) -> anyhow::Result<http::Request<hyper::Body>> {
        let mut builder = http::Request::builder()
            .uri(
                url.path_and_query()
                    .ok_or_else(|| ClientError::PathAndQueryNotFound)?
                    .as_str(),
            )
            .method(self.method.clone())
            .version(self.http_version);

        builder
            .headers_mut()
            .context("Failed to get header from builder")?
            .extend(self.headers.iter().map(|(k, v)| (k.clone(), v.clone())));

        if let Some(body) = self.body {
            Ok(builder.body(hyper::Body::from(body))?)
        } else {
            Ok(builder.body(hyper::Body::empty())?)
        }
    }

    pub async fn work(&mut self) -> anyhow::Result<RequestResult> {
        let timeout = if let Some(timeout) = self.timeout {
            tokio::time::delay_for(timeout).boxed()
        } else {
            futures::future::pending().boxed()
        };

        let do_req = async {
            let mut start = std::time::Instant::now();
            let mut connection_time: Option<ConnectionTime> = None;

            let mut send_request = if let Some(send_request) = self.client.take() {
                send_request
            } else {
                let addr = (
                    self.lookup_ip().await?,
                    get_http_port(&self.url).ok_or_else(|| ClientError::PortNotFound)?,
                );
                let dns_lookup = std::time::Instant::now();
                let send_request = self.client(addr).await?;
                let dialup = std::time::Instant::now();

                connection_time = Some(ConnectionTime { dns_lookup, dialup });
                send_request
            };
            while futures::future::poll_fn(|ctx| send_request.poll_ready(ctx))
                .await
                .is_err()
            {
                start = std::time::Instant::now();
                let addr = (
                    self.lookup_ip().await?,
                    get_http_port(&self.url).ok_or_else(|| ClientError::PortNotFound)?,
                );
                let dns_lookup = std::time::Instant::now();
                send_request = self.client(addr).await?;
                let dialup = std::time::Instant::now();
                connection_time = Some(ConnectionTime { dns_lookup, dialup });
            }
            let request = self.request(&self.url)?;
            match send_request.send_request(request).await {
                Ok(res) => {
                    let (parts, mut stream) = res.into_parts();
                    let mut status = parts.status;

                    let mut len_sum = 0;
                    while let Some(chunk) = stream.next().await {
                        len_sum += chunk?.len();
                    }

                    if self.redirect_limit != 0 {
                        if let Some(location) = parts.headers.get("Location") {
                            let (send_request_redirect, new_status, len) = self
                                .redirect(
                                    send_request,
                                    &self.url.clone(),
                                    location,
                                    self.redirect_limit,
                                )
                                .await?;

                            send_request = send_request_redirect;
                            status = new_status;
                            len_sum += len;
                        }
                    }

                    let end = std::time::Instant::now();

                    let result = RequestResult {
                        start,
                        end,
                        status,
                        len_bytes: len_sum,
                        connection_time,
                    };

                    if !self.disable_keepalive {
                        self.client = Some(send_request);
                    }

                    return Ok::<_, anyhow::Error>(result);
                }
                Err(e) => {
                    self.client = Some(send_request);
                    return Err(e.into());
                }
            }
        };

        tokio::select! {
            res = do_req => {
                res
            }
            _ = timeout => {
                anyhow::bail!("timeout");
            }
        }
    }
    fn redirect<'a>(
        &'a mut self,
        send_request: hyper::client::conn::SendRequest<hyper::Body>,
        base_url: &'a http::Uri,
        location: &'a http::header::HeaderValue,
        limit: usize,
    ) -> futures::future::BoxFuture<
        'a,
        anyhow::Result<(
            hyper::client::conn::SendRequest<hyper::Body>,
            http::StatusCode,
            usize,
        )>,
    > {
        async move {
            if limit == 0 {
                anyhow::bail!(ClientError::TooManyRedirect);
            }
            let url: http::Uri = location.to_str()?.parse()?;
            let url = if url.authority().is_none() {
                // location was relative url
                let mut parts = base_url.clone().into_parts();
                parts.path_and_query = url.path_and_query().cloned();
                http::Uri::from_parts(parts)?
            } else {
                url
            };

            let (mut send_request, send_request_base) =
                if base_url.authority() == url.authority() && !self.disable_keepalive {
                    // reuse connection
                    (send_request, None)
                } else {
                    let port = get_http_port(&url).ok_or_else(|| ClientError::PortNotFound)?;
                    let addr = (self.lookup_ip_url(&url).await?, port);
                    (self.client(addr).await?, Some(send_request))
                };

            while futures::future::poll_fn(|ctx| send_request.poll_ready(ctx))
                .await
                .is_err()
            {
                let port = get_http_port(&url).ok_or_else(|| ClientError::PortNotFound)?;
                let addr = (self.lookup_ip_url(&url).await?, port);
                send_request = self.client(addr).await?;
            }

            let request = self.request(&url)?;
            let res = send_request.send_request(request).await?;
            let (parts, mut stream) = res.into_parts();
            let mut status = parts.status;

            let mut len_sum = 0;
            while let Some(chunk) = stream.next().await {
                len_sum += chunk?.len();
            }

            if let Some(location) = parts.headers.get("Location") {
                let (send_request_redirect, new_status, len) = self
                    .redirect(send_request, &url, location, limit - 1)
                    .await?;
                send_request = send_request_redirect;
                status = new_status;
                len_sum += len;
            }

            if let Some(send_request_base) = send_request_base {
                Ok((send_request_base, status, len_sum))
            } else {
                Ok((send_request, status, len_sum))
            }
        }
        .boxed()
    }
}

fn get_http_port(url: &http::Uri) -> Option<u16> {
    url.port_u16().or_else(|| {
        if url.scheme() == Some(&http::uri::Scheme::HTTP) {
            Some(80)
        } else if url.scheme() == Some(&http::uri::Scheme::HTTPS) {
            Some(443)
        } else {
            None
        }
    })
}

/// Check error was "Too many open file"
fn is_too_many_open_files(res: &anyhow::Result<RequestResult>) -> bool {
    res.as_ref()
        .err()
        .and_then(|err| err.downcast_ref::<std::io::Error>())
        .map(|err| err.raw_os_error() == Some(24))
        .unwrap_or(false)
}

/// Run n tasks by m workers
pub async fn work(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<anyhow::Result<RequestResult>>,
    n_tasks: usize,
    n_workers: usize,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = AtomicUsize::new(0);

    let mut futures_unordered = (0..n_workers)
        .map(|_| async {
            let mut w = client_builder.build();
            while counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                let res = w.work().await;
                let is_cancel = is_too_many_open_files(&res);
                report_tx.send(res).unwrap();
                if is_cancel {
                    break;
                }
            }
        })
        .collect::<FuturesUnordered<_>>();

    while futures_unordered.next().await.is_some() {}
}

/// n tasks by m workers limit to qps works in a second
pub async fn work_with_qps(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<anyhow::Result<RequestResult>>,
    qps: usize,
    n_tasks: usize,
    n_workers: usize,
) {
    let (tx, rx) = crossbeam::channel::unbounded();

    tokio::spawn(async move {
        let start = std::time::Instant::now();
        for i in 0..n_tasks {
            tx.send(()).unwrap();
            tokio::time::delay_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
        }
        // tx gone
    });

    let mut futures_unordered = (0..n_workers)
        .map(|_| async {
            let mut w = client_builder.build();
            while let Ok(()) = rx.recv() {
                let res = w.work().await;
                let is_cancel = is_too_many_open_files(&res);
                report_tx.send(res).unwrap();
                if is_cancel {
                    break;
                }
            }
        })
        .collect::<FuturesUnordered<_>>();

    while futures_unordered.next().await.is_some() {}
}

/// Run until dead_line by n workers
pub async fn work_until(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<anyhow::Result<RequestResult>>,
    dead_line: std::time::Instant,
    n_workers: usize,
) {
    let mut futures_unordered = (0..n_workers)
        .map(|_| async {
            let mut w = client_builder.build();
            loop {
                let res = w.work().await;
                let is_cancel = is_too_many_open_files(&res);
                report_tx.send(res).unwrap();
                if is_cancel {
                    break;
                }
            }
        })
        .collect::<FuturesUnordered<_>>();

    let _ = tokio::time::timeout_at(dead_line.into(), async {
        while futures_unordered.next().await.is_some() {}
    })
    .await;
}

/// Run until dead_line by n workers limit to qps works in a second
pub async fn work_until_with_qps(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<anyhow::Result<RequestResult>>,
    qps: usize,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_workers: usize,
) {
    let (tx, rx) = crossbeam::channel::bounded(qps);

    let gen = tokio::spawn(async move {
        for i in 0.. {
            if std::time::Instant::now() > dead_line {
                break;
            }
            if tx.send(()).is_err() {
                break;
            }
            tokio::time::delay_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
        }
        // tx gone
    });

    let mut futures_unordered = (0..n_workers)
        .map(|_| async {
            let mut w = client_builder.build();
            while let Ok(()) = rx.recv() {
                let res = w.work().await;
                let is_cancel = is_too_many_open_files(&res);
                report_tx.send(res).unwrap();
                if is_cancel {
                    break;
                }
            }
        })
        .collect::<FuturesUnordered<_>>();

    let _ = tokio::time::timeout_at(dead_line.into(), async {
        while futures_unordered.next().await.is_some() {}
    })
    .await;

    let _ = gen.await;
}
