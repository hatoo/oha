use futures::future::FutureExt;
use futures::StreamExt;
use rand::prelude::*;
use std::sync::Arc;
use thiserror::Error;

use crate::url_generator::{UrlGenerator, UrlGeneratorError};
use crate::ConnectToEntry;

#[derive(Debug, Clone)]
pub struct ConnectionTime {
    pub dns_lookup: std::time::Instant,
    pub dialup: std::time::Instant,
}

#[derive(Debug, Clone)]
/// a result for a request
pub struct RequestResult {
    // When the query should started
    pub start_latency_correction: Option<std::time::Instant>,
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
        self.end - self.start_latency_correction.unwrap_or(self.start)
    }
}

#[allow(clippy::upper_case_acronyms)]
struct DNS {
    connect_to: Arc<Vec<ConnectToEntry>>,
    resolver: Arc<
        trust_dns_resolver::AsyncResolver<
            trust_dns_resolver::name_server::GenericConnection,
            trust_dns_resolver::name_server::GenericConnectionProvider<
                trust_dns_resolver::name_server::TokioRuntime,
            >,
        >,
    >,
}

impl DNS {
    /// Perform a DNS lookup for a given url and returns (ip_addr, port)
    async fn lookup<R: Rng>(
        &self,
        url: &http::Uri,
        rng: &mut R,
    ) -> Result<(std::net::IpAddr, u16), ClientError> {
        let host = url.host().ok_or(ClientError::HostNotFound)?;
        let port = get_http_port(url).ok_or(ClientError::PortNotFound)?;

        // Try to find an override (passed via `--connect-to`) that applies to this (host, port)
        let (host, port) = if let Some(entry) = self
            .connect_to
            .iter()
            .find(|entry| entry.requested_port == port && entry.requested_host == host)
        {
            (entry.target_host.as_str(), entry.target_port)
        } else {
            (host, port)
        };

        let host = if host.starts_with('[') && host.ends_with(']') {
            // host is [ipv6] format
            // remove first [ and last ]
            &host[1..host.len() - 1]
        } else {
            host
        };

        // Perform actual DNS lookup, either on the original (host, port), or
        // on the (host, port) specified with `--connect-to`.
        let addrs = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(Box::new)?
            .iter()
            .collect::<Vec<_>>();

        let addr = *addrs.choose(rng).ok_or(ClientError::DNSNoRecord)?;

        Ok((addr, port))
    }
}

pub struct ClientBuilder {
    pub http_version: http::Version,
    pub url_generator: UrlGenerator,
    pub method: http::Method,
    pub headers: http::header::HeaderMap,
    pub body: Option<&'static [u8]>,
    pub timeout: Option<std::time::Duration>,
    pub redirect_limit: usize,
    /// always discard when used a connection.
    pub disable_keepalive: bool,
    pub connect_to: Arc<Vec<ConnectToEntry>>,
    pub resolver: Arc<
        trust_dns_resolver::AsyncResolver<
            trust_dns_resolver::name_server::GenericConnection,
            trust_dns_resolver::name_server::GenericConnectionProvider<
                trust_dns_resolver::name_server::TokioRuntime,
            >,
        >,
    >,
    pub insecure: bool,
    #[cfg(unix)]
    pub unix_socket: Option<std::path::PathBuf>,
}

impl ClientBuilder {
    pub fn build(&self) -> Client {
        Client {
            url_generator: self.url_generator.clone(),
            method: self.method.clone(),
            headers: self.headers.clone(),
            body: self.body,
            dns: DNS {
                resolver: self.resolver.clone(),
                connect_to: self.connect_to.clone(),
            },
            client: None,
            timeout: self.timeout,
            http_version: self.http_version,
            redirect_limit: self.redirect_limit,
            disable_keepalive: self.disable_keepalive,
            insecure: self.insecure,
            #[cfg(unix)]
            unix_socket: self.unix_socket.clone(),
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
    #[error(transparent)]
    // Use Box here because ResolveError is big.
    ResolveError(#[from] Box<trust_dns_resolver::error::ResolveError>),

    #[cfg(feature = "native-tls")]
    #[error(transparent)]
    NativeTlsError(#[from] native_tls::Error),

    #[cfg(feature = "rustls")]
    #[error(transparent)]
    RustlsError(#[from] rustls::Error),

    #[cfg(feature = "rustls")]
    #[error(transparent)]
    InvalidHost(#[from] rustls::client::InvalidDnsNameError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    HttpError(#[from] http::Error),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error(transparent)]
    InvalidUriParts(#[from] http::uri::InvalidUriParts),
    #[error("Authority is missing. This is a bug.")]
    MissingAuthority,
    #[error(transparent)]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),
    #[error("Failed to get header from builder")]
    GetHeaderFromBuilderError,
    #[error(transparent)]
    HeaderToStrError(#[from] http::header::ToStrError),
    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri),
    #[error("timeout")]
    Timeout,
    #[error(transparent)]
    UrlGeneratorError(#[from] UrlGeneratorError),
}

pub struct Client {
    http_version: http::Version,
    url_generator: UrlGenerator,
    method: http::Method,
    headers: http::header::HeaderMap,
    body: Option<&'static [u8]>,
    dns: DNS,
    client: Option<hyper::client::conn::SendRequest<hyper::Body>>,
    timeout: Option<std::time::Duration>,
    redirect_limit: usize,
    disable_keepalive: bool,
    insecure: bool,
    #[cfg(unix)]
    pub unix_socket: Option<std::path::PathBuf>,
}

impl Client {
    #[cfg(unix)]
    async fn client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &http::Uri,
    ) -> Result<hyper::client::conn::SendRequest<hyper::Body>, ClientError> {
        if url.scheme() == Some(&http::uri::Scheme::HTTPS) {
            self.tls_client(addr, url).await
        } else if let Some(socket_path) = &self.unix_socket {
            let stream = tokio::net::UnixStream::connect(socket_path).await?;
            let (send, conn) = hyper::client::conn::handshake(stream).await?;
            tokio::spawn(conn);
            Ok(send)
        } else {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            // stream.set_keepalive(std::time::Duration::from_secs(1).into())?;
            let (send, conn) = hyper::client::conn::handshake(stream).await?;
            tokio::spawn(conn);
            Ok(send)
        }
    }

    #[cfg(not(unix))]
    async fn client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &http::Uri,
    ) -> Result<hyper::client::conn::SendRequest<hyper::Body>, ClientError> {
        if url.scheme() == Some(&http::uri::Scheme::HTTPS) {
            self.tls_client(addr, url).await
        } else {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            // stream.set_keepalive(std::time::Duration::from_secs(1).into())?;
            let (send, conn) = hyper::client::conn::handshake(stream).await?;
            tokio::spawn(conn);
            Ok(send)
        }
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    async fn tls_client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &http::Uri,
    ) -> Result<hyper::client::conn::SendRequest<hyper::Body>, ClientError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

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
            .connect(url.host().ok_or(ClientError::HostNotFound)?, stream)
            .await?;

        let (send, conn) = hyper::client::conn::handshake(stream).await?;
        tokio::spawn(conn);
        Ok(send)
    }

    #[cfg(feature = "rustls")]
    async fn tls_client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &http::Uri,
    ) -> Result<hyper::client::conn::SendRequest<hyper::Body>, ClientError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        let mut root_cert_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs()? {
            root_cert_store.add(&rustls::Certificate(cert.0)).ok(); // ignore error
        }
        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        if self.insecure {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(AcceptAnyServerCert));
        }
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let domain = rustls::ServerName::try_from(url.host().ok_or(ClientError::HostNotFound)?)?;
        let stream = connector.connect(domain, stream).await?;

        let (send, conn) = hyper::client::conn::handshake(stream).await?;
        tokio::spawn(conn);
        Ok(send)
    }

    fn request(&self, url: &http::Uri) -> Result<http::Request<hyper::Body>, ClientError> {
        let mut builder = http::Request::builder()
            .uri(
                url.path_and_query()
                    .ok_or(ClientError::PathAndQueryNotFound)?
                    .as_str(),
            )
            .method(self.method.clone())
            .version(self.http_version);

        builder
            .headers_mut()
            .ok_or(ClientError::GetHeaderFromBuilderError)?
            .extend(self.headers.iter().map(|(k, v)| (k.clone(), v.clone())));

        if let Some(body) = self.body {
            Ok(builder.body(hyper::Body::from(body))?)
        } else {
            Ok(builder.body(hyper::Body::empty())?)
        }
    }

    pub async fn work<R: Rng + Send>(&mut self, rng: &mut R) -> Result<RequestResult, ClientError> {
        let timeout = if let Some(timeout) = self.timeout {
            tokio::time::sleep(timeout).boxed()
        } else {
            std::future::pending().boxed()
        };

        let do_req = async {
            let url = self.url_generator.generate(rng)?;
            let mut start = std::time::Instant::now();
            let mut connection_time: Option<ConnectionTime> = None;

            let mut send_request = if let Some(send_request) = self.client.take() {
                send_request
            } else {
                let addr = self.dns.lookup(&url, rng).await?;
                let dns_lookup = std::time::Instant::now();
                let send_request = self.client(addr, &url).await?;
                let dialup = std::time::Instant::now();

                connection_time = Some(ConnectionTime { dns_lookup, dialup });
                send_request
            };
            while futures::future::poll_fn(|ctx| send_request.poll_ready(ctx))
                .await
                .is_err()
            {
                start = std::time::Instant::now();
                let addr = self.dns.lookup(&url, rng).await?;
                let dns_lookup = std::time::Instant::now();
                send_request = self.client(addr, &url).await?;
                let dialup = std::time::Instant::now();
                connection_time = Some(ConnectionTime { dns_lookup, dialup });
            }
            let request = self.request(&url)?;
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
                                .redirect(send_request, &url, location, self.redirect_limit, rng)
                                .await?;

                            send_request = send_request_redirect;
                            status = new_status;
                            len_sum = len;
                        }
                    }

                    let end = std::time::Instant::now();

                    let result = RequestResult {
                        start_latency_correction: None,
                        start,
                        end,
                        status,
                        len_bytes: len_sum,
                        connection_time,
                    };

                    if !self.disable_keepalive {
                        self.client = Some(send_request);
                    }

                    Ok::<_, ClientError>(result)
                }
                Err(e) => {
                    self.client = Some(send_request);
                    Err(e.into())
                }
            }
        };

        tokio::select! {
            res = do_req => {
                res
            }
            _ = timeout => {
                Err(ClientError::Timeout)
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn redirect<'a, R: Rng + Send>(
        &'a self,
        send_request: hyper::client::conn::SendRequest<hyper::Body>,
        base_url: &'a http::Uri,
        location: &'a http::header::HeaderValue,
        limit: usize,
        rng: &'a mut R,
    ) -> futures::future::BoxFuture<
        'a,
        Result<
            (
                hyper::client::conn::SendRequest<hyper::Body>,
                http::StatusCode,
                usize,
            ),
            ClientError,
        >,
    > {
        async move {
            if limit == 0 {
                return Err(ClientError::TooManyRedirect);
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
                    let addr = self.dns.lookup(&url, rng).await?;
                    (self.client(addr, &url).await?, Some(send_request))
                };

            while futures::future::poll_fn(|ctx| send_request.poll_ready(ctx))
                .await
                .is_err()
            {
                let addr = self.dns.lookup(&url, rng).await?;
                send_request = self.client(addr, &url).await?;
            }

            let mut request = self.request(&url)?;
            if url.authority() != base_url.authority() {
                request.headers_mut().insert(
                    http::header::HOST,
                    http::HeaderValue::from_str(
                        url.authority()
                            .ok_or(ClientError::MissingAuthority)?
                            .as_str(),
                    )?,
                );
            }
            let res = send_request.send_request(request).await?;
            let (parts, mut stream) = res.into_parts();
            let mut status = parts.status;

            let mut len_sum = 0;
            while let Some(chunk) = stream.next().await {
                len_sum += chunk?.len();
            }

            if let Some(location) = parts.headers.get("Location") {
                let (send_request_redirect, new_status, len) = self
                    .redirect(send_request, &url, location, limit - 1, rng)
                    .await?;
                send_request = send_request_redirect;
                status = new_status;
                len_sum = len;
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

/// A server certificate verifier that accepts any certificate.
#[cfg(feature = "rustls")]
struct AcceptAnyServerCert;

#[cfg(feature = "rustls")]
impl rustls::client::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::HandshakeSignatureValid::assertion())
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
fn is_too_many_open_files(res: &Result<RequestResult, ClientError>) -> bool {
    res.as_ref()
        .err()
        .map(|err| match err {
            ClientError::IoError(io_error) => io_error.raw_os_error() == Some(libc::EMFILE),
            _ => false,
        })
        .unwrap_or(false)
}

/// Run n tasks by m workers
pub async fn work(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    n_tasks: usize,
    n_workers: usize,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));

    let futures = (0..n_workers)
        .map(|_| {
            let mut w = client_builder.build();
            let mut rng = StdRng::from_entropy();
            let report_tx = report_tx.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                while counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                    let res = w.work(&mut rng).await;
                    let is_cancel = is_too_many_open_files(&res);
                    report_tx.send_async(res).await.unwrap();
                    if is_cancel {
                        break;
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    for f in futures {
        let _ = f.await;
    }
}

/// n tasks by m workers limit to qps works in a second
pub async fn work_with_qps(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    qps: usize,
    n_tasks: usize,
    n_workers: usize,
) {
    let (tx, rx) = flume::unbounded();

    tokio::spawn(async move {
        let start = std::time::Instant::now();
        for i in 0..n_tasks {
            tokio::time::sleep_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
            tx.send_async(()).await.unwrap();
        }
        // tx gone
    });

    let futures = (0..n_workers)
        .map(|_| {
            let mut w = client_builder.build();
            let mut rng = StdRng::from_entropy();
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(()) = rx.recv_async().await {
                    let res = w.work(&mut rng).await;
                    let is_cancel = is_too_many_open_files(&res);
                    report_tx.send_async(res).await.unwrap();
                    if is_cancel {
                        break;
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    for f in futures {
        let _ = f.await;
    }
}

/// n tasks by m workers limit to qps works in a second with latency correction
pub async fn work_with_qps_latency_correction(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    qps: usize,
    n_tasks: usize,
    n_workers: usize,
) {
    let (tx, rx) = flume::unbounded();

    tokio::spawn(async move {
        let start = std::time::Instant::now();
        for i in 0..n_tasks {
            tx.send_async(std::time::Instant::now()).await.unwrap();
            tokio::time::sleep_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
        }
        // tx gone
    });

    let futures = (0..n_workers)
        .map(|_| {
            let mut w = client_builder.build();
            let mut rng = StdRng::from_entropy();
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(start) = rx.recv_async().await {
                    let mut res = w.work(&mut rng).await;

                    if let Ok(request_result) = &mut res {
                        request_result.start_latency_correction = Some(start);
                    }

                    let is_cancel = is_too_many_open_files(&res);
                    report_tx.send_async(res).await.unwrap();
                    if is_cancel {
                        break;
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    for f in futures {
        let _ = f.await;
    }
}

/// Run until dead_line by n workers
pub async fn work_until(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    dead_line: std::time::Instant,
    n_workers: usize,
) {
    let futures = (0..n_workers)
        .map(|_| {
            let report_tx = report_tx.clone();
            let mut w = client_builder.build();
            let mut rng = StdRng::from_entropy();
            tokio::spawn(async move {
                loop {
                    let res = w.work(&mut rng).await;
                    let is_cancel = is_too_many_open_files(&res);
                    report_tx.send_async(res).await.unwrap();
                    if is_cancel {
                        break;
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    tokio::time::sleep_until(dead_line.into()).await;
    for f in futures {
        f.abort();
    }
}

/// Run until dead_line by n workers limit to qps works in a second
pub async fn work_until_with_qps(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    qps: usize,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_workers: usize,
) {
    let (tx, rx) = flume::bounded(qps);

    tokio::spawn(async move {
        for i in 0.. {
            if std::time::Instant::now() > dead_line {
                break;
            }
            tokio::time::sleep_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
            if tx.send_async(()).await.is_err() {
                break;
            }
        }
        // tx gone
    });

    let futures = (0..n_workers)
        .map(|_| {
            let mut w = client_builder.build();
            let mut rng = StdRng::from_entropy();
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(()) = rx.recv_async().await {
                    let res = w.work(&mut rng).await;
                    let is_cancel = is_too_many_open_files(&res);
                    report_tx.send_async(res).await.unwrap();
                    if is_cancel {
                        break;
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    tokio::time::sleep_until(dead_line.into()).await;
    for f in futures {
        f.abort();
    }
}

/// Run until dead_line by n workers limit to qps works in a second with latency correction
pub async fn work_until_with_qps_latency_correction(
    client_builder: ClientBuilder,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    qps: usize,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_workers: usize,
) {
    let (tx, rx) = flume::unbounded();

    tokio::spawn(async move {
        for i in 0.. {
            let now = std::time::Instant::now();
            if now > dead_line {
                break;
            }
            tokio::time::sleep_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
            if tx.send_async(now).await.is_err() {
                break;
            }
        }
        // tx gone
    });

    let futures = (0..n_workers)
        .map(|_| {
            let mut w = client_builder.build();
            let mut rng = StdRng::from_entropy();
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(start) = rx.recv_async().await {
                    let mut res = w.work(&mut rng).await;

                    if let Ok(request_result) = &mut res {
                        request_result.start_latency_correction = Some(start);
                    }

                    let is_cancel = is_too_many_open_files(&res);
                    report_tx.send_async(res).await.unwrap();
                    if is_cancel {
                        break;
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    tokio::time::sleep_until(dead_line.into()).await;
    for f in futures {
        f.abort();
    }
}
