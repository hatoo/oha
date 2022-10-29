use futures::future::FutureExt;
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use rand::prelude::*;
use std::{pin::Pin, sync::Arc};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{http_wrapper::SendRequestX, ConnectToEntry};

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

#[allow(clippy::upper_case_acronyms)]
struct DNS {
    // To pick a random address from DNS.
    rng: rand::rngs::StdRng,
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
    async fn lookup(&mut self, url: &http::Uri) -> Result<(std::net::IpAddr, u16), ClientError> {
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

        let addr = *addrs
            .choose(&mut self.rng)
            .ok_or(ClientError::DNSNoRecord)?;

        Ok((addr, port))
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
}

impl ClientBuilder {
    pub fn build(&self) -> Client {
        Client {
            url: self.url.clone(),
            method: self.method.clone(),
            headers: self.headers.clone(),
            body: self.body,
            dns: DNS {
                resolver: self.resolver.clone(),
                connect_to: self.connect_to.clone(),
                rng: rand::rngs::StdRng::from_entropy(),
            },
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
}

pub struct Client {
    http_version: http::Version,
    url: http::Uri,
    method: http::Method,
    headers: http::header::HeaderMap,
    body: Option<&'static [u8]>,
    dns: DNS,
    client: Option<SendRequestX<Full<&'static [u8]>>>,
    timeout: Option<std::time::Duration>,
    redirect_limit: usize,
    disable_keepalive: bool,
    insecure: bool,
}

pub async fn handshake<T, B>(
    http_versin: http::Version,
    io: T,
) -> Result<SendRequestX<B>, ClientError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + 'static + Send,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if http_versin == http::Version::HTTP_2 {
        #[derive(Clone)]
        /// An Executor that uses the tokio runtime.
        pub struct TokioExecutor;

        impl<F> hyper::rt::Executor<F> for TokioExecutor
        where
            F: std::future::Future + Send + 'static,
            F::Output: Send + 'static,
        {
            fn execute(&self, fut: F) {
                tokio::task::spawn(fut);
            }
        }
        let (send, conn) = hyper::client::conn::http2::Builder::new()
            .executor(TokioExecutor)
            .handshake(io)
            .await?;
        tokio::spawn(conn);
        Ok(SendRequestX::Http2(send))
    } else {
        let (send, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);
        Ok(SendRequestX::Http1(send))
    }
}

impl Client {
    async fn client(
        &mut self,
        addr: (std::net::IpAddr, u16),
    ) -> Result<SendRequestX<Full<&'static [u8]>>, ClientError> {
        if self.url.scheme() == Some(&http::uri::Scheme::HTTPS) {
            self.tls_client(addr).await
        } else {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            // stream.set_keepalive(std::time::Duration::from_secs(1).into())?;
            Ok(handshake(self.http_version, stream).await?)
        }
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    async fn tls_client(
        &mut self,
        addr: (std::net::IpAddr, u16),
    ) -> Result<SendRequestX<Full<&'static [u8]>>, ClientError> {
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
            .connect(self.url.host().ok_or(ClientError::HostNotFound)?, stream)
            .await?;

        handshake(self.http_version, stream).await
    }

    #[cfg(feature = "rustls")]
    async fn tls_client(
        &mut self,
        addr: (std::net::IpAddr, u16),
    ) -> Result<SendRequestX<Full<&'static [u8]>>, ClientError> {
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
        let domain =
            rustls::ServerName::try_from(self.url.host().ok_or(ClientError::HostNotFound)?)?;
        let stream = connector.connect(domain, stream).await?;

        Ok(handshake(self.http_version, stream).await?)
    }

    fn request(&self, url: &http::Uri) -> Result<http::Request<Full<&'static [u8]>>, ClientError> {
        let mut builder = http::Request::builder()
            .uri(url)
            .method(self.method.clone())
            .version(self.http_version);

        builder
            .headers_mut()
            .ok_or(ClientError::GetHeaderFromBuilderError)?
            .extend(self.headers.iter().map(|(k, v)| (k.clone(), v.clone())));

        if let Some(body) = self.body {
            Ok(builder.body(Full::new(body))?)
        } else {
            Ok(builder.body(Full::new(&[][..]))?)
        }
    }

    pub async fn work(&mut self) -> Result<RequestResult, ClientError> {
        let timeout = if let Some(timeout) = self.timeout {
            tokio::time::sleep(timeout).boxed()
        } else {
            std::future::pending().boxed()
        };

        let do_req = async {
            let mut start = std::time::Instant::now();
            let mut connection_time: Option<ConnectionTime> = None;

            let mut send_request = if let Some(send_request) = self.client.take() {
                send_request
            } else {
                let addr = self.dns.lookup(&self.url).await?;
                let dns_lookup = std::time::Instant::now();
                let send_request = self.client(addr).await?;
                let dialup = std::time::Instant::now();

                connection_time = Some(ConnectionTime { dns_lookup, dialup });
                send_request
            };
            while futures::future::poll_fn(|cx| send_request.poll_ready(cx))
                .await
                .is_err()
            {
                start = std::time::Instant::now();
                let addr = self.dns.lookup(&self.url).await?;
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
                    while let Some(chunk) = futures::future::poll_fn(|cx| {
                        Incoming::poll_frame(Pin::new(&mut stream), cx)
                    })
                    .await
                    {
                        len_sum += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
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
                            len_sum = len;
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
    fn redirect<'a>(
        &'a mut self,
        send_request: SendRequestX<Full<&'static [u8]>>,
        base_url: &'a http::Uri,
        location: &'a http::header::HeaderValue,
        limit: usize,
    ) -> futures::future::BoxFuture<
        'a,
        Result<(SendRequestX<Full<&'static [u8]>>, http::StatusCode, usize), ClientError>,
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
                    let addr = self.dns.lookup(&url).await?;
                    (self.client(addr).await?, Some(send_request))
                };

            while futures::future::poll_fn(|cx| send_request.poll_ready(cx))
                .await
                .is_err()
            {
                let addr = self.dns.lookup(&url).await?;
                send_request = self.client(addr).await?;
            }

            let mut request = self.request(&url)?;
            if url.authority() != self.url.authority() {
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
            while let Some(chunk) =
                futures::future::poll_fn(|cx| Incoming::poll_frame(Pin::new(&mut stream), cx)).await
            {
                len_sum += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
            }

            if let Some(location) = parts.headers.get("Location") {
                let (send_request_redirect, new_status, len) = self
                    .redirect(send_request, &url, location, limit - 1)
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
        _dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
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
            let report_tx = report_tx.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                while counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                    let res = w.work().await;
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
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(()) = rx.recv_async().await {
                    let res = w.work().await;
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
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(start) = rx.recv_async().await {
                    let mut res = w.work().await;

                    if let Ok(request_result) = &mut res {
                        request_result.start = start;
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
            tokio::spawn(tokio::time::timeout_at(dead_line.into(), async move {
                loop {
                    let res = w.work().await;
                    let is_cancel = is_too_many_open_files(&res);
                    report_tx.send_async(res).await.unwrap();
                    if is_cancel {
                        break;
                    }
                }
            }))
        })
        .collect::<Vec<_>>();

    for f in futures {
        let _ = f.await;
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

    let gen = tokio::spawn(async move {
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
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::time::timeout_at(
                dead_line.into(),
                tokio::spawn(async move {
                    while let Ok(()) = rx.recv_async().await {
                        let res = w.work().await;
                        let is_cancel = is_too_many_open_files(&res);
                        report_tx.send_async(res).await.unwrap();
                        if is_cancel {
                            break;
                        }
                    }
                }),
            )
        })
        .collect::<Vec<_>>();

    for f in futures {
        let _ = f.await;
    }

    let _ = gen.await;
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

    let gen = tokio::spawn(async move {
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
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::time::timeout_at(
                dead_line.into(),
                tokio::spawn(async move {
                    while let Ok(start) = rx.recv_async().await {
                        let mut res = w.work().await;

                        if let Ok(request_result) = &mut res {
                            request_result.start = start;
                        }

                        let is_cancel = is_too_many_open_files(&res);
                        report_tx.send_async(res).await.unwrap();
                        if is_cancel {
                            break;
                        }
                    }
                }),
            )
        })
        .collect::<Vec<_>>();

    for f in futures {
        let _ = f.await;
    }

    let _ = gen.await;
}
