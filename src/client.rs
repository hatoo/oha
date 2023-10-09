use futures::future::FutureExt;
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use hyper::rt::{Read, Write};
use rand::prelude::*;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use url::{ParseError, Url};

use crate::tokiort::{TokioExecutor, TokioIo};
use crate::url_generator::{UrlGenerator, UrlGeneratorError};
use crate::ConnectToEntry;

type SendRequestHttp1 = hyper::client::conn::http1::SendRequest<Full<&'static [u8]>>;
type SendRequestHttp2 = hyper::client::conn::http2::SendRequest<Full<&'static [u8]>>;

#[derive(Debug, Clone, Copy)]
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

pub struct Dns {
    pub connect_to: Vec<ConnectToEntry>,
    pub resolver:
        trust_dns_resolver::AsyncResolver<trust_dns_resolver::name_server::TokioConnectionProvider>,
}

impl Dns {
    /// Perform a DNS lookup for a given url and returns (ip_addr, port)
    async fn lookup<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
    ) -> Result<(std::net::IpAddr, u16), ClientError> {
        let host = url.host_str().ok_or(ClientError::HostNotFound)?;
        let port = url
            .port_or_known_default()
            .ok_or(ClientError::PortNotFound)?;

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

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("failed to get port from URL")]
    PortNotFound,
    #[error("failed to get host from URL")]
    HostNotFound,
    #[error("No record returned from DNS")]
    DNSNoRecord,
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
    #[error(transparent)]
    UrlParseError(#[from] ParseError),
}

pub struct Client {
    pub http_version: http::Version,
    pub url_generator: UrlGenerator,
    pub method: http::Method,
    pub headers: http::header::HeaderMap,
    pub body: Option<&'static [u8]>,
    pub dns: Dns,
    // client: Option<hyper::client::conn::SendRequest<hyper::Body>>,
    pub timeout: Option<std::time::Duration>,
    pub redirect_limit: usize,
    pub disable_keepalive: bool,
    pub insecure: bool,
    #[cfg(unix)]
    pub unix_socket: Option<std::path::PathBuf>,
}

struct ClientStateHttp1 {
    rng: StdRng,
    send_request: Option<SendRequestHttp1>,
}

impl Default for ClientStateHttp1 {
    fn default() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            send_request: None,
        }
    }
}

struct ClientStateHttp2 {
    rng: StdRng,
    send_request: SendRequestHttp2,
}

impl ClientStateHttp2 {
    fn new(send_request: SendRequestHttp2) -> Self {
        Self {
            rng: StdRng::from_entropy(),
            send_request,
        }
    }
}

impl Clone for ClientStateHttp2 {
    fn clone(&self) -> Self {
        Self {
            rng: StdRng::from_entropy(),
            send_request: self.send_request.clone(),
        }
    }
}

pub enum QueryLimit {
    Qps(usize),
    Burst(std::time::Duration, usize),
}

trait Io: Read + Write + Unpin + Send {}
type IoBox = Box<dyn Io>;

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for TokioIo<T> {}

impl Client {
    fn is_http2(&self) -> bool {
        self.http_version == http::Version::HTTP_2
    }

    #[cfg(unix)]
    async fn client(&self, addr: (std::net::IpAddr, u16), url: &Url) -> Result<IoBox, ClientError> {
        if url.scheme() == "https" {
            self.tls_client(addr, url).await
        } else if let Some(socket_path) = &self.unix_socket {
            let stream = tokio::net::UnixStream::connect(socket_path).await?;
            let io = TokioIo::new(stream);
            Ok(Box::new(io))
        } else {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            // stream.set_keepalive(std::time::Duration::from_secs(1).into())?;
            let io = TokioIo::new(stream);
            Ok(Box::new(io))
        }
    }

    #[cfg(not(unix))]
    async fn client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &Url,
    ) -> Result<hyper::client::conn::SendRequest<hyper::Body>, ClientError> {
        if url.scheme() == "https" {
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
        url: &Url,
    ) -> Result<IoBox, ClientError> {
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
            .connect(url.host_str().ok_or(ClientError::HostNotFound)?, stream)
            .await?;

        let io = TokioIo::new(stream);
        Ok(Box::new(io))
    }

    #[cfg(feature = "rustls")]
    async fn tls_client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &Url,
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
        let domain =
            rustls::ServerName::try_from(url.host_str().ok_or(ClientError::HostNotFound)?)?;
        let stream = connector.connect(domain, stream).await?;

        let (send, conn) = hyper::client::conn::handshake(stream).await?;
        tokio::spawn(conn);
        Ok(send)
    }

    fn request(&self, url: &Url) -> Result<http::Request<Full<&'static [u8]>>, ClientError> {
        let mut builder = http::Request::builder()
            .uri(if self.is_http2() {
                &url[..]
            } else {
                &url[url::Position::BeforePath..]
            })
            .method(self.method.clone())
            .version(self.http_version);

        *builder
            .headers_mut()
            .ok_or(ClientError::GetHeaderFromBuilderError)? = self.headers.clone();

        if let Some(body) = self.body {
            Ok(builder.body(Full::new(body))?)
        } else {
            Ok(builder.body(Full::default())?)
        }
    }

    async fn work_http1(
        &self,
        client_state: &mut ClientStateHttp1,
    ) -> Result<RequestResult, ClientError> {
        let timeout = if let Some(timeout) = self.timeout {
            tokio::time::sleep(timeout).boxed()
        } else {
            std::future::pending().boxed()
        };

        let do_req = async {
            let url = self.url_generator.generate(&mut client_state.rng)?;
            let mut start = std::time::Instant::now();
            let mut connection_time: Option<ConnectionTime> = None;

            let mut send_request = if let Some(send_request) = client_state.send_request.take() {
                send_request
            } else {
                let addr = self.dns.lookup(&url, &mut client_state.rng).await?;
                let dns_lookup = std::time::Instant::now();
                let io = self.client(addr, &url).await?;
                let dialup = std::time::Instant::now();

                connection_time = Some(ConnectionTime { dns_lookup, dialup });
                let (send_request, conn) = hyper::client::conn::http1::handshake(io).await?;
                tokio::spawn(conn);
                send_request
            };
            while futures::future::poll_fn(|ctx| send_request.poll_ready(ctx))
                .await
                .is_err()
            {
                start = std::time::Instant::now();
                let addr = self.dns.lookup(&url, &mut client_state.rng).await?;
                let dns_lookup = std::time::Instant::now();
                let io = self.client(addr, &url).await?;
                let (sr, conn) = hyper::client::conn::http1::handshake(io).await?;
                tokio::spawn(conn);
                send_request = sr;
                let dialup = std::time::Instant::now();
                connection_time = Some(ConnectionTime { dns_lookup, dialup });
            }
            let request = self.request(&url)?;
            match send_request.send_request(request).await {
                Ok(res) => {
                    let (parts, mut stream) = res.into_parts();
                    let status = parts.status;

                    let mut len_sum = 0;
                    while let Some(chunk) = futures::future::poll_fn(|cx| {
                        Incoming::poll_frame(Pin::new(&mut stream), cx)
                    })
                    .await
                    {
                        len_sum += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
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
                        client_state.send_request = Some(send_request);
                    }

                    Ok::<_, ClientError>(result)
                }
                Err(e) => {
                    client_state.send_request = Some(send_request);
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
    async fn connect_http2<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
    ) -> Result<(ConnectionTime, SendRequestHttp2), ClientError> {
        let addr = self.dns.lookup(url, rng).await?;
        let dns_lookup = std::time::Instant::now();
        let io = self.client(addr, url).await?;
        let (send_request, conn) = hyper::client::conn::http2::handshake(TokioExecutor, io).await?;
        tokio::spawn(conn);
        let dialup = std::time::Instant::now();
        Ok((ConnectionTime { dns_lookup, dialup }, send_request))
    }

    async fn work_http2(
        &self,
        client_state: &mut ClientStateHttp2,
    ) -> Result<RequestResult, ClientError> {
        let timeout = if let Some(timeout) = self.timeout {
            tokio::time::sleep(timeout).boxed()
        } else {
            std::future::pending().boxed()
        };

        let do_req = async {
            let url = self.url_generator.generate(&mut client_state.rng)?;
            let start = std::time::Instant::now();
            let connection_time: Option<ConnectionTime> = None;

            let request = self.request(&url)?;
            match client_state.send_request.send_request(request).await {
                Ok(res) => {
                    let (parts, mut stream) = res.into_parts();
                    let status = parts.status;

                    let mut len_sum = 0;
                    while let Some(chunk) = futures::future::poll_fn(|cx| {
                        Incoming::poll_frame(Pin::new(&mut stream), cx)
                    })
                    .await
                    {
                        len_sum += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
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

                    Ok::<_, ClientError>(result)
                }
                Err(e) => Err(e.into()),
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
    client: Client,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    n_tasks: usize,
    n_workers: usize,
    n_http2_parallel: usize,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));

    let client = Arc::new(client);

    let futures = if client.is_http2() {
        (0..n_workers)
            .map(|_| {
                let report_tx = report_tx.clone();
                let counter = counter.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    let mut rng = StdRng::from_entropy();
                    let url = client.url_generator.generate(&mut rng).unwrap();
                    let (connection_time, send_request) =
                        client.connect_http2(&url, &mut rng).await.unwrap();

                    let client_state = ClientStateHttp2::new(send_request);

                    let futures = (0..n_http2_parallel)
                        .map(|_| {
                            let report_tx = report_tx.clone();
                            let counter = counter.clone();
                            let client = client.clone();
                            let mut client_state = client_state.clone();
                            tokio::spawn(async move {
                                while counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                                    let mut res = client.work_http2(&mut client_state).await;
                                    let is_cancel = is_too_many_open_files(&res);
                                    if let Ok(ref mut res) = res {
                                        res.connection_time = Some(connection_time);
                                    }
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
                })
            })
            .collect::<Vec<_>>()
    } else {
        (0..n_workers)
            .map(|_| {
                let report_tx = report_tx.clone();
                let counter = counter.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    let mut client_state = ClientStateHttp1::default();
                    while counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                        let res = client.work_http1(&mut client_state).await;
                        let is_cancel = is_too_many_open_files(&res);
                        report_tx.send_async(res).await.unwrap();
                        if is_cancel {
                            break;
                        }
                    }
                })
            })
            .collect::<Vec<_>>()
    };

    for f in futures {
        let _ = f.await;
    }
}

/// n tasks by m workers limit to qps works in a second
pub async fn work_with_qps(
    client: Client,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    n_tasks: usize,
    n_workers: usize,
) {
    let (tx, rx) = flume::unbounded();

    match query_limit {
        QueryLimit::Qps(qps) => {
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
        }
        QueryLimit::Burst(duration, rate) => {
            tokio::spawn(async move {
                let mut n = 0;
                // Handle via rate till n_tasks out of bound
                while n + rate < n_tasks {
                    tokio::time::sleep(duration).await;
                    for _ in 0..rate {
                        tx.send_async(()).await.unwrap();
                    }
                    n += rate;
                }
                // Handle the remaining tasks
                if n_tasks > n {
                    tokio::time::sleep(duration).await;
                    for _ in 0..n_tasks - n {
                        tx.send_async(()).await.unwrap();
                    }
                }
                // tx gone
            });
        }
    }

    let client = Arc::new(client);

    let futures = (0..n_workers)
        .map(|_| {
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            let client = client.clone();
            tokio::spawn(async move {
                let mut client_state = ClientStateHttp1::default();
                while let Ok(()) = rx.recv_async().await {
                    let res = client.work_http1(&mut client_state).await;
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
    client: Client,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    n_tasks: usize,
    n_workers: usize,
) {
    let (tx, rx) = flume::unbounded();

    match query_limit {
        QueryLimit::Qps(qps) => {
            tokio::spawn(async move {
                let start = std::time::Instant::now();
                for i in 0..n_tasks {
                    tokio::time::sleep_until(
                        (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
                    )
                    .await;
                    tx.send_async(std::time::Instant::now()).await.unwrap();
                }
                // tx gone
            });
        }
        QueryLimit::Burst(duration, rate) => {
            tokio::spawn(async move {
                let mut n = 0;
                // Handle via rate till n_tasks out of bound
                while n + rate < n_tasks {
                    tokio::time::sleep(duration).await;
                    let now = std::time::Instant::now();
                    for _ in 0..rate {
                        tx.send_async(now).await.unwrap();
                    }
                    n += rate;
                }
                // Handle the remaining tasks
                if n_tasks > n {
                    tokio::time::sleep(duration).await;
                    let now = std::time::Instant::now();
                    for _ in 0..n_tasks - n {
                        tx.send_async(now).await.unwrap();
                    }
                }
                // tx gone
            });
        }
    }

    let client = Arc::new(client);

    let futures = (0..n_workers)
        .map(|_| {
            let client = client.clone();
            let mut client_state = ClientStateHttp1::default();
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(start) = rx.recv_async().await {
                    let mut res = client.work_http1(&mut client_state).await;

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
    client: Client,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    dead_line: std::time::Instant,
    n_workers: usize,
) {
    let client = Arc::new(client);
    let futures = (0..n_workers)
        .map(|_| {
            let client = client.clone();
            let report_tx = report_tx.clone();
            let mut client_state = ClientStateHttp1::default();
            tokio::spawn(async move {
                loop {
                    let res = client.work_http1(&mut client_state).await;
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
    client: Client,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_workers: usize,
) {
    let rx = match query_limit {
        QueryLimit::Qps(qps) => {
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
            rx
        }
        QueryLimit::Burst(duration, rate) => {
            let (tx, rx) = flume::unbounded();
            tokio::spawn(async move {
                // Handle via rate till deadline is reached
                for _ in 0.. {
                    if std::time::Instant::now() > dead_line {
                        break;
                    }

                    tokio::time::sleep(duration).await;
                    for _ in 0..rate {
                        tx.send_async(()).await.unwrap();
                    }
                }
                // tx gone
            });
            rx
        }
    };

    let client = Arc::new(client);

    let futures = (0..n_workers)
        .map(|_| {
            let client = client.clone();
            let mut client_state = ClientStateHttp1::default();
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(()) = rx.recv_async().await {
                    let res = client.work_http1(&mut client_state).await;
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
    client: Client,
    report_tx: flume::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_workers: usize,
) {
    let (tx, rx) = flume::unbounded();
    match query_limit {
        QueryLimit::Qps(qps) => {
            tokio::spawn(async move {
                for i in 0.. {
                    tokio::time::sleep_until(
                        (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
                    )
                    .await;
                    let now = std::time::Instant::now();
                    if now > dead_line {
                        break;
                    }
                    if tx.send_async(now).await.is_err() {
                        break;
                    }
                }
                // tx gone
            });
        }
        QueryLimit::Burst(duration, rate) => {
            tokio::spawn(async move {
                // Handle via rate till deadline is reached
                loop {
                    tokio::time::sleep(duration).await;
                    let now = std::time::Instant::now();
                    if now > dead_line {
                        break;
                    }

                    for _ in 0..rate {
                        tx.send_async(now).await.unwrap();
                    }
                }
                // tx gone
            });
        }
    };

    let client = Arc::new(client);

    let futures = (0..n_workers)
        .map(|_| {
            let client = client.clone();
            let mut client_state = ClientStateHttp1::default();
            let report_tx = report_tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                while let Ok(start) = rx.recv_async().await {
                    let mut res = client.work_http1(&mut client_state).await;

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
