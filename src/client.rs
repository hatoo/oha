use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, http};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::prelude::*;
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    time::Instant,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use url::{ParseError, Url};

use crate::{
    ConnectToEntry,
    pcg64si::Pcg64Si,
    request_generator::{RequestGenerationError, RequestGenerator},
    url_generator::UrlGeneratorError,
};

#[cfg(feature = "http3")]
use crate::client_h3::send_debug_request_http3;

type SendRequestHttp1 = hyper::client::conn::http1::SendRequest<Full<Bytes>>;
type SendRequestHttp2 = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

#[derive(Debug, Clone, Copy)]
pub struct ConnectionTime {
    pub dns_lookup: std::time::Instant,
    pub dialup: std::time::Instant,
}

#[derive(Debug, Clone)]
/// a result for a request
pub struct RequestResult {
    pub rng: Pcg64Si,
    // When the query should started
    pub start_latency_correction: Option<std::time::Instant>,
    /// When the query started
    pub start: std::time::Instant,
    /// DNS + dialup
    /// None when reuse connection
    pub connection_time: Option<ConnectionTime>,
    /// First body byte received
    pub first_byte: Option<std::time::Instant>,
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

// encapsulates the HTTP generation of the work type. Used internally only for conditional logic.
#[derive(Debug, Clone, Copy, PartialEq)]
enum HttpWorkType {
    H1,
    H2,
    #[cfg(feature = "http3")]
    H3,
}

pub struct Dns {
    pub connect_to: Vec<ConnectToEntry>,
    pub resolver:
        hickory_resolver::Resolver<hickory_resolver::name_server::TokioConnectionProvider>,
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

        // Try to find an override (passed via `--connect-to`) that applies to this (host, port),
        // choosing one randomly if several match.
        let (host, port) = if let Some(entry) = self
            .connect_to
            .iter()
            .filter(|entry| entry.requested_port == port && entry.requested_host == host)
            .collect::<Vec<_>>()
            .choose(rng)
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
    #[error("Redirection limit has reached")]
    TooManyRedirect,
    #[error(transparent)]
    // Use Box here because ResolveError is big.
    Resolve(#[from] Box<hickory_resolver::ResolveError>),

    #[cfg(feature = "native-tls")]
    #[error(transparent)]
    NativeTls(#[from] native_tls::Error),

    #[cfg(feature = "rustls")]
    #[error(transparent)]
    Rustls(#[from] rustls::Error),

    #[cfg(feature = "rustls")]
    #[error(transparent)]
    InvalidDnsName(#[from] rustls_pki_types::InvalidDnsNameError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Http(#[from] http::Error),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    InvalidUriParts(#[from] http::uri::InvalidUriParts),
    #[error(transparent)]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),
    #[error("Failed to get header from builder")]
    GetHeaderFromBuilder,
    #[error(transparent)]
    HeaderToStr(#[from] http::header::ToStrError),
    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri),
    #[error("timeout")]
    Timeout,
    #[error("aborted due to deadline")]
    Deadline,
    #[error(transparent)]
    UrlGenerator(#[from] UrlGeneratorError),
    #[error(transparent)]
    UrlParse(#[from] ParseError),
    #[error("Request generation error: {0}")]
    RequestGeneration(#[from] RequestGenerationError),
    #[cfg(feature = "http3")]
    #[error(transparent)]
    Http3(#[from] crate::client_h3::Http3Error),
}

pub struct Client {
    pub request_generator: RequestGenerator,
    pub url: Url,
    pub http_version: http::Version,
    pub proxy_http_version: http::Version,
    pub proxy_headers: http::header::HeaderMap,
    pub dns: Dns,
    pub timeout: Option<std::time::Duration>,
    pub redirect_limit: usize,
    pub disable_keepalive: bool,
    pub proxy_url: Option<Url>,
    #[cfg(unix)]
    pub unix_socket: Option<std::path::PathBuf>,
    #[cfg(feature = "vsock")]
    pub vsock_addr: Option<tokio_vsock::VsockAddr>,
    #[cfg(feature = "rustls")]
    pub rustls_configs: crate::tls_config::RuslsConfigs,
    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    pub native_tls_connectors: crate::tls_config::NativeTlsConnectors,
}

#[cfg(test)]
impl Default for Client {
    fn default() -> Self {
        Self {
            request_generator: RequestGenerator {
                url_generator: UrlGenerator::new_static("http://example.com".parse().unwrap()),
                http_proxy: None,
                method: http::Method::GET,
                version: http::Version::HTTP_11,
                headers: http::header::HeaderMap::new(),
                body: Bytes::new(),
                aws_config: None,
            },
            url: "http://example.com".parse().unwrap(),
            http_version: http::Version::HTTP_11,
            proxy_http_version: http::Version::HTTP_11,
            proxy_headers: http::header::HeaderMap::new(),
            dns: Dns {
                resolver: hickory_resolver::Resolver::builder_tokio().unwrap().build(),
                connect_to: Vec::new(),
            },
            timeout: None,
            redirect_limit: 0,
            disable_keepalive: false,
            proxy_url: None,
            #[cfg(unix)]
            unix_socket: None,
            #[cfg(feature = "vsock")]
            vsock_addr: None,
            #[cfg(feature = "rustls")]
            rustls_configs: crate::tls_config::RuslsConfigs::new(false, None, None),
            #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
            native_tls_connectors: crate::tls_config::NativeTlsConnectors::new(false, None, None),
        }
    }
}

struct ClientStateHttp1 {
    rng: Pcg64Si,
    send_request: Option<SendRequestHttp1>,
}

impl Default for ClientStateHttp1 {
    fn default() -> Self {
        Self {
            rng: SeedableRng::from_os_rng(),
            send_request: None,
        }
    }
}

struct ClientStateHttp2 {
    rng: Pcg64Si,
    send_request: SendRequestHttp2,
}

pub enum QueryLimit {
    Qps(f64),
    Burst(std::time::Duration, usize),
}

// To avoid dynamic dispatch
// I'm not sure how much this is effective
pub(crate) enum Stream {
    Tcp(TcpStream),
    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    Tls(tokio_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls")]
    // Box for large variant
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(feature = "vsock")]
    Vsock(tokio_vsock::VsockStream),
    #[cfg(feature = "http3")]
    Quic(quinn::Connection),
}

impl Stream {
    async fn handshake_http1(self, with_upgrade: bool) -> Result<SendRequestHttp1, ClientError> {
        match self {
            Stream::Tcp(stream) => {
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                if with_upgrade {
                    tokio::spawn(conn.with_upgrades());
                } else {
                    tokio::spawn(conn);
                }
                Ok(send_request)
            }
            Stream::Tls(stream) => {
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                if with_upgrade {
                    tokio::spawn(conn.with_upgrades());
                } else {
                    tokio::spawn(conn);
                }
                Ok(send_request)
            }
            #[cfg(unix)]
            Stream::Unix(stream) => {
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                if with_upgrade {
                    tokio::spawn(conn.with_upgrades());
                } else {
                    tokio::spawn(conn);
                }
                Ok(send_request)
            }
            #[cfg(feature = "vsock")]
            Stream::Vsock(stream) => {
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                if with_upgrade {
                    tokio::spawn(conn.with_upgrades());
                } else {
                    tokio::spawn(conn);
                }
                Ok(send_request)
            }
            #[cfg(feature = "http3")]
            Stream::Quic(_) => {
                panic!("quic is not supported in http1")
            }
        }
    }
    async fn handshake_http2(self) -> Result<SendRequestHttp2, ClientError> {
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder
            // from nghttp2's default
            .initial_stream_window_size((1 << 30) - 1)
            .initial_connection_window_size((1 << 30) - 1);

        match self {
            Stream::Tcp(stream) => {
                let (send_request, conn) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            Stream::Tls(stream) => {
                let (send_request, conn) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            #[cfg(unix)]
            Stream::Unix(stream) => {
                let (send_request, conn) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            #[cfg(feature = "vsock")]
            Stream::Vsock(stream) => {
                let (send_request, conn) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            #[cfg(feature = "http3")]
            Stream::Quic(_) => {
                panic!("quic is not supported in http2")
            }
        }
    }
}

impl Client {
    #[inline]
    fn is_http2(&self) -> bool {
        self.http_version == http::Version::HTTP_2
    }

    #[inline]
    pub fn is_http1(&self) -> bool {
        self.http_version <= http::Version::HTTP_11
    }

    #[inline]
    fn is_proxy_http2(&self) -> bool {
        self.proxy_http_version == http::Version::HTTP_2
    }

    fn is_work_http2(&self) -> bool {
        if self.proxy_url.is_some() {
            if self.url.scheme() == "https" {
                self.is_http2()
            } else {
                self.is_proxy_http2()
            }
        } else {
            self.is_http2()
        }
    }

    fn work_type(&self) -> HttpWorkType {
        #[cfg(feature = "http3")]
        if self.http_version == http::Version::HTTP_3 {
            return HttpWorkType::H3;
        }
        if self.is_work_http2() {
            HttpWorkType::H2
        } else {
            HttpWorkType::H1
        }
    }

    /// Perform a DNS lookup to cache it
    /// This is useful to avoid DNS lookup latency at the first concurrent requests
    pub async fn pre_lookup(&self) -> Result<(), ClientError> {
        // If the client is using a unix socket, we don't need to do a DNS lookup
        #[cfg(unix)]
        if self.unix_socket.is_some() {
            return Ok(());
        }
        // If the client is using a vsock address, we don't need to do a DNS lookup
        #[cfg(feature = "vsock")]
        if self.vsock_addr.is_some() {
            return Ok(());
        }

        let mut rng = StdRng::from_os_rng();
        // It automatically caches the result
        self.dns.lookup(&self.url, &mut rng).await?;
        Ok(())
    }

    pub fn generate_request(
        &self,
        rng: &mut Pcg64Si,
    ) -> Result<(Request<Full<Bytes>>, Pcg64Si), ClientError> {
        let snapshot = *rng;
        let req = self.request_generator.generate(rng)?;
        Ok((req, snapshot))
    }

    /**
     * Returns a stream of the underlying transport. NOT a HTTP client
     */
    pub(crate) async fn client<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
        http_version: http::Version,
    ) -> Result<(Instant, Stream), ClientError> {
        // TODO: Allow the connect timeout to be configured
        let timeout_duration = tokio::time::Duration::from_secs(5);

        #[cfg(feature = "http3")]
        if http_version == http::Version::HTTP_3 {
            let addr = self.dns.lookup(url, rng).await?;
            let dns_lookup = Instant::now();
            let stream = tokio::time::timeout(timeout_duration, self.quic_client(addr, url)).await;
            return match stream {
                Ok(Ok(stream)) => Ok((dns_lookup, stream)),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(ClientError::Timeout),
            };
        }
        if url.scheme() == "https" {
            let addr = self.dns.lookup(url, rng).await?;
            let dns_lookup = Instant::now();
            // If we do not put a timeout here then the connections attempts will
            // linger long past the configured timeout
            let stream =
                tokio::time::timeout(timeout_duration, self.tls_client(addr, url, http_version))
                    .await;
            return match stream {
                Ok(Ok(stream)) => Ok((dns_lookup, stream)),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(ClientError::Timeout),
            };
        }
        #[cfg(unix)]
        if let Some(socket_path) = &self.unix_socket {
            let dns_lookup = Instant::now();
            let stream = tokio::time::timeout(
                timeout_duration,
                tokio::net::UnixStream::connect(socket_path),
            )
            .await;
            return match stream {
                Ok(Ok(stream)) => Ok((dns_lookup, Stream::Unix(stream))),
                Ok(Err(err)) => Err(ClientError::Io(err)),
                Err(_) => Err(ClientError::Timeout),
            };
        }
        #[cfg(feature = "vsock")]
        if let Some(addr) = self.vsock_addr {
            let dns_lookup = Instant::now();
            let stream =
                tokio::time::timeout(timeout_duration, tokio_vsock::VsockStream::connect(addr))
                    .await;
            return match stream {
                Ok(Ok(stream)) => Ok((dns_lookup, Stream::Vsock(stream))),
                Ok(Err(err)) => Err(ClientError::Io(err)),
                Err(_) => Err(ClientError::Timeout),
            };
        }
        // HTTP
        let addr = self.dns.lookup(url, rng).await?;
        let dns_lookup = Instant::now();
        let stream =
            tokio::time::timeout(timeout_duration, tokio::net::TcpStream::connect(addr)).await;
        match stream {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                Ok((dns_lookup, Stream::Tcp(stream)))
            }
            Ok(Err(err)) => Err(ClientError::Io(err)),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    async fn tls_client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &Url,
        http_version: http::Version,
    ) -> Result<Stream, ClientError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        let stream = self.connect_tls(stream, url, http_version).await?;

        Ok(Stream::Tls(stream))
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    async fn connect_tls<S>(
        &self,
        stream: S,
        url: &Url,
        http_version: http::Version,
    ) -> Result<tokio_native_tls::TlsStream<S>, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let connector = self
            .native_tls_connectors
            .connector(http_version >= http::Version::HTTP_2);
        let stream = connector
            .connect(url.host_str().ok_or(ClientError::HostNotFound)?, stream)
            .await?;

        Ok(stream)
    }

    #[cfg(feature = "rustls")]
    async fn connect_tls<S>(
        &self,
        stream: S,
        url: &Url,
        http_version: http::Version,
    ) -> Result<Box<tokio_rustls::client::TlsStream<S>>, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let connector =
            tokio_rustls::TlsConnector::from(self.rustls_configs.config(http_version).clone());
        let domain = rustls_pki_types::ServerName::try_from(
            url.host_str().ok_or(ClientError::HostNotFound)?,
        )?;
        let stream = connector.connect(domain.to_owned(), stream).await?;

        Ok(Box::new(stream))
    }

    async fn client_http1<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
    ) -> Result<(Instant, SendRequestHttp1), ClientError> {
        if let Some(proxy_url) = &self.proxy_url {
            let http_proxy_version = if self.is_proxy_http2() {
                http::Version::HTTP_2
            } else {
                http::Version::HTTP_11
            };
            let (dns_lookup, stream) = self.client(proxy_url, rng, http_proxy_version).await?;
            if url.scheme() == "https" {
                // Do CONNECT request to proxy
                let req = {
                    let mut builder =
                        http::Request::builder()
                            .method(Method::CONNECT)
                            .uri(format!(
                                "{}:{}",
                                url.host_str().unwrap(),
                                url.port_or_known_default().unwrap()
                            ));
                    *builder
                        .headers_mut()
                        .ok_or(ClientError::GetHeaderFromBuilder)? = self.proxy_headers.clone();
                    builder.body(http_body_util::Full::default())?
                };
                let res = if self.proxy_http_version == http::Version::HTTP_2 {
                    let mut send_request = stream.handshake_http2().await?;
                    send_request.send_request(req).await?
                } else {
                    let mut send_request = stream.handshake_http1(true).await?;
                    send_request.send_request(req).await?
                };
                let stream = hyper::upgrade::on(res).await?;
                let stream = self
                    .connect_tls(TokioIo::new(stream), url, self.http_version)
                    .await?;
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok((dns_lookup, send_request))
            } else {
                // Send full URL in request() for HTTP proxy
                Ok((dns_lookup, stream.handshake_http1(false).await?))
            }
        } else {
            let (dns_lookup, stream) = self.client(url, rng, http::Version::HTTP_11).await?;
            Ok((dns_lookup, stream.handshake_http1(false).await?))
        }
    }

    /*
    #[inline]
    pub(crate) fn request(&self, url: &Url) -> Result<http::Request<Full<Bytes>>, ClientError> {
        let use_proxy = self.proxy_url.is_some() && url.scheme() == "http";

        let mut builder = http::Request::builder()
            .uri(if !(self.is_http1()) || use_proxy {
                &url[..]
            } else {
                &url[url::Position::BeforePath..]
            })
            .method(self.method.clone())
            .version(if use_proxy {
                self.proxy_http_version
            } else {
                self.http_version
            });

        let bytes = self.body.map(Bytes::from_static);

        let body = if let Some(body) = &bytes {
            Full::new(body.clone())
        } else {
            Full::default()
        };

        let mut headers = self.headers.clone();

        // Apply AWS SigV4 if configured
        if let Some(aws_config) = &self.aws_config {
            aws_config.sign_request(self.method.as_str(), &mut headers, url, bytes)?
        }

        if use_proxy {
            for (key, value) in self.proxy_headers.iter() {
                headers.insert(key, value.clone());
            }
        }

        *builder
            .headers_mut()
            .ok_or(ClientError::GetHeaderFromBuilder)? = headers;

        let request = builder.body(body)?;

        Ok(request)
    }
    */

    async fn work_http1(
        &self,
        client_state: &mut ClientStateHttp1,
    ) -> Result<RequestResult, ClientError> {
        let do_req = async {
            let (request, rng) = self.generate_request(&mut client_state.rng)?;
            let mut start = std::time::Instant::now();
            let mut first_byte: Option<std::time::Instant> = None;
            let mut connection_time: Option<ConnectionTime> = None;

            let mut send_request = if let Some(send_request) = client_state.send_request.take() {
                send_request
            } else {
                let (dns_lookup, send_request) =
                    self.client_http1(&self.url, &mut client_state.rng).await?;
                let dialup = std::time::Instant::now();

                connection_time = Some(ConnectionTime { dns_lookup, dialup });
                send_request
            };
            while send_request.ready().await.is_err() {
                // This gets hit when the connection for HTTP/1.1 faults
                // This re-connects
                start = std::time::Instant::now();
                let (dns_lookup, send_request_) =
                    self.client_http1(&self.url, &mut client_state.rng).await?;
                send_request = send_request_;
                let dialup = std::time::Instant::now();
                connection_time = Some(ConnectionTime { dns_lookup, dialup });
            }
            match send_request.send_request(request).await {
                Ok(res) => {
                    let (parts, mut stream) = res.into_parts();
                    let status = parts.status;

                    let mut len_bytes = 0;
                    while let Some(chunk) = stream.frame().await {
                        if first_byte.is_none() {
                            first_byte = Some(std::time::Instant::now())
                        }
                        len_bytes += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
                    }

                    /*
                    if self.redirect_limit != 0 {
                        if let Some(location) = parts.headers.get("Location") {
                            let (send_request_redirect, new_status, len) = self
                                .redirect(
                                    send_request,
                                    &self.url,
                                    location,
                                    self.redirect_limit,
                                    &mut client_state.rng,
                                )
                                .await?;

                            send_request = send_request_redirect;
                            status = new_status;
                            len_bytes = len;
                        }
                    }
                    */

                    let end = std::time::Instant::now();

                    let result = RequestResult {
                        rng,
                        start_latency_correction: None,
                        start,
                        first_byte,
                        end,
                        status,
                        len_bytes,
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

        if let Some(timeout) = self.timeout {
            tokio::select! {
                res = do_req => {
                    res
                }
                _ = tokio::time::sleep(timeout) => {
                    Err(ClientError::Timeout)
                }
            }
        } else {
            do_req.await
        }
    }

    async fn connect_http2<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
    ) -> Result<(ConnectionTime, SendRequestHttp2), ClientError> {
        if let Some(proxy_url) = &self.proxy_url {
            let http_proxy_version = if self.is_proxy_http2() {
                http::Version::HTTP_2
            } else {
                http::Version::HTTP_11
            };
            let (dns_lookup, stream) = self.client(proxy_url, rng, http_proxy_version).await?;
            if url.scheme() == "https" {
                let req = {
                    let mut builder =
                        http::Request::builder()
                            .method(Method::CONNECT)
                            .uri(format!(
                                "{}:{}",
                                url.host_str().unwrap(),
                                url.port_or_known_default().unwrap()
                            ));
                    *builder
                        .headers_mut()
                        .ok_or(ClientError::GetHeaderFromBuilder)? = self.proxy_headers.clone();
                    builder.body(http_body_util::Full::default())?
                };
                let res = if self.proxy_http_version == http::Version::HTTP_2 {
                    let mut send_request = stream.handshake_http2().await?;
                    send_request.send_request(req).await?
                } else {
                    let mut send_request = stream.handshake_http1(true).await?;
                    send_request.send_request(req).await?
                };
                let stream = hyper::upgrade::on(res).await?;
                let stream = self
                    .connect_tls(TokioIo::new(stream), url, http::Version::HTTP_2)
                    .await?;
                let (send_request, conn) =
                    hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                        // from nghttp2's default
                        .initial_stream_window_size((1 << 30) - 1)
                        .initial_connection_window_size((1 << 30) - 1)
                        .handshake(TokioIo::new(stream))
                        .await?;
                tokio::spawn(conn);
                let dialup = std::time::Instant::now();

                Ok((ConnectionTime { dns_lookup, dialup }, send_request))
            } else {
                let send_request = stream.handshake_http2().await?;
                let dialup = std::time::Instant::now();
                Ok((ConnectionTime { dns_lookup, dialup }, send_request))
            }
        } else {
            let (dns_lookup, stream) = self.client(url, rng, self.http_version).await?;
            let send_request = stream.handshake_http2().await?;
            let dialup = std::time::Instant::now();
            Ok((ConnectionTime { dns_lookup, dialup }, send_request))
        }
    }

    async fn work_http2(
        &self,
        client_state: &mut ClientStateHttp2,
    ) -> Result<RequestResult, ClientError> {
        let do_req = async {
            let (request, rng) = self.generate_request(&mut client_state.rng)?;
            let start = std::time::Instant::now();
            let mut first_byte: Option<std::time::Instant> = None;
            let connection_time: Option<ConnectionTime> = None;

            match client_state.send_request.send_request(request).await {
                Ok(res) => {
                    let (parts, mut stream) = res.into_parts();
                    let status = parts.status;

                    let mut len_bytes = 0;
                    while let Some(chunk) = stream.frame().await {
                        if first_byte.is_none() {
                            first_byte = Some(std::time::Instant::now())
                        }
                        len_bytes += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
                    }

                    let end = std::time::Instant::now();

                    let result = RequestResult {
                        rng,
                        start_latency_correction: None,
                        start,
                        first_byte,
                        end,
                        status,
                        len_bytes,
                        connection_time,
                    };

                    Ok::<_, ClientError>(result)
                }
                Err(e) => Err(e.into()),
            }
        };

        if let Some(timeout) = self.timeout {
            tokio::select! {
                res = do_req => {
                    res
                }
                _ = tokio::time::sleep(timeout) => {
                    Err(ClientError::Timeout)
                }
            }
        } else {
            do_req.await
        }
    }

    /*
    #[allow(clippy::type_complexity)]
    async fn redirect<R: Rng + Send>(
        &self,
        send_request: SendRequestHttp1,
        base_url: &Url,
        location: &http::header::HeaderValue,
        limit: usize,
        rng: &mut R,
    ) -> Result<(SendRequestHttp1, http::StatusCode, usize), ClientError> {
        if limit == 0 {
            return Err(ClientError::TooManyRedirect);
        }
        let url = match Url::parse(location.to_str()?) {
            Ok(url) => url,
            Err(ParseError::RelativeUrlWithoutBase) => Url::options()
                .base_url(Some(base_url))
                .parse(location.to_str()?)?,
            Err(err) => Err(err)?,
        };

        let (mut send_request, send_request_base) =
            if base_url.authority() == url.authority() && !self.disable_keepalive {
                // reuse connection
                (send_request, None)
            } else {
                let (_dns_lookup, stream) = self.client_http1(&url, rng).await?;
                (stream, Some(send_request))
            };

        while send_request.ready().await.is_err() {
            let (_dns_lookup, stream) = self.client_http1(&url, rng).await?;
            send_request = stream;
        }

        let mut request = self.request(&url)?;
        if url.authority() != base_url.authority() {
            request.headers_mut().insert(
                http::header::HOST,
                http::HeaderValue::from_str(url.authority())?,
            );
        }
        let res = send_request.send_request(request).await?;
        let (parts, mut stream) = res.into_parts();
        let mut status = parts.status;

        let mut len_bytes = 0;
        while let Some(chunk) = stream.frame().await {
            len_bytes += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
        }

        if let Some(location) = parts.headers.get("Location") {
            let (send_request_redirect, new_status, len) =
                Box::pin(self.redirect(send_request, &url, location, limit - 1, rng)).await?;
            send_request = send_request_redirect;
            status = new_status;
            len_bytes = len;
        }

        if let Some(send_request_base) = send_request_base {
            Ok((send_request_base, status, len_bytes))
        } else {
            Ok((send_request, status, len_bytes))
        }
    }
    */
}

/// Check error and decide whether to cancel the connection
pub(crate) fn is_cancel_error(res: &Result<RequestResult, ClientError>) -> bool {
    matches!(res, Err(ClientError::Deadline)) || is_too_many_open_files(res)
}

/// Check error was "Too many open file"
fn is_too_many_open_files(res: &Result<RequestResult, ClientError>) -> bool {
    res.as_ref()
        .err()
        .map(|err| match err {
            ClientError::Io(io_error) => io_error.raw_os_error() == Some(libc::EMFILE),
            _ => false,
        })
        .unwrap_or(false)
}

/// Check error was any Hyper error (primarily for HTTP2 connection errors)
fn is_hyper_error(res: &Result<RequestResult, ClientError>) -> bool {
    res.as_ref()
        .err()
        .map(|err| match err {
            // REVIEW: IoErrors, if indicating the underlying connection has failed,
            // should also cause a stop of HTTP2 requests
            ClientError::Io(_) => true,
            ClientError::Hyper(_) => true,
            _ => false,
        })
        .unwrap_or(false)
}

async fn setup_http2<R: Rng>(
    client: &Client,
    rng: &mut R,
) -> Result<(ConnectionTime, SendRequestHttp2), ClientError> {
    let (connection_time, send_request) = client.connect_http2(&client.url, rng).await?;

    Ok((connection_time, send_request))
}

async fn work_http2_once(
    client: &Client,
    client_state: &mut ClientStateHttp2,
    report_tx: &kanal::Sender<Result<RequestResult, ClientError>>,
    connection_time: ConnectionTime,
    start_latency_correction: Option<Instant>,
) -> (bool, bool) {
    let mut res = client.work_http2(client_state).await;
    let is_cancel = is_cancel_error(&res);
    let is_reconnect = is_hyper_error(&res);
    set_connection_time(&mut res, connection_time);
    if let Some(start_latency_correction) = start_latency_correction {
        set_start_latency_correction(&mut res, start_latency_correction);
    }
    report_tx.send(res).unwrap();
    (is_cancel, is_reconnect)
}

pub(crate) fn set_connection_time<E>(
    res: &mut Result<RequestResult, E>,
    connection_time: ConnectionTime,
) {
    if let Ok(res) = res {
        res.connection_time = Some(connection_time);
    }
}

pub(crate) fn set_start_latency_correction<E>(
    res: &mut Result<RequestResult, E>,
    start_latency_correction: std::time::Instant,
) {
    if let Ok(res) = res {
        res.start_latency_correction = Some(start_latency_correction);
    }
}

pub async fn work_debug<W: Write>(w: &mut W, client: Arc<Client>) -> Result<(), ClientError> {
    let mut rng = Pcg64Si::from_os_rng();
    let (request, _) = client.generate_request(&mut rng)?;

    writeln!(w, "{request:#?}")?;

    let response = match client.work_type() {
        #[cfg(feature = "http3")]
        HttpWorkType::H3 => {
            let (_, (h3_connection, client_state)) = client.connect_http3(&url, &mut rng).await?;

            send_debug_request_http3(h3_connection, client_state, request).await?
        }
        HttpWorkType::H2 => {
            let (_, mut client_state) = client.connect_http2(&client.url, &mut rng).await?;
            let response = client_state.send_request(request).await?;
            let (parts, body) = response.into_parts();
            let body = body.collect().await.unwrap().to_bytes();

            http::Response::from_parts(parts, body)
        }
        HttpWorkType::H1 => {
            let (_dns_lookup, mut send_request) =
                client.client_http1(&client.url, &mut rng).await?;

            let response = send_request.send_request(request).await?;
            let (parts, body) = response.into_parts();
            let body = body.collect().await.unwrap().to_bytes();

            http::Response::from_parts(parts, body)
        }
    };

    writeln!(w, "{response:#?}")?;

    Ok(())
}

/// Run n tasks by m workers
pub async fn work(
    client: Arc<Client>,
    report_tx: kanal::Sender<Result<RequestResult, ClientError>>,
    n_tasks: usize,
    n_connections: usize,
    n_http2_parallel: usize,
) {
    #[cfg(feature = "http3")]
    if matches!(client.work_type(), HttpWorkType::H3) {
        crate::client_h3::work(client, report_tx, n_tasks, n_connections, n_http2_parallel).await;
        return;
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));

    match client.work_type() {
        #[cfg(feature = "http3")]
        HttpWorkType::H3 => unreachable!(),
        HttpWorkType::H2 => {
            let futures = (0..n_connections)
                .map(|_| {
                    let report_tx = report_tx.clone();
                    let counter = counter.clone();
                    let client = client.clone();
                    tokio::spawn(async move {
                        let mut rng: Pcg64Si = SeedableRng::from_os_rng();
                        loop {
                            match setup_http2(&client, &mut rng).await {
                                Ok((connection_time, send_request)) => {
                                    let futures = (0..n_http2_parallel)
                                        .map(|_| {
                                            let report_tx = report_tx.clone();
                                            let counter = counter.clone();
                                            let client = client.clone();

                                            let mut client_state = ClientStateHttp2 {
                                                rng: SeedableRng::from_os_rng(),
                                                send_request: send_request.clone(),
                                            };
                                            tokio::spawn(async move {
                                                while counter.fetch_add(1, Ordering::Relaxed)
                                                    < n_tasks
                                                {
                                                    let (is_cancel, is_reconnect) =
                                                        work_http2_once(
                                                            &client,
                                                            &mut client_state,
                                                            &report_tx,
                                                            connection_time,
                                                            None,
                                                        )
                                                        .await;

                                                    if is_cancel || is_reconnect {
                                                        return is_cancel;
                                                    }
                                                }

                                                true
                                            })
                                        })
                                        .collect::<Vec<_>>();

                                    let mut connection_gone = false;
                                    for f in futures {
                                        match f.await {
                                            Ok(true) => {
                                                // All works done
                                                connection_gone = true;
                                            }
                                            Err(_) => {
                                                // Unexpected
                                                connection_gone = true;
                                            }
                                            _ => {}
                                        }
                                    }

                                    if connection_gone {
                                        return;
                                    }
                                }
                                Err(err) => {
                                    if counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                                        report_tx.send(Err(err)).unwrap();
                                    } else {
                                        return;
                                    }
                                }
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();
            for f in futures {
                let _ = f.await;
            }
        }
        HttpWorkType::H1 => {
            let futures = (0..n_connections)
                .map(|_| {
                    let report_tx = report_tx.clone();
                    let counter = counter.clone();
                    let client = client.clone();
                    tokio::spawn(async move {
                        let mut client_state = ClientStateHttp1::default();
                        while counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                            let res = client.work_http1(&mut client_state).await;
                            let is_cancel = is_cancel_error(&res);
                            report_tx.send(res).unwrap();
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
    };
}

/// n tasks by m workers limit to qps works in a second
pub async fn work_with_qps(
    client: Arc<Client>,
    report_tx: kanal::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    n_tasks: usize,
    n_connections: usize,
    n_http_parallel: usize,
) {
    #[cfg(feature = "http3")]
    if matches!(client.work_type(), HttpWorkType::H3) {
        crate::client_h3::work_with_qps(
            client,
            report_tx,
            query_limit,
            n_tasks,
            n_connections,
            n_http_parallel,
        )
        .await;
        return;
    }

    let (tx, rx) = kanal::unbounded::<()>();

    let work_queue = async move {
        match query_limit {
            QueryLimit::Qps(qps) => {
                let start = std::time::Instant::now();
                for i in 0..n_tasks {
                    tokio::time::sleep_until(
                        (start + std::time::Duration::from_secs_f64(i as f64 * 1f64 / qps)).into(),
                    )
                    .await;
                    tx.send(())?;
                }
            }
            QueryLimit::Burst(duration, rate) => {
                let mut n = 0;
                // Handle via rate till n_tasks out of bound
                while n + rate < n_tasks {
                    tokio::time::sleep(duration).await;
                    for _ in 0..rate {
                        tx.send(())?;
                    }
                    n += rate;
                }
                // Handle the remaining tasks
                if n_tasks > n {
                    tokio::time::sleep(duration).await;
                    for _ in 0..n_tasks - n {
                        tx.send(())?;
                    }
                }
            }
        }
        // tx gone
        drop(tx);
        Ok::<(), kanal::SendError>(())
    };

    let rx = rx.to_async();
    match client.work_type() {
        #[cfg(feature = "http3")]
        HttpWorkType::H3 => unreachable!(),
        HttpWorkType::H2 => {
            let futures = (0..n_connections)
                .map(|_| {
                    let report_tx = report_tx.clone();
                    let rx = rx.clone();
                    let client = client.clone();
                    tokio::spawn(async move {
                        let mut rng: Pcg64Si = SeedableRng::from_os_rng();
                        loop {
                            match setup_http2(&client, &mut rng).await {
                                Ok((connection_time, send_request)) => {
                                    let futures = (0..n_http_parallel)
                                        .map(|_| {
                                            let report_tx = report_tx.clone();
                                            let rx = rx.clone();
                                            let client = client.clone();
                                            let mut client_state = ClientStateHttp2 {
                                                rng: SeedableRng::from_os_rng(),
                                                send_request: send_request.clone(),
                                            };
                                            tokio::spawn(async move {
                                                while let Ok(()) = rx.recv().await {
                                                    let (is_cancel, is_reconnect) =
                                                        work_http2_once(
                                                            &client,
                                                            &mut client_state,
                                                            &report_tx,
                                                            connection_time,
                                                            None,
                                                        )
                                                        .await;

                                                    if is_cancel || is_reconnect {
                                                        return is_cancel;
                                                    }
                                                }
                                                true
                                            })
                                        })
                                        .collect::<Vec<_>>();
                                    let mut connection_gone = false;
                                    for f in futures {
                                        match f.await {
                                            Ok(true) => {
                                                // All works done
                                                connection_gone = true;
                                            }
                                            Err(_) => {
                                                // Unexpected
                                                connection_gone = true;
                                            }
                                            _ => {}
                                        }
                                    }
                                    if connection_gone {
                                        return;
                                    }
                                }
                                Err(err) => {
                                    // Consume a task
                                    if let Ok(()) = rx.recv().await {
                                        report_tx.send(Err(err)).unwrap();
                                    } else {
                                        return;
                                    }
                                }
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            work_queue.await.unwrap();
            for f in futures {
                let _ = f.await;
            }
        }
        HttpWorkType::H1 => {
            let futures = (0..n_connections)
                .map(|_| {
                    let report_tx = report_tx.clone();
                    let rx = rx.clone();
                    let client = client.clone();
                    tokio::spawn(async move {
                        let mut client_state = ClientStateHttp1::default();
                        while let Ok(()) = rx.recv().await {
                            let res = client.work_http1(&mut client_state).await;
                            let is_cancel = is_cancel_error(&res);
                            report_tx.send(res).unwrap();
                            if is_cancel {
                                break;
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            work_queue.await.unwrap();
            for f in futures {
                let _ = f.await;
            }
        }
    };
}

/// n tasks by m workers limit to qps works in a second with latency correction
pub async fn work_with_qps_latency_correction(
    client: Arc<Client>,
    report_tx: kanal::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    n_tasks: usize,
    n_connections: usize,
    n_http2_parallel: usize,
) {
    #[cfg(feature = "http3")]
    if matches!(client.work_type(), HttpWorkType::H3) {
        crate::client_h3::work_with_qps_latency_correction(
            client,
            report_tx,
            query_limit,
            n_tasks,
            n_connections,
            n_http2_parallel,
        )
        .await;
        return;
    }

    let (tx, rx) = kanal::unbounded();

    let work_queue = async move {
        match query_limit {
            QueryLimit::Qps(qps) => {
                let start = std::time::Instant::now();
                for i in 0..n_tasks {
                    tokio::time::sleep_until(
                        (start + std::time::Duration::from_secs_f64(i as f64 * 1f64 / qps)).into(),
                    )
                    .await;
                    let now = std::time::Instant::now();
                    tx.send(now)?;
                }
            }
            QueryLimit::Burst(duration, rate) => {
                let mut n = 0;
                // Handle via rate till n_tasks out of bound
                while n + rate < n_tasks {
                    tokio::time::sleep(duration).await;
                    let now = std::time::Instant::now();
                    for _ in 0..rate {
                        tx.send(now)?;
                    }
                    n += rate;
                }
                // Handle the remaining tasks
                if n_tasks > n {
                    tokio::time::sleep(duration).await;
                    let now = std::time::Instant::now();
                    for _ in 0..n_tasks - n {
                        tx.send(now)?;
                    }
                }
            }
        }

        // tx gone
        drop(tx);
        Ok::<(), kanal::SendError>(())
    };

    let rx = rx.to_async();
    match client.work_type() {
        #[cfg(feature = "http3")]
        HttpWorkType::H3 => unreachable!(),
        HttpWorkType::H2 => {
            let futures = (0..n_connections)
                .map(|_| {
                    let report_tx = report_tx.clone();
                    let rx = rx.clone();
                    let client = client.clone();
                    tokio::spawn(async move {
                        let mut rng: Pcg64Si = SeedableRng::from_os_rng();
                        loop {
                            match setup_http2(&client, &mut rng).await {
                                Ok((connection_time, send_request)) => {
                                    let futures = (0..n_http2_parallel)
                                        .map(|_| {
                                            let report_tx = report_tx.clone();
                                            let rx = rx.clone();
                                            let client = client.clone();
                                            let mut client_state = ClientStateHttp2 {
                                                rng: SeedableRng::from_os_rng(),
                                                send_request: send_request.clone(),
                                            };
                                            tokio::spawn(async move {
                                                while let Ok(start) = rx.recv().await {
                                                    let (is_cancel, is_reconnect) =
                                                        work_http2_once(
                                                            &client,
                                                            &mut client_state,
                                                            &report_tx,
                                                            connection_time,
                                                            Some(start),
                                                        )
                                                        .await;

                                                    if is_cancel || is_reconnect {
                                                        return is_cancel;
                                                    }
                                                }
                                                true
                                            })
                                        })
                                        .collect::<Vec<_>>();
                                    let mut connection_gone = false;
                                    for f in futures {
                                        match f.await {
                                            Ok(true) => {
                                                // All works done
                                                connection_gone = true;
                                            }
                                            Err(_) => {
                                                // Unexpected
                                                connection_gone = true;
                                            }
                                            _ => {}
                                        }
                                    }
                                    if connection_gone {
                                        return;
                                    }
                                }
                                Err(err) => {
                                    // Consume a task
                                    if rx.recv().await.is_ok() {
                                        report_tx.send(Err(err)).unwrap();
                                    } else {
                                        return;
                                    }
                                }
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            work_queue.await.unwrap();
            for f in futures {
                let _ = f.await;
            }
        }
        HttpWorkType::H1 => {
            let futures = (0..n_connections)
                .map(|_| {
                    let client = client.clone();
                    let mut client_state = ClientStateHttp1::default();
                    let report_tx = report_tx.clone();
                    let rx = rx.clone();
                    tokio::spawn(async move {
                        while let Ok(start) = rx.recv().await {
                            let mut res = client.work_http1(&mut client_state).await;
                            set_start_latency_correction(&mut res, start);
                            let is_cancel = is_cancel_error(&res);
                            report_tx.send(res).unwrap();
                            if is_cancel {
                                break;
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            work_queue.await.unwrap();
            for f in futures {
                let _ = f.await;
            }
        }
    }
}

/// Run until dead_line by n workers
pub async fn work_until(
    client: Arc<Client>,
    report_tx: kanal::Sender<Result<RequestResult, ClientError>>,
    dead_line: std::time::Instant,
    n_connections: usize,
    n_http_parallel: usize,
    wait_ongoing_requests_after_deadline: bool,
) {
    #[cfg(feature = "http3")]
    if matches!(client.work_type(), HttpWorkType::H3) {
        crate::client_h3::work_until(
            client,
            report_tx,
            dead_line,
            n_connections,
            n_http_parallel,
            wait_ongoing_requests_after_deadline,
        )
        .await;
        return;
    }

    match client.work_type() {
        #[cfg(feature = "http3")]
        HttpWorkType::H3 => unreachable!(),
        HttpWorkType::H2 => {
            // Using semaphore to control the deadline
            // Maybe there is a better concurrent primitive to do this
            let s = Arc::new(tokio::sync::Semaphore::new(0));

            let futures = (0..n_connections)
                .map(|_| {
                    let client = client.clone();
                    let report_tx = report_tx.clone();
                    let s = s.clone();
                    tokio::spawn(async move {
                        let s = s.clone();
                        // Keep trying to establish or re-establish connections up to the deadline
                        let mut rng: Pcg64Si = SeedableRng::from_os_rng();
                        loop {
                            match setup_http2(&client, &mut rng).await {
                                Ok((connection_time, send_request)) => {
                                    // Setup the parallel workers for each HTTP2 connection
                                    let futures = (0..n_http_parallel)
                                        .map(|_| {
                                            let client = client.clone();
                                            let report_tx = report_tx.clone();
                                            let mut client_state = ClientStateHttp2 {
                                                rng: SeedableRng::from_os_rng(),
                                                send_request: send_request.clone(),
                                            };
                                            let s = s.clone();
                                            tokio::spawn(async move {
                                                // This is where HTTP2 loops to make all the requests for a given client and worker
                                                loop {
                                                    let (is_cancel, is_reconnect) =
                                                        work_http2_once(
                                                            &client,
                                                            &mut client_state,
                                                            &report_tx,
                                                            connection_time,
                                                            None,
                                                        )
                                                        .await;

                                                    let is_cancel = is_cancel || s.is_closed();
                                                    if is_cancel || is_reconnect {
                                                        break is_cancel;
                                                    }
                                                }
                                            })
                                        })
                                        .collect::<Vec<_>>();

                                    let mut connection_gone = false;
                                    for f in futures {
                                        tokio::select! {
                                            r = f => {
                                                match r {
                                                    Ok(true) => {
                                                        // All works done
                                                        connection_gone = true;
                                                    }
                                                    Err(_) => {
                                                        // Unexpected
                                                        connection_gone = true;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            _ = s.acquire() => {
                                                report_tx.send(Err(ClientError::Deadline)).unwrap();
                                                connection_gone = true;
                                            }
                                        }
                                    }
                                    if connection_gone {
                                        return;
                                    }
                                }

                                Err(err) => {
                                    report_tx.send(Err(err)).unwrap();
                                    if s.is_closed() {
                                        break;
                                    }
                                }
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            tokio::time::sleep_until(dead_line.into()).await;
            s.close();

            for f in futures {
                let _ = f.await;
            }
        }
        HttpWorkType::H1 => {
            let is_end = Arc::new(AtomicBool::new(false));

            let futures = (0..n_connections)
                .map(|_| {
                    let client = client.clone();
                    let report_tx = report_tx.clone();
                    let mut client_state = ClientStateHttp1::default();
                    let is_end = is_end.clone();
                    tokio::spawn(async move {
                        loop {
                            let res = client.work_http1(&mut client_state).await;
                            let is_cancel = is_cancel_error(&res);
                            report_tx.send(res).unwrap();
                            if is_cancel || is_end.load(Relaxed) {
                                break;
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            tokio::time::sleep_until(dead_line.into()).await;
            is_end.store(true, Relaxed);

            if wait_ongoing_requests_after_deadline {
                for f in futures {
                    let _ = f.await;
                }
            } else {
                for f in futures {
                    f.abort();
                    if let Err(e) = f.await {
                        if e.is_cancelled() {
                            report_tx.send(Err(ClientError::Deadline)).unwrap();
                        }
                    }
                }
            }
        }
    };
}

/// Run until dead_line by n workers limit to qps works in a second
#[allow(clippy::too_many_arguments)]
pub async fn work_until_with_qps(
    client: Arc<Client>,
    report_tx: kanal::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_connections: usize,
    n_http2_parallel: usize,
    wait_ongoing_requests_after_deadline: bool,
) {
    #[cfg(feature = "http3")]
    if matches!(client.work_type(), HttpWorkType::H3) {
        crate::client_h3::work_until_with_qps(
            client,
            report_tx,
            query_limit,
            start,
            dead_line,
            n_connections,
            n_http2_parallel,
            wait_ongoing_requests_after_deadline,
        )
        .await;
        return;
    }

    let rx = match query_limit {
        QueryLimit::Qps(qps) => {
            let (tx, rx) = kanal::unbounded::<()>();
            tokio::spawn(async move {
                for i in 0.. {
                    if std::time::Instant::now() > dead_line {
                        break;
                    }
                    tokio::time::sleep_until(
                        (start + std::time::Duration::from_secs_f64(i as f64 * 1f64 / qps)).into(),
                    )
                    .await;
                    let _ = tx.send(());
                }
                // tx gone
            });
            rx
        }
        QueryLimit::Burst(duration, rate) => {
            let (tx, rx) = kanal::unbounded();
            tokio::spawn(async move {
                // Handle via rate till deadline is reached
                for _ in 0.. {
                    if std::time::Instant::now() > dead_line {
                        break;
                    }

                    tokio::time::sleep(duration).await;
                    for _ in 0..rate {
                        let _ = tx.send(());
                    }
                }
                // tx gone
            });
            rx
        }
    };

    let rx = rx.to_async();
    match client.work_type() {
        #[cfg(feature = "http3")]
        HttpWorkType::H3 => unreachable!(),
        HttpWorkType::H2 => {
            let s = Arc::new(tokio::sync::Semaphore::new(0));

            let futures = (0..n_connections)
                .map(|_| {
                    let client = client.clone();
                    let report_tx = report_tx.clone();
                    let rx = rx.clone();
                    let s = s.clone();
                    tokio::spawn(async move {
                        let mut rng: Pcg64Si = SeedableRng::from_os_rng();
                        loop {
                            match setup_http2(&client, &mut rng).await {
                                Ok((connection_time, send_request)) => {
                                    let futures = (0..n_http2_parallel)
                                        .map(|_| {
                                            let client = client.clone();
                                            let report_tx = report_tx.clone();
                                            let rx = rx.clone();
                                            let mut client_state = ClientStateHttp2 {
                                                rng: SeedableRng::from_os_rng(),
                                                send_request: send_request.clone(),
                                            };
                                            let s = s.clone();
                                            tokio::spawn(async move {
                                                while let Ok(()) = rx.recv().await {
                                                    let (is_cancel, is_reconnect) =
                                                        work_http2_once(
                                                            &client,
                                                            &mut client_state,
                                                            &report_tx,
                                                            connection_time,
                                                            None,
                                                        )
                                                        .await;

                                                    let is_cancel = is_cancel || s.is_closed();
                                                    if is_cancel || is_reconnect {
                                                        return is_cancel;
                                                    }
                                                }
                                                true
                                            })
                                        })
                                        .collect::<Vec<_>>();
                                    let mut connection_gone = false;
                                    for f in futures {
                                        tokio::select! {
                                            r = f => {
                                                match r {
                                                    Ok(true) => {
                                                        // All works done
                                                        connection_gone = true;
                                                    }
                                                    Err(_) => {
                                                        // Unexpected
                                                        connection_gone = true;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            _ = s.acquire() => {
                                                report_tx.send(Err(ClientError::Deadline)).unwrap();
                                                connection_gone = true;
                                            }
                                        }
                                    }
                                    if connection_gone {
                                        return;
                                    }
                                }
                                Err(err) => {
                                    // Consume a task
                                    if rx.recv().await.is_ok() {
                                        report_tx.send(Err(err)).unwrap();
                                    } else {
                                        return;
                                    }

                                    if s.is_closed() {
                                        return;
                                    }
                                }
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            tokio::time::sleep_until(dead_line.into()).await;
            s.close();

            for f in futures {
                let _ = f.await;
            }
        }
        HttpWorkType::H1 => {
            let is_end = Arc::new(AtomicBool::new(false));

            let futures = (0..n_connections)
                .map(|_| {
                    let client = client.clone();
                    let mut client_state = ClientStateHttp1::default();
                    let report_tx = report_tx.clone();
                    let rx = rx.clone();
                    let is_end = is_end.clone();
                    tokio::spawn(async move {
                        while let Ok(()) = rx.recv().await {
                            let res = client.work_http1(&mut client_state).await;
                            let is_cancel = is_cancel_error(&res);
                            report_tx.send(res).unwrap();
                            if is_cancel || is_end.load(Relaxed) {
                                break;
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            tokio::time::sleep_until(dead_line.into()).await;
            is_end.store(true, Relaxed);

            if wait_ongoing_requests_after_deadline {
                for f in futures {
                    let _ = f.await;
                }
            } else {
                for f in futures {
                    f.abort();
                    if let Err(e) = f.await {
                        if e.is_cancelled() {
                            report_tx.send(Err(ClientError::Deadline)).unwrap();
                        }
                    }
                }
            }
        }
    }
}

/// Run until dead_line by n workers limit to qps works in a second with latency correction
#[allow(clippy::too_many_arguments)]
pub async fn work_until_with_qps_latency_correction(
    client: Arc<Client>,
    report_tx: kanal::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_connections: usize,
    n_http2_parallel: usize,
    wait_ongoing_requests_after_deadline: bool,
) {
    #[cfg(feature = "http3")]
    if matches!(client.work_type(), HttpWorkType::H3) {
        crate::client_h3::work_until_with_qps_latency_correction(
            client,
            report_tx,
            query_limit,
            start,
            dead_line,
            n_connections,
            n_http2_parallel,
            wait_ongoing_requests_after_deadline,
        )
        .await;
        return;
    }

    let (tx, rx) = kanal::unbounded();
    match query_limit {
        QueryLimit::Qps(qps) => {
            tokio::spawn(async move {
                for i in 0.. {
                    tokio::time::sleep_until(
                        (start + std::time::Duration::from_secs_f64(i as f64 * 1f64 / qps)).into(),
                    )
                    .await;
                    let now = std::time::Instant::now();
                    if now > dead_line {
                        break;
                    }
                    let _ = tx.send(now);
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
                        let _ = tx.send(now);
                    }
                }
                // tx gone
            });
        }
    };

    let rx = rx.to_async();
    match client.work_type() {
        #[cfg(feature = "http3")]
        HttpWorkType::H3 => unreachable!(),
        HttpWorkType::H2 => {
            let s = Arc::new(tokio::sync::Semaphore::new(0));

            let futures = (0..n_connections)
                .map(|_| {
                    let client = client.clone();
                    let report_tx = report_tx.clone();
                    let rx = rx.clone();
                    let s = s.clone();
                    tokio::spawn(async move {
                        let mut rng: Pcg64Si = SeedableRng::from_os_rng();
                        loop {
                            match setup_http2(&client, &mut rng).await {
                                Ok((connection_time, send_request)) => {
                                    let futures = (0..n_http2_parallel)
                                        .map(|_| {
                                            let client = client.clone();
                                            let report_tx = report_tx.clone();
                                            let rx = rx.clone();
                                            let mut client_state = ClientStateHttp2 {
                                                rng: SeedableRng::from_os_rng(),
                                                send_request: send_request.clone(),
                                            };
                                            let s = s.clone();
                                            tokio::spawn(async move {
                                                while let Ok(start) = rx.recv().await {
                                                    let (is_cancel, is_reconnect) =
                                                        work_http2_once(
                                                            &client,
                                                            &mut client_state,
                                                            &report_tx,
                                                            connection_time,
                                                            Some(start),
                                                        )
                                                        .await;
                                                    let is_cancel = is_cancel || s.is_closed();
                                                    if is_cancel || is_reconnect {
                                                        return is_cancel;
                                                    }
                                                }
                                                true
                                            })
                                        })
                                        .collect::<Vec<_>>();
                                    let mut connection_gone = false;
                                    for f in futures {
                                        tokio::select! {
                                            r = f => {
                                                match r {
                                                    Ok(true) => {
                                                        // All works done
                                                        connection_gone = true;
                                                    }
                                                    Err(_) => {
                                                        // Unexpected
                                                        connection_gone = true;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            _ = s.acquire() => {
                                                report_tx.send(Err(ClientError::Deadline)).unwrap();
                                                connection_gone = true;
                                            }
                                        }
                                    }
                                    if connection_gone {
                                        return;
                                    }
                                }

                                Err(err) => {
                                    if rx.recv().await.is_ok() {
                                        report_tx.send(Err(err)).unwrap();
                                    } else {
                                        return;
                                    }

                                    if s.is_closed() {
                                        return;
                                    }
                                }
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            tokio::time::sleep_until(dead_line.into()).await;
            s.close();

            for f in futures {
                let _ = f.await;
            }
        }
        HttpWorkType::H1 => {
            let is_end = Arc::new(AtomicBool::new(false));

            let futures = (0..n_connections)
                .map(|_| {
                    let client = client.clone();
                    let mut client_state = ClientStateHttp1::default();
                    let report_tx = report_tx.clone();
                    let rx = rx.clone();
                    let is_end = is_end.clone();
                    tokio::spawn(async move {
                        while let Ok(start) = rx.recv().await {
                            let mut res = client.work_http1(&mut client_state).await;
                            set_start_latency_correction(&mut res, start);
                            let is_cancel = is_cancel_error(&res);
                            report_tx.send(res).unwrap();
                            if is_cancel || is_end.load(Relaxed) {
                                break;
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            tokio::time::sleep_until(dead_line.into()).await;
            is_end.store(true, Relaxed);

            if wait_ongoing_requests_after_deadline {
                for f in futures {
                    let _ = f.await;
                }
            } else {
                for f in futures {
                    f.abort();
                    if let Err(e) = f.await {
                        if e.is_cancelled() {
                            report_tx.send(Err(ClientError::Deadline)).unwrap();
                        }
                    }
                }
            }
        }
    }
}

/// Optimized workers for `--no-tui` mode
pub mod fast {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicIsize, Ordering},
    };

    use rand::SeedableRng;

    use crate::{
        client::{
            ClientError, ClientStateHttp1, ClientStateHttp2, HttpWorkType, is_cancel_error,
            is_hyper_error, set_connection_time, setup_http2,
        },
        pcg64si::Pcg64Si,
        result_data::ResultData,
    };

    use super::Client;

    /// Run n tasks by m workers
    pub async fn work(
        client: Arc<Client>,
        report_tx: kanal::Sender<ResultData>,
        n_tasks: usize,
        n_connections: usize,
        n_http_parallel: usize,
    ) {
        #[cfg(feature = "http3")]
        if matches!(client.work_type(), HttpWorkType::H3) {
            crate::client_h3::fast::work(
                client,
                report_tx,
                n_tasks,
                n_connections,
                n_http_parallel,
            )
            .await;
            return;
        }

        let counter = Arc::new(AtomicIsize::new(n_tasks as isize));
        let num_threads = num_cpus::get_physical();
        let connections = (0..num_threads).filter_map(|i| {
            let num_connection = n_connections / num_threads
                + (if (n_connections % num_threads) > i {
                    1
                } else {
                    0
                });
            if num_connection > 0 {
                Some(num_connection)
            } else {
                None
            }
        });
        let token = tokio_util::sync::CancellationToken::new();

        let handles = match client.work_type() {
            #[cfg(feature = "http3")]
            HttpWorkType::H3 => unreachable!(),
            HttpWorkType::H2 => {
                connections
                    .map(|num_connections| {
                        let report_tx = report_tx.clone();
                        let counter = counter.clone();
                        let client = client.clone();
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap();
                        let token = token.clone();

                        std::thread::spawn(move || {
                            let client = client.clone();
                            let local = tokio::task::LocalSet::new();
                            for _ in 0..num_connections {
                                let report_tx = report_tx.clone();
                                let counter = counter.clone();
                                let client = client.clone();
                                let token = token.clone();
                                local.spawn_local(Box::pin(async move {
                                    let mut has_err = false;
                                    let mut result_data_err = ResultData::default();
                                    let mut rng: Pcg64Si = SeedableRng::from_os_rng();
                                    loop {
                                        let client = client.clone();
                                        match setup_http2(&client, &mut rng).await {
                                            Ok((connection_time, send_request)) => {
                                                let futures = (0..n_http_parallel)
                                                    .map(|_| {
                                                        let mut client_state = ClientStateHttp2 {
                                                            rng: SeedableRng::from_os_rng(),
                                                            send_request: send_request.clone(),
                                                        };
                                                        let counter = counter.clone();
                                                        let client = client.clone();
                                                        let report_tx = report_tx.clone();
                                                        let token = token.clone();
                                                        tokio::task::spawn_local(async move {
                                                            let mut result_data =
                                                                ResultData::default();

                                                            let work = async {
                                                                while counter
                                                                    .fetch_sub(1, Ordering::Relaxed)
                                                                    > 0
                                                                {
                                                                    let mut res = client
                                                                        .work_http2(
                                                                            &mut client_state,
                                                                        )
                                                                        .await;
                                                                    let is_cancel =
                                                                        is_cancel_error(&res);
                                                                    let is_reconnect =
                                                                        is_hyper_error(&res);
                                                                    set_connection_time(
                                                                        &mut res,
                                                                        connection_time,
                                                                    );

                                                                    result_data.push(res);

                                                                    if is_cancel || is_reconnect {
                                                                        return is_cancel;
                                                                    }
                                                                }
                                                                true
                                                            };

                                                            let is_cancel = tokio::select! {
                                                                is_cancel = work => {
                                                                    is_cancel
                                                                }
                                                                _ = token.cancelled() => {
                                                                    true
                                                                }
                                                            };

                                                            report_tx.send(result_data).unwrap();
                                                            is_cancel
                                                        })
                                                    })
                                                    .collect::<Vec<_>>();

                                                let mut connection_gone = false;
                                                for f in futures {
                                                    match f.await {
                                                        Ok(true) => {
                                                            // All works done
                                                            connection_gone = true;
                                                        }
                                                        Err(_) => {
                                                            // Unexpected
                                                            connection_gone = true;
                                                        }
                                                        _ => {}
                                                    }
                                                }

                                                if connection_gone {
                                                    break;
                                                }
                                            }
                                            Err(err) => {
                                                if counter.fetch_sub(1, Ordering::Relaxed) > 0 {
                                                    has_err = true;
                                                    result_data_err.push(Err(err));
                                                } else {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    if has_err {
                                        report_tx.send(result_data_err).unwrap();
                                    }
                                }));
                            }

                            rt.block_on(local);
                        })
                    })
                    .collect::<Vec<_>>()
            }
            HttpWorkType::H1 => connections
                .map(|num_connection| {
                    let report_tx = report_tx.clone();
                    let counter = counter.clone();
                    let client = client.clone();
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();

                    let token = token.clone();
                    std::thread::spawn(move || {
                        let local = tokio::task::LocalSet::new();

                        for _ in 0..num_connection {
                            let report_tx = report_tx.clone();
                            let counter = counter.clone();
                            let client = client.clone();
                            let token = token.clone();
                            local.spawn_local(Box::pin(async move {
                                let mut result_data = ResultData::default();

                                tokio::select! {
                                    _ = token.cancelled() => {}
                                    _ = async {
                                        let mut client_state = ClientStateHttp1::default();
                                        while counter.fetch_sub(1, Ordering::Relaxed) > 0 {
                                            let res = client.work_http1(&mut client_state).await;
                                            let is_cancel = is_cancel_error(&res);
                                            result_data.push(res);
                                            if is_cancel {
                                                break;
                                            }
                                        }
                                    } => {}
                                }
                                report_tx.send(result_data).unwrap();
                            }));
                        }
                        rt.block_on(local);
                    })
                })
                .collect::<Vec<_>>(),
        };

        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.unwrap();
            token.cancel();
        });

        tokio::task::block_in_place(|| {
            for handle in handles {
                let _ = handle.join();
            }
        });
    }

    /// Run until dead_line by n workers
    pub async fn work_until(
        client: Arc<Client>,
        report_tx: kanal::Sender<ResultData>,
        dead_line: std::time::Instant,
        n_connections: usize,
        n_http_parallel: usize,
        wait_ongoing_requests_after_deadline: bool,
    ) {
        #[cfg(feature = "http3")]
        if matches!(client.work_type(), HttpWorkType::H3) {
            crate::client_h3::fast::work_until(
                client,
                report_tx,
                dead_line,
                n_connections,
                n_http_parallel,
                wait_ongoing_requests_after_deadline,
            )
            .await;
            return;
        }

        let num_threads = num_cpus::get_physical();

        let is_end = Arc::new(AtomicBool::new(false));
        let connections = (0..num_threads).filter_map(|i| {
            let num_connection = n_connections / num_threads
                + (if (n_connections % num_threads) > i {
                    1
                } else {
                    0
                });
            if num_connection > 0 {
                Some(num_connection)
            } else {
                None
            }
        });
        let token = tokio_util::sync::CancellationToken::new();
        let handles = match client.work_type() {
            #[cfg(feature = "http3")]
            HttpWorkType::H3 => unreachable!(),
            HttpWorkType::H2 => {
                connections
                .map(|num_connections| {
                    let report_tx = report_tx.clone();
                    let client = client.clone();
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    let token = token.clone();
                    let is_end = is_end.clone();

                    std::thread::spawn(move || {
                        let client = client.clone();
                        let local = tokio::task::LocalSet::new();
                        for _ in 0..num_connections {
                            let report_tx = report_tx.clone();
                            let client = client.clone();
                            let token = token.clone();
                            let is_end = is_end.clone();
                            local.spawn_local(Box::pin(async move {
                                let mut has_err = false;
                                let mut result_data_err = ResultData::default();
                                let mut rng: Pcg64Si = SeedableRng::from_os_rng();
                                loop {
                                    let client = client.clone();
                                    match setup_http2(&client, &mut rng).await {
                                        Ok((connection_time, send_request)) => {
                                            let futures = (0..n_http_parallel)
                                                .map(|_| {
                                                    let mut client_state = ClientStateHttp2 {
                                                        rng: SeedableRng::from_os_rng(),
                                                        send_request: send_request.clone(),
                                                    };
                                                    let client = client.clone();
                                                    let report_tx = report_tx.clone();
                                                    let token = token.clone();
                                                    let is_end = is_end.clone();
                                                    tokio::task::spawn_local(async move {
                                                        let mut result_data = ResultData::default();

                                                        let work = async {
                                                            loop {
                                                                let mut res = client
                                                                    .work_http2(&mut client_state)
                                                                    .await;
                                                                let is_cancel = is_cancel_error(&res) || is_end.load(Ordering::Relaxed);
                                                                let is_reconnect = is_hyper_error(&res);
                                                                set_connection_time(
                                                                    &mut res,
                                                                    connection_time,
                                                                );

                                                                result_data.push(res);

                                                                if is_cancel || is_reconnect {
                                                                    return is_cancel;
                                                                }
                                                            }
                                                        };

                                                        let is_cancel = tokio::select! {
                                                            is_cancel = work => {
                                                                is_cancel
                                                            }
                                                            _ = token.cancelled() => {
                                                                result_data.push(Err(ClientError::Deadline));
                                                                true
                                                            }
                                                        };

                                                        report_tx.send(result_data).unwrap();
                                                        is_cancel
                                                    })
                                                })
                                                .collect::<Vec<_>>();

                                            let mut connection_gone = false;
                                            for f in futures {
                                                match f.await {
                                                    Ok(true) => {
                                                        // All works done
                                                        connection_gone = true;
                                                    }
                                                    Err(_) => {
                                                        // Unexpected
                                                        connection_gone = true;
                                                    }
                                                    _ => {}
                                                }
                                            }

                                            if connection_gone {
                                                break;
                                            }
                                        }
                                        Err(err) => {
                                            has_err = true;
                                            result_data_err.push(Err(err));
                                            if is_end.load(Ordering::Relaxed) {
                                                break;
                                            }
                                        }
                                    }
                                }
                                if has_err {
                                    report_tx.send(result_data_err).unwrap();
                                }
                            }));
                        }

                        rt.block_on(local);
                    })
                })
                .collect::<Vec<_>>()
            }
            HttpWorkType::H1 => connections
                .map(|num_connection| {
                    let report_tx = report_tx.clone();
                    let is_end = is_end.clone();
                    let client = client.clone();
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();

                    let token = token.clone();
                    std::thread::spawn(move || {
                        let local = tokio::task::LocalSet::new();

                        for _ in 0..num_connection {
                            let report_tx = report_tx.clone();
                            let is_end = is_end.clone();
                            let client = client.clone();
                            let token = token.clone();
                            local.spawn_local(Box::pin(async move {
                                let mut result_data = ResultData::default();

                                let work = async {
                                    let mut client_state = ClientStateHttp1::default();
                                    loop {
                                        let res = client.work_http1(&mut client_state).await;
                                        let is_cancel = is_cancel_error(&res);
                                        result_data.push(res);
                                        if is_cancel || is_end.load(Ordering::Relaxed) {
                                            break;
                                        }
                                    }
                                };

                                tokio::select! {
                                    _ = work => {
                                    }
                                    _ = token.cancelled() => {
                                        result_data.push(Err(ClientError::Deadline));
                                    }
                                }
                                report_tx.send(result_data).unwrap();
                            }));
                        }
                        rt.block_on(local);
                    })
                })
                .collect::<Vec<_>>(),
        };
        tokio::select! {
            _ = tokio::time::sleep_until(dead_line.into()) => {
            }
            _ = tokio::signal::ctrl_c() => {
            }
        }

        is_end.store(true, Ordering::Relaxed);

        if !wait_ongoing_requests_after_deadline {
            token.cancel();
        }
        tokio::task::block_in_place(|| {
            for handle in handles {
                let _ = handle.join();
            }
        });
    }
}
