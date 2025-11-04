use std::{
    convert::Infallible,
    error::Error as StdError,
    fs::File,
    future::Future,
    io::Write,
    net::{Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, OnceLock, atomic::AtomicU16},
};

use axum::{Router, extract::Path, response::Redirect, routing::get};
use bytes::Bytes;
use clap::Parser;
use http::{HeaderMap, Request, Response};
use http_body_util::BodyExt;
use http_mitm_proxy::MitmProxy;
use hyper::{
    body::{Body, Incoming},
    http,
    service::{HttpService, service_fn},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rstest::rstest;
use rstest_reuse::{self, *};
#[cfg(feature = "http3")]
mod common;

async fn run<'a>(args: impl Iterator<Item = &'a str>) {
    let opts = oha::Opts::parse_from(
        ["oha", "--no-tui", "--output-format", "quiet"]
            .into_iter()
            .chain(args),
    );

    oha::run(opts).await.unwrap();
}

// Port 5111- is reserved for testing
static PORT: AtomicU16 = AtomicU16::new(5111);

fn next_port() -> u16 {
    PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn install_crypto_provider() {
    static INSTALL: OnceLock<()> = OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        );
    });
}

async fn bind_port(port: u16) -> tokio::net::TcpListener {
    let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);

    tokio::net::TcpListener::bind(addr).await.unwrap()
}

async fn bind_port_and_increment() -> (tokio::net::TcpListener, u16) {
    let port = next_port();
    let listener = bind_port(port).await;
    (listener, port)
}

async fn bind_port_ipv6(port: u16) -> tokio::net::TcpListener {
    let addr = SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST), port);

    tokio::net::TcpListener::bind(addr).await.unwrap()
}

#[derive(Clone, Copy, PartialEq)]
enum HttpWorkType {
    H1,
    H2,
    #[cfg(feature = "http3")]
    H3,
}

fn http_work_type(args: &[&str]) -> HttpWorkType {
    // Check for HTTP/2
    if args.contains(&"--http2") || args.windows(2).any(|w| w == ["--http-version", "2"]) {
        return HttpWorkType::H2;
    }

    // Check for HTTP/3 when the feature is enabled
    #[cfg(feature = "http3")]
    if args.contains(&"--http3") || args.windows(2).any(|w| w == ["--http-version", "3"]) {
        return HttpWorkType::H3;
    }

    // Default to HTTP/1.1
    HttpWorkType::H1
}

#[cfg(feature = "http3")]
#[template]
#[rstest]
#[case("1.1")]
#[case("2")]
#[case("3")]
fn test_all_http_versions(#[case] http_version_param: &str) {}

#[cfg(not(feature = "http3"))]
#[template]
#[rstest]
#[case("1.1")]
#[case("2")]
fn test_all_http_versions(#[case] http_version_param: &str) {}

async fn get_req(path: &str, args: &[&str]) -> Request<Bytes> {
    let (tx, rx) = kanal::unbounded();

    let port = next_port();

    let work_type = http_work_type(args);
    let listener = bind_port(port).await;

    tokio::spawn(async move {
        match work_type {
            HttpWorkType::H2 => loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let tx = tx.clone();
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(tcp),
                        service_fn(move |req: Request<Incoming>| {
                            let tx = tx.clone();
                            async move {
                                let (parts, body) = req.into_parts();
                                let body_bytes = body.collect().await.unwrap().to_bytes();
                                let req = Request::from_parts(parts, body_bytes);
                                tx.send(req).unwrap();
                                Ok::<_, Infallible>(Response::new("Hello World".to_string()))
                            }
                        }),
                    )
                    .await;
            },
            HttpWorkType::H1 => {
                let (tcp, _) = listener.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(tcp),
                        service_fn(move |req: Request<Incoming>| {
                            let tx = tx.clone();

                            async move {
                                let (parts, body) = req.into_parts();
                                let body_bytes = body.collect().await.unwrap().to_bytes();
                                let req = Request::from_parts(parts, body_bytes);
                                tx.send(req).unwrap();
                                Ok::<_, Infallible>(Response::new("Hello World".to_string()))
                            }
                        }),
                    )
                    .await
                    .unwrap();
            }
            #[cfg(feature = "http3")]
            HttpWorkType::H3 => {
                drop(listener);
                common::h3_server(tx, port).await.unwrap();
            }
        }
    });

    let mut args = args.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    args.push("-n".to_string());
    args.push("1".to_string());
    match work_type {
        HttpWorkType::H1 | HttpWorkType::H2 => {
            args.push(format!("http://127.0.0.1:{port}{path}"));
        }
        #[cfg(feature = "http3")]
        HttpWorkType::H3 => {
            args.push("--insecure".to_string());
            args.push(format!("https://127.0.0.1:{port}{path}"));
        }
    }

    run(args.iter().map(|s| s.as_str())).await;

    rx.try_recv().unwrap().unwrap()
}

async fn redirect(n: usize, is_relative: bool, limit: usize) -> bool {
    let (tx, rx) = kanal::unbounded();

    let (listener, port) = bind_port_and_increment().await;

    let app = Router::new().route(
        "/{n}",
        get(move |Path(x): Path<usize>| async move {
            Ok::<_, Infallible>(if x == n {
                tx.send(()).unwrap();
                Redirect::permanent("/end")
            } else if is_relative {
                Redirect::permanent(&format!("/{}", x + 1))
            } else {
                Redirect::permanent(&format!("http://localhost:{}/{}", port, x + 1))
            })
        }),
    );

    tokio::spawn(async { axum::serve(listener, app).await });

    let args = [
        "-n".to_string(),
        "1".to_string(),
        "--redirect".to_string(),
        limit.to_string(),
        format!("http://127.0.0.1:{port}/0"),
    ];

    run(args.iter().map(|s| s.as_str())).await;

    rx.try_recv().unwrap().is_some()
}

async fn get_host_with_connect_to(host: &'static str) -> String {
    let (tx, rx) = kanal::unbounded();

    let app = Router::new().route(
        "/",
        get(|header: HeaderMap| async move {
            tx.send(header.get("host").unwrap().to_str().unwrap().to_string())
                .unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port_and_increment().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args = [
        "-n".to_string(),
        "1".to_string(),
        format!("http://{host}/"),
        "--connect-to".to_string(),
        format!("{host}:80:localhost:{port}"),
    ];
    run(args.iter().map(|s| s.as_str())).await;

    rx.try_recv().unwrap().unwrap()
}

async fn get_host_with_connect_to_ipv6_target(host: &'static str) -> String {
    let (tx, rx) = kanal::unbounded();
    let app = Router::new().route(
        "/",
        get(|header: HeaderMap| async move {
            tx.send(header.get("host").unwrap().to_str().unwrap().to_string())
                .unwrap();
            "Hello World"
        }),
    );

    let port = next_port();
    let listener = bind_port_ipv6(port).await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args = [
        "-n".to_string(),
        "1".to_string(),
        format!("http://{host}/"),
        "--connect-to".to_string(),
        format!("{host}:80:[::1]:{port}"),
    ];

    run(args.iter().map(|s| s.as_str())).await;

    rx.try_recv().unwrap().unwrap()
}

async fn get_host_with_connect_to_ipv6_requested() -> String {
    let (tx, rx) = kanal::unbounded();
    let app = Router::new().route(
        "/",
        get(|header: HeaderMap| async move {
            tx.send(header.get("host").unwrap().to_str().unwrap().to_string())
                .unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port_and_increment().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args = [
        "-n".to_string(),
        "1".to_string(),
        "http://[::1]/".to_string(),
        "--connect-to".to_string(),
        format!("[::1]:80:localhost:{port}"),
    ];
    run(args.iter().map(|s| s.as_str())).await;

    rx.try_recv().unwrap().unwrap()
}

async fn get_host_with_connect_to_redirect(host: &'static str) -> String {
    let (tx, rx) = kanal::unbounded();

    let app = Router::new()
        .route(
            "/source",
            get(move || async move { Redirect::permanent(&format!("http://{host}/destination")) }),
        )
        .route(
            "/destination",
            get(move || async move {
                tx.send(host.to_string()).unwrap();
                "Hello World"
            }),
        );

    let (listener, port) = bind_port_and_increment().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args = [
        "-n".to_string(),
        "1".to_string(),
        format!("http://{host}/source"),
        "--connect-to".to_string(),
        format!("{host}:80:localhost:{port}"),
    ];
    run(args.iter().map(|s| s.as_str())).await;

    rx.try_recv().unwrap().unwrap()
}

async fn test_request_count(args: &[&str]) -> usize {
    let (tx, rx) = kanal::unbounded();

    let app = Router::new().route(
        "/",
        get(|| async move {
            tx.send(()).unwrap();
            "Success"
        }),
    );

    let (listener, port) = bind_port_and_increment().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let mut args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    args.push(format!("http://127.0.0.1:{port}"));
    run(args.iter().map(|s| s.as_str())).await;

    let mut count = 0;
    while let Ok(Some(())) = rx.try_recv() {
        count += 1;
    }
    count
}

// Randomly spread 100 requests on two matching --connect-to targets, and return a count for each
async fn distribution_on_two_matching_connect_to(host: &'static str) -> (i32, i32) {
    let (tx1, rx1) = kanal::unbounded();
    let (tx2, rx2) = kanal::unbounded();

    let app1 = Router::new().route(
        "/",
        get(move || async move {
            tx1.send(()).unwrap();
            "Success1"
        }),
    );

    let app2 = Router::new().route(
        "/",
        get(move || async move {
            tx2.send(()).unwrap();
            "Success2"
        }),
    );

    let (listener1, port1) = bind_port_and_increment().await;
    tokio::spawn(async { axum::serve(listener1, app1).await });

    let (listener2, port2) = bind_port_and_increment().await;
    tokio::spawn(async { axum::serve(listener2, app2).await });

    let args = [
        "-n".to_string(),
        "100".to_string(),
        format!("http://{host}/"),
        "--connect-to".to_string(),
        format!("{host}:80:localhost:{port1}"),
        "--connect-to".to_string(),
        format!("{host}:80:localhost:{port2}"),
    ];
    run(args.iter().map(|s| s.as_str())).await;

    let mut count1 = 0;
    let mut count2 = 0;
    loop {
        if rx1.try_recv().unwrap().is_some() {
            count1 += 1;
        } else if rx2.try_recv().unwrap().is_some() {
            count2 += 1;
        } else {
            break;
        }
    }
    (count1, count2)
}

#[apply(test_all_http_versions)]
#[tokio::test(flavor = "multi_thread")]
async fn test_enable_compression_default(http_version_param: &str) {
    let req = get_req("/", &["--http-version", http_version_param]).await;
    let accept_encoding: Vec<&str> = req
        .headers()
        .get("accept-encoding")
        .unwrap()
        .to_str()
        .unwrap()
        .split(", ")
        .collect();

    assert!(accept_encoding.contains(&"gzip"));
    assert!(accept_encoding.contains(&"br"));
}

#[apply(test_all_http_versions)]
#[tokio::test(flavor = "multi_thread")]
async fn test_setting_custom_header(http_version_param: &str) {
    let req = get_req(
        "/",
        &["--http-version", http_version_param, "-H", "foo: bar"],
    )
    .await;
    assert_eq!(req.headers().get("foo").unwrap().to_str().unwrap(), "bar");
}

#[tokio::test(flavor = "multi_thread")]
#[apply(test_all_http_versions)]
async fn test_setting_accept_header(http_version_param: &str) {
    let req = get_req(
        "/",
        &["-A", "text/html", "--http-version", http_version_param],
    )
    .await;
    assert_eq!(
        req.headers().get("accept").unwrap().to_str().unwrap(),
        "text/html"
    );
    let req = get_req(
        "/",
        &[
            "-H",
            "accept:text/html",
            "--http-version",
            http_version_param,
        ],
    )
    .await;
    assert_eq!(
        req.headers().get("accept").unwrap().to_str().unwrap(),
        "text/html"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[apply(test_all_http_versions)]
async fn test_setting_body(http_version_param: &str) {
    let req = get_req(
        "/",
        &["-d", "hello body", "--http-version", http_version_param],
    )
    .await;
    assert_eq!(
        req.into_body(),
        &b"hello body"[..] /* This looks dirty... Any suggestion? */
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_setting_content_type_header() {
    let req = get_req("/", &["-T", "text/html"]).await;
    assert_eq!(
        req.headers().get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );
    let req = get_req("/", &["-H", "content-type:text/html"]).await;
    assert_eq!(
        req.headers().get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );

    let req = get_req("/", &["--http2", "-T", "text/html"]).await;
    assert_eq!(
        req.headers().get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );
    let req = get_req("/", &["--http2", "-H", "content-type:text/html"]).await;
    assert_eq!(
        req.headers().get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );
}

#[apply(test_all_http_versions)]
#[tokio::test(flavor = "multi_thread")]
async fn test_setting_basic_auth(http_version_param: &str) {
    let req = get_req(
        "/",
        &["-a", "hatoo:pass", "--http-version", http_version_param],
    )
    .await;
    assert_eq!(
        req.headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Basic aGF0b286cGFzcw=="
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_setting_host() {
    let req = get_req("/", &["--host", "hatoo.io"]).await;
    assert_eq!(
        req.headers().get("host").unwrap().to_str().unwrap(),
        "hatoo.io"
    );

    let req = get_req("/", &["-H", "host:hatoo.io"]).await;
    assert_eq!(
        req.headers().get("host").unwrap().to_str().unwrap(),
        "hatoo.io"
    );

    // You shouldn't set host header when using HTTP/2
    // Use --connect-to instead
}

#[tokio::test(flavor = "multi_thread")]
async fn test_setting_method() {
    assert_eq!(get_req("/", &[]).await.method(), http::method::Method::GET);
    assert_eq!(
        get_req("/", &["-m", "GET"]).await.method(),
        http::method::Method::GET
    );
    assert_eq!(
        get_req("/", &["-m", "POST"]).await.method(),
        http::method::Method::POST
    );
    assert_eq!(
        get_req("/", &["-m", "CONNECT"]).await.method(),
        http::method::Method::CONNECT
    );
    assert_eq!(
        get_req("/", &["-m", "DELETE"]).await.method(),
        http::method::Method::DELETE
    );
    assert_eq!(
        get_req("/", &["-m", "HEAD"]).await.method(),
        http::method::Method::HEAD
    );
    assert_eq!(
        get_req("/", &["-m", "OPTIONS"]).await.method(),
        http::method::Method::OPTIONS
    );
    assert_eq!(
        get_req("/", &["-m", "PATCH"]).await.method(),
        http::method::Method::PATCH
    );
    assert_eq!(
        get_req("/", &["-m", "PUT"]).await.method(),
        http::method::Method::PUT
    );
    assert_eq!(
        get_req("/", &["-m", "TRACE"]).await.method(),
        http::method::Method::TRACE
    );

    assert_eq!(
        get_req("/", &["--http2"]).await.method(),
        http::method::Method::GET
    );
    assert_eq!(
        get_req("/", &["--http2", "-m", "GET"]).await.method(),
        http::method::Method::GET
    );
    assert_eq!(
        get_req("/", &["--http2", "-m", "POST"]).await.method(),
        http::method::Method::POST
    );
    assert_eq!(
        get_req("/", &["--http2", "-m", "DELETE"]).await.method(),
        http::method::Method::DELETE
    );
    assert_eq!(
        get_req("/", &["--http2", "-m", "HEAD"]).await.method(),
        http::method::Method::HEAD
    );
    assert_eq!(
        get_req("/", &["--http2", "-m", "OPTIONS"]).await.method(),
        http::method::Method::OPTIONS
    );
    assert_eq!(
        get_req("/", &["--http2", "-m", "PATCH"]).await.method(),
        http::method::Method::PATCH
    );
    assert_eq!(
        get_req("/", &["--http2", "-m", "PUT"]).await.method(),
        http::method::Method::PUT
    );
    assert_eq!(
        get_req("/", &["--http2", "-m", "TRACE"]).await.method(),
        http::method::Method::TRACE
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_query() {
    assert_eq!(
        get_req("/index?a=b&c=d", &[]).await.uri().to_string(),
        "/index?a=b&c=d".to_string()
    );

    assert_eq!(
        get_req("/index?a=b&c=d", &["--http2"])
            .await
            .uri()
            .to_string()
            .split('/')
            .next_back()
            .unwrap(),
        "index?a=b&c=d".to_string()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_query_rand_regex() {
    let req = get_req("/[a-z][0-9][a-z]", &["--rand-regex-url"]).await;
    let chars = req
        .uri()
        .to_string()
        .trim_start_matches('/')
        .chars()
        .collect::<Vec<char>>();
    assert_eq!(chars.len(), 3);
    assert!(chars[0].is_ascii_lowercase());
    assert!(chars[1].is_ascii_digit());
    assert!(chars[2].is_ascii_lowercase());

    let req = get_req("/[a-z][0-9][a-z]", &["--http2", "--rand-regex-url"]).await;
    let chars = req
        .uri()
        .to_string()
        .split('/')
        .next_back()
        .unwrap()
        .chars()
        .collect::<Vec<char>>();
    assert_eq!(chars.len(), 3);
    assert!(chars[0].is_ascii_lowercase());
    assert!(chars[1].is_ascii_digit());
    assert!(chars[2].is_ascii_lowercase());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_redirect() {
    for n in 1..=5 {
        assert!(redirect(n, true, 10).await);
        assert!(redirect(n, false, 10).await);
    }
    for n in 11..=15 {
        assert!(!redirect(n, true, 10).await);
        assert!(!redirect(n, false, 10).await);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to() {
    assert_eq!(
        get_host_with_connect_to("invalid.example.org").await,
        "invalid.example.org"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_randomness() {
    let (count1, count2) = distribution_on_two_matching_connect_to("invalid.example.org").await;
    assert!(count1 + count2 == 100);
    assert!(count1 >= 10 && count2 >= 10); // should not be too flaky with 100 coin tosses
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_ipv6_target() {
    assert_eq!(
        get_host_with_connect_to_ipv6_target("invalid.example.org").await,
        "invalid.example.org"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_ipv6_requested() {
    assert_eq!(get_host_with_connect_to_ipv6_requested().await, "[::1]")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_redirect() {
    assert_eq!(
        get_host_with_connect_to_redirect("invalid.example.org").await,
        "invalid.example.org"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_http_proxy_override() {
    let (tx, rx) = kanal::unbounded();
    let proxy_port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", proxy_port))
        .await
        .unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let tx = tx.clone();

        hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |req: Request<Incoming>| {
                    let tx = tx.clone();
                    async move {
                        let authority = req
                            .uri()
                            .authority()
                            .map(|a| a.to_string())
                            .expect("proxy received origin-form request");
                        let host = req
                            .headers()
                            .get("host")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string())
                            .unwrap_or_default();
                        tx.send((authority, host)).unwrap();
                        Ok::<_, Infallible>(Response::new("proxy".to_string()))
                    }
                }),
            )
            .await
            .unwrap();
    });

    let override_port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let args = [
        "-n".to_string(),
        "1".to_string(),
        "-x".to_string(),
        format!("http://127.0.0.1:{proxy_port}"),
        "--connect-to".to_string(),
        format!("example.test:80:127.0.0.1:{override_port}"),
        "http://example.test/".to_string(),
    ];
    run(args.iter().map(|s| s.as_str())).await;

    let (authority, host) = rx.try_recv().unwrap().unwrap();
    assert_eq!(authority, format!("127.0.0.1:{override_port}"));
    assert_eq!(host, "example.test");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_https_proxy_connect_override() {
    let (connect_tx, connect_rx) = kanal::unbounded();
    let (host_tx, host_rx) = kanal::unbounded();

    let service = service_fn(move |req: Request<Incoming>| {
        let host_tx = host_tx.clone();
        async move {
            let host = req
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_default();
            host_tx.send(host).unwrap();
            Ok::<_, Infallible>(Response::new("Hello World".to_string()))
        }
    });

    let (proxy_port, proxy_serve) =
        bind_proxy_with_recorder(service, false, connect_tx.clone()).await;

    tokio::spawn(proxy_serve);

    let override_port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let args = vec![
        "-n".to_string(),
        "1".to_string(),
        "--insecure".to_string(),
        "-x".to_string(),
        format!("http://127.0.0.1:{proxy_port}"),
        "--proxy-header".to_string(),
        "proxy-authorization: test".to_string(),
        "--connect-to".to_string(),
        format!("example.test:443:127.0.0.1:{override_port}"),
        "https://example.test/".to_string(),
    ];
    run(args.iter().map(|s| s.as_str())).await;

    let connect_target = connect_rx.try_recv().unwrap().unwrap();
    assert_eq!(connect_target, format!("127.0.0.1:{override_port}"));
    let host_header = host_rx.try_recv().unwrap().unwrap();
    assert_eq!(host_header, "example.test");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ipv6() {
    let (tx, rx) = kanal::unbounded();

    let app = Router::new().route(
        "/",
        get(|| async move {
            tx.send(()).unwrap();
            "Hello World"
        }),
    );

    let port = next_port();
    let listener = bind_port_ipv6(port).await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args = [
        "-n".to_string(),
        "1".to_string(),
        format!("http://[::1]:{port}/"),
    ];
    run(args.iter().map(|s| s.as_str())).await;

    rx.try_recv().unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_query_limit() {
    // burst 10 requests with delay of 2s and rate of 4
    let mut args = vec!["-n", "10", "--burst-delay", "2s", "--burst-rate", "4"];
    assert_eq!(test_request_count(args.as_slice()).await, 10);
    args.push("--http2");
    assert_eq!(test_request_count(args.as_slice()).await, 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_query_limit_with_time_limit() {
    // 1.75 qps for 2sec = expect 4 requests at times 0, 0.571, 1.142, 1,714sec
    assert_eq!(test_request_count(&["-z", "2s", "-q", "1.75"]).await, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_http_versions() {
    assert_eq!(get_req("/", &[]).await.version(), http::Version::HTTP_11);
    assert_eq!(
        get_req("/", &["--http2"]).await.version(),
        http::Version::HTTP_2
    );
    assert_eq!(
        get_req("/", &["--http-version", "2"]).await.version(),
        http::Version::HTTP_2
    );
    #[cfg(feature = "http3")]
    assert_eq!(
        get_req("/", &["--http-version", "3"]).await.version(),
        http::Version::HTTP_3
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn test_unix_socket() {
    let (tx, rx) = kanal::unbounded();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("socket");

    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        actix_web::HttpServer::new(move || {
            let tx = actix_web::web::Data::new(tx.clone());
            actix_web::App::new().service(actix_web::web::resource("/").to(move || {
                let tx = tx.clone();
                async move {
                    tx.send(()).unwrap();
                    "Hello World"
                }
            }))
        })
        .listen_uds(listener)
        .unwrap()
        .run()
        .await
        .unwrap();
    });

    let args = [
        "-n".to_string(),
        "1".to_string(),
        "--unix-socket".to_string(),
        path.to_str().unwrap().to_string(),
        "http://unix-socket.invalid-tld/".to_string(),
    ];
    run(args.iter().map(|s| s.as_str())).await;

    rx.try_recv().unwrap().unwrap();
}

fn make_root_issuer() -> rcgen::Issuer<'static, rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::default();

    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<HTTP-MITM-PROXY CA>".to_string()),
    );
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let signing_key = rcgen::KeyPair::generate().unwrap();

    rcgen::Issuer::new(params, signing_key)
}

async fn bind_proxy<S>(service: S, http2: bool) -> (u16, impl Future<Output = ()>)
where
    S: HttpService<Incoming> + Clone + Send + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::ResBody: Send + Sync + 'static,
    <S::ResBody as Body>::Data: Send,
    <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::Future: Send,
{
    let port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tcp_listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();

    install_crypto_provider();
    let issuer = make_root_issuer();
    let proxy = Arc::new(http_mitm_proxy::MitmProxy::new(Some(issuer), None));

    let serve = async move {
        let (stream, _) = tcp_listener.accept().await.unwrap();

        let proxy = proxy.clone();
        let service = service.clone();

        let outer = service_fn(move |req| {
            // Test --proxy-header option
            assert_eq!(
                req.headers()
                    .get("proxy-authorization")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "test"
            );

            MitmProxy::wrap_service(proxy.clone(), service.clone()).call(req)
        });

        tokio::spawn(async move {
            if http2 {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), outer)
                    .await;
            } else {
                let _ = hyper::server::conn::http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(TokioIo::new(stream), outer)
                    .with_upgrades()
                    .await;
            }
        });
    };

    (port, serve)
}

async fn bind_proxy_with_recorder<S>(
    service: S,
    http2: bool,
    recorder: kanal::Sender<String>,
) -> (u16, impl Future<Output = ()>)
where
    S: HttpService<Incoming> + Clone + Send + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::ResBody: Send + Sync + 'static,
    <S::ResBody as Body>::Data: Send,
    <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::Future: Send,
{
    let port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tcp_listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();

    install_crypto_provider();
    let issuer = make_root_issuer();
    let proxy = Arc::new(http_mitm_proxy::MitmProxy::new(Some(issuer), None));

    let serve = async move {
        let (stream, _) = tcp_listener.accept().await.unwrap();

        let proxy = proxy.clone();
        let service = service.clone();
        let recorder = recorder.clone();

        let outer = service_fn(move |req| {
            let recorder = recorder.clone();
            if req.method() == hyper::Method::CONNECT {
                recorder.send(req.uri().to_string()).unwrap();
            }

            assert_eq!(
                req.headers()
                    .get("proxy-authorization")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "test"
            );

            MitmProxy::wrap_service(proxy.clone(), service.clone()).call(req)
        });

        tokio::spawn(async move {
            if http2 {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), outer)
                    .await;
            } else {
                let _ = hyper::server::conn::http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(TokioIo::new(stream), outer)
                    .with_upgrades()
                    .await;
            }
        });
    };

    (port, serve)
}

async fn test_proxy_with_setting(https: bool, http2: bool, proxy_http2: bool) {
    let (proxy_port, proxy_serve) = bind_proxy(
        service_fn(|_req| async {
            let res = Response::new("Hello World".to_string());
            Ok::<_, Infallible>(res)
        }),
        proxy_http2,
    )
    .await;

    tokio::spawn(proxy_serve);

    let mut args = Vec::new();

    let scheme = if https { "https" } else { "http" };
    args.extend(
        [
            "--no-tui",
            "-n",
            "1",
            "--no-tui",
            "--output-format",
            "quiet",
            "--insecure",
            "-x",
        ]
        .into_iter()
        .map(|s| s.to_string()),
    );
    args.push(format!("http://127.0.0.1:{proxy_port}/"));
    args.extend(
        ["--proxy-header", "proxy-authorization: test"]
            .into_iter()
            .map(|s| s.to_string()),
    );
    args.push(format!("{scheme}://example.com/"));
    if http2 {
        args.push("--http2".to_string());
    }
    if proxy_http2 {
        args.push("--proxy-http2".to_string());
    }

    use clap::Parser;
    let opts = oha::Opts::try_parse_from(args).unwrap();
    oha::run(opts).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proxy() {
    for https in [false, true] {
        for http2 in [false, true] {
            for proxy_http2 in [false, true] {
                test_proxy_with_setting(https, http2, proxy_http2).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_google() {
    let temp_path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let args = vec![
        "oha".to_string(),
        "--no-tui".to_string(),
        "-n".to_string(),
        "1".to_string(),
        "https://www.google.com/".to_string(),
        "--output".to_string(),
        temp_path.to_str().unwrap().to_string(),
    ];
    let opts = oha::Opts::try_parse_from(args).unwrap();
    oha::run(opts).await.unwrap();

    let output = std::fs::read_to_string(&temp_path).unwrap();
    assert!(output.contains("[200] 1 responses\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_json_schema() {
    let app = Router::new().route("/", get(|| async move { "Hello World" }));

    let (listener, port) = bind_port_and_increment().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    const SCHEMA: &str = include_str!("../schema.json");
    let schema_value: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema_value).unwrap();

    let temp_path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let args = vec![
        "oha".to_string(),
        "--no-tui".to_string(),
        "-n".to_string(),
        "10".to_string(),
        "--output-format".to_string(),
        "json".to_string(),
        format!("http://127.0.0.1:{port}/"),
        "--output".to_string(),
        temp_path.to_str().unwrap().to_string(),
    ];
    let opts = oha::Opts::try_parse_from(args).unwrap();
    oha::run(opts).await.unwrap();

    let output_json = std::fs::read_to_string(&temp_path).unwrap();

    let temp_path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let args = vec![
        "oha".to_string(),
        "--no-tui".to_string(),
        "-n".to_string(),
        "10".to_string(),
        "--output-format".to_string(),
        "json".to_string(),
        "--stats-success-breakdown".to_string(),
        format!("http://127.0.0.1:{port}/"),
        "--output".to_string(),
        temp_path.to_str().unwrap().to_string(),
    ];
    let opts = oha::Opts::try_parse_from(args).unwrap();
    oha::run(opts).await.unwrap();
    let output_json_stats_success_breakdown = std::fs::read_to_string(&temp_path).unwrap();

    let value: serde_json::Value = serde_json::from_str(&output_json).unwrap();
    let value_stats_success_breakdown: serde_json::Value =
        serde_json::from_str(&output_json_stats_success_breakdown).unwrap();

    if validator.validate(&value).is_err() {
        for error in validator.iter_errors(&value) {
            eprintln!("{error}");
        }
        panic!("JSON schema validation failed\n{output_json}");
    }

    if validator.validate(&value_stats_success_breakdown).is_err() {
        for error in validator.iter_errors(&value_stats_success_breakdown) {
            eprintln!("{error}");
        }
        panic!("JSON schema validation failed\n{output_json_stats_success_breakdown}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_csv_output() {
    let app = Router::new().route("/", get(|| async move { "Hello World" }));

    let (listener, port) = bind_port_and_increment().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let temp_path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let args = vec![
        "oha".to_string(),
        "--no-tui".to_string(),
        "-n".to_string(),
        "5".to_string(),
        "--output-format".to_string(),
        "csv".to_string(),
        format!("http://127.0.0.1:{port}/"),
        "--output".to_string(),
        temp_path.to_str().unwrap().to_string(),
    ];
    let opts = oha::Opts::try_parse_from(args).unwrap();
    oha::run(opts).await.unwrap();
    let output_csv = std::fs::read_to_string(&temp_path).unwrap();

    // Validate that we get CSV output in following format,
    // header and one row for each request:
    // request-start,DNS,DNS+dialup,Response-delay,request-duration,bytes,status
    // 0.002211678,0.000374078,0.001148565,0.002619327,0.002626127,11,200
    // ...

    let lines: Vec<&str> = output_csv.lines().collect();
    assert_eq!(lines.len(), 6);
    assert_eq!(
        lines[0],
        "request-start,DNS,DNS+dialup,Response-delay,request-duration,bytes,status"
    );
    let mut latest_start = 0f64;
    for line in lines.iter().skip(1) {
        let parts: Vec<&str> = line.split(",").collect();
        assert_eq!(parts.len(), 7);
        // validate that the requests are in ascending time order
        let current_start = f64::from_str(parts[0]).unwrap();
        assert!(current_start >= latest_start);
        latest_start = current_start;
        assert!(f64::from_str(parts[1]).unwrap() > 0f64);
        assert!(f64::from_str(parts[2]).unwrap() > 0f64);
        assert!(f64::from_str(parts[3]).unwrap() > 0f64);
        assert!(f64::from_str(parts[4]).unwrap() > 0f64);
        assert_eq!(usize::from_str(parts[5]).unwrap(), 11);
        assert_eq!(u16::from_str(parts[6]).unwrap(), 200);
    }
}

fn setup_mtls_server(
    dir: std::path::PathBuf,
) -> (u16, impl Future<Output = Result<(), std::io::Error>>) {
    let port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(|| async { "Hello, World" }));

    let make_cert = || {
        // Workaround for mac & native-tls
        // https://github.com/sfackler/rust-native-tls/issues/225
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();

        let cert = params.self_signed(&key_pair).unwrap();
        (cert, key_pair)
    };

    let server_cert = make_cert();
    let client_cert = make_cert();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(client_cert.0.der().clone()).unwrap();
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.0.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                server_cert.1.serialize_der(),
            )),
        )
        .unwrap();

    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));

    File::create(dir.join("server.crt"))
        .unwrap()
        .write_all(server_cert.0.pem().as_bytes())
        .unwrap();

    File::create(dir.join("client.crt"))
        .unwrap()
        .write_all(client_cert.0.pem().as_bytes())
        .unwrap();

    File::create(dir.join("client.key"))
        .unwrap()
        .write_all(client_cert.1.serialize_pem().as_bytes())
        .unwrap();

    (
        port,
        axum_server::bind_rustls(addr, config).serve(app.into_make_service()),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mtls() {
    let dir = tempfile::tempdir().unwrap();
    let (port, server) = setup_mtls_server(dir.path().to_path_buf());

    tokio::spawn(server);

    let args = vec![
        "-n".to_string(),
        "1".to_string(),
        "--cacert".to_string(),
        dir.path().join("server.crt").to_string_lossy().to_string(),
        "--cert".to_string(),
        dir.path().join("client.crt").to_string_lossy().to_string(),
        "--key".to_string(),
        dir.path().join("client.key").to_string_lossy().to_string(),
        format!("https://localhost:{port}/"),
    ];

    run(args.iter().map(|s| s.as_str())).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_body_path_lines() {
    let body = "0\n1\n2";
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(body.as_bytes()).unwrap();

    let tmp_path = tmp.path().to_str().unwrap();

    let mut counts = [0; 3];
    for _ in 0..32 {
        let req = get_req("/", ["-Z", tmp_path, "-m", "POST"].as_slice()).await;

        let req_body = req.into_body();
        let line = std::str::from_utf8(&req_body).unwrap();
        counts[line.parse::<usize>().unwrap()] += 1;
    }

    // test failure rate should be very low
    assert!(counts.iter().all(|&c| c > 0));
}
