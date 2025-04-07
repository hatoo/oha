use std::{
    convert::Infallible,
    error::Error as StdError,
    fs::File,
    future::Future,
    io::Write,
    net::{Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, atomic::AtomicU16},
};

use assert_cmd::Command;
use axum::{Router, extract::Path, response::Redirect, routing::get};
use http::{HeaderMap, Request, Response};
use http_body_util::BodyExt;
use http_mitm_proxy::MitmProxy;
use hyper::{
    body::{Body, Incoming},
    http,
    service::{HttpService, service_fn},
};
use hyper_util::rt::{TokioExecutor, TokioIo};

// Port 5111- is reserved for testing
static PORT: AtomicU16 = AtomicU16::new(5111);

async fn bind_port() -> (tokio::net::TcpListener, u16) {
    let port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);

    (tokio::net::TcpListener::bind(addr).await.unwrap(), port)
}

async fn bind_port_ipv6() -> (tokio::net::TcpListener, u16) {
    let port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let addr = SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST), port);

    (tokio::net::TcpListener::bind(addr).await.unwrap(), port)
}

async fn get_req(path: &str, args: &[&str]) -> Request<hyper::body::Incoming> {
    let (tx, rx) = flume::unbounded();

    let (listener, port) = bind_port().await;

    let http2 = args.iter().any(|&arg| arg == "--http2")
        || args.windows(2).any(|w| w == ["--http-version", "2"]);

    tokio::spawn(async move {
        if http2 {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let tx = tx.clone();
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(tcp),
                        service_fn(move |req| {
                            let tx = tx.clone();

                            async move {
                                tx.send(req).unwrap();
                                Ok::<_, Infallible>(Response::new("Hello World".to_string()))
                            }
                        }),
                    )
                    .await;
            }
        } else {
            let (tcp, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(tcp),
                    service_fn(move |req| {
                        let tx = tx.clone();

                        async move {
                            tx.send(req).unwrap();
                            Ok::<_, Infallible>(Response::new("Hello World".to_string()))
                        }
                    }),
                )
                .await
                .unwrap();
        }
    });

    let mut command = Command::cargo_bin("oha").unwrap();
    command
        .args(["-n", "1", "--no-tui"])
        .args(args)
        .arg(format!("http://127.0.0.1:{port}{path}"));

    tokio::task::spawn_blocking(move || {
        command.assert().success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn redirect(n: usize, is_relative: bool, limit: usize) -> bool {
    let (tx, rx) = flume::unbounded();

    let (listener, port) = bind_port().await;

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

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui", "--redirect"])
            .arg(limit.to_string())
            .arg(format!("http://127.0.0.1:{port}/0"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().is_ok()
}

async fn get_host_with_connect_to(host: &'static str) -> String {
    let (tx, rx) = flume::unbounded();

    let app = Router::new().route(
        "/",
        get(|header: HeaderMap| async move {
            tx.send(header.get("host").unwrap().to_str().unwrap().to_string())
                .unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .arg(format!("http://{host}/"))
            .arg("--connect-to")
            .arg(format!("{host}:80:localhost:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_host_with_connect_to_ipv6_target(host: &'static str) -> String {
    let (tx, rx) = flume::unbounded();
    let app = Router::new().route(
        "/",
        get(|header: HeaderMap| async move {
            tx.send(header.get("host").unwrap().to_str().unwrap().to_string())
                .unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port_ipv6().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .arg(format!("http://{host}/"))
            .arg("--connect-to")
            .arg(format!("{host}:80:[::1]:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_host_with_connect_to_ipv6_requested() -> String {
    let (tx, rx) = flume::unbounded();
    let app = Router::new().route(
        "/",
        get(|header: HeaderMap| async move {
            tx.send(header.get("host").unwrap().to_str().unwrap().to_string())
                .unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .arg("http://[::1]/")
            .arg("--connect-to")
            .arg(format!("[::1]:80:localhost:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_host_with_connect_to_redirect(host: &'static str) -> String {
    let (tx, rx) = flume::unbounded();

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

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .arg(format!("http://{host}/source"))
            .arg("--connect-to")
            .arg(format!("{host}:80:localhost:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn test_request_count(args: &[&str]) -> usize {
    let (tx, rx) = flume::unbounded();

    let app = Router::new().route(
        "/",
        get(|| async move {
            tx.send(()).unwrap();
            "Success"
        }),
    );

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["--no-tui"])
            .args(args)
            .arg(format!("http://127.0.0.1:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    let mut count = 0;
    while let Ok(()) = rx.try_recv() {
        count += 1;
    }
    count
}

// Randomly spread 100 requests on two matching --connect-to targets, and return a count for each
async fn distribution_on_two_matching_connect_to(host: &'static str) -> (i32, i32) {
    let (tx1, rx1) = flume::unbounded();
    let (tx2, rx2) = flume::unbounded();

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

    let (listener1, port1) = bind_port().await;
    tokio::spawn(async { axum::serve(listener1, app1).await });

    let (listener2, port2) = bind_port().await;
    tokio::spawn(async { axum::serve(listener2, app2).await });

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "100", "--no-tui"])
            .arg(format!("http://{host}/"))
            .arg("--connect-to")
            .arg(format!("{host}:80:localhost:{port1}"))
            .arg("--connect-to")
            .arg(format!("{host}:80:localhost:{port2}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    let mut count1 = 0;
    let mut count2 = 0;
    loop {
        if rx1.try_recv().is_ok() {
            count1 += 1;
        } else if rx2.try_recv().is_ok() {
            count2 += 1;
        } else {
            break;
        }
    }
    (count1, count2)
}

#[tokio::test]
async fn test_enable_compression_default() {
    let req = get_req("/", &[]).await;
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

    let req = get_req("/", &["--http2"]).await;
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

#[tokio::test]
async fn test_setting_custom_header() {
    let req = get_req("/", &["-H", "foo: bar", "--"]).await;
    assert_eq!(req.headers().get("foo").unwrap().to_str().unwrap(), "bar");
    let req = get_req("/", &["-H", "foo:bar", "--"]).await;
    assert_eq!(req.headers().get("foo").unwrap().to_str().unwrap(), "bar");

    let req = get_req("/", &["--http2", "-H", "foo: bar", "--"]).await;
    assert_eq!(req.headers().get("foo").unwrap().to_str().unwrap(), "bar");
    let req = get_req("/", &["--http2", "-H", "foo:bar", "--"]).await;
    assert_eq!(req.headers().get("foo").unwrap().to_str().unwrap(), "bar");
}

#[tokio::test]
async fn test_setting_accept_header() {
    let req = get_req("/", &["-A", "text/html"]).await;
    assert_eq!(
        req.headers().get("accept").unwrap().to_str().unwrap(),
        "text/html"
    );
    let req = get_req("/", &["-H", "accept:text/html"]).await;
    assert_eq!(
        req.headers().get("accept").unwrap().to_str().unwrap(),
        "text/html"
    );

    let req = get_req("/", &["--http2", "-A", "text/html"]).await;
    assert_eq!(
        req.headers().get("accept").unwrap().to_str().unwrap(),
        "text/html"
    );
    let req = get_req("/", &["--http2", "-H", "accept:text/html"]).await;
    assert_eq!(
        req.headers().get("accept").unwrap().to_str().unwrap(),
        "text/html"
    );
}

#[tokio::test]
async fn test_setting_body() {
    let req = get_req("/", &["-d", "hello body"]).await;
    assert_eq!(
        req.into_body().collect().await.unwrap().to_bytes(),
        &b"hello body"[..] /* This looks dirty... Any suggestion? */
    );

    let req = get_req("/", &["--http2", "-d", "hello body"]).await;
    assert_eq!(
        req.into_body().collect().await.unwrap().to_bytes(),
        &b"hello body"[..] /* This looks dirty... Any suggestion? */
    );
}

#[tokio::test]
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

#[tokio::test]
async fn test_setting_basic_auth() {
    let req = get_req("/", &["-a", "hatoo:pass"]).await;
    assert_eq!(
        req.headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Basic aGF0b286cGFzcw=="
    );

    let req = get_req("/", &["--http2", "-a", "hatoo:pass"]).await;
    assert_eq!(
        req.headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Basic aGF0b286cGFzcw=="
    );
}

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
async fn test_connect_to() {
    assert_eq!(
        get_host_with_connect_to("invalid.example.org").await,
        "invalid.example.org"
    )
}

#[tokio::test]
async fn test_connect_to_randomness() {
    let (count1, count2) = distribution_on_two_matching_connect_to("invalid.example.org").await;
    assert!(count1 >= 10 && count2 >= 10); // should not be too flaky with 100 coin tosses
    assert!(count1 + count2 == 100);
}

#[tokio::test]
async fn test_connect_to_ipv6_target() {
    assert_eq!(
        get_host_with_connect_to_ipv6_target("invalid.example.org").await,
        "invalid.example.org"
    )
}

#[tokio::test]
async fn test_connect_to_ipv6_requested() {
    assert_eq!(get_host_with_connect_to_ipv6_requested().await, "[::1]")
}

#[tokio::test]
async fn test_connect_to_redirect() {
    assert_eq!(
        get_host_with_connect_to_redirect("invalid.example.org").await,
        "invalid.example.org"
    )
}

#[tokio::test]
async fn test_ipv6() {
    let (tx, rx) = flume::unbounded();

    let app = Router::new().route(
        "/",
        get(|| async move {
            tx.send(()).unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port_ipv6().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .arg(format!("http://[::1]:{port}/"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap();
}

#[tokio::test]
async fn test_query_limit() {
    // burst 10 requests with delay of 2s and rate of 4
    let mut args = vec!["-n", "10", "--burst-delay", "2s", "--burst-rate", "4"];
    assert_eq!(test_request_count(args.as_slice()).await, 10);
    args.push("--http2");
    assert_eq!(test_request_count(args.as_slice()).await, 10);
}

#[tokio::test]
async fn test_query_limit_with_time_limit() {
    // 1.75 qps for 2sec = expect 4 requests at times 0, 0.571, 1.142, 1,714sec
    assert_eq!(test_request_count(&["-z", "2s", "-q", "1.75"]).await, 4);
}

#[tokio::test]
async fn test_http2() {
    assert_eq!(get_req("/", &[]).await.version(), http::Version::HTTP_11);
    assert_eq!(
        get_req("/", &["--http2"]).await.version(),
        http::Version::HTTP_2
    );
    assert_eq!(
        get_req("/", &["--http-version", "2"]).await.version(),
        http::Version::HTTP_2
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_unix_socket() {
    let (tx, rx) = flume::unbounded();

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

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args([
                "-n",
                "1",
                "--no-tui",
                "--unix-socket",
                path.to_str().unwrap(),
                "http://unix-socket.invalid-tld/",
            ])
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap();
}

fn make_root_cert() -> rcgen::CertifiedKey {
    let mut param = rcgen::CertificateParams::default();

    param.distinguished_name = rcgen::DistinguishedName::new();
    param.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<HTTP-MITM-PROXY CA>".to_string()),
    );
    param.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = param.self_signed(&key_pair).unwrap();

    rcgen::CertifiedKey { cert, key_pair }
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

    let cert = make_root_cert();
    let proxy = Arc::new(http_mitm_proxy::MitmProxy::new(Some(cert), None));

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
        ["--no-tui", "--debug", "--insecure", "-x"]
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

#[tokio::test]
async fn test_proxy() {
    for https in [false, true] {
        for http2 in [false, true] {
            for proxy_http2 in [false, true] {
                test_proxy_with_setting(https, http2, proxy_http2).await;
            }
        }
    }
}

#[test]
fn test_google() {
    Command::cargo_bin("oha")
        .unwrap()
        .args(["-n", "1", "--no-tui"])
        .arg("https://www.google.com/")
        .assert()
        .success()
        .stdout(predicates::str::contains("[200] 1 responses"));
}

#[tokio::test]
async fn test_json_schema() {
    let app = Router::new().route("/", get(|| async move { "Hello World" }));

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    const SCHEMA: &str = include_str!("../schema.json");
    let schema_value: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema_value).unwrap();

    let output_json: String = String::from_utf8(
        tokio::task::spawn_blocking(move || {
            Command::cargo_bin("oha")
                .unwrap()
                .args(["-n", "10", "--no-tui", "--output-format", "json"])
                .arg(format!("http://127.0.0.1:{port}/"))
                .assert()
                .get_output()
                .stdout
                .clone()
        })
        .await
        .unwrap(),
    )
    .unwrap();

    let output_json_stats_success_breakdown: String = String::from_utf8(
        tokio::task::spawn_blocking(move || {
            Command::cargo_bin("oha")
                .unwrap()
                .args([
                    "-n",
                    "10",
                    "--no-tui",
                    "--output-format",
                    "json",
                    "--stats-success-breakdown",
                ])
                .arg(format!("http://127.0.0.1:{port}/"))
                .assert()
                .get_output()
                .stdout
                .clone()
        })
        .await
        .unwrap(),
    )
    .unwrap();

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

#[tokio::test]
async fn test_csv_output() {
    let app = Router::new().route("/", get(|| async move { "Hello World" }));

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let output_csv: String = String::from_utf8(
        tokio::task::spawn_blocking(move || {
            Command::cargo_bin("oha")
                .unwrap()
                .args(["-n", "5", "--no-tui", "--output-format", "csv"])
                .arg(format!("http://127.0.0.1:{port}/"))
                .assert()
                .get_output()
                .stdout
                .clone()
        })
        .await
        .unwrap(),
    )
    .unwrap();

    // Validate that we get CSV output in following format,
    // header and one row for each request:
    // request-start,DNS,DNS+dialup,request-duration,bytes,status
    // 0.002219628,0.000309806,0.001021632,0.002023073,11,200
    // ...

    let lines: Vec<&str> = output_csv.lines().collect();
    assert_eq!(lines.len(), 6);
    assert_eq!(
        lines[0],
        "request-start,DNS,DNS+dialup,request-duration,bytes,status"
    );
    let mut latest_start = 0f64;
    for line in lines.iter().skip(1) {
        let parts: Vec<&str> = line.split(",").collect();
        assert_eq!(parts.len(), 6);
        // validate that the requests are in ascending time order
        let current_start = f64::from_str(parts[0]).unwrap();
        println!("current: {current_start}");
        assert!(current_start >= latest_start);
        latest_start = current_start;
        assert!(f64::from_str(parts[1]).unwrap() > 0f64);
        assert!(f64::from_str(parts[2]).unwrap() > 0f64);
        assert!(f64::from_str(parts[3]).unwrap() > 0f64);
        assert_eq!(usize::from_str(parts[4]).unwrap(), 11);
        assert_eq!(u16::from_str(parts[5]).unwrap(), 200);
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
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        rcgen::CertifiedKey { cert, key_pair }
    };

    let server_cert = make_cert();
    let client_cert = make_cert();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(client_cert.cert.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                server_cert.key_pair.serialize_der(),
            )),
        )
        .unwrap();

    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));

    File::create(dir.join("server.crt"))
        .unwrap()
        .write_all(server_cert.cert.pem().as_bytes())
        .unwrap();

    File::create(dir.join("client.crt"))
        .unwrap()
        .write_all(client_cert.cert.pem().as_bytes())
        .unwrap();

    File::create(dir.join("client.key"))
        .unwrap()
        .write_all(client_cert.key_pair.serialize_pem().as_bytes())
        .unwrap();

    (
        port,
        axum_server::bind_rustls(addr, config).serve(app.into_make_service()),
    )
}

#[tokio::test]
async fn test_mtls() {
    let dir = tempfile::tempdir().unwrap();
    let (port, server) = setup_mtls_server(dir.path().to_path_buf());

    tokio::spawn(server);

    let mut command = Command::cargo_bin("oha").unwrap();
    command
        .args([
            "--debug",
            "--cacert",
            dir.path().join("server.crt").to_str().unwrap(),
            "--cert",
            dir.path().join("client.crt").to_str().unwrap(),
            "--key",
            dir.path().join("client.key").to_str().unwrap(),
        ])
        .arg(format!("https://localhost:{port}/"));
    tokio::task::spawn_blocking(move || {
        command.assert().success();
    })
    .await
    .unwrap();
}
