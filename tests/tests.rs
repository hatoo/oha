use std::{
    convert::Infallible,
    error::Error as StdError,
    future::Future,
    net::{Ipv6Addr, SocketAddr},
    sync::{atomic::AtomicU16, Arc},
};

use assert_cmd::Command;
use axum::{extract::Path, response::Redirect, routing::get, Router};
use http::{HeaderMap, Request, Response};
use http_body_util::BodyExt;
use http_mitm_proxy::MitmProxy;
use hyper::{
    body::{Body, Incoming},
    http,
    service::{service_fn, HttpService},
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
        "/:n",
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

async fn burst_10_req_delay_2s_rate_4(iteration: u8, args: &[&str]) -> usize {
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
            .args([
                "-n",
                iteration.to_string().as_str(),
                "--no-tui",
                "--burst-delay",
                "2s",
                "--burst-rate",
                "4",
            ])
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
            .last()
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
        .last()
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
    assert_eq!(burst_10_req_delay_2s_rate_4(10, &[],).await, 10);
    assert_eq!(burst_10_req_delay_2s_rate_4(10, &["--http2"],).await, 10);
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
        loop {
            let (stream, _) = tcp_listener.accept().await.unwrap();

            let proxy = proxy.clone();
            let service = service.clone();
            tokio::spawn(async move {
                if http2 {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            MitmProxy::wrap_service(proxy, service),
                        )
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(
                            TokioIo::new(stream),
                            MitmProxy::wrap_service(proxy, service),
                        )
                        .with_upgrades()
                        .await;
                }
            });
        }
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

    let cargo_bin = Command::cargo_bin("oha").unwrap();
    let mut proc = tokio::process::Command::new(cargo_bin.get_program());
    std::mem::drop(cargo_bin);

    let scheme = if https { "https" } else { "http" };
    proc.args(["--no-tui", "--debug", "--insecure", "-x"])
        .arg(format!("http://127.0.0.1:{proxy_port}/"))
        .arg(format!("{scheme}://example.com/"));
    if http2 {
        proc.arg("--http2");
    }
    if proxy_http2 {
        proc.arg("--proxy-http2");
    }

    proc.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let stdout = proc
        .spawn()
        .unwrap()
        .wait_with_output()
        .await
        .unwrap()
        .stdout;

    assert!(String::from_utf8(stdout).unwrap().contains("Hello World"),);
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
                .args(["-n", "10", "--no-tui", "-j"])
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
                .args(["-n", "10", "--no-tui", "-j", "--stats-success-breakdown"])
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
