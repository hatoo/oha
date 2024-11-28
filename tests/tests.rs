use std::{
    convert::Infallible,
    net::{Ipv6Addr, SocketAddr},
    sync::atomic::AtomicU16,
};

use assert_cmd::Command;
use axum::{extract::Path, response::Redirect, routing::get, Router};
use http::{HeaderMap, Request, Response};
use http_body_util::BodyExt;
use hyper::{http, service::service_fn};
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

#[tokio::test]
async fn test_proxy_http_http() {
    let (tx, rx) = flume::unbounded();
    let (listener, port) = bind_port().await;
    let proxy_port = PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let client = http_mitm_proxy::DefaultClient::new().unwrap();
    let proxy = http_mitm_proxy::MitmProxy::<&'static rcgen::CertifiedKey>::new(None, None);
    let proxy_server = proxy
        .bind(
            ("127.0.0.1", proxy_port),
            service_fn(move |mut req| {
                let client = client.clone();

                async move {
                    req.headers_mut()
                        .insert("x-oha-test-through-proxy", "true".parse().unwrap());

                    let (res, _) = client.send_request(req).await?;

                    Ok::<_, http_mitm_proxy::default_client::Error>(res)
                }
            }),
        )
        .await
        .unwrap();
    tokio::spawn(proxy_server);

    tokio::spawn(async move {
        loop {
            let tx = tx.clone();
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
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["--no-tui", "--debug", "-x"])
            .arg(format!("http://127.0.0.1:{proxy_port}/"))
            .arg(format!("http://127.0.0.1:{port}/"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    let req = rx.try_recv().unwrap();

    assert_eq!(
        req.headers().get("x-oha-test-through-proxy").unwrap(),
        "true"
    );
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
