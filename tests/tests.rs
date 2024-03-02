use std::{
    convert::Infallible,
    net::{Ipv6Addr, SocketAddr},
    sync::atomic::AtomicU16,
};

use assert_cmd::Command;
use axum::{
    extract::Path,
    response::Redirect,
    routing::{any, get},
    Router,
};
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, Request, Response};
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

async fn get_header_body(args: &[&str]) -> (HeaderMap, bytes::Bytes) {
    let (tx, rx) = flume::unbounded();

    let app = Router::new().route(
        "/",
        get(
            |header: HeaderMap, req: axum::extract::Request| async move {
                let mut body = Vec::new();
                let mut stream = req.into_body().into_data_stream();
                while let Some(data) = stream.next().await {
                    body.extend_from_slice(data.unwrap().as_ref());
                }
                tx.send((header, Bytes::from(body))).unwrap();
                "Hello World"
            },
        ),
    );

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .args(args)
            .arg(format!("http://127.0.0.1:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_method(args: &[&str]) -> http::method::Method {
    let (tx, rx) = flume::unbounded();
    let app = Router::new().route(
        "/",
        any(|method: http::method::Method| async move {
            tx.send(method).unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .args(args)
            .arg(format!("http://127.0.0.1:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_query(p: &'static str, args: &[&str]) -> String {
    let (tx, rx) = flume::unbounded();

    let app = Router::new().route(
        "/index",
        get(move |req: Request<axum::body::Body>| async move {
            tx.send(req.uri().to_string()).unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .args(args)
            .arg(format!("http://127.0.0.1:{port}{p}"))
            .assert()
            .success()
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_path_rand_regex(p: &'static str, args: &[&str]) -> String {
    use hyper::Error;

    let (tx, rx) = flume::unbounded();

    let (listener, port) = bind_port().await;
    tokio::spawn(async move {
        loop {
            let (socket, _remote_addr) = listener.accept().await.unwrap();
            let tx = tx.clone();
            let service = service_fn(move |req| {
                let tx = tx.clone();
                async move {
                    let (parts, _) = req.into_parts();
                    tx.send(parts.uri.to_string()).unwrap();
                    Ok::<_, Error>(Response::new("Hello World".to_string()))
                }
            });
            tokio::spawn(async move {
                hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await
            });
        }
    });

    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui", "--rand-regex-url"])
            .args(args)
            .arg(format!(r"http://127.0.0.1:{port}{p}"))
            .assert()
            .success();
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
    let header = get_header_body(&[]).await.0;
    let accept_encoding: Vec<&str> = header
        .get("accept-encoding")
        .unwrap()
        .to_str()
        .unwrap()
        .split(", ")
        .collect();

    assert!(accept_encoding.contains(&"gzip"));
    assert!(accept_encoding.contains(&"br"));

    let header = get_header_body(&["--http2"]).await.0;
    let accept_encoding: Vec<&str> = header
        .get("accept-encoding")
        .unwrap()
        .to_str()
        .unwrap()
        .split(", ")
        .collect();

    assert!(accept_encoding.contains(&"gzip"));
    assert!(accept_encoding.contains(&"br"));
}

async fn get_http_version(args: &[&str]) -> http::Version {
    let (tx, rx) = flume::unbounded();

    let app = Router::new().route(
        "/",
        get(|req: Request<axum::body::Body>| async move {
            tx.send(req.version()).unwrap();
            "Hello World"
        }),
    );

    let (listener, port) = bind_port().await;
    tokio::spawn(async { axum::serve(listener, app).await });

    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .args(args)
            .arg(format!("http://127.0.0.1:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

#[tokio::test]
async fn test_setting_custom_header() {
    let header = get_header_body(&["-H", "foo: bar", "--"]).await.0;
    assert_eq!(header.get("foo").unwrap().to_str().unwrap(), "bar");
    let header = get_header_body(&["-H", "foo:bar", "--"]).await.0;
    assert_eq!(header.get("foo").unwrap().to_str().unwrap(), "bar");

    let header = get_header_body(&["--http2", "-H", "foo: bar", "--"])
        .await
        .0;
    assert_eq!(header.get("foo").unwrap().to_str().unwrap(), "bar");
    let header = get_header_body(&["--http2", "-H", "foo:bar", "--"]).await.0;
    assert_eq!(header.get("foo").unwrap().to_str().unwrap(), "bar");
}

#[tokio::test]
async fn test_setting_accept_header() {
    let header = get_header_body(&["-A", "text/html"]).await.0;
    assert_eq!(header.get("accept").unwrap().to_str().unwrap(), "text/html");
    let header = get_header_body(&["-H", "accept:text/html"]).await.0;
    assert_eq!(header.get("accept").unwrap().to_str().unwrap(), "text/html");

    let header = get_header_body(&["--http2", "-A", "text/html"]).await.0;
    assert_eq!(header.get("accept").unwrap().to_str().unwrap(), "text/html");
    let header = get_header_body(&["--http2", "-H", "accept:text/html"])
        .await
        .0;
    assert_eq!(header.get("accept").unwrap().to_str().unwrap(), "text/html");
}

#[tokio::test]
async fn test_setting_body() {
    let body = get_header_body(&["-d", "hello body"]).await.1;
    assert_eq!(
        body.as_ref(),
        &b"hello body"[..] /* This looks dirty... Any suggestion? */
    );

    let body = get_header_body(&["--http2", "-d", "hello body"]).await.1;
    assert_eq!(
        body.as_ref(),
        &b"hello body"[..] /* This looks dirty... Any suggestion? */
    );
}

#[tokio::test]
async fn test_setting_content_type_header() {
    let header = get_header_body(&["-T", "text/html"]).await.0;
    assert_eq!(
        header.get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );
    let header = get_header_body(&["-H", "content-type:text/html"]).await.0;
    assert_eq!(
        header.get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );

    let header = get_header_body(&["--http2", "-T", "text/html"]).await.0;
    assert_eq!(
        header.get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );
    let header = get_header_body(&["--http2", "-H", "content-type:text/html"])
        .await
        .0;
    assert_eq!(
        header.get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );
}

#[tokio::test]
async fn test_setting_basic_auth() {
    let header = get_header_body(&["-a", "hatoo:pass"]).await.0;
    assert_eq!(
        header.get("authorization").unwrap().to_str().unwrap(),
        "Basic aGF0b286cGFzcw=="
    );

    let header = get_header_body(&["--http2", "-a", "hatoo:pass"]).await.0;
    assert_eq!(
        header.get("authorization").unwrap().to_str().unwrap(),
        "Basic aGF0b286cGFzcw=="
    );
}

#[tokio::test]
async fn test_setting_host() {
    let header = get_header_body(&["--host", "hatoo.io"]).await.0;
    assert_eq!(header.get("host").unwrap().to_str().unwrap(), "hatoo.io");

    let header = get_header_body(&["-H", "host:hatoo.io"]).await.0;
    assert_eq!(header.get("host").unwrap().to_str().unwrap(), "hatoo.io");

    // You shouldn't set host header when using HTTP/2
    // Use --connect-to instead
}

#[tokio::test]
async fn test_setting_method() {
    assert_eq!(get_method(&[]).await, http::method::Method::GET);
    assert_eq!(get_method(&["-m", "GET"]).await, http::method::Method::GET);
    assert_eq!(
        get_method(&["-m", "POST"]).await,
        http::method::Method::POST
    );
    assert_eq!(
        get_method(&["-m", "CONNECT"]).await,
        http::method::Method::CONNECT
    );
    assert_eq!(
        get_method(&["-m", "DELETE"]).await,
        http::method::Method::DELETE
    );
    assert_eq!(
        get_method(&["-m", "HEAD"]).await,
        http::method::Method::HEAD
    );
    assert_eq!(
        get_method(&["-m", "OPTIONS"]).await,
        http::method::Method::OPTIONS
    );
    assert_eq!(
        get_method(&["-m", "PATCH"]).await,
        http::method::Method::PATCH
    );
    assert_eq!(get_method(&["-m", "PUT"]).await, http::method::Method::PUT);
    assert_eq!(
        get_method(&["-m", "TRACE"]).await,
        http::method::Method::TRACE
    );

    assert_eq!(get_method(&["--http2"]).await, http::method::Method::GET);
    assert_eq!(
        get_method(&["--http2", "-m", "GET"]).await,
        http::method::Method::GET
    );
    assert_eq!(
        get_method(&["--http2", "-m", "POST"]).await,
        http::method::Method::POST
    );
    assert_eq!(
        get_method(&["--http2", "-m", "DELETE"]).await,
        http::method::Method::DELETE
    );
    assert_eq!(
        get_method(&["--http2", "-m", "HEAD"]).await,
        http::method::Method::HEAD
    );
    assert_eq!(
        get_method(&["--http2", "-m", "OPTIONS"]).await,
        http::method::Method::OPTIONS
    );
    assert_eq!(
        get_method(&["--http2", "-m", "PATCH"]).await,
        http::method::Method::PATCH
    );
    assert_eq!(
        get_method(&["--http2", "-m", "PUT"]).await,
        http::method::Method::PUT
    );
    assert_eq!(
        get_method(&["--http2", "-m", "TRACE"]).await,
        http::method::Method::TRACE
    );
}

#[tokio::test]
async fn test_query() {
    assert_eq!(
        get_query("/index?a=b&c=d", &[]).await,
        "/index?a=b&c=d".to_string()
    );

    assert_eq!(
        get_query("/index?a=b&c=d", &["--http2"])
            .await
            .split('/')
            .last()
            .unwrap(),
        "index?a=b&c=d".to_string()
    );
}

#[tokio::test]
async fn test_query_rand_regex() {
    let query = get_path_rand_regex("/[a-z][0-9][a-z]", &[]).await;
    let chars = query.trim_start_matches('/').chars().collect::<Vec<char>>();
    assert_eq!(chars.len(), 3);
    assert!(chars[0].is_ascii_lowercase());
    assert!(chars[1].is_ascii_digit());
    assert!(chars[2].is_ascii_lowercase());

    let query = get_path_rand_regex("/[a-z][0-9][a-z]", &["--http2"]).await;
    let chars = query
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
    assert_eq!(get_http_version(&[]).await, http::Version::HTTP_11);
    assert_eq!(get_http_version(&["--http2"]).await, http::Version::HTTP_2);
    assert_eq!(
        get_http_version(&["--http-version", "2"]).await,
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
                    tx.send_async(()).await.unwrap();
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
                "http://localhost/",
            ])
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap();
}
