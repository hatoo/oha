use std::net::Ipv6Addr;

use assert_cmd::Command;
use get_port::Ops;
use tokio::sync::Mutex;
use warp::{http::HeaderMap, Filter};

lazy_static::lazy_static! {
    static ref PORT_LOCK: Mutex<()> = Mutex::new(());
}

async fn get_header_body(args: &[&str]) -> (HeaderMap, bytes::Bytes) {
    let (tx, rx) = flume::unbounded();
    let report_headers = warp::any()
        .and(warp::header::headers_cloned())
        .and(warp::filters::body::bytes())
        .map(move |headers: HeaderMap, body: bytes::Bytes| {
            tx.send((headers, body)).unwrap();
            "Hello World"
        });

    let _guard = PORT_LOCK.lock().await;
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    tokio::spawn(warp::serve(report_headers).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

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
    let report_headers = warp::any().and(warp::filters::method::method()).map(
        move |method: http::method::Method| {
            tx.send(method).unwrap();
            "Hello World"
        },
    );

    let _guard = PORT_LOCK.lock().await;
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    tokio::spawn(warp::serve(report_headers).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

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

async fn get_query(p: &'static str) -> String {
    let (tx, rx) = flume::unbounded();
    let report_headers = warp::path!(String).and(warp::filters::query::raw()).map(
        move |path: String, query: String| {
            tx.send(path + "?" + &query).unwrap();
            "Hello World"
        },
    );

    let _guard = PORT_LOCK.lock().await;
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    tokio::spawn(warp::serve(report_headers).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .arg(format!("http://127.0.0.1:{port}/{p}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_path_rand_regex(p: &'static str) -> String {
    let (tx, rx) = flume::unbounded();
    let report_headers = warp::path!(String).map(move |path: String| {
        tx.send(path).unwrap();
        "Hello World"
    });

    let _guard = PORT_LOCK.lock().await;
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    tokio::spawn(warp::serve(report_headers).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui", "--rand-regex-url"])
            .arg(format!(r"http://127\.0\.0\.1:{port}/{p}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn redirect(n: usize, is_relative: bool, limit: usize) -> bool {
    let (tx, rx) = flume::unbounded();
    let _guard = PORT_LOCK.lock().await;
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();

    let route = warp::path!(usize).map(move |x| {
        if x == n {
            tx.send(()).unwrap();
            http::Response::builder().status(200).body("OK").unwrap()
        } else if is_relative {
            http::Response::builder()
                .status(301)
                .header("Location", format!("/{}", x + 1))
                .body("OK")
                .unwrap()
        } else {
            http::Response::builder()
                .status(301)
                .header("Location", format!("http://localhost:{}/{}", port, x + 1))
                .body("OK")
                .unwrap()
        }
    });

    tokio::spawn(warp::serve(route).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

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
    let report_host =
        warp::get()
            .and(warp::filters::header::header("host"))
            .map(move |host: String| {
                tx.send(host).unwrap();
                "Hello World"
            });

    let _guard = PORT_LOCK.lock().await;
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    tokio::spawn(warp::serve(report_host).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

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
    let report_host =
        warp::get()
            .and(warp::filters::header::header("host"))
            .map(move |host: String| {
                tx.send(host).unwrap();
                "Hello World"
            });

    let _guard = PORT_LOCK.lock().await;
    // sic. the `get_port` crate doesn't support IpV6 addresses, so we check
    // with 127.0.0.1 even though we bind on ::1 later.
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    let addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    tokio::spawn(warp::serve(report_host).run((addr, port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(["-n", "1", "--no-tui"])
            .arg(format!("http://{host}/"))
            .arg("--connect-to")
            .arg(format!("{host}:80:[{addr}]:{port}"))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_host_with_connect_to_ipv6_requested() -> String {
    let (tx, rx) = flume::unbounded();
    let report_host =
        warp::get()
            .and(warp::filters::header::header("host"))
            .map(move |host: String| {
                tx.send(host).unwrap();
                "Hello World"
            });

    let _guard = PORT_LOCK.lock().await;
    // sic. the `get_port` crate doesn't support IpV6 addresses, so we check
    // with 127.0.0.1 even though we bind on ::1 later.
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    tokio::spawn(warp::serve(report_host).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

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
    let redirect = warp::get().and(warp::path!("source")).map(move || {
        let uri = http::Uri::try_from(format!("http://{host}/destination")).unwrap();
        warp::redirect(uri)
    });
    let report_host = warp::get()
        .and(warp::path!("destination"))
        .and(warp::filters::header::header("host"))
        .map(move |host: String| {
            tx.send(host).unwrap();
            "Hello World"
        });
    let routes = redirect.or(report_host);

    let _guard = PORT_LOCK.lock().await;
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    tokio::spawn(warp::serve(routes).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

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
}

#[tokio::test]
async fn test_setting_custom_header() {
    let header = get_header_body(&["-H", "foo: bar", "--"]).await.0;
    assert_eq!(header.get("foo").unwrap().to_str().unwrap(), "bar");
    let header = get_header_body(&["-H", "foo:bar", "--"]).await.0;
    assert_eq!(header.get("foo").unwrap().to_str().unwrap(), "bar");
}

#[tokio::test]
async fn test_setting_accept_header() {
    let header = get_header_body(&["-A", "text/html"]).await.0;
    assert_eq!(header.get("accept").unwrap().to_str().unwrap(), "text/html");
}

#[tokio::test]
async fn test_setting_body() {
    let body = get_header_body(&["-d", "hello body"]).await.1;
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
}

#[tokio::test]
async fn test_setting_basic_auth() {
    let header = get_header_body(&["-a", "hatoo:pass"]).await.0;
    assert_eq!(
        header.get("authorization").unwrap().to_str().unwrap(),
        "Basic aGF0b286cGFzcw=="
    );
}

#[tokio::test]
async fn test_setting_host() {
    let header = get_header_body(&["--host", "hatoo.io"]).await.0;
    assert_eq!(header.get("host").unwrap().to_str().unwrap(), "hatoo.io");
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
}

#[tokio::test]
async fn test_query() {
    assert_eq!(
        get_query("index?a=b&c=d").await,
        "index?a=b&c=d".to_string()
    );
}

#[tokio::test]
async fn test_query_rand_regex() {
    let query = get_path_rand_regex("[a-z][0-9][a-z]").await;
    let chars = query.chars().collect::<Vec<char>>();
    assert_eq!(chars.len(), 3);
    assert!(chars[0].is_ascii_lowercase());
    assert!(chars[1].is_ascii_digit());
    assert!(chars[2].is_ascii_lowercase());
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
async fn test_ipv6() {
    let (tx, rx) = flume::unbounded();
    let report_host =
        warp::get()
            .and(warp::filters::header::header("host"))
            .map(move |host: String| {
                tx.send(host).unwrap();
                "Hello World"
            });

    let _guard = PORT_LOCK.lock().await;
    // sic. the `get_port` crate doesn't support IpV6 addresses, so we check
    // with 127.0.0.1 even though we bind on ::1 later.
    let port = get_port::tcp::TcpPort::any("127.0.0.1").unwrap();
    let addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    tokio::spawn(warp::serve(report_host).run((addr, port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

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
