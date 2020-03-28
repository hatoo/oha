use assert_cmd::Command;
use std::sync::Mutex;
use warp::{http::HeaderMap, Filter};

lazy_static::lazy_static! {
    static ref PORT_LOCK: Mutex<()> = Mutex::new(());
}

async fn get_header_body(args: &[&str]) -> (HeaderMap, bytes::Bytes) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let report_headers = warp::any()
        .and(warp::header::headers_cloned())
        .and(warp::filters::body::bytes())
        .map(move |headers: HeaderMap, body: bytes::Bytes| {
            tx.send((headers, body)).unwrap();
            "Hello World"
        });

    let _guard = PORT_LOCK.lock().unwrap();
    let port = get_port::get_port().unwrap();
    tokio::spawn(warp::serve(report_headers).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(&["-n", "1", "--no-tui"])
            .args(args)
            .arg(format!("http://127.0.0.1:{}", port))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_method(args: &[&str]) -> http::method::Method {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let report_headers = warp::any().and(warp::filters::method::method()).map(
        move |method: http::method::Method| {
            tx.send(method).unwrap();
            "Hello World"
        },
    );

    let _guard = PORT_LOCK.lock().unwrap();
    let port = get_port::get_port().unwrap();
    tokio::spawn(warp::serve(report_headers).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(&["-n", "1", "--no-tui"])
            .args(args)
            .arg(format!("http://127.0.0.1:{}", port))
            .assert()
            .success();
    })
    .await
    .unwrap();

    rx.try_recv().unwrap()
}

async fn get_query(p: &'static str) -> String {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let report_headers = warp::path!(String).and(warp::filters::query::raw()).map(
        move |path: String, query: String| {
            tx.send(path + "?" + &query).unwrap();
            "Hello World"
        },
    );

    let _guard = PORT_LOCK.lock().unwrap();
    let port = get_port::get_port().unwrap();
    tokio::spawn(warp::serve(report_headers).run(([127, 0, 0, 1], port)));
    // It's not guaranteed that the port is used here.
    // So we can't drop guard here.

    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("oha")
            .unwrap()
            .args(&["-n", "1", "--no-tui"])
            .arg(format!("http://127.0.0.1:{}/{}", port, p))
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
