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

    Command::cargo_bin("oha")
        .unwrap()
        .args(&["-n", "1", "--no-tui"])
        .args(args)
        .arg(format!("http://127.0.0.1:{}", port))
        .assert()
        .success();

    rx.try_recv().unwrap()
}

#[tokio::main]
#[test]
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

#[tokio::main]
#[test]
async fn test_setting_custom_header() {
    let header = get_header_body(&["-H", "foo: bar", "--"]).await.0;
    assert_eq!(header.get("foo").unwrap().to_str().unwrap(), "bar");
}

#[tokio::main]
#[test]
async fn test_setting_accept_header() {
    let header = get_header_body(&["-A", "text/html"]).await.0;
    assert_eq!(header.get("accept").unwrap().to_str().unwrap(), "text/html");
}

#[tokio::main]
#[test]
async fn test_setting_body() {
    let body = get_header_body(&["-d", "hello body"]).await.1;
    assert_eq!(
        body.as_ref(),
        &b"hello body"[..] /* This looks dirty... Any suggestion? */
    );
}

#[tokio::main]
#[test]
async fn test_setting_content_type_header() {
    let header = get_header_body(&["-T", "text/html"]).await.0;
    assert_eq!(
        header.get("content-type").unwrap().to_str().unwrap(),
        "text/html"
    );
}
