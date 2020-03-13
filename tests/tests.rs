use assert_cmd::Command;
use std::sync::Mutex;
use warp::{http::HeaderMap, Filter};

lazy_static::lazy_static! {
    static ref PORT_LOCK: Mutex<()> = Mutex::new(());
}

async fn get_header(args: &[&str]) -> HeaderMap {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let report_headers =
        warp::any()
            .and(warp::header::headers_cloned())
            .map(move |headers: HeaderMap| {
                tx.send(headers).unwrap();
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
    let header = get_header(&[]).await;
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
    let header = get_header(&["-H", "foo: bar", "--"]).await;
    assert_eq!(header.get("foo").unwrap().to_str().unwrap(), "bar");
}

#[tokio::main]
#[test]
async fn test_setting_accept_header() {
    let header = get_header(&["-A", "text/html"]).await;
    assert_eq!(header.get("accept").unwrap().to_str().unwrap(), "text/html");
}
