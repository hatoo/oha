use assert_cmd::Command;
use warp::{http::HeaderMap, Filter};

async fn get_header(args: &[&str]) -> HeaderMap {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let report_headers =
        warp::any()
            .and(warp::header::headers_cloned())
            .map(move |headers: HeaderMap| {
                tx.send(headers).unwrap();
                "Hello World"
            });
    let port = get_port::get_port().unwrap();
    tokio::spawn(warp::serve(report_headers).run(([127, 0, 0, 1], port)));

    Command::cargo_bin("oha")
        .unwrap()
        .args(args)
        .args(&["-n", "1", "--no-tui"])
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
