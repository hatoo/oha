use anyhow::Context;
use clap::Clap;
use url::Url;

#[derive(Clap)]
#[clap(version = "0.0.0", author = "hatoo")]
struct Opts {
    url: String,
}

lazy_static::lazy_static! {
    static ref CLIENT: reqwest::Client = reqwest::Client::new();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts: Opts = Opts::parse();
    let url = Url::parse(opts.url.as_str())?;

    let c: usize = 50;
    let n: usize = 200;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let mut waits = Vec::new();
    let start = std::time::Instant::now();

    for _ in 0..c {
        let tx = tx.clone();
        let url = url.clone();
        // wait exit for the program
        // exit program while running reqwest cause error
        let (w_tx, w_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            loop {
                let url = url.clone();
                let resp = CLIENT.get(url).send().await?;
                let status = resp.status();
                resp.bytes().await?;
                if tx.send(status).is_err() {
                    let _ = w_tx.send(());
                    return Ok::<(), anyhow::Error>(());
                }
            }
        });
        waits.push(w_rx);
    }

    for _ in 0..n {
        rx.recv().await.context("recv")?;
    }
    rx.close();

    let duration = std::time::Instant::now() - start;

    for w in waits {
        w.await?;
    }

    dbg!(duration);
    dbg!(n as f64 / duration.as_secs_f64());

    Ok(())
}
