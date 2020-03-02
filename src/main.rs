use clap::Clap;
use url::Url;

#[derive(Clap)]
#[clap(version = "0.0.0", author = "hatoo")]
struct Opts {
    url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts: Opts = Opts::parse();
    let url = Url::parse(opts.url.as_str())?;
    let client = reqwest::Client::new();

    let c: usize = 50;
    let n: usize = 200;

    let tasks = crossbeam::deque::Worker::new_fifo();

    for _ in 0..n {
        tasks.push(());
    }

    let stealer = tasks.stealer();
    let mut jobs = Vec::new();

    let start = std::time::Instant::now();

    for _ in 0..c {
        let url = url.clone();
        let client = client.clone();
        let stealer = stealer.clone();
        let job = tokio::spawn(async move {
            while let crossbeam::deque::Steal::Success(()) = stealer.steal() {
                let url = url.clone();
                let resp = client.get(url).send().await?;
                let _status = resp.status();
                resp.bytes().await?;
            }
            Ok::<(), anyhow::Error>(())
        });
        jobs.push(job);
    }

    futures::future::join_all(jobs).await;

    let duration = std::time::Instant::now() - start;

    dbg!(duration);
    dbg!(n as f64 / duration.as_secs_f64());

    Ok(())
}
