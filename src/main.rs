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
        tasks.push(async {
            let resp = client.get(url.clone()).send().await?;
            let status = resp.status();
            resp.bytes().await?;
            Ok::<_, anyhow::Error>(status)
        });
    }

    let start = std::time::Instant::now();

    work(tasks.stealer(), c).await;

    let duration = std::time::Instant::now() - start;

    dbg!(duration);
    dbg!(n as f64 / duration.as_secs_f64());

    Ok(())
}

async fn work<T>(
    stealer: crossbeam::deque::Stealer<impl std::future::Future<Output = T>>,
    n_workers: usize,
) -> Vec<Vec<T>> {
    futures::future::join_all(
        (0..n_workers)
            .map(|_| async {
                let mut ret = Vec::new();
                while let crossbeam::deque::Steal::Success(w) = stealer.steal() {
                    ret.push(w.await);
                }
                ret
            })
            .collect::<Vec<_>>(),
    )
    .await
}
