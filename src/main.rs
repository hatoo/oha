use clap::Clap;
use url::Url;

#[derive(Clap)]
#[clap(version = "0.0.0", author = "hatoo")]
struct Opts {
    #[clap(help = "URL to request")]
    url: String,
    #[clap(help = "Number of requests", short = "n", default_value = "200")]
    n_requests: usize,
    #[clap(help = "Number of workers", short = "c", default_value = "50")]
    n_workers: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts: Opts = Opts::parse();
    let url = Url::parse(opts.url.as_str())?;
    let client = reqwest::Client::new();

    let mut tasks = Vec::new();

    for _ in 0..opts.n_requests {
        tasks.push(async {
            let resp = client.get(url.clone()).send().await?;
            let status = resp.status();
            resp.bytes().await?;
            Ok::<_, anyhow::Error>(status)
        });
    }

    let start = std::time::Instant::now();

    let res = work(tasks, opts.n_workers).await;
    let duration = std::time::Instant::now() - start;
    dbg!(res.into_iter().map(|v| v.len()).collect::<Vec<_>>());

    dbg!(duration);
    dbg!(opts.n_requests as f64 / duration.as_secs_f64());

    Ok(())
}

async fn work<T, I: IntoIterator<Item = impl std::future::Future<Output = T>>>(
    tasks: I,
    n_workers: usize,
) -> Vec<Vec<T>> {
    let injector = crossbeam::deque::Injector::new();

    for t in tasks {
        injector.push(t);
    }

    futures::future::join_all((0..n_workers).map(|_| async {
        let mut ret = Vec::new();
        while let crossbeam::deque::Steal::Success(w) = injector.steal() {
            ret.push(w.await);
        }
        ret
    }))
    .await
}

async fn work_duration<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    duration: std::time::Duration,
    n_workers: usize,
) -> Vec<Vec<T>> {
    let start = std::time::Instant::now();
    futures::future::join_all((0..n_workers).map(|_| async {
        let mut ret = Vec::new();
        while (std::time::Instant::now() - start) < duration {
            ret.push(task_generator().await);
        }
        ret
    }))
    .await
}
