pub async fn work<T, I: IntoIterator<Item = impl std::future::Future<Output = T>>>(
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

pub async fn work_duration<T, F: std::future::Future<Output = T>>(
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
