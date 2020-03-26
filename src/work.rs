#![allow(dead_code)]

/// Run n tasks by m workers
/// Currently We use Fn() -> F as "task generator".
/// Any replacement?
pub async fn work<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    n_tasks: usize,
    n_workers: usize,
) -> Vec<Vec<T>> {
    let injector = crossbeam::deque::Injector::new();

    for _ in 0..n_tasks {
        injector.push(());
    }

    futures::future::join_all((0..n_workers).map(|_| async {
        let mut ret = Vec::new();
        while let crossbeam::deque::Steal::Success(()) = injector.steal() {
            ret.push(task_generator().await);
        }
        ret
    }))
    .await
}

/// n tasks by m workers limit to qps works in a second
pub async fn work_with_qps<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    qps: usize,
    n_tasks: usize,
    n_workers: usize,
) -> Vec<Vec<T>> {
    let (tx, rx) = crossbeam::channel::unbounded();

    tokio::spawn(async move {
        let start = std::time::Instant::now();
        for i in 0..n_tasks {
            tx.send(()).unwrap();
            tokio::time::delay_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
        }
        // tx gone
    });

    futures::future::join_all((0..n_workers).map(|_| async {
        let mut ret = Vec::new();
        while let Ok(()) = rx.recv() {
            ret.push(task_generator().await)
        }
        ret
    }))
    .await
}

/// Run until dead_line by n workers
pub async fn work_until<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    dead_line: std::time::Instant,
    n_workers: usize,
) -> Vec<Vec<T>> {
    futures::future::join_all((0..n_workers).map(|_| async {
        let mut ret = Vec::new();
        while std::time::Instant::now() < dead_line {
            ret.push(task_generator().await);
        }
        ret
    }))
    .await
}

/// Run until dead_line by n workers limit to qps works in a second
pub async fn work_until_with_qps<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    qps: usize,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_workers: usize,
) -> Vec<Vec<T>> {
    let (tx, rx) = crossbeam::channel::bounded(qps);

    let gen = tokio::spawn(async move {
        for i in 0.. {
            if std::time::Instant::now() > dead_line {
                break;
            }
            if tx.send(()).is_err() {
                break;
            }
            tokio::time::delay_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
        }
        // tx gone
    });

    let ret = futures::future::join_all((0..n_workers).map(|_| async {
        let mut ret = Vec::new();
        while let Ok(()) = rx.recv() {
            if std::time::Instant::now() > dead_line {
                break;
            }
            ret.push(task_generator().await)
        }
        ret
    }))
    .await;

    let _ = gen.await;
    ret
}
