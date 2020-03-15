use futures::prelude::*;

/// Run n tasks by m workers
/// Currently We use Fn() -> F as "task generator".
/// Any replacement?
pub async fn work<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    n_tasks: usize,
    n_workers: usize,
) -> Vec<T> {
    futures::stream::iter(0..n_tasks)
        .map(|_| async { task_generator().await })
        .buffer_unordered(n_workers)
        .collect()
        .await
}

/// n tasks by m workers limit to qps works in a second
pub async fn work_with_qps<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    qps: usize,
    n_tasks: usize,
    n_workers: usize,
) -> Vec<T> {
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
    });

    futures::stream::iter(0..n_tasks)
        .map(|_| async {
            rx.recv().unwrap();
            task_generator().await
        })
        .buffer_unordered(n_workers)
        .collect()
        .await
}

/// Run until dead_line by n workers
pub async fn work_until<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    dead_line: std::time::Instant,
    n_workers: usize,
) -> Vec<T> {
    futures::stream::repeat(())
        .map(|_| async { task_generator().await })
        .take_while(|_| async { std::time::Instant::now() < dead_line })
        .buffer_unordered(n_workers)
        .collect()
        .await
}

/// Run until dead_line by n workers limit to qps works in a second
pub async fn work_until_with_qps<T, F: std::future::Future<Output = T>>(
    task_generator: impl Fn() -> F,
    qps: usize,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_workers: usize,
) -> Vec<T> {
    let (tx, rx) = crossbeam::channel::bounded(qps);

    let gen = tokio::spawn(async move {
        for i in 0.. {
            if tx.send(()).is_err() {
                break;
            }
            tokio::time::delay_until(
                (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
            )
            .await;
        }
    });

    let ret = futures::stream::repeat(())
        .map(|_| async {
            rx.recv().unwrap();
            task_generator().await
        })
        .take_while(|_| async { std::time::Instant::now() < dead_line })
        .buffer_unordered(n_workers)
        .collect()
        .await;

    std::mem::drop(rx);

    let _ = gen.await;
    ret
}
