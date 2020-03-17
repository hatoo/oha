use tokio::stream::StreamExt;

fn watch_nofile() -> tokio::sync::watch::Receiver<usize> {
    let (tx, rx) = tokio::sync::watch::channel(0);

    tokio::spawn(async move {
        while let Ok(()) = tx.broadcast(
            tokio::fs::read_dir("/dev/fd")
                .await?
                .fold(0usize, |a, _| a + 1)
                .await,
        ) {}

        Ok::<(), anyhow::Error>(())
    });

    rx
}
