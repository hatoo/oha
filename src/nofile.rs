use tokio::stream::StreamExt;

pub fn watch_nofile() -> tokio::sync::watch::Receiver<usize> {
    let (tx, rx) = tokio::sync::watch::channel(0);

    std::thread::spawn(move || {
        while {
            /*
            let n = tokio::fs::read_dir("/dev/fd")
                .await?
                .fold(0usize, |a, _| a + 1)
                .await;
                */
            let n = std::fs::read_dir("/dev/fd")?.count();
            // dbg!(n);
            tx.broadcast(n).is_ok()
        } {}

        dbg!("leave");
        Ok::<(), anyhow::Error>(())
    });

    rx
}
