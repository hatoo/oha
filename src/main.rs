use clap::{CommandFactory, Parser};
use oha::{Opts, run};

fn main() {
    let num_workers_threads = std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        // Prefer to use physical cores rather than logical one because it's more performant empirically.
        .unwrap_or(num_cpus::get_physical());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_workers_threads)
        .enable_all()
        .build()
        .unwrap();

    let opts = Opts::parse();

    if let Some(shell) = opts.completions {
        clap_complete::generate(shell, &mut Opts::command(), "oha", &mut std::io::stdout());
        return;
    }

    if let Err(e) = rt.block_on(run(opts)) {
        eprintln!("Error: {e}");
        std::process::exit(libc::EXIT_FAILURE);
    }
}
