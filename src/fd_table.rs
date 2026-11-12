//! Reserve Linux's FD table before runtime threads share it.
//!
//! Growing a shared FD table calls synchronize_rcu() in expand_fdtable(). Other
//! threads allocating FDs wait for the resize too. During connection startup,
//! this can block all runtime workers in socket() for tens of milliseconds.
//! A temporary high-numbered FD grows the table while we are still single
//! threaded, before the load test starts. Closing it does not shrink the table.

use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub fn reserve(n_connections: usize, worker_threads: usize) -> io::Result<()> {
    // Include inherited FDs. The directory's own FD only adds a little slack.
    let open_fds_end = std::fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<usize>().ok())
        .max()
        .unwrap_or(2)
        .saturating_add(1);
    // Fast-mode workers have their own runtimes. Allow three FDs per worker
    // for runtime I/O, plus headroom for DNS, output files and other setup.
    let slots = open_fds_end
        .saturating_add(n_connections)
        .saturating_add(worker_threads.saturating_mul(3))
        .saturating_add(64);
    let (soft_limit, _) = rlimit::getrlimit(rlimit::Resource::NOFILE)?;
    let Some(last_allowed) = soft_limit.checked_sub(1) else {
        return Ok(());
    };
    let target = (slots.saturating_sub(1) as u64)
        .min(last_allowed)
        .min(i32::MAX as u64) as i32;

    let file = File::open("/dev/null")?;
    // SAFETY: file owns a valid descriptor. F_DUPFD_CLOEXEC creates a new FD
    // at or above target without replacing an existing descriptor.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, target) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a fresh owned descriptor. Close it immediately;
    // only the expanded kernel table is needed during the test.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fd_size() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("FDSize:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn check_in_child(test_name: &str, limited: bool) {
        // Isolate both the FD table and RLIMIT_NOFILE from parallel tests.
        if std::env::var_os("OHA_FD_TABLE_TEST_CHILD").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture"])
                .env("OHA_FD_TABLE_TEST_CHILD", "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }
        if limited {
            let (_, hard) = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap();
            rlimit::setrlimit(rlimit::Resource::NOFILE, 128, hard).unwrap();
        }
        let limits = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap();
        let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
        reserve(if limited { usize::MAX } else { 100 }, 4).unwrap();
        assert!(fd_size() >= if limited { 128 } else { 164 });
        assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
        assert_eq!(rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap(), limits);
    }

    #[test]
    fn reserves_without_leaking_fds() {
        check_in_child("fd_table::tests::reserves_without_leaking_fds", false);
    }

    #[test]
    fn respects_fd_limit_and_handles_overflow() {
        check_in_child(
            "fd_table::tests::respects_fd_limit_and_handles_overflow",
            true,
        );
    }
}
