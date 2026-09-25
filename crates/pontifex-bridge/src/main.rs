//! Thin enclave entry — all logic lives in the library's `run`.

#[cfg(target_os = "linux")]
fn main() -> eyre::Result<()> {
    // At least two workers: the serve loop blocks a worker in the accept()
    // syscall, so a single-vCPU enclave needs a second to drive boot and timers.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .max(2);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?
        .block_on(pontifex_bridge::run())
}

#[cfg(not(target_os = "linux"))]
fn main() -> eyre::Result<()> {
    eyre::bail!("pontifex-bridge runs only inside a Linux Nitro enclave")
}
