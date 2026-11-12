use std::{error::Error, fs, num::NonZeroUsize, thread, time::Duration};

use audio_verifier_enclave::{Limits, app, measure_jobs, mem_total};
use nautilus::{NautilusContext, ServerConfig};

const VSOCK_PORT: u32 = 3000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    audio_verifier::self_test()?;
    let ctx = NautilusContext::from_runtime()?;
    let cpus = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let memory = fs::read_to_string("/proc/meminfo")
        .ok()
        .as_deref()
        .and_then(mem_total);
    let jobs = measure_jobs(cpus, memory);
    println!("[server] public key: {}", ctx.public_key_hex());
    println!(
        "[server] /measure jobs: {jobs} ({cpus} vCPUs, MemTotal {} MiB)",
        memory.map_or_else(|| "unknown".into(), |bytes| (bytes >> 20).to_string())
    );
    // `serve_vsock` reads only the connection limits. 256 connections match the host bridge;
    // fewer let a few idle connections lock out every request until the header timeout.
    let config = ServerConfig {
        max_connections: 256,
        header_read_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
        ..ServerConfig::default()
    };
    println!("[server] listening on vsock port {VSOCK_PORT}");
    nautilus::serve_vsock(VSOCK_PORT, app(ctx, Limits::new(jobs)), config).await?;
    Ok(())
}
