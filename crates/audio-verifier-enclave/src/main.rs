use std::{error::Error, fs, num::NonZeroUsize, thread, time::Duration};

use audio_verifier_enclave::{
    Limits, Pins, UploadKey, app_with, measure_jobs, mem_total, self_test,
};
use nautilus::{NautilusContext, ServerConfig};

const VSOCK_PORT: u32 = 3000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    self_test()?;
    let ctx = NautilusContext::from_runtime()?;
    let cpus = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let memory = fs::read_to_string("/proc/meminfo")
        .ok()
        .as_deref()
        .and_then(mem_total);
    let jobs = measure_jobs(cpus, memory);
    let upload_key = UploadKey::generate();
    println!("[server] public key: {}", ctx.public_key_hex());
    println!(
        "[server] upload key: {}",
        hex::encode(upload_key.public_key())
    );
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
    let app = app_with(ctx, Limits::new(jobs), Pins::pinned(), upload_key);
    nautilus::serve_vsock(VSOCK_PORT, app, config).await?;
    Ok(())
}
