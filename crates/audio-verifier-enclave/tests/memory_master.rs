//! One file of nearly 256 MiB through the real router, decoded, encrypted, given its blob ID,
//! sealed and sent: the job's peak must stay within `MEASURE_JOB_BYTES`. The file is white
//! noise that ffmpeg makes; without ffmpeg the test is skipped. It is alone in its binary, so
//! the process's peak RSS is its own.

use std::process::Command;

use audio_verifier_enclave::{Limits, MAX_FILE_BYTES, MEASURE_JOB_BYTES, app};
use axum::{
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use nautilus::{EnclaveIdentity, NautilusContext, testing::FakeAttestor};
use tower::ServiceExt as _;

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .expect("status")
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    debug_assertions,
    ignore = "decoding 256 MiB unoptimized takes a minute: --release"
)]
async fn a_256_mib_master_fits_its_job() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("noise_256m.flac");
    if !path.exists() {
        let made = Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
            ])
            .arg("aevalsrc=0.9*(2*random(0)-1)|0.9*(2*random(1)-1):s=192000:d=430")
            .args([
                "-c:a",
                "flac",
                "-sample_fmt",
                "s32",
                "-bits_per_raw_sample",
                "24",
            ])
            .args(["-compression_level", "0"])
            .arg(&path)
            .status();
        if !matches!(made, Ok(status) if status.success()) {
            eprintln!("ffmpeg unavailable, skipping the 256 MiB master");
            return;
        }
    }
    let length = std::fs::metadata(&path).expect("noise").len();
    assert!(length > MAX_FILE_BYTES - (16 << 20) && length <= MAX_FILE_BYTES);
    let ctx = NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    );
    let router = app(ctx, Limits::new(1));
    // The file is read as the body is, so the process holds no copy of it.
    let mut file = std::fs::File::open(&path).expect("noise");
    let chunks = futures_util::stream::poll_fn(move |_| {
        let mut chunk = vec![0; 256 << 10];
        let count = std::io::Read::read(&mut file, &mut chunk).expect("read");
        chunk.truncate(count);
        std::task::Poll::Ready((count > 0).then(|| Ok::<_, std::io::Error>(Bytes::from(chunk))))
    });
    let before = peak_rss_kib();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/measure?recording_id={}", "c0".repeat(32)))
        .header(header::CONTENT_LENGTH, length)
        .body(Body::from_stream(chunks))
        .expect("request");
    let started = std::time::Instant::now();
    let response = router.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    let mut received = 0;
    while let Some(chunk) = futures_util::StreamExt::next(&mut body).await {
        received += chunk.expect("chunk").len();
    }
    let grown = peak_rss_kib().saturating_sub(before);
    eprintln!(
        "{length}-byte master: {received} response bytes in {:?}; peak RSS grew by {grown} KiB",
        started.elapsed()
    );
    assert!(received as u64 > length);
    assert!(
        grown * 1024 < MEASURE_JOB_BYTES,
        "peak RSS grew by {grown} KiB"
    );
}
