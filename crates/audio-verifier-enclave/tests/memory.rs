//! Two concurrent 256 MiB bodies, each one frame that never ends, through the real router: each
//! job stops after its window, so together they cost tens of MiB rather than 512. This test is
//! alone in its binary, so the process's peak RSS is its own.

use std::path::Path;

use audio_verifier_enclave::{Limits, MAX_FILE_BYTES, MEASURE_JOB_BYTES, app};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, StatusCode, header},
};
use nautilus::{EnclaveIdentity, NautilusContext, testing::FakeAttestor};
use tower::ServiceExt as _;

fn crc8(bytes: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in bytes {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .expect("status")
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM")
}

/// STREAMINFO for 4096-sample stereo 16-bit frames of unknown size, one frame header and a FIXED
/// order-0 subframe with Rice parameter 0, then zeros up to `total` bytes, made in 64 KiB chunks
/// as the body is read.
fn unterminated(total: usize) -> Request<Body> {
    let mut head = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../audio-verifier/tests/fixtures/s16_stereo_44100.flac"),
    )
    .expect("fixture")[..42]
        .to_vec();
    head[4] |= 0x80;
    head[8..10].copy_from_slice(&4096u16.to_be_bytes());
    head[10..12].copy_from_slice(&4096u16.to_be_bytes());
    head[12..18].fill(0);
    let mut frame = vec![0xff, 0xf8, 0xc9, 0x18, 0x00];
    frame.push(crc8(&frame));
    head.extend(frame);
    head.push(0x10);
    let zeros = total - head.len();
    let stream = futures_util::stream::unfold((Some(head), zeros), |(head, left)| async move {
        if let Some(head) = head {
            return Some((Ok::<_, std::io::Error>(Bytes::from(head)), (None, left)));
        }
        if left == 0 {
            return None;
        }
        let count = left.min(64 << 10);
        Some((Ok(Bytes::from(vec![0u8; count])), (None, left - count)))
    });
    Request::builder()
        .method("POST")
        .uri("/measure")
        .header(header::CONTENT_LENGTH, total)
        .body(Body::from_stream(stream))
        .expect("request")
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("JSON"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unterminated_frames_cost_a_window_each() {
    let ctx = NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    );
    let router = app(ctx, Limits::new(2));
    let before = peak_rss_kib();
    let total = MAX_FILE_BYTES as usize;
    let (first, second) = tokio::join!(
        send(&router, unterminated(total)),
        send(&router, unterminated(total))
    );
    let grown = peak_rss_kib().saturating_sub(before);
    eprintln!("two concurrent {total}-byte bodies: peak RSS grew by {grown} KiB");
    for (status, value) in [first, second] {
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{value}");
        let message = value["message"].as_str().expect("message");
        assert!(message.contains("is over 16777215 bytes"), "{message}");
    }
    assert!(
        grown * 1024 < 2 * MEASURE_JOB_BYTES,
        "peak RSS grew by {grown} KiB"
    );
}
