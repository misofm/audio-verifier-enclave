//! Regressions from the review of `/v1/measure`, through the real router: a file's verdict and
//! error never depend on how its body is chunked, and agree with the library's buffered
//! `measure`.

use std::path::Path;

use audio_verifier::measure;
use audio_verifier_enclave::{DEFAULT_MAX_BODY_BYTES, app};
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt as _;
use nautilus::{EnclaveIdentity, NautilusContext, testing::FakeAttestor};
use tower::ServiceExt as _;

type Chunk = Result<Bytes, std::io::Error>;

fn router() -> Router {
    let ctx = NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    );
    app(ctx, DEFAULT_MAX_BODY_BYTES, 2)
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../audio-verifier/tests/fixtures")
            .join(name),
    )
    .expect("fixture")
}

/// A `/v1/measure` request whose body arrives as `parts`, one chunk each.
fn chunked(parts: Vec<&[u8]>) -> Request<Body> {
    let length: usize = parts.iter().map(|part| part.len()).sum();
    let chunks: Vec<Chunk> = parts
        .into_iter()
        .map(|part| Ok(Bytes::copy_from_slice(part)))
        .collect();
    Request::builder()
        .method("POST")
        .uri("/v1/measure")
        .header(header::CONTENT_LENGTH, length)
        .body(Body::from_stream(futures_util::stream::iter(chunks)))
        .expect("request")
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, serde_json::from_slice(&bytes).expect("JSON"))
}

/// Measures `bytes` buffered, then sends them to `/v1/measure` in chunks of several sizes and
/// split in two at every `step`-th offset; every response must be the buffered refusal.
async fn refused_everywhere(bytes: &[u8], step: usize) {
    let router = router();
    let error = measure(bytes).expect_err("refused when buffered");
    let expected =
        serde_json::json!({ "error": "application_error", "message": error.to_string() });
    for size in [1, 7, 100, 4096, bytes.len()] {
        let request = chunked(bytes.chunks(size).collect());
        let (status, value) = send(&router, request).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "chunks of {size}");
        assert_eq!(value, expected, "chunks of {size}");
    }
    for split in (1..bytes.len()).step_by(step) {
        let (head, tail) = bytes.split_at(split);
        let (status, value) = send(&router, chunked(vec![head, tail])).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "split at {split}: {value}"
        );
        assert_eq!(value, expected, "split at {split}");
    }
}

#[tokio::test]
async fn overlong_rice_code_is_refused_however_the_body_is_split() {
    // Signed by /v1/measure when split at byte 100 before the fix.
    refused_everywhere(&fixture("overlong_rice.flac"), 1).await;
}

#[tokio::test]
async fn canonical_file_with_an_overlong_rice_code_is_refused() {
    // Signed when buffered, on main and on the branch, before the fix.
    refused_everywhere(&fixture("overlong_rice_canonical.flac"), 61).await;
}

#[tokio::test]
async fn trailing_bytes_in_their_own_chunk_are_refused() {
    let router = router();
    let bytes = fixture("s16_stereo_44100.flac");
    let mut id3 = b"TAG".to_vec();
    id3.resize(128, 0);
    for trailer in [id3, vec![0], bytes[42..].to_vec()] {
        let request = chunked(vec![&bytes, &trailer]);
        let (status, value) = send(&router, request).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{value}");
        assert!(!value.to_string().contains("signature"));
    }
}
