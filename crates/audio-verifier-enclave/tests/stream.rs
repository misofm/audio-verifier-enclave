use std::{path::Path, time::Duration};

use audio_verifier::{AudioPayload, measure};
use audio_verifier_enclave::{
    AUDIO_INTENT, DEFAULT_MAX_BODY_BYTES, MASTER_FILE_INTENT, MEASURE_CHUNK_TIMEOUT,
    MEASURE_REQUEST_TIMEOUT, MasterFilePayload, MeasureResponse, ProcessDataResponse, StreamConfig,
    app, measure_routes, server_config, stream_config,
};
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, Response, StatusCode, header},
};
use http_body_util::BodyExt as _;
use nautilus::{
    EnclaveIdentity, IntentMessage, NautilusContext, ServerConfig, SignedResponse, intent_message,
    testing::FakeAttestor, verify_signed_response,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use tower::ServiceExt as _;

type Chunk = Result<Bytes, std::io::Error>;

fn context() -> NautilusContext {
    NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    )
}

fn fixture() -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../audio-verifier/tests/fixtures/s16_stereo_44100.flac"),
    )
    .expect("fixture")
}

/// The fixture with a codec-style VORBIS_COMMENT and 8 KiB of PADDING after STREAMINFO.
fn tagged(canonical: &[u8]) -> Vec<u8> {
    let vendor = b"reference libFLAC 1.5.0 20250211";
    let mut comment = (vendor.len() as u32).to_le_bytes().to_vec();
    comment.extend_from_slice(vendor);
    comment.extend_from_slice(&0u32.to_le_bytes());
    let mut out = canonical[..42].to_vec();
    out[4] &= 0x7f;
    out.push(0x04);
    out.extend_from_slice(&(comment.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&comment);
    out.extend_from_slice(&[0x81, 0x00, 0x20, 0x00]);
    out.extend_from_slice(&[0; 8192]);
    out.extend_from_slice(&canonical[42..]);
    out
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn request(body: Body, length: Option<usize>) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri("/v1/measure");
    if let Some(length) = length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    builder.body(body).expect("request")
}

/// `bytes` as a network body in chunks of `chunk` bytes, declaring `length`.
fn streamed(bytes: &[u8], chunk: usize, length: Option<usize>) -> Request<Body> {
    let chunks: Vec<Chunk> = bytes
        .chunks(chunk.min(bytes.len().max(1)))
        .map(|part| Ok(Bytes::copy_from_slice(part)))
        .collect();
    request(
        Body::from_stream(futures_util::stream::iter(chunks)),
        length,
    )
}

/// A body fed by hand: the request and the sender for its chunks.
fn open_body(length: usize) -> (Request<Body>, mpsc::Sender<Chunk>) {
    let (sender, mut receiver) = mpsc::channel::<Chunk>(4);
    let stream = futures_util::stream::poll_fn(move |cx| receiver.poll_recv(cx));
    (request(Body::from_stream(stream), Some(length)), sender)
}

/// `/v1/measure` jobs the test routers run at once.
const CONCURRENT: usize = 2;

fn router(limit: usize) -> Router {
    app(context(), server_config(limit), CONCURRENT).expect("config")
}

async fn json(response: Response<Body>) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, serde_json::from_slice(&bytes).expect("JSON"))
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    json(router.clone().oneshot(request).await.expect("response")).await
}

fn verify(ctx: &NautilusContext, body: &MeasureResponse, audio: &AudioPayload, file: &[u8]) {
    let signed_audio = SignedResponse {
        response: IntentMessage {
            intent: AUDIO_INTENT,
            timestamp_ms: body.audio.timestamp_ms,
            data: audio.clone(),
        },
        signature: body.audio.signature.clone(),
    };
    verify_signed_response(&ctx.public_key(), AUDIO_INTENT, &signed_audio)
        .expect("audio signature verifies over the rebuilt intent message");
    let signed_file = SignedResponse {
        response: IntentMessage {
            intent: MASTER_FILE_INTENT,
            timestamp_ms: body.master_file.timestamp_ms,
            data: MasterFilePayload {
                audio: audio.clone(),
                file_size: file.len() as u64,
                file_sha256: sha256(file),
            },
        },
        signature: body.master_file.signature.clone(),
    };
    verify_signed_response(&ctx.public_key(), MASTER_FILE_INTENT, &signed_file)
        .expect("file signature verifies over the rebuilt intent message");
    let swapped = SignedResponse {
        response: IntentMessage {
            intent: MASTER_FILE_INTENT,
            ..signed_audio.response
        },
        signature: signed_audio.signature,
    };
    assert!(verify_signed_response(&ctx.public_key(), MASTER_FILE_INTENT, &swapped).is_err());
}

#[tokio::test]
async fn streamed_file_is_signed_twice_with_one_timestamp() {
    let ctx = context();
    let router = app(
        ctx.clone(),
        server_config(DEFAULT_MAX_BODY_BYTES),
        CONCURRENT,
    )
    .expect("config");
    let bytes = fixture();
    let measured = measure(&bytes).expect("fixture");
    for chunk in [1, 7, 4096, 1 << 20, usize::MAX] {
        let (status, value) = send(&router, streamed(&bytes, chunk, Some(bytes.len()))).await;
        assert_eq!(status, StatusCode::OK, "chunks of {chunk}: {value}");
        let keys = |value: &serde_json::Value| {
            let mut keys: Vec<String> =
                value.as_object().expect("object").keys().cloned().collect();
            keys.sort();
            keys
        };
        assert_eq!(keys(&value), ["audio", "master_file", "public_key"]);
        assert_eq!(
            keys(&value["master_file"]),
            [
                "file_sha256",
                "file_size",
                "intent",
                "signature",
                "timestamp_ms"
            ]
        );
        assert_eq!(value["audio"]["intent"], AUDIO_INTENT.0);
        assert_eq!(value["master_file"]["intent"], MASTER_FILE_INTENT.0);
        assert_eq!(value["master_file"]["file_size"], bytes.len().to_string());
        assert_eq!(
            value["master_file"]["file_sha256"],
            hex::encode(sha256(&bytes))
        );
        assert_eq!(value["audio"]["samples_per_channel"], "11025");

        let body: MeasureResponse = serde_json::from_value(value).expect("shape");
        assert_eq!(body.audio.timestamp_ms, body.master_file.timestamp_ms);
        assert!(body.audio.timestamp_ms > 1_700_000_000_000);
        assert_eq!(
            body.audio.data.pcm_digest,
            hex::encode(&measured.pcm_digest)
        );
        assert_eq!(body.public_key, ctx.public_key_hex());
        verify(&ctx, &body, &measured, &bytes);
    }
}

#[tokio::test]
async fn tags_are_skipped_on_both_routes() {
    let ctx = context();
    let router = app(
        ctx.clone(),
        server_config(DEFAULT_MAX_BODY_BYTES),
        CONCURRENT,
    )
    .expect("config");
    let canonical = fixture();
    let tagged = tagged(&canonical);
    let measured = measure(&canonical).expect("fixture");

    let (status, value) = send(&router, streamed(&tagged, 4096, Some(tagged.len()))).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let body: MeasureResponse = serde_json::from_value(value).expect("shape");
    assert_eq!(
        body.audio.data.pcm_digest,
        hex::encode(&measured.pcm_digest)
    );
    assert_eq!(
        body.master_file.data.file_sha256,
        hex::encode(sha256(&tagged))
    );
    verify(&ctx, &body, &measured, &tagged);

    let process = Request::builder()
        .method("POST")
        .uri("/process_data")
        .body(Body::from(tagged))
        .expect("request");
    let (status, value) = send(&router, process).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let body: ProcessDataResponse = serde_json::from_value(value).expect("shape");
    assert_eq!(
        body.audio.data.pcm_digest,
        hex::encode(&measured.pcm_digest)
    );
}

#[tokio::test]
async fn other_metadata_is_rejected_on_both_routes() {
    let canonical = fixture();
    let mut picture = canonical[..42].to_vec();
    picture[4] &= 0x7f;
    picture.extend_from_slice(&[0x86, 0, 0, 64]);
    picture.extend_from_slice(&[0; 64]);
    picture.extend_from_slice(&canonical[42..]);
    let router = router(DEFAULT_MAX_BODY_BYTES);
    let (status, value) = send(&router, streamed(&picture, 4096, Some(picture.len()))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(value["error"], "application_error");
    let message = value["message"].as_str().expect("message");
    assert!(message.contains("metadata block type 6"), "{message}");
    assert!(!value.to_string().contains("signature"));

    let process = Request::builder()
        .method("POST")
        .uri("/process_data")
        .body(Body::from(picture))
        .expect("request");
    let (status, value) = send(&router, process).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(value["message"], message);
}

#[tokio::test]
async fn invalid_bodies_are_rejected_unsigned() {
    let router = router(DEFAULT_MAX_BODY_BYTES);
    let mut corrupt = fixture();
    corrupt[30] ^= 1;
    let audio = measure(&fixture()).expect("fixture");
    let message = intent_message(AUDIO_INTENT, 1_750_000_000_000, &audio).expect("BCS");
    for (bytes, reason) in [
        (corrupt, "MD5"),
        (message, "fLaC"),
        (Vec::new(), "too short"),
    ] {
        let (status, value) = send(&router, streamed(&bytes, 4096, Some(bytes.len()))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{value}");
        assert_eq!(value["error"], "application_error");
        let text = value["message"].as_str().expect("message");
        assert!(text.contains(reason), "{text}");
        assert!(!value.to_string().contains("signature"));
    }
}

#[tokio::test]
async fn length_is_required_bounded_and_honoured() {
    let bytes = fixture();
    let small = router(bytes.len() - 1);
    let router = router(DEFAULT_MAX_BODY_BYTES);
    let (status, value) = send(&router, streamed(&bytes, 4096, None)).await;
    assert_eq!(status, StatusCode::LENGTH_REQUIRED);
    assert_eq!(value["error"], "length_required");

    let (status, value) = send(&small, streamed(&bytes, 4096, Some(bytes.len()))).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value["error"], "body_too_large");

    for declared in [bytes.len() - 1, bytes.len() + 1] {
        let (status, value) = send(&router, streamed(&bytes, 4096, Some(declared))).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "declared {declared}: {value}"
        );
        assert_eq!(value["error"], "body_read_failed");
        assert!(!value.to_string().contains("signature"));
    }
}

#[tokio::test]
async fn excessive_decoded_work_is_rejected_from_streaminfo() {
    let mut bytes = fixture();
    bytes[21] |= 0x0f;
    bytes[22..26].fill(0xff);
    let (request, sender) = open_body(bytes.len());
    sender
        .send(Ok(Bytes::copy_from_slice(&bytes[..42])))
        .await
        .expect("send");
    // The rest of the body never arrives: the verdict comes from STREAMINFO alone.
    let response = router(DEFAULT_MAX_BODY_BYTES)
        .oneshot(request)
        .await
        .expect("response");
    let (status, value) = json(response).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(value["message"].as_str().unwrap().contains("decoded PCM"));
    assert!(!value.to_string().contains("signature"));
    drop(sender);
}

#[tokio::test]
async fn concurrent_measurements_are_bounded() {
    let router = router(DEFAULT_MAX_BODY_BYTES);
    let bytes = fixture();
    let mut pending = Vec::new();
    for _ in 0..CONCURRENT {
        let (request, sender) = open_body(bytes.len());
        let mut response = Box::pin(router.clone().oneshot(request));
        assert!(futures_util::poll!(&mut response).is_pending());
        pending.push((response, sender));
    }
    let (status, value) = send(&router, streamed(&bytes, 4096, Some(bytes.len()))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(value["error"], "overloaded");

    // `/process_data` has its own permit.
    let process = Request::builder()
        .method("POST")
        .uri("/process_data")
        .body(Body::from(bytes.clone()))
        .expect("request");
    assert_eq!(send(&router, process).await.0, StatusCode::OK);

    let (response, sender) = pending.pop().expect("pending");
    sender
        .send(Ok(Bytes::from(bytes.clone())))
        .await
        .expect("send");
    drop(sender);
    assert_eq!(
        json(response.await.expect("response")).await.0,
        StatusCode::OK
    );
    let (status, _) = send(&router, streamed(&bytes, 4096, Some(bytes.len()))).await;
    assert_eq!(status, StatusCode::OK);
}

fn quick(chunk_timeout: Duration, request_timeout: Duration) -> Router {
    measure_routes(
        context(),
        StreamConfig {
            max_file_bytes: DEFAULT_MAX_BODY_BYTES as u64,
            max_concurrent: 1,
            chunk_timeout,
            request_timeout,
        },
    )
}

#[tokio::test]
async fn stalled_body_times_out() {
    let router = quick(Duration::from_millis(50), Duration::from_secs(30));
    let bytes = fixture();
    let (request, sender) = open_body(bytes.len());
    sender
        .send(Ok(Bytes::copy_from_slice(&bytes[..1000])))
        .await
        .expect("send");
    let (status, value) = send(&router, request).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(value["error"], "body_read_timeout");
    drop(sender);
    // The permit came back with the stalled request.
    let (status, _) = send(&router, streamed(&bytes, 4096, Some(bytes.len()))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn request_deadline_covers_the_whole_measurement() {
    let router = quick(Duration::from_secs(30), Duration::from_millis(50));
    let bytes = fixture();
    let (request, sender) = open_body(bytes.len());
    let (status, value) = send(&router, request).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(value["error"], "request_timeout");
    drop(sender);
    // The decoder stops once its input ends and returns the permit: the next request is not
    // refused for concurrency, and gets a deadline of its own.
    let mut status = StatusCode::TOO_MANY_REQUESTS;
    for _ in 0..100 {
        let (request, sender) = open_body(bytes.len());
        status = send(&router, request).await.0;
        drop(sender);
        if status != StatusCode::TOO_MANY_REQUESTS {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn nautilus_deadlines_do_not_apply_to_the_stream() {
    let config = ServerConfig {
        request_timeout: Duration::from_millis(50),
        body_read_timeout: Duration::from_millis(50),
        ..server_config(DEFAULT_MAX_BODY_BYTES)
    };
    let router = app(context(), config, CONCURRENT).expect("config");
    let bytes = fixture();
    let (request, sender) = open_body(bytes.len());
    let response = tokio::spawn(router.oneshot(request));
    tokio::time::sleep(Duration::from_millis(200)).await;
    sender.send(Ok(Bytes::from(bytes))).await.expect("send");
    drop(sender);
    let (status, value) = json(response.await.expect("task").expect("response")).await;
    assert_eq!(status, StatusCode::OK, "{value}");
}

#[test]
fn stream_limits_follow_the_body_limit() {
    let config = stream_config(DEFAULT_MAX_BODY_BYTES, 3);
    assert_eq!(config.max_file_bytes, 256 * 1024 * 1024);
    assert_eq!(config.max_concurrent, 3);
    assert_eq!(config.chunk_timeout, MEASURE_CHUNK_TIMEOUT);
    assert_eq!(config.request_timeout, MEASURE_REQUEST_TIMEOUT);
    assert!(config.chunk_timeout < config.request_timeout);
}
