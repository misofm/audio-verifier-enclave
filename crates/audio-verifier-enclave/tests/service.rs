//! The service through its router: `/health`, `/attest` and `/measure`.

use std::{
    path::Path,
    sync::{Mutex, mpsc},
    time::Duration,
};

use audio_verifier::{AudioFacts, measure};
use audio_verifier_enclave::{
    ATTEST_BODY_BYTES, AUDIO_INTENT, AudioPayload, Limits, MASTER_FILE_INTENT, MAX_FILE_BYTES,
    MEASURED_MASTER_TYPE, MasterFilePayload, MeasureResponse, Pins, app, app_with_pins, identity,
    master::{MASTER_ASSOCIATED_DATA, SEAL_KEY_SERVER, SEAL_THRESHOLD},
    tink,
};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, Response, StatusCode, header},
};
use futures_util::stream;
use nautilus::{
    AttestationError, AttestationRequest, Attestor, EnclaveIdentity, IntentMessage,
    NautilusContext, SignedResponse, intent_message, testing::FakeAttestor, verify_signed_response,
};
use rand::{SeedableRng as _, rngs::StdRng};
use seal_crypto::{
    EncryptedObject, IBEPublicKeys, IBEUserSecretKeys, create_full_id, ibe, seal_decrypt,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tower::ServiceExt as _;
use walrus_core::BlobId;

type Chunk = Result<Bytes, std::io::Error>;

/// `/measure` jobs the test routers run at once.
const JOBS: usize = 2;

fn context() -> NautilusContext {
    NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    )
}

fn router() -> Router {
    app(context(), Limits::new(JOBS))
}

/// The image's pins with a policy package and a key server key of the tests' own, so a test
/// can open the sealed DEK.
fn test_pins() -> (Pins, ibe::MasterKey) {
    let (master_key, pk) = ibe::generate_key_pair(&mut StdRng::seed_from_u64(5));
    let pins = Pins {
        key_server_pk: pk,
        ..Pins::with_package("0x5ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea1")
    };
    (pins, master_key)
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../audio-verifier/tests/fixtures")
        .join(name);
    std::fs::read(path).expect("fixture")
}

fn request(method: &str, uri: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(body.into())
        .expect("request")
}

/// The Recording the tests seal masters to.
const RECORDING_ID: [u8; 32] = [0xc0; 32];

/// A `/measure` request declaring `length`, if any.
fn measure_request(body: Body, length: Option<usize>) -> Request<Body> {
    let uri = format!("/measure?recording_id=0x{}", hex::encode(RECORDING_ID));
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(length) = length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    builder.body(body).expect("request")
}

/// `parts` as a network body, one chunk each, declaring `length`.
fn chunked(parts: Vec<&[u8]>, length: usize) -> Request<Body> {
    let chunks: Vec<Chunk> = parts
        .into_iter()
        .map(|part| Ok(Bytes::copy_from_slice(part)))
        .collect();
    measure_request(Body::from_stream(stream::iter(chunks)), Some(length))
}

/// `bytes` as a network body in chunks of at most `chunk` bytes.
fn streamed(bytes: &[u8], chunk: usize) -> Request<Body> {
    chunked(bytes.chunks(chunk).collect(), bytes.len())
}

/// A body fed by hand: the request and the sender for its chunks.
fn open_body(length: usize) -> (Request<Body>, tokio::sync::mpsc::Sender<Chunk>) {
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Chunk>(4);
    let body = Body::from_stream(stream::poll_fn(move |cx| receiver.poll_recv(cx)));
    (measure_request(body, Some(length)), sender)
}

/// The response's status, JSON and the ciphertext after it, if it is a measured master.
async fn read(response: Response<Body>) -> (StatusCode, Value, Option<Vec<u8>>) {
    let status = response.status();
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let length = response.headers().get(header::CONTENT_LENGTH).cloned();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    if content_type.as_ref().and_then(|value| value.to_str().ok()) != Some(MEASURED_MASTER_TYPE) {
        return (status, serde_json::from_slice(&bytes).expect("JSON"), None);
    }
    assert_eq!(status, StatusCode::OK);
    let length: usize = length.expect("length").to_str().unwrap().parse().unwrap();
    assert_eq!(length, bytes.len());
    let newline = bytes
        .iter()
        .position(|&byte| byte == b'\n')
        .expect("newline");
    let value: Value = serde_json::from_slice(&bytes[..newline]).expect("JSON");
    let ciphertext = bytes[newline + 1..].to_vec();
    assert_eq!(value["ciphertext_size"], ciphertext.len().to_string());
    (status, value, Some(ciphertext))
}

async fn json(response: Response<Body>) -> (StatusCode, Value) {
    let (status, value, _) = read(response).await;
    (status, value)
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
    json(router.clone().oneshot(request).await.expect("response")).await
}

async fn send_measured(router: &Router, request: Request<Body>) -> (StatusCode, Value, Vec<u8>) {
    let (status, value, ciphertext) =
        read(router.clone().oneshot(request).await.expect("response")).await;
    (status, value, ciphertext.unwrap_or_default())
}

#[tokio::test]
async fn health_reports_the_injected_identity() {
    let ctx = context();
    let router = app(ctx.clone(), Limits::new(JOBS));
    let (status, value) = send(&router, request("GET", "/health", Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value,
        json!({ "pk": ctx.public_key_hex(), "address": ctx.sui_address() })
    );
}

#[tokio::test]
async fn attest_binds_the_nonce_and_the_key() {
    let attestor = FakeAttestor::default();
    let ctx = NautilusContext::with_signer(EnclaveIdentity::from_seed([9u8; 32]), attestor.clone());
    let router = app(ctx.clone(), Limits::new(JOBS));
    let body = r#"{ "nonce": "0a0b0c" }"#;
    let (status, value) = send(&router, request("POST", "/attest", body)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let document = hex::decode(value["attestation"].as_str().expect("hex")).expect("hex");
    let document: Value = serde_json::from_slice(&document).expect("fake document");
    assert_eq!(document["nonce"], "0a0b0c");
    assert_eq!(document["public_key"], ctx.public_key_hex());
    let requests = attestor.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].nonce.as_deref(), Some(&[10u8, 11, 12][..]));
    assert_eq!(requests[0].user_data, None);
}

#[tokio::test]
async fn attest_requires_a_nonce_and_nothing_else() {
    let router = router();
    for body in [
        "",
        "{}",
        r#"{ "nonce": "" }"#,
        r#"{ "nonce": "zz" }"#,
        r#"{ "nonce": "0a", "user_data": "0b" }"#,
    ] {
        let (status, value) = send(&router, request("POST", "/attest", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {value}");
        assert_eq!(value["error"], "invalid_request", "{body}");
    }
    let oversized = format!(r#"{{ "nonce": "{}" }}"#, "00".repeat(513));
    let (status, value) = send(&router, request("POST", "/attest", oversized)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = value["message"].as_str().expect("message");
    assert!(message.contains("at most 512 bytes"), "{message}");
}

#[tokio::test]
async fn attest_body_is_bounded() {
    let router = router();
    // A declared length over the limit is refused before any of the body is read.
    let declared = Request::builder()
        .method("POST")
        .uri("/attest")
        .header(header::CONTENT_LENGTH, ATTEST_BODY_BYTES + 1)
        .body(Body::from_stream(stream::pending::<Chunk>()))
        .expect("request");
    let (status, value) = send(&router, declared).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value["error"], "body_too_large");

    // Without one, the body is refused once it delivers more than the limit.
    let body = format!(
        r#"{{ "nonce": "0a", "pad": "{}" }}"#,
        " ".repeat(ATTEST_BODY_BYTES)
    );
    let chunks: Vec<Chunk> = body
        .as_bytes()
        .chunks(100)
        .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
        .collect();
    let streamed = Body::from_stream(stream::iter(chunks));
    let (status, value) = send(&router, request("POST", "/attest", streamed)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value["error"], "body_too_large");
}

/// An attestor that reports each attestation and blocks it until released.
struct Gate {
    entered: UnboundedSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Attestor for Gate {
    fn name(&self) -> &'static str {
        "gate"
    }

    fn attest(&self, _request: AttestationRequest) -> Result<Vec<u8>, AttestationError> {
        self.entered.send(()).expect("entered");
        self.release.lock().expect("lock").recv().expect("released");
        Err(AttestationError::Unavailable("closed".into()))
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, AttestationError> {
        Ok(vec![0; len])
    }
}

#[tokio::test]
async fn attestations_run_one_at_a_time() {
    let (entered, mut attesting) = unbounded_channel();
    let (release, gate) = mpsc::channel();
    let gate = Gate {
        entered,
        release: Mutex::new(gate),
    };
    let ctx = NautilusContext::with_signer(EnclaveIdentity::from_seed([9u8; 32]), gate);
    let router = app(ctx, Limits::new(JOBS));
    let body = r#"{ "nonce": "0a" }"#;
    let first = tokio::spawn(router.clone().oneshot(request("POST", "/attest", body)));
    attesting.recv().await.expect("attesting");

    let (status, value) = send(&router, request("POST", "/attest", body)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(value["error"], "overloaded");
    let health = request("GET", "/health", Body::empty());
    assert_eq!(send(&router, health).await.0, StatusCode::OK);

    release.send(()).expect("release");
    let (status, value) = json(first.await.expect("task").expect("response")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["error"], "attestation_unavailable");
}

#[tokio::test]
async fn unknown_routes_and_methods_get_json_errors() {
    let router = router();
    for uri in [
        "/process_data",
        "/v1/measure",
        "/attestation",
        "/health_check",
    ] {
        let (status, value) = send(&router, request("POST", uri, Body::empty())).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(value["error"], "not_found");
    }
    for (method, uri) in [("GET", "/attest"), ("GET", "/measure"), ("POST", "/health")] {
        let (status, value) = send(&router, request(method, uri, Body::empty())).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {uri}");
        assert_eq!(value["error"], "method_not_allowed");
    }
}

/// The payload `body` signed for `facts`: its blob ID and sealed DEK, which must be the blob ID
/// of `ciphertext` and a Seal encryption to it under `pins`.
fn payload(
    body: &MeasureResponse,
    facts: &AudioFacts,
    ciphertext: &[u8],
    pins: &Pins,
) -> AudioPayload {
    let blob_id = pins.blob_id(ciphertext).expect("blob ID");
    assert_eq!(body.audio.data.blob_id, blob_id.to_string());
    assert_eq!(
        body.audio.data.blob_id_u256,
        audio_verifier_enclave::u256_le_decimal(&blob_id.0)
    );
    let sealed_dek = hex::decode(&body.audio.data.sealed_dek).expect("hex");
    let object: EncryptedObject = bcs::from_bytes(&sealed_dek).expect("EncryptedObject");
    assert_eq!(object.package_id, pins.package);
    assert_eq!(object.id, identity(&RECORDING_ID, &blob_id));
    assert_eq!(object.services, vec![(pins.key_server, 1)]);
    assert_eq!(object.threshold, SEAL_THRESHOLD);
    assert_eq!(pins.key_server.to_string(), SEAL_KEY_SERVER);
    AudioPayload::new(facts.clone(), blob_id.0, sealed_dek)
}

/// Opens the sealed DEK with the key server's master key and decrypts `ciphertext`.
fn open(
    payload: &AudioPayload,
    ciphertext: &[u8],
    pins: &Pins,
    master_key: &ibe::MasterKey,
) -> Vec<u8> {
    let object: EncryptedObject = bcs::from_bytes(&payload.sealed_dek).expect("EncryptedObject");
    let blob_id = BlobId(payload.blob_id);
    let full_id = create_full_id(
        &pins.package.into_inner(),
        &identity(&RECORDING_ID, &blob_id),
    );
    let keys = IBEUserSecretKeys::BonehFranklinBLS12381(
        [(pins.key_server, ibe::extract(master_key, &full_id))].into(),
    );
    let public = IBEPublicKeys::BonehFranklinBLS12381(vec![pins.key_server_pk]);
    let dek: [u8; 32] = seal_decrypt(&object, &keys, Some(&public))
        .expect("the DEK opens")
        .try_into()
        .expect("32 bytes");
    tink::decrypt(&dek, MASTER_ASSOCIATED_DATA, ciphertext).expect("the ciphertext opens")
}

/// Rebuilds both signed messages from `audio` and `file` and checks `body`'s signatures over
/// them, and that neither verifies under the other's intent.
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
                file_sha256: Sha256::digest(file).to_vec(),
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
async fn file_is_encrypted_sealed_and_signed_twice_however_chunked() {
    let ctx = context();
    let (pins, master_key) = test_pins();
    let router = app_with_pins(ctx.clone(), Limits::new(JOBS), pins.clone());
    let bytes = fixture("s16_stereo_44100.flac");
    let measured = measure(&bytes).expect("fixture");
    let mut blob_ids = Vec::new();
    for chunk in [1, 7, 4096, 1 << 20, bytes.len()] {
        let (status, value, ciphertext) = send_measured(&router, streamed(&bytes, chunk)).await;
        assert_eq!(status, StatusCode::OK, "chunks of {chunk}: {value}");
        let body: MeasureResponse = serde_json::from_value(value.clone()).expect("shape");
        let expected = json!({
            "audio": {
                "intent": 0,
                "timestamp_ms": body.audio.timestamp_ms,
                "channels": 2,
                "bit_depth": 16,
                "sample_rate_hz": 44_100,
                "samples_per_channel": "11025",
                "pcm_digest": hex::encode(&measured.pcm_digest),
                "channel_layout": [0, 1],
                "blob_id": body.audio.data.blob_id,
                "blob_id_u256": body.audio.data.blob_id_u256,
                "sealed_dek": body.audio.data.sealed_dek,
                "signature": body.audio.signature,
            },
            "master_file": {
                "intent": 2,
                "timestamp_ms": body.audio.timestamp_ms,
                "file_size": bytes.len().to_string(),
                "file_sha256": hex::encode(Sha256::digest(&bytes)),
                "signature": body.master_file.signature,
            },
            "ciphertext_size": tink::ciphertext_size(bytes.len() as u64).to_string(),
            "public_key": ctx.public_key_hex(),
        });
        assert_eq!(value, expected, "chunks of {chunk}");
        assert!(body.audio.timestamp_ms > 1_700_000_000_000);
        let payload = payload(&body, &measured, &ciphertext, &pins);
        verify(&ctx, &body, &payload, &bytes);
        assert_eq!(open(&payload, &ciphertext, &pins, &master_key), bytes);
        blob_ids.push(body.audio.data.blob_id);
    }
    // Every request has its own DEK, salt and nonce prefix, so its own ciphertext.
    blob_ids.sort();
    blob_ids.dedup();
    assert_eq!(blob_ids.len(), 5);
}

#[tokio::test]
async fn the_image_pins_seal_to_the_committee_key_server() {
    let router = router();
    let bytes = fixture("s16_mono_44100.flac");
    let (status, value, ciphertext) = send_measured(&router, streamed(&bytes, 4096)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let body: MeasureResponse = serde_json::from_value(value).expect("shape");
    assert_eq!(body.audio.data.channel_layout, [2]);
    payload(
        &body,
        &measure(&bytes).expect("fixture"),
        &ciphertext,
        &Pins::pinned(),
    );
}

/// `canonical` with a codec-style VORBIS_COMMENT and 8 KiB of PADDING after STREAMINFO.
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

#[tokio::test]
async fn tags_do_not_change_the_audio_but_are_in_the_file_binding() {
    let ctx = context();
    let (pins, master_key) = test_pins();
    let router = app_with_pins(ctx.clone(), Limits::new(JOBS), pins.clone());
    let canonical = fixture("s16_stereo_44100.flac");
    let tagged = tagged(&canonical);
    let measured = measure(&canonical).expect("fixture");
    let (status, value, ciphertext) = send_measured(&router, streamed(&tagged, 4096)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let body: MeasureResponse = serde_json::from_value(value).expect("shape");
    assert_eq!(
        body.audio.data.pcm_digest,
        hex::encode(&measured.pcm_digest)
    );
    assert_eq!(
        body.master_file.data.file_sha256,
        hex::encode(Sha256::digest(&tagged))
    );
    let payload = payload(&body, &measured, &ciphertext, &pins);
    verify(&ctx, &body, &payload, &tagged);
    // The whole file is encrypted, its tags included.
    assert_eq!(open(&payload, &ciphertext, &pins, &master_key), tagged);
}

#[tokio::test]
async fn rejected_files_get_the_library_verdict_unsigned_however_chunked() {
    let router = router();
    let canonical = fixture("s16_stereo_44100.flac");
    let mut corrupt = canonical.clone();
    corrupt[30] ^= 1;
    let audio = AudioPayload::new(measure(&canonical).expect("fixture"), [3; 32], vec![4; 8]);
    let message = intent_message(AUDIO_INTENT, 1_750_000_000_000, &audio).expect("BCS");
    let mut picture = canonical[..42].to_vec();
    picture[4] &= 0x7f;
    picture.extend_from_slice(&[0x86, 0, 0, 64]);
    picture.extend_from_slice(&[0; 64]);
    picture.extend_from_slice(&canonical[42..]);
    let mut id3 = b"TAG".to_vec();
    id3.resize(128, 0);
    let files = [
        ("corrupt MD5", corrupt),
        ("not FLAC", message),
        ("empty", Vec::new()),
        ("PICTURE block", picture),
        ("overlong Rice code", fixture("overlong_rice.flac")),
        (
            "overlong Rice code",
            fixture("overlong_rice_canonical.flac"),
        ),
        ("trailing ID3 tag", [&canonical[..], &id3].concat()),
        ("trailing zero", [&canonical[..], &[0]].concat()),
        (
            "frames repeated",
            [&canonical[..], &canonical[42..]].concat(),
        ),
    ];
    for (name, bytes) in files {
        let error = measure(&bytes).expect_err(name);
        let expected = json!({ "error": "application_error", "message": error.to_string() });
        let mut requests: Vec<Request<Body>> = [1, 7, 4096, usize::MAX]
            .map(|chunk| streamed(&bytes, chunk))
            .into();
        // Split where the canonical file ends: a trailer arrives alone in the last chunk.
        if bytes.len() > canonical.len() {
            let (file, trailer) = bytes.split_at(canonical.len());
            requests.push(chunked(vec![file, trailer], bytes.len()));
        }
        for request in requests {
            let (status, value) = send(&router, request).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {value}");
            assert_eq!(value, expected, "{name}");
        }
    }
}

#[tokio::test]
async fn the_recording_id_is_required_once_as_32_hex_bytes() {
    let router = router();
    let bytes = fixture("s16_stereo_44100.flac");
    let id = hex::encode(RECORDING_ID);
    for query in [
        String::new(),
        "?recording=0x00".into(),
        "?recording_id=".into(),
        format!("?recording_id=0x{}", &id[2..]),
        format!("?recording_id=0x{id}00"),
        format!("?recording_id=0x{}zz", &id[2..]),
        format!("?recording_id=0x{id}&recording_id=0x{id}"),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/measure{query}"))
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(Body::from(bytes.clone()))
            .expect("request");
        let (status, value) = send(&router, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {value}");
        assert_eq!(value["error"], "invalid_request", "{query}");
    }
    for query in [
        format!("?recording_id={id}"),
        format!("?x=1&recording_id=0x{}", id.to_uppercase()),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/measure{query}"))
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(Body::from(bytes.clone()))
            .expect("request");
        let (status, value) = send(&router, request).await;
        assert_eq!(status, StatusCode::OK, "{query}: {value}");
    }
}

#[tokio::test]
async fn length_is_required_bounded_and_honoured() {
    let router = router();
    let bytes = fixture("s16_stereo_44100.flac");
    let no_length = Body::from_stream(stream::iter([Ok::<_, std::io::Error>(Bytes::from(
        bytes.clone(),
    ))]));
    let (status, value) = send(&router, measure_request(no_length, None)).await;
    assert_eq!(status, StatusCode::LENGTH_REQUIRED);
    assert_eq!(value["error"], "length_required");

    let (oversized, _sender) = open_body(MAX_FILE_BYTES as usize + 1);
    let (status, value) = send(&router, oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value["error"], "body_too_large");

    for declared in [bytes.len() - 1, bytes.len() + 1] {
        let (status, value) = send(&router, chunked(vec![&bytes], declared)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "declared {declared}");
        assert_eq!(value["error"], "body_read_failed", "declared {declared}");
    }
}

#[tokio::test]
async fn excessive_decoded_work_is_refused_before_the_body_arrives() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    bytes[21] |= 0x0f;
    bytes[22..26].fill(0xff);
    let (request, sender) = open_body(bytes.len());
    sender
        .send(Ok(Bytes::copy_from_slice(&bytes[..42])))
        .await
        .expect("send");
    // The rest of the body never arrives: the verdict comes from STREAMINFO alone.
    let (status, value) = send(&router(), request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        value["message"],
        "decoded PCM exceeds the 4 GiB service limit"
    );
}

#[tokio::test]
async fn concurrent_measurements_are_bounded() {
    let router = router();
    let bytes = fixture("s16_stereo_44100.flac");
    let mut pending = Vec::new();
    for _ in 0..JOBS {
        let (request, sender) = open_body(bytes.len());
        let mut response = Box::pin(router.clone().oneshot(request));
        assert!(futures_util::poll!(&mut response).is_pending());
        pending.push((response, sender));
    }
    let (status, value) = send(&router, streamed(&bytes, 4096)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(value["error"], "overloaded");
    let health = request("GET", "/health", Body::empty());
    assert_eq!(send(&router, health).await.0, StatusCode::OK);

    let (response, sender) = pending.pop().expect("pending");
    sender
        .send(Ok(Bytes::from(bytes.clone())))
        .await
        .expect("send");
    drop(sender);
    let (status, _) = json(response.await.expect("response")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        send(&router, streamed(&bytes, 4096)).await.0,
        StatusCode::OK
    );
}

fn quick(chunk_timeout: Duration, request_timeout: Duration) -> Router {
    let limits = Limits {
        chunk_timeout,
        request_timeout,
        ..Limits::new(1)
    };
    app(context(), limits)
}

#[tokio::test]
async fn stalled_body_times_out() {
    let router = quick(Duration::from_millis(50), Duration::from_secs(30));
    let bytes = fixture("s16_stereo_44100.flac");
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
    assert_eq!(
        send(&router, streamed(&bytes, 4096)).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn request_deadline_covers_the_whole_measurement() {
    let router = quick(Duration::from_secs(30), Duration::from_millis(50));
    let bytes = fixture("s16_stereo_44100.flac");
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
