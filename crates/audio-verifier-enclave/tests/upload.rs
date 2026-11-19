//! The encrypted upload through the router: `/upload-key` and `/upload`, and the committed
//! vectors `vectors/upload_key_intent.json` and `vectors/upload_hpke.json`.

use std::path::Path;

use audio_verifier_enclave::{
    Limits, Pins, UPLOAD_KEY_INTENT, UploadKey, app_with,
    master::MASTER_ASSOCIATED_DATA,
    tink,
    upload::{
        UPLOAD_KEY_LIFETIME_MS, UploadKeyPayload, frame_aad, policy_id, records, sign_upload_key,
        upload_info,
    },
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use hpke::{
    Deserializable as _, OpModeS, Serializable as _,
    aead::{AeadCtxS, AesGcm256},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use nautilus::{
    EnclaveIdentity, IntentMessage, NautilusContext, SignedResponse, Timestamp, intent_message,
    testing::FakeAttestor, verify_signed_response,
};
use rand::{RngCore as _, SeedableRng as _, rngs::StdRng};
use seal_crypto::{EncryptedObject, IBEPublicKeys, IBEUserSecretKeys, create_full_id, ibe};
use serde::Serialize;
use serde_json::{Value, json};
use tower::ServiceExt as _;
use walrus_core::BlobId;

type Kem = X25519HkdfSha256;
type Sender = AeadCtxS<AesGcm256, HkdfSha256, Kem>;

const RECORDING_ID: [u8; 32] = [0xc0; 32];

/// A refused upload: its name, start record, frames and the refusal's message.
type Case<'a> = (&'a str, &'a [u8], &'a [Vec<u8>], &'a str);

/// hpke 0.13's RNG traits over a seeded `StdRng`, or fixed bytes for vectors.
enum Rng {
    Seeded(Box<StdRng>),
    Fixed([u8; 32]),
}

impl rand_core_09::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        match self {
            Self::Seeded(rng) => rng.fill_bytes(dst),
            Self::Fixed(bytes) => dst.copy_from_slice(&bytes[..dst.len()]),
        }
    }
}

impl rand_core_09::CryptoRng for Rng {}

fn context() -> NautilusContext {
    NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    )
}

/// The image's pins with a key server key of the tests' own, so a test can open the DEK.
fn test_pins() -> (Pins, ibe::MasterKey) {
    let (master_key, pk) = ibe::generate_key_pair(&mut StdRng::seed_from_u64(5));
    let pins = Pins {
        key_server_pk: pk,
        ..Pins::with_package("0x5ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea15ea1")
    };
    (pins, master_key)
}

fn router(key_ikm: [u8; 32]) -> (Router, Pins, ibe::MasterKey) {
    let (pins, master_key) = test_pins();
    let router = app_with(
        context(),
        Limits::new(2),
        pins.clone(),
        UploadKey::from_ikm(&key_ikm),
    );
    (router, pins, master_key)
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../audio-verifier/tests/fixtures")
        .join(name);
    std::fs::read(path).expect("fixture")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// An HPKE sender to `public` for an upload of `file_size` bytes to `recording`, and its start
/// record.
fn sender(
    public: &[u8; 32],
    recording: &[u8; 32],
    file_size: u64,
    expires_ms: u64,
    rng: &mut Rng,
) -> (Vec<u8>, Sender) {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(public).expect("X25519 key");
    let info = upload_info(&policy_id(), recording, file_size, expires_ms);
    let (enc, sender) =
        hpke::setup_sender::<AesGcm256, HkdfSha256, Kem, _>(&OpModeS::Base, &pk, &info, rng)
            .expect("sender");
    let start = json!({
        "enc": hex::encode(enc.to_bytes()),
        "recording_id": format!("0x{}", hex::encode(recording)),
        "file_size": file_size.to_string(),
        "key_expires_ms": expires_ms.to_string(),
    });
    (serde_json::to_vec(&start).unwrap(), sender)
}

/// `u64be(offset) ‖ seal(chunk)`, sealed with `last` in its associated data.
fn frame(sender: &mut Sender, offset: u64, chunk: &[u8], last: bool) -> Vec<u8> {
    let mut frame = offset.to_be_bytes().to_vec();
    frame.extend(sender.seal(chunk, &frame_aad(offset, last)).expect("seal"));
    frame
}

/// `file` encrypted to `public` for `recording`, in frames of `chunk` bytes.
fn upload(
    public: &[u8; 32],
    recording: &[u8; 32],
    file: &[u8],
    chunk: usize,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut rng = Rng::Seeded(Box::new(StdRng::seed_from_u64(3)));
    let expires = now_ms() + 60_000;
    let (start, mut sender) = sender(public, recording, file.len() as u64, expires, &mut rng);
    let mut frames = Vec::new();
    for (index, part) in file.chunks(chunk).enumerate() {
        let offset = (index * chunk) as u64;
        let last = offset as usize + part.len() == file.len();
        frames.push(frame(&mut sender, offset, part, last));
    }
    (start, frames)
}

async fn post(router: &Router, start: &[u8], frames: &[Vec<u8>]) -> (StatusCode, Value, Vec<u8>) {
    let mut parts: Vec<&[u8]> = vec![start];
    parts.extend(frames.iter().map(Vec::as_slice));
    let request = Request::post("/upload").body(records(&parts)).unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    match bytes.iter().position(|&byte| byte == b'\n') {
        Some(newline) if status == StatusCode::OK => (
            status,
            serde_json::from_slice(&bytes[..newline]).unwrap(),
            bytes[newline + 1..].to_vec(),
        ),
        _ => (status, serde_json::from_slice(&bytes).unwrap(), Vec::new()),
    }
}

async fn upload_key(router: &Router) -> Value {
    let request = Request::get("/upload-key").body(Body::empty()).unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test]
async fn the_upload_key_is_signed_with_an_expiry() {
    let (router, ..) = router([0x11; 32]);
    let key = upload_key(&router).await;
    let ctx = context();
    let x25519 = UploadKey::from_ikm(&[0x11; 32]).public_key();
    assert_eq!(key["intent"], 3);
    assert_eq!(key["context"], "miso-master-upload-v1");
    assert_eq!(key["x25519_public_key"], hex::encode(x25519));
    assert_eq!(key["public_key"], ctx.public_key_hex());
    let timestamp_ms = key["timestamp_ms"].as_u64().unwrap();
    let expires_ms: u64 = key["expires_ms"].as_str().unwrap().parse().unwrap();
    assert_eq!(expires_ms, timestamp_ms + UPLOAD_KEY_LIFETIME_MS);
    let signed = SignedResponse {
        response: IntentMessage {
            intent: UPLOAD_KEY_INTENT,
            timestamp_ms,
            data: UploadKeyPayload {
                context: b"miso-master-upload-v1".to_vec(),
                x25519_public_key: x25519.to_vec(),
                expires_ms,
            },
        },
        signature: key["signature"].as_str().unwrap().into(),
    };
    verify_signed_response(&ctx.public_key(), UPLOAD_KEY_INTENT, &signed).expect("verifies");
    // Not a measurement's signature.
    assert!(
        verify_signed_response(
            &ctx.public_key(),
            audio_verifier_enclave::AUDIO_INTENT,
            &signed
        )
        .is_err()
    );
}

#[tokio::test]
async fn an_upload_measures_and_seals_as_its_file() {
    let (router, pins, master_key) = router([0x11; 32]);
    let public = UploadKey::from_ikm(&[0x11; 32]).public_key();
    let file = fixture("s24_stereo_48000.flac");
    let (start, frames) = upload(&public, &RECORDING_ID, &file, 4096);
    assert!(frames.len() > 8);
    let (status, measured, ciphertext) = post(&router, &start, &frames).await;
    assert_eq!(status, StatusCode::OK, "{measured}");
    assert_eq!(measured["master_file"]["file_size"], file.len().to_string());
    assert_eq!(
        measured["master_file"]["file_blake3"],
        hex::encode(blake3::hash(&file).as_bytes())
    );
    assert_eq!(measured["audio"]["channels"], 2);
    assert_eq!(measured["audio"]["bit_depth"], 24);
    assert_eq!(measured["ciphertext_size"], ciphertext.len().to_string());

    // The same file measured over `/measure` has the same facts.
    let uri = format!("/measure?recording_id={}", hex::encode(RECORDING_ID));
    let request = Request::post(uri)
        .header("content-length", file.len())
        .body(Body::from(file.clone()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let newline = bytes.iter().position(|&byte| byte == b'\n').unwrap();
    let direct: Value = serde_json::from_slice(&bytes[..newline]).unwrap();
    for field in [
        "pcm_digest",
        "samples_per_channel",
        "channel_layout",
        "sample_rate_hz",
    ] {
        assert_eq!(measured["audio"][field], direct["audio"][field], "{field}");
    }

    // The ciphertext is the file, under a DEK sealed to the recording and the blob.
    let sealed = hex::decode(measured["audio"]["sealed_dek"].as_str().unwrap()).unwrap();
    let object: EncryptedObject = bcs::from_bytes(&sealed).unwrap();
    let blob_id: BlobId = measured["audio"]["blob_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(pins.blob_id(&ciphertext).unwrap(), blob_id);
    let full_id = create_full_id(
        &pins.package.into_inner(),
        &audio_verifier_enclave::identity(&RECORDING_ID, &blob_id),
    );
    let keys = IBEUserSecretKeys::BonehFranklinBLS12381(
        [(pins.key_server, ibe::extract(&master_key, &full_id))].into(),
    );
    let public_keys = IBEPublicKeys::BonehFranklinBLS12381(vec![pins.key_server_pk]);
    let dek: [u8; 32] = seal_crypto::seal_decrypt(&object, &keys, Some(&public_keys))
        .unwrap()
        .try_into()
        .unwrap();
    let opened = tink::decrypt(&dek, MASTER_ASSOCIATED_DATA, &ciphertext).unwrap();
    assert_eq!(opened, file);
}

#[tokio::test]
async fn tampered_uploads_are_refused() {
    let (router, ..) = router([0x11; 32]);
    let public = UploadKey::from_ikm(&[0x11; 32]).public_key();
    let file = fixture("s24_stereo_48000.flac");
    let (start, frames) = upload(&public, &RECORDING_ID, &file, 4096);
    let n = frames.len();

    let mut reordered = frames.clone();
    reordered.swap(1, 2);
    // The same, with each offset header rewritten to its new place: the sequence nonces and
    // the sealed offsets still disagree.
    let mut relabeled = reordered.clone();
    relabeled[1][..8].copy_from_slice(&4096u64.to_be_bytes());
    relabeled[2][..8].copy_from_slice(&8192u64.to_be_bytes());
    let mut dropped = frames.clone();
    dropped.remove(1);
    let mut changed = frames.clone();
    changed[1][100] ^= 1;
    let mut repeated = frames.clone();
    repeated.insert(2, frames[1].clone());
    // A frame whose offset header names the next frame's place: its own sealed bytes do not
    // open there.
    let mut moved = frames.clone();
    moved.remove(1);
    moved[1][..8].copy_from_slice(&4096u64.to_be_bytes());
    let mut extra = frames.clone();
    extra.push(b"after the end".to_vec());
    // The start record names another recording than the one the client encrypted for.
    let mut other: Value = serde_json::from_slice(&start).unwrap();
    other["recording_id"] = json!(format!("0x{}", hex::encode([0xc1u8; 32])));
    let other = serde_json::to_vec(&other).unwrap();
    // Encrypted to another key than the enclave's.
    let wrong_key = UploadKey::from_ikm(&[0x12; 32]).public_key();
    let (wrong_start, wrong_frames) = upload(&wrong_key, &RECORDING_ID, &file, 4096);
    // A middle frame marked as the last.
    let mut rng = Rng::Seeded(Box::new(StdRng::seed_from_u64(4)));
    let expires = now_ms() + 60_000;
    let (early_start, mut s) = sender(&public, &RECORDING_ID, file.len() as u64, expires, &mut rng);
    let early: Vec<Vec<u8>> = file
        .chunks(4096)
        .enumerate()
        .map(|(index, part)| frame(&mut s, (index * 4096) as u64, part, index == 1))
        .collect();

    let cases: Vec<Case> = vec![
        ("reordered", &start, &reordered, "where 4096 was next"),
        (
            "reordered, offsets rewritten",
            &start,
            &relabeled,
            "does not open",
        ),
        ("dropped", &start, &dropped, "where 4096 was next"),
        ("changed byte", &start, &changed, "does not open"),
        ("repeated", &start, &repeated, "where 8192 was next"),
        ("moved", &start, &moved, "does not open"),
        (
            "truncated",
            &start,
            &frames[..n - 1],
            "the upload ended after",
        ),
        (
            "after the final frame",
            &start,
            &extra,
            "continues after its final frame",
        ),
        ("another recording", &other, &frames, "does not open"),
        ("another key", &wrong_start, &wrong_frames, "does not open"),
        ("early final flag", &early_start, &early, "does not open"),
    ];
    for (name, start, frames, expected) in cases {
        let (status, value, ciphertext) = post(&router, start, frames).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {value}");
        assert_eq!(value["error"], "upload_rejected", "{name}: {value}");
        let message = value["message"].as_str().unwrap();
        assert!(message.contains(expected), "{name}: {message}");
        assert!(ciphertext.is_empty(), "{name}");
    }
}

#[tokio::test]
async fn an_expired_or_unknown_key_expiry_is_refused() {
    let (router, ..) = router([0x11; 32]);
    let public = UploadKey::from_ikm(&[0x11; 32]).public_key();
    let file = fixture("s24_stereo_48000.flac");
    for (expires, error) in [
        (now_ms() - 1, "upload_key_expired"),
        (
            now_ms() + UPLOAD_KEY_LIFETIME_MS + 60_000,
            "upload_rejected",
        ),
    ] {
        let mut rng = Rng::Seeded(Box::new(StdRng::seed_from_u64(6)));
        let (start, mut s) = sender(&public, &RECORDING_ID, file.len() as u64, expires, &mut rng);
        let frames = vec![frame(&mut s, 0, &file, true)];
        let (status, value, _) = post(&router, &start, &frames).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
        assert_eq!(value["error"], error, "{value}");
    }
}

#[tokio::test]
async fn a_bad_start_record_is_refused() {
    let (router, ..) = router([0x11; 32]);
    for start in [
        &b"not json"[..],
        br#"{"enc":"00","recording_id":"0x00","file_size":"1","key_expires_ms":"1"}"#,
        br#"{"enc":"zz","recording_id":"0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0","file_size":"1","key_expires_ms":"99999999999999"}"#,
        br#"{"enc":"00","recording_id":"0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0","file_size":"0","key_expires_ms":"1","extra":1}"#,
    ] {
        let (status, value, _) = post(&router, start, &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
        assert_eq!(value["error"], "upload_rejected", "{value}");
    }
    let request = Request::post("/upload").body(Body::empty()).unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[derive(Serialize)]
struct KeyVector {
    intent: u8,
    timestamp_ms: u64,
    x25519_ikm: String,
    x25519_public_key: String,
    context: String,
    expires_ms: String,
    payload_bcs_hex: String,
    intent_message_hex: String,
    public_key: String,
    signature: String,
}

#[derive(Serialize)]
struct FrameVector {
    offset: u64,
    last: bool,
    plaintext_hex: String,
    aad_hex: String,
    frame_hex: String,
}

#[derive(Serialize)]
struct HpkeVector {
    suite: &'static str,
    x25519_ikm: String,
    x25519_public_key: String,
    ephemeral_ikm: String,
    policy: String,
    recording_id: String,
    file_size: String,
    key_expires_ms: String,
    info_hex: String,
    enc: String,
    frames: Vec<FrameVector>,
}

/// Fails, after regenerating it for review, if `vectors/{name}` is not `value`.
fn assert_committed<T: Serialize>(name: &str, value: &T) {
    let rendered = serde_json::to_string_pretty(value).expect("JSON") + "\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    if std::fs::read_to_string(&path).ok().as_deref() != Some(rendered.as_str()) {
        std::fs::write(&path, &rendered).expect("write vector");
        panic!("vectors/{name} was stale and has been regenerated; review and commit it");
    }
}

#[test]
fn the_upload_vectors_are_committed() {
    const TIMESTAMP_MS: u64 = 1_750_000_000_000;
    let ctx = NautilusContext::with_signer(
        EnclaveIdentity::from_seed([7u8; 32]),
        FakeAttestor::default(),
    );
    let ikm = [0x11u8; 32];
    let key = UploadKey::from_ikm(&ikm);
    let signed = sign_upload_key(&ctx, Timestamp::from_ms(TIMESTAMP_MS), &key).unwrap();
    let payload = UploadKeyPayload {
        context: b"miso-master-upload-v1".to_vec(),
        x25519_public_key: key.public_key().to_vec(),
        expires_ms: TIMESTAMP_MS + UPLOAD_KEY_LIFETIME_MS,
    };
    let message = intent_message(UPLOAD_KEY_INTENT, TIMESTAMP_MS, &payload).unwrap();
    assert_committed(
        "upload_key_intent.json",
        &KeyVector {
            intent: signed.intent,
            timestamp_ms: signed.timestamp_ms,
            x25519_ikm: hex::encode(ikm),
            x25519_public_key: signed.x25519_public_key,
            context: signed.context,
            expires_ms: signed.expires_ms,
            payload_bcs_hex: hex::encode(bcs::to_bytes(&payload).unwrap()),
            intent_message_hex: hex::encode(message),
            public_key: signed.public_key,
            signature: signed.signature,
        },
    );

    let ephemeral = [0x22u8; 32];
    let file_size = 11u64;
    let expires_ms = TIMESTAMP_MS + UPLOAD_KEY_LIFETIME_MS;
    let mut rng = Rng::Fixed(ephemeral);
    let (start, mut s) = sender(
        &key.public_key(),
        &RECORDING_ID,
        file_size,
        expires_ms,
        &mut rng,
    );
    let start: Value = serde_json::from_slice(&start).unwrap();
    let mut frames = Vec::new();
    for (offset, chunk) in [(0u64, &b"miso "[..]), (5, &b"master"[..])] {
        let last = offset + chunk.len() as u64 == file_size;
        frames.push(FrameVector {
            offset,
            last,
            plaintext_hex: hex::encode(chunk),
            aad_hex: hex::encode(frame_aad(offset, last)),
            frame_hex: hex::encode(frame(&mut s, offset, chunk, last)),
        });
    }
    assert_committed(
        "upload_hpke.json",
        &HpkeVector {
            suite: "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM; base mode",
            x25519_ikm: hex::encode(ikm),
            x25519_public_key: hex::encode(key.public_key()),
            ephemeral_ikm: hex::encode(ephemeral),
            policy: hex::encode(policy_id()),
            recording_id: hex::encode(RECORDING_ID),
            file_size: file_size.to_string(),
            key_expires_ms: expires_ms.to_string(),
            info_hex: hex::encode(upload_info(
                &policy_id(),
                &RECORDING_ID,
                file_size,
                expires_ms,
            )),
            enc: start["enc"].as_str().unwrap().into(),
            frames,
        },
    );
}
