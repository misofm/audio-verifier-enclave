//! The encrypted upload: `GET /upload-key` and `POST /upload`. The browser encrypts the FLAC
//! file to the enclave with HPKE (RFC 9180, base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
//! AES-256-GCM), so the host and everything in front of it carry only ciphertext.
//!
//! The X25519 key is made at boot, inside the enclave, and never leaves it. `/upload-key`
//! signs its public key with the enclave's per-boot Ed25519 key under [`UPLOAD_KEY_INTENT`],
//! with an expiry; a client checks the signature and that the Ed25519 key is registered with the
//! on-chain `EnclavePolicy<AUDIO_VERIFIER>`, then encrypts to it.
//!
//! `/upload`'s body is records, each `u32be(length) ‖ bytes`: first the [`StartRecord`] (JSON),
//! then the frames, each `u64be(offset) ‖ seal(chunk)`, in order, 1 to [`MAX_FRAME_PLAINTEXT`]
//! bytes of the file each. The HPKE context's sequence numbers are the frames' nonces, and the
//! associated data is [`frame_aad`] (the offset and whether the frame ends the file), so a
//! reordered, dropped, repeated, altered or misplaced frame does not open. The plaintext goes
//! straight into `/measure`'s pipeline; it is never written anywhere.

use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::BytesMut;
use futures_util::{Stream, StreamExt as _};
use hpke::{
    Deserializable as _, Kem as _, OpModeR, Serializable as _,
    aead::{AeadCtxR, AesGcm256},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use nautilus::{ErrorCode, Intent, NautilusContext, NautilusError, SignedResponse, Timestamp};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, time::timeout};

use crate::{MAX_FILE_BYTES, Service, measure, refuse, refuse_status};

/// Intent of the signed `IntentMessage<UploadKeyPayload>`: the enclave's upload key. Intents 0
/// and 2 are the measurement's; 1 is retired.
pub const UPLOAD_KEY_INTENT: Intent = Intent(3);

/// The protocol's label: the signed key's `context`, and the start of every HPKE `info`.
pub const UPLOAD_PROTOCOL: &str = "miso-master-upload-v1";

/// The on-chain `EnclavePolicy<AUDIO_VERIFIER>` on testnet, named in every HPKE `info`: the
/// policy a client checked the upload key against.
pub const AUDIO_VERIFIER_POLICY: &str =
    "0xeb9fdb274f4edbda86b322cbb876a4f92aa6b9e58964d6d5953ff0cead49160e";

/// How long a signed upload key is offered for. The key itself lives as long as the boot.
pub const UPLOAD_KEY_LIFETIME_MS: u64 = 10 * 60 * 1000;

/// Most plaintext bytes in one frame.
pub const MAX_FRAME_PLAINTEXT: usize = 1 << 20;

/// A frame's offset header.
pub const FRAME_OFFSET_BYTES: usize = 8;

/// AES-256-GCM's tag, after every sealed chunk.
pub const FRAME_TAG_BYTES: usize = 16;

/// Largest start record.
const START_RECORD_BYTES: usize = 4 << 10;

/// Largest frame record.
const FRAME_RECORD_BYTES: usize = FRAME_OFFSET_BYTES + MAX_FRAME_PLAINTEXT + FRAME_TAG_BYTES;

type Kem = X25519HkdfSha256;
type Receiver = AeadCtxR<AesGcm256, HkdfSha256, Kem>;

/// The enclave's X25519 upload key.
pub struct UploadKey {
    secret: <Kem as hpke::Kem>::PrivateKey,
    public: [u8; 32],
}

impl UploadKey {
    /// A fresh key from the kernel's randomness, made once per boot.
    pub fn generate() -> Self {
        let mut ikm = [0u8; 32];
        OsRng.fill_bytes(&mut ikm);
        let key = Self::from_ikm(&ikm);
        ikm.fill(0);
        key
    }

    /// The key `DeriveKeyPair(ikm)` gives, for tests and vectors.
    pub fn from_ikm(ikm: &[u8]) -> Self {
        let (secret, public) = Kem::derive_keypair(ikm);
        let public = public.to_bytes().into();
        Self { secret, public }
    }

    /// The X25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }
}

/// BCS layout of the upload key signed under [`UPLOAD_KEY_INTENT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadKeyPayload {
    /// [`UPLOAD_PROTOCOL`]'s bytes.
    pub context: Vec<u8>,
    /// The X25519 public key, 32 bytes.
    pub x25519_public_key: Vec<u8>,
    /// Until when the key is offered, in milliseconds since the Unix epoch.
    pub expires_ms: u64,
}

/// The `/upload-key` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadKeyJson {
    /// [`UPLOAD_KEY_INTENT`].
    pub intent: u8,
    /// Signing time, from the enclave clock.
    pub timestamp_ms: u64,
    /// [`UPLOAD_PROTOCOL`].
    pub context: String,
    /// The X25519 public key, hex.
    pub x25519_public_key: String,
    /// Until when the key is offered, as a decimal string.
    pub expires_ms: String,
    /// Ed25519 signature over the BCS intent message, hex.
    pub signature: String,
    /// The enclave's Ed25519 public key, hex.
    pub public_key: String,
}

/// Signs `key`'s public key at `timestamp`, offered for [`UPLOAD_KEY_LIFETIME_MS`].
pub fn sign_upload_key(
    ctx: &NautilusContext,
    timestamp: Timestamp,
    key: &UploadKey,
) -> Result<UploadKeyJson, NautilusError> {
    let payload = UploadKeyPayload {
        context: UPLOAD_PROTOCOL.as_bytes().to_vec(),
        x25519_public_key: key.public.to_vec(),
        expires_ms: timestamp.as_ms().saturating_add(UPLOAD_KEY_LIFETIME_MS),
    };
    let expires_ms = payload.expires_ms;
    let signed: SignedResponse<UploadKeyPayload> =
        ctx.sign_intent_stamped(UPLOAD_KEY_INTENT, timestamp, payload)?;
    Ok(UploadKeyJson {
        intent: signed.response.intent.0,
        timestamp_ms: signed.response.timestamp_ms,
        context: UPLOAD_PROTOCOL.into(),
        x25519_public_key: hex::encode(key.public),
        expires_ms: expires_ms.to_string(),
        signature: signed.signature,
        public_key: ctx.public_key_hex(),
    })
}

/// The HPKE `info` of an upload: [`UPLOAD_PROTOCOL`], the policy, the Recording, the file's
/// size and the key's expiry, `label ‖ policy (32) ‖ recording (32) ‖ u64be ‖ u64be`.
pub fn upload_info(
    policy: &[u8; 32],
    recording_id: &[u8; 32],
    file_size: u64,
    key_expires_ms: u64,
) -> Vec<u8> {
    let mut info = Vec::with_capacity(UPLOAD_PROTOCOL.len() + 80);
    info.extend_from_slice(UPLOAD_PROTOCOL.as_bytes());
    info.extend_from_slice(policy);
    info.extend_from_slice(recording_id);
    info.extend_from_slice(&file_size.to_be_bytes());
    info.extend_from_slice(&key_expires_ms.to_be_bytes());
    info
}

/// A frame's associated data: `u64be(offset) ‖ last`, `last` 1 on the frame that ends the
/// file, else 0.
pub fn frame_aad(offset: u64, last: bool) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&offset.to_be_bytes());
    aad[8] = u8::from(last);
    aad
}

/// The pinned policy's object ID.
pub fn policy_id() -> [u8; 32] {
    measure::object_id(AUDIO_VERIFIER_POLICY).expect("the pinned policy is an object ID")
}

/// `vectors/upload_hpke.json`: an upload of `miso master` in two frames, which `@hpke/core`
/// seals byte for byte as the enclave expects.
const KNOWN_ENC: &str = "e3b9708aaa21a7f1e62a95ee28d1e5d60b0fceed6c68599013a54b318e9e0b15";
const KNOWN_FRAMES: [(u64, &str, &str); 2] = [
    (
        0,
        "6d69736f20",
        "f9a3ef99134a602d59c1f024e24cce2aea698d1e65",
    ),
    (
        5,
        "6d6173746572",
        "d9b3ec9f152a40bcb60e0b4181eb8760aa29839ac603",
    ),
];

/// Opens the known upload, so that a build whose HPKE disagrees refuses to start.
pub fn self_test() -> Result<(), &'static str> {
    let failed = "self-test failed: HPKE upload";
    let key = UploadKey::from_ikm(&[0x11; 32]);
    let enc = hex::decode(KNOWN_ENC).map_err(|_| failed)?;
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc).map_err(|_| failed)?;
    let info = upload_info(&policy_id(), &[0xc0; 32], 11, 1_750_000_600_000);
    let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        &key.secret,
        &enc,
        &info,
    )
    .map_err(|_| failed)?;
    for (offset, plaintext, sealed) in KNOWN_FRAMES {
        let sealed = hex::decode(sealed).map_err(|_| failed)?;
        let last = offset == 5;
        let opened = receiver
            .open(&sealed, &frame_aad(offset, last))
            .map_err(|_| failed)?;
        if hex::encode(opened) != plaintext {
            return Err(failed);
        }
    }
    Ok(())
}

/// The first record of `/upload`: what the client encrypted to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRecord {
    /// The client's HPKE encapsulated key (its ephemeral X25519 public key), hex.
    pub enc: String,
    /// The Recording the master is sealed to, hex.
    pub recording_id: String,
    /// The file's bytes, a decimal string.
    pub file_size: String,
    /// The signed key's `expires_ms`, a decimal string.
    pub key_expires_ms: String,
}

pub(crate) async fn upload_key(State(service): State<Arc<Service>>) -> Response {
    let ctx = &service.ctx;
    match ctx
        .now()
        .and_then(|now| sign_upload_key(ctx, now, &service.upload_key))
    {
        Ok(signed) => Json(signed).into_response(),
        Err(_) => refuse(ErrorCode::InternalError, "internal error"),
    }
}

fn rejected(message: impl Into<String>) -> Response {
    refuse_status(StatusCode::BAD_REQUEST, "upload_rejected", message)
}

pub(crate) async fn upload(State(service): State<Arc<Service>>, request: Request) -> Response {
    let Ok(permit) = Arc::clone(&service.measure_permits).try_acquire_owned() else {
        return refuse(ErrorCode::Overloaded, "server is at its concurrency limit");
    };
    let deadline = service.limits.request_timeout;
    let mut records = Records::new(
        request.into_body().into_data_stream(),
        service.limits.chunk_timeout,
    );
    let upload = async {
        let (receiver, file_size, recording_id) = start(&service, &mut records).await?;
        Ok::<_, Response>(
            measure::run(&service, permit, file_size, recording_id, |sender| {
                deliver(&mut records, receiver, file_size, sender)
            })
            .await,
        )
    };
    let response = match timeout(deadline, upload).await {
        Ok(Ok(response) | Err(response)) => response,
        Err(_) => refuse(
            ErrorCode::RequestTimeout,
            format!("the request took longer than {deadline:?}"),
        ),
    };
    records.drain();
    response
}

/// Reads and checks the start record, and opens the HPKE context it names.
async fn start<S>(
    service: &Service,
    records: &mut Records<S>,
) -> Result<(Receiver, u64, [u8; 32]), Response>
where
    S: Stream<Item = Result<Bytes, axum::Error>> + Unpin + Send + 'static,
{
    let Some(record) = records.next(START_RECORD_BYTES).await? else {
        return Err(rejected("the upload has no start record"));
    };
    let start: StartRecord = serde_json::from_slice(&record)
        .map_err(|error| rejected(format!("invalid start record: {error}")))?;
    let recording_id = measure::object_id(&start.recording_id).map_err(rejected)?;
    let decimal = |value: &str, field: &str| {
        value
            .parse::<u64>()
            .map_err(|_| format!("{field} is not a decimal u64"))
    };
    let file_size = decimal(&start.file_size, "file_size").map_err(rejected)?;
    let key_expires_ms = decimal(&start.key_expires_ms, "key_expires_ms").map_err(rejected)?;
    if file_size == 0 {
        return Err(rejected("the file is empty"));
    }
    if file_size > MAX_FILE_BYTES {
        return Err(refuse(
            ErrorCode::BodyTooLarge,
            format!("the file is {file_size} bytes; the limit is {MAX_FILE_BYTES}"),
        ));
    }
    let now = service
        .ctx
        .now()
        .map_err(|_| refuse(ErrorCode::InternalError, "internal error"))?
        .as_ms();
    if key_expires_ms < now {
        return Err(refuse_status(
            StatusCode::BAD_REQUEST,
            "upload_key_expired",
            "the upload key has expired; fetch it again",
        ));
    }
    if key_expires_ms > now.saturating_add(UPLOAD_KEY_LIFETIME_MS) {
        return Err(rejected(
            "key_expires_ms is later than any key this enclave signs",
        ));
    }
    let enc = hex::decode(start.enc.strip_prefix("0x").unwrap_or(&start.enc))
        .ok()
        .and_then(|bytes| <Kem as hpke::Kem>::EncappedKey::from_bytes(&bytes).ok())
        .ok_or_else(|| rejected("enc is not a 32-byte X25519 public key"))?;
    let info = upload_info(&policy_id(), &recording_id, file_size, key_expires_ms);
    let receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        &service.upload_key.secret,
        &enc,
        &info,
    )
    .map_err(|_| rejected("enc does not set up an HPKE context"))?;
    Ok((receiver, file_size, recording_id))
}

/// Opens the frames in order and sends their plaintext to the decoder, until the frame that
/// ends the file; the body must end there. Anything else is refused, and the decoder is sent a
/// read error, so it never accepts a partial file.
async fn deliver<S>(
    records: &mut Records<S>,
    mut receiver: Receiver,
    file_size: u64,
    sender: mpsc::Sender<std::io::Result<Bytes>>,
) -> Result<(), Response>
where
    S: Stream<Item = Result<Bytes, axum::Error>> + Unpin + Send + 'static,
{
    let mut offset = 0u64;
    let refused = loop {
        let next = tokio::select! {
            next = records.next(FRAME_RECORD_BYTES) => next,
            // The decoder has stopped, and its verdict is final: stop reading the body.
            () = sender.closed() => return Ok(()),
        };
        let frame = match next {
            Err(refused) => break refused,
            Ok(None) if offset == file_size => return Ok(()),
            Ok(None) => {
                break rejected(format!(
                    "the upload ended after {offset} of its {file_size} bytes"
                ));
            }
            Ok(Some(_)) if offset == file_size => {
                break rejected("the upload continues after its final frame");
            }
            Ok(Some(frame)) => frame,
        };
        let Some(plaintext_len) = frame
            .len()
            .checked_sub(FRAME_OFFSET_BYTES + FRAME_TAG_BYTES)
            .filter(|&len| len > 0)
        else {
            break rejected(format!("a frame of {} bytes is too short", frame.len()));
        };
        let at = u64::from_be_bytes(frame[..FRAME_OFFSET_BYTES].try_into().expect("8 bytes"));
        if at != offset {
            break rejected(format!("a frame at offset {at}, where {offset} was next"));
        }
        let end = offset + plaintext_len as u64;
        if end > file_size {
            break rejected(format!(
                "a frame ends at {end}, past the file's {file_size}"
            ));
        }
        let aad = frame_aad(offset, end == file_size);
        let Ok(plaintext) = receiver.open(&frame[FRAME_OFFSET_BYTES..], &aad) else {
            break rejected(format!("the frame at offset {offset} does not open"));
        };
        offset = end;
        if sender.send(Ok(Bytes::from(plaintext))).await.is_err() {
            return Ok(());
        }
    };
    let _ = sender
        .send(Err(std::io::Error::other(
            "the upload did not arrive whole",
        )))
        .await;
    Err(refused)
}

/// How long a refused upload's body is still read, and thrown away, after the answer: a client
/// still sending it would otherwise see the connection reset, and could lose the answer.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The body as `u32be(length) ‖ bytes` records.
struct Records<S> {
    stream: S,
    buffer: BytesMut,
    ended: bool,
    chunk_timeout: Duration,
}

impl<S> Records<S>
where
    S: Stream<Item = Result<Bytes, axum::Error>> + Unpin + Send + 'static,
{
    /// Reads what is left of the body in the background, for at most [`DRAIN_TIMEOUT`], once the
    /// answer is on its way.
    fn drain(self) {
        if self.ended {
            return;
        }
        let mut stream = self.stream;
        tokio::spawn(timeout(DRAIN_TIMEOUT, async move {
            while let Some(Ok(_)) = stream.next().await {}
        }));
    }

    fn new(stream: S, chunk_timeout: Duration) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
            ended: false,
            chunk_timeout,
        }
    }

    /// Reads until `wanted` bytes are buffered; `false` when the body ended first.
    async fn fill(&mut self, wanted: usize) -> Result<bool, Response> {
        while self.buffer.len() < wanted {
            if self.ended {
                return Ok(false);
            }
            match timeout(self.chunk_timeout, self.stream.next()).await {
                Err(_) => {
                    return Err(refuse(
                        ErrorCode::BodyReadTimeout,
                        format!("the body sent nothing for {:?}", self.chunk_timeout),
                    ));
                }
                Ok(None) => self.ended = true,
                Ok(Some(Err(error))) => {
                    return Err(refuse(
                        ErrorCode::BodyReadFailed,
                        format!("reading the body failed: {error}"),
                    ));
                }
                Ok(Some(Ok(chunk))) => self.buffer.extend_from_slice(&chunk),
            }
        }
        Ok(true)
    }

    /// The next record, of at most `limit` bytes; `None` when the body ends between records.
    async fn next(&mut self, limit: usize) -> Result<Option<Bytes>, Response> {
        if !self.fill(4).await? {
            return if self.buffer.is_empty() {
                Ok(None)
            } else {
                Err(rejected("the body ends inside a record's length"))
            };
        }
        let length = u32::from_be_bytes(self.buffer[..4].try_into().expect("4 bytes")) as usize;
        if length > limit {
            return Err(rejected(format!(
                "a record of {length} bytes is over its {limit}"
            )));
        }
        if !self.fill(4 + length).await? {
            return Err(rejected("the body ends inside a record"));
        }
        let mut record = self.buffer.split_to(4 + length);
        Ok(Some(record.split_off(4).freeze()))
    }
}

/// A body of records, for clients and tests: each part prefixed with its `u32be` length.
pub fn records(parts: &[&[u8]]) -> Body {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(&(part.len() as u32).to_be_bytes());
        body.extend_from_slice(part);
    }
    Body::from(body)
}
