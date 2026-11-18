//! `GET /upload`, a WebSocket: the browser's encrypted upload, relayed to the enclave's
//! `/upload`, and the ciphertext the enclave makes stored in R2 through a presigned `PUT`.
//!
//! The caller (the API Worker, through its Workers VPC service) has checked who is uploading
//! and names the upload in headers: `x-miso-recording-id`, `x-miso-file-size` and
//! `x-miso-upload-url`, the presigned R2 `PUT` for the ciphertext. The gateway sees only the
//! client's HPKE ciphertext and the enclave's Tink ciphertext; it never holds a key.
//!
//! Messages, text ones JSON:
//!
//! 1. gateway: `{ "type": "upload_key", "key": <the enclave's /upload-key> }`.
//! 2. client: `{ "type": "start", "enc", "recording_id", "file_size", "key_expires_ms" }`,
//!    the recording and size those of the headers.
//! 3. client: binary frames `u64be(offset) ‖ seal(chunk)`, in order, each acknowledged by
//!    `{ "type": "ack", "received": <bytes of the file through it> }` once the enclave's request
//!    has taken it.
//! 4. gateway, once the ciphertext is in R2: `{ "type": "done", "measured": <the enclave's
//!    JSON> }`; or at any point `{ "type": "error", "error", "message" }`. Then it closes.

use std::{io, sync::Arc, time::Duration};

use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use bytes::Bytes;
use futures_util::stream;
use http_body::Frame;
use http_body_util::{BodyExt as _, Empty, Limited, StreamBody};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{sync::mpsc, time::timeout};
use url::Url;

use crate::{
    Gateway, MAX_FILE_BYTES, MEASURED_MASTER_TYPE, describe, enclave::Opened, is_object_id, refuse,
    walrus,
};

/// Most plaintext bytes in one frame, the enclave's limit.
pub const MAX_FRAME_PLAINTEXT: usize = 1 << 20;

/// A frame's offset header and AES-256-GCM tag.
const FRAME_OVERHEAD: usize = 8 + 16;

/// Largest WebSocket message: a whole frame, or the start message.
const MAX_MESSAGE: usize = MAX_FRAME_PLAINTEXT + FRAME_OVERHEAD;

/// Records queued for the enclave before the gateway stops reading the socket.
const QUEUED_RECORDS: usize = 4;

/// How long the client has to send its start message after the key, and each frame after the
/// last.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);

/// The upload the caller authorized, from its headers.
#[derive(Debug, Clone)]
struct Target {
    /// Lowercase hex, without `0x`.
    recording_id: String,
    file_size: u64,
    upload_url: Url,
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn bare(id: &str) -> String {
    id.strip_prefix("0x").unwrap_or(id).to_ascii_lowercase()
}

/// A refused upgrade: its status, error code and message.
type Refusal = (StatusCode, &'static str, String);

impl Target {
    fn from_headers(gateway: &Gateway, headers: &HeaderMap) -> Result<Self, Refusal> {
        let invalid = |message: &str| (StatusCode::BAD_REQUEST, "invalid_request", message.into());
        let recording_id = header(headers, "x-miso-recording-id")
            .filter(|id| is_object_id(id))
            .ok_or_else(|| invalid("x-miso-recording-id must be a 32-byte hex object ID"))?;
        let file_size = header(headers, "x-miso-file-size")
            .and_then(|size| size.parse::<u64>().ok())
            .filter(|&size| size > 0)
            .ok_or_else(|| invalid("x-miso-file-size must be a positive decimal"))?;
        if file_size > MAX_FILE_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                format!("the file is {file_size} bytes, over {MAX_FILE_BYTES}"),
            ));
        }
        let url = header(headers, "x-miso-upload-url")
            .ok_or_else(|| invalid("x-miso-upload-url is required"))?;
        let upload_url = gateway
            .config
            .policy
            .check(url)
            .map_err(|message| (StatusCode::BAD_REQUEST, "url_not_allowed", message))?;
        Ok(Self {
            recording_id: bare(recording_id),
            file_size,
            upload_url,
        })
    }
}

/// Why an upload stopped, as the client is told.
#[derive(Debug)]
struct Failure {
    error: String,
    message: String,
}

impl Failure {
    fn new(error: &str, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    #[serde(rename = "type")]
    kind: String,
    enc: String,
    recording_id: String,
    file_size: String,
    key_expires_ms: String,
}

/// The enclave's start record: the client's start without its type.
#[derive(Serialize)]
struct StartRecord<'a> {
    enc: &'a str,
    recording_id: &'a str,
    file_size: &'a str,
    key_expires_ms: &'a str,
}

pub(crate) async fn upload(
    State(gateway): State<Arc<Gateway>>,
    headers: HeaderMap,
    socket: WebSocketUpgrade,
) -> Response {
    let target = match Target::from_headers(&gateway, &headers) {
        Ok(target) => target,
        Err((status, error, message)) => return refuse(status, error, message),
    };
    let Ok(permit) = Arc::clone(&gateway.in_flight).try_acquire_owned() else {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "overloaded",
            "the gateway is at its concurrency limit",
        );
    };
    socket
        .max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            session(&gateway, target, socket).await;
        })
}

async fn session(gateway: &Gateway, target: Target, mut socket: WebSocket) {
    let deadline = gateway.config.request_timeout + gateway.config.publisher.timeout;
    let outcome = match timeout(deadline, relay(gateway, &target, &mut socket)).await {
        Ok(outcome) => outcome,
        Err(_) => Err(Failure::new(
            "request_timeout",
            format!("the upload took longer than {deadline:?}"),
        )),
    };
    let last = match outcome {
        Ok(measured) => json!({ "type": "done", "measured": measured }),
        Err(failure) => {
            eprintln!("[upload] {}: {}", failure.error, failure.message);
            json!({ "type": "error", "error": failure.error, "message": failure.message })
        }
    };
    let _ = socket.send(Message::Text(last.to_string().into())).await;
    let close = CloseFrame {
        code: 1000,
        reason: "".into(),
    };
    let _ = socket.send(Message::Close(Some(close))).await;
}

/// The next message from the client within [`MESSAGE_TIMEOUT`], skipping pings and pongs.
async fn next(socket: &mut WebSocket) -> Result<Message, Failure> {
    loop {
        match timeout(MESSAGE_TIMEOUT, socket.recv()).await {
            Err(_) => {
                return Err(Failure::new(
                    "body_read_timeout",
                    format!("the client sent nothing for {MESSAGE_TIMEOUT:?}"),
                ));
            }
            Ok(None | Some(Ok(Message::Close(_)))) => {
                return Err(Failure::new("closed", "the client closed the upload"));
            }
            Ok(Some(Err(error))) => {
                return Err(Failure::new("body_read_failed", error.to_string()));
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Ok(message))) => return Ok(message),
        }
    }
}

fn record(bytes: &[u8]) -> Bytes {
    let mut record = Vec::with_capacity(4 + bytes.len());
    record.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    record.extend_from_slice(bytes);
    Bytes::from(record)
}

async fn send_text(socket: &mut WebSocket, value: Value) -> Result<(), Failure> {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .map_err(|_| Failure::new("closed", "the client went away"))
}

fn enclave_unavailable(message: String) -> Failure {
    Failure::new("enclave_unavailable", message)
}

/// The upload: the key, the start, the frames to the enclave, and its ciphertext to R2.
async fn relay(
    gateway: &Gateway,
    target: &Target,
    socket: &mut WebSocket,
) -> Result<Value, Failure> {
    let key = gateway
        .enclave
        .send(
            axum::http::Request::get("/upload-key")
                .body(Empty::<Bytes>::new())
                .expect("the request is well formed"),
        )
        .await
        .map_err(enclave_unavailable)?;
    let status = key.status();
    let key = key
        .into_body()
        .collect()
        .await
        .map_err(|error| enclave_unavailable(error.to_string()))?
        .to_bytes();
    let key: Value = serde_json::from_slice(&key)
        .ok()
        .filter(|_| status == StatusCode::OK)
        .ok_or_else(|| enclave_unavailable(format!("/upload-key answered {status}")))?;
    send_text(socket, json!({ "type": "upload_key", "key": key })).await?;

    let Message::Text(start) = next(socket).await? else {
        return Err(Failure::new(
            "invalid_request",
            "the first message must be the start",
        ));
    };
    let start: Start = serde_json::from_str(&start)
        .map_err(|error| Failure::new("invalid_request", format!("invalid start: {error}")))?;
    if start.kind != "start" {
        return Err(Failure::new(
            "invalid_request",
            "the first message must be the start",
        ));
    }
    if bare(&start.recording_id) != target.recording_id
        || start.file_size != target.file_size.to_string()
    {
        return Err(Failure::new(
            "invalid_request",
            "the start names another recording or size than the upload was authorized for",
        ));
    }
    let start_record = serde_json::to_vec(&StartRecord {
        enc: &start.enc,
        recording_id: &start.recording_id,
        file_size: &start.file_size,
        key_expires_ms: &start.key_expires_ms,
    })
    .expect("the record serializes");

    let (records, mut queue) = mpsc::channel::<io::Result<Frame<Bytes>>>(QUEUED_RECORDS);
    let body = StreamBody::new(stream::poll_fn(move |cx| queue.poll_recv(cx)));
    let request = axum::http::Request::post("/upload")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .expect("the request is well formed");
    let enclave = gateway.enclave.clone();
    let mut answer = tokio::spawn(async move { enclave.open(request).await });
    let mut records = Some(records);
    let queued = |records: &Option<mpsc::Sender<_>>, bytes: Bytes| {
        let records = records.clone();
        async move {
            match records {
                Some(records) => records.send(Ok(Frame::data(bytes))).await.is_ok(),
                None => false,
            }
        }
    };
    if !queued(&records, record(&start_record)).await {
        return Err(enclave_unavailable("the enclave refused the upload".into()));
    }

    let mut received = 0u64;
    let opened = loop {
        if received == target.file_size {
            // The whole file has been sent: the enclave's answer is next.
            records = None;
            break timeout(gateway.config.request_timeout, &mut answer).await;
        }
        let message = tokio::select! {
            biased;
            // The enclave answered before the end: a refusal.
            opened = &mut answer => break Ok(opened),
            message = next(socket) => message?,
        };
        let Message::Binary(frame) = message else {
            return Err(Failure::new(
                "invalid_request",
                "a frame must be a binary message",
            ));
        };
        let offset = frame
            .get(..8)
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("8 bytes")));
        let length = frame
            .len()
            .checked_sub(FRAME_OVERHEAD)
            .filter(|&len| len > 0);
        let (Some(offset), Some(length)) = (offset, length) else {
            return Err(Failure::new("invalid_request", "a frame is too short"));
        };
        if offset != received || received + length as u64 > target.file_size {
            return Err(Failure::new(
                "invalid_request",
                format!("a frame at offset {offset} of {length} bytes, where {received} was next"),
            ));
        }
        if !queued(&records, record(&frame)).await {
            // The enclave stopped reading: its answer says why.
            records = None;
            break timeout(gateway.config.request_timeout, &mut answer).await;
        }
        received += length as u64;
        send_text(socket, json!({ "type": "ack", "received": received })).await?;
    };
    drop(records);
    let opened = match opened {
        Err(_) => {
            answer.abort();
            return Err(Failure::new(
                "request_timeout",
                "the enclave took too long to answer",
            ));
        }
        Ok(Err(_)) => return Err(enclave_unavailable("the enclave request failed".into())),
        Ok(Ok(opened)) => opened.map_err(enclave_unavailable)?,
    };
    store(gateway, target, opened).await
}

/// The enclave's answer: a measured master's ciphertext stored in R2 and its JSON, or the
/// enclave's refusal.
async fn store(gateway: &Gateway, target: &Target, opened: Opened) -> Result<Value, Failure> {
    let status = opened.response.status();
    let content_type = opened.response.headers().get(header::CONTENT_TYPE);
    let measured = status == StatusCode::OK
        && content_type.is_some_and(|value| value.as_bytes() == MEASURED_MASTER_TYPE.as_bytes());
    if !measured {
        let body = Limited::new(opened.response.into_body(), 1 << 20)
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default();
        let refusal: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let field = |name: &str| refusal.get(name).and_then(Value::as_str).map(str::to_owned);
        return Err(Failure {
            error: field("error").unwrap_or_else(|| "enclave_unavailable".into()),
            message: field("message").unwrap_or_else(|| format!("the enclave answered {status}")),
        });
    }
    let walrus::Measured {
        head,
        size,
        ciphertext,
        _connection,
        ..
    } = walrus::split(opened).await.map_err(enclave_unavailable)?;
    let put = gateway
        .client
        .put(target.upload_url.clone())
        .header(header::CONTENT_LENGTH, size)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(reqwest::Body::wrap_stream(ciphertext))
        .send();
    let answer = timeout(gateway.config.publisher.timeout, put)
        .await
        .map_err(|_| Failure::new("request_timeout", "storing the ciphertext timed out"))?
        .map_err(|error| Failure::new("upload_failed", describe(error)))?;
    if !answer.status().is_success() {
        let status = answer.status();
        let text = answer.text().await.unwrap_or_default();
        let excerpt: String = text.chars().take(300).collect();
        return Err(Failure::new(
            "upload_failed",
            format!("R2 answered {status}: {excerpt}"),
        ));
    }
    Ok(Value::Object(head))
}
