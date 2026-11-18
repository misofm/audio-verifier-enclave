//! `POST /measure`: the FLAC file as a streamed body, measured and encrypted as it arrives.
//!
//! Chunks go through a bounded channel to `measure_reader` on the blocking pool, which encrypts
//! each one as it takes it, so a request holds the decoder's window, the queued chunks and the
//! ciphertext. Once the file is measured, the same job computes the ciphertext's Walrus blob ID
//! and seals the DEK to it. The response is the signed JSON, a newline, then the ciphertext; the
//! job's permit is held until the ciphertext is sent.

use std::{io, sync::Arc, time::Duration};

use audio_verifier::{AudioFacts, FileStats, measure_reader};
use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::{StreamExt as _, stream};
use nautilus::ErrorCode;
use rand::{RngCore as _, rngs::OsRng};
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc},
    task::spawn_blocking,
    time::{Instant, timeout, timeout_at},
};

use crate::{
    AudioPayload, MAX_FILE_BYTES, Pins, Service, content_length,
    master::MASTER_ASSOCIATED_DATA,
    refuse, refuse_status, sign_measurement,
    tink::{Encryptor, KEY_BYTES},
};

/// Body chunks queued for the decoder before the route stops reading.
const QUEUED_CHUNKS: usize = 16;

/// The media type of a `/measure` response: the JSON of [`crate::MeasureResponse`], a newline,
/// then `ciphertext_size` bytes of ciphertext.
pub const MEASURED_MASTER_TYPE: &str = "application/vnd.miso.measured-master";

/// Ciphertext sent per response chunk; each is a copy, so a stalled reader never holds the
/// whole ciphertext.
const SEND_CHUNK: usize = 1 << 20;

/// A measured and encrypted file.
struct Sealed {
    facts: AudioFacts,
    file: FileStats,
    ciphertext: Vec<u8>,
    blob_id: [u8; 32],
    sealed_dek: Vec<u8>,
}

enum Failure {
    Refused(audio_verifier::Error),
    Internal(String),
}

/// Measures the file from `reader`, encrypting what it reads, then derives the blob ID and the
/// sealed DEK. The DEK never leaves this function.
fn measure_and_seal(
    receiver: mpsc::Receiver<io::Result<Bytes>>,
    declared: u64,
    recording_id: &[u8; 32],
    pins: &Pins,
) -> Result<Sealed, Failure> {
    let mut dek = [0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut dek);
    let mut reader = ChannelReader {
        receiver,
        current: Bytes::new(),
        encryptor: Encryptor::new(&dek, MASTER_ASSOCIATED_DATA, &mut OsRng, declared),
    };
    let (facts, file) = measure_reader(&mut reader).map_err(Failure::Refused)?;
    let encryptor = reader.encryptor;
    if encryptor.taken() != file.len {
        return Err(Failure::Internal(format!(
            "encrypted {} bytes of a {}-byte file",
            encryptor.taken(),
            file.len
        )));
    }
    let ciphertext = encryptor.finish();
    let blob_id = pins.blob_id(&ciphertext).map_err(Failure::Internal)?;
    let sealed_dek = pins
        .seal_dek(recording_id, &blob_id, &dek)
        .map_err(Failure::Internal)?;
    dek.fill(0);
    Ok(Sealed {
        facts,
        file,
        ciphertext,
        blob_id: blob_id.0,
        sealed_dek,
    })
}

/// The `recording_id` query parameter: the 32-byte object ID of the Recording the master is
/// sealed to, as hex with or without `0x`.
fn recording_id(request: &Request) -> Result<[u8; 32], String> {
    let query = request.uri().query().unwrap_or_default();
    let mut values = query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("recording_id="));
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err("the recording_id query parameter is required once".into());
    };
    let digits = value.strip_prefix("0x").unwrap_or(value);
    let invalid = || format!("recording_id {value:?} is not a 32-byte hex object ID");
    if digits.len() != 64 {
        return Err(invalid());
    }
    let bytes = hex::decode(digits).map_err(|_| invalid())?;
    Ok(bytes.try_into().expect("64 hex digits are 32 bytes"))
}

pub(crate) async fn measure(State(service): State<Arc<Service>>, request: Request) -> Response {
    let recording_id = match recording_id(&request) {
        Ok(recording_id) => recording_id,
        Err(message) => return refuse(ErrorCode::InvalidRequest, message),
    };
    let Some(declared) = content_length(&request) else {
        return refuse_status(
            StatusCode::LENGTH_REQUIRED,
            "length_required",
            "Content-Length is required",
        );
    };
    if declared > MAX_FILE_BYTES {
        return refuse(
            ErrorCode::BodyTooLarge,
            format!("the file is {declared} bytes; the limit is {MAX_FILE_BYTES}"),
        );
    }
    let Ok(permit) = Arc::clone(&service.measure_permits).try_acquire_owned() else {
        return refuse(ErrorCode::Overloaded, "server is at its concurrency limit");
    };
    let deadline = service.limits.request_timeout;
    match timeout(
        deadline,
        run(
            &service,
            permit,
            request.into_body(),
            declared,
            recording_id,
        ),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => refuse(
            ErrorCode::RequestTimeout,
            format!("the request took longer than {deadline:?}"),
        ),
    }
}

async fn run(
    service: &Service,
    permit: OwnedSemaphorePermit,
    body: Body,
    declared: u64,
    recording_id: [u8; 32],
) -> Response {
    let (sender, receiver) = mpsc::channel(QUEUED_CHUNKS);
    let pins = Arc::clone(&service.pins);
    // The permit is held until the job stops, also when this future is dropped at the
    // deadline: dropping `sender` ends its input, so it stops soon after. A job that succeeds
    // hands the permit on to the response, with the ciphertext.
    let job = spawn_blocking(move || {
        let sealed = measure_and_seal(receiver, declared, &recording_id, &pins);
        (sealed, permit)
    });
    let delivered = deliver(body, declared, service.limits.chunk_timeout, sender).await;
    let measured = job.await;
    if let Err(refused) = delivered {
        return refused;
    }
    let (sealed, permit) = match measured {
        Ok((Ok(sealed), permit)) => (sealed, permit),
        Ok((Err(Failure::Refused(error)), _)) => {
            return refuse(ErrorCode::ApplicationError, error.to_string());
        }
        Ok((Err(Failure::Internal(error)), _)) => {
            eprintln!("[measure] failed: {error}");
            return refuse(ErrorCode::InternalError, "internal error");
        }
        Err(_) => return refuse(ErrorCode::InternalError, "internal error"),
    };
    let Sealed {
        facts,
        file,
        ciphertext,
        blob_id,
        sealed_dek,
    } = sealed;
    let ctx = &service.ctx;
    let payload = AudioPayload::new(facts, blob_id, sealed_dek);
    let signed = ctx
        .now()
        .and_then(|now| sign_measurement(ctx, now, payload, &file, ciphertext.len() as u64));
    let Ok(signed) = signed else {
        return refuse(ErrorCode::InternalError, "internal error");
    };
    let mut head = serde_json::to_vec(&signed).expect("the response serializes");
    head.push(b'\n');
    respond(head, ciphertext, permit, service.limits)
}

/// The response: `head`, then `ciphertext` from a task that holds `permit` until it has sent
/// it, or until the reader stalls for the chunk timeout or the response passes its deadline.
fn respond(
    head: Vec<u8>,
    ciphertext: Vec<u8>,
    permit: OwnedSemaphorePermit,
    limits: crate::Limits,
) -> Response {
    let length = head.len() + ciphertext.len();
    let (sender, mut receiver) = mpsc::channel::<io::Result<Bytes>>(2);
    tokio::spawn(async move {
        let _permit = permit;
        let deadline = Instant::now() + limits.response_timeout;
        for chunk in ciphertext.chunks(SEND_CHUNK) {
            let stall = (Instant::now() + limits.chunk_timeout).min(deadline);
            let sent = timeout_at(stall, sender.send(Ok(Bytes::copy_from_slice(chunk)))).await;
            if !matches!(sent, Ok(Ok(()))) {
                eprintln!("[measure] the ciphertext was not taken in time; abandoned");
                return;
            }
        }
    });
    let receiver = stream::poll_fn(move |cx| receiver.poll_recv(cx));
    let body = stream::once(async move { Ok(Bytes::from(head)) }).chain(receiver);
    let mut response = Body::from_stream(body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(MEASURED_MASTER_TYPE),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    response
}

/// Forwards `body` to the decoder until it ends or the decoder stops. A body that stalls, fails,
/// or delivers other than `declared` bytes is refused, and the decoder is sent a read error, so
/// it never accepts a partial or overlong body.
async fn deliver(
    body: Body,
    declared: u64,
    chunk_timeout: Duration,
    sender: mpsc::Sender<io::Result<Bytes>>,
) -> Result<(), Response> {
    let mut stream = body.into_data_stream();
    let mut received = 0u64;
    let failed = |message: String| refuse(ErrorCode::BodyReadFailed, message);
    let refused = loop {
        let next = tokio::select! {
            next = timeout(chunk_timeout, stream.next()) => next,
            // The decoder has stopped, and its verdict is final: stop reading the body.
            () = sender.closed() => return Ok(()),
        };
        let chunk = match next {
            Err(_) => {
                break refuse(
                    ErrorCode::BodyReadTimeout,
                    format!("the body sent nothing for {chunk_timeout:?}"),
                );
            }
            Ok(None) if received == declared => return Ok(()),
            Ok(None) => {
                break failed(format!(
                    "the body ended after {received} of its {declared} bytes"
                ));
            }
            Ok(Some(Err(error))) => break failed(format!("reading the body failed: {error}")),
            Ok(Some(Ok(chunk))) => chunk,
        };
        received += chunk.len() as u64;
        if received > declared {
            break failed(format!("the body is longer than its {declared} bytes"));
        }
        if sender.send(Ok(chunk)).await.is_err() {
            return Ok(());
        }
    };
    let _ = sender
        .send(Err(io::Error::other("the body did not arrive whole")))
        .await;
    Err(refused)
}

/// The body's chunks, read synchronously by the decoder and encrypted as each arrives.
struct ChannelReader {
    receiver: mpsc::Receiver<io::Result<Bytes>>,
    current: Bytes,
    encryptor: Encryptor,
}

impl io::Read for ChannelReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.current.is_empty() {
            match self.receiver.blocking_recv() {
                Some(Ok(chunk)) => {
                    self.encryptor.update(&chunk);
                    self.current = chunk;
                }
                Some(Err(error)) => return Err(error),
                None => return Ok(0),
            }
        }
        let count = buffer.len().min(self.current.len());
        buffer[..count].copy_from_slice(&self.current.split_to(count));
        Ok(count)
    }
}
