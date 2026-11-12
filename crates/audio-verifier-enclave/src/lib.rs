//! The service's router: `POST /measure`, `POST /attest` and `GET /health`. Nautilus's own
//! router is not used: it always mounts `/process_data`, and it buffers bodies whole.

mod measure;

use std::{sync::Arc, time::Duration};

use audio_verifier::{AudioPayload, FileStats};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt as _;
use nautilus::{
    AttestationError, ErrorCode, HealthCheckBody, Intent, NautilusContext, NautilusError,
    SignedResponse, Timestamp, decode_hex, encode_hex,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::Semaphore, task::spawn_blocking, time::timeout};

/// Intent of the signed `IntentMessage<AudioPayload>`, verified on chain by
/// `audio_verifier::verify_audio`.
pub const AUDIO_INTENT: Intent = Intent(0);

/// Intent of the signed `IntentMessage<MasterFilePayload>`, verified off chain. Intent 1 was a
/// retired payload and is not reused.
pub const MASTER_FILE_INTENT: Intent = Intent(2);

/// Largest file `/measure` accepts.
pub const MAX_FILE_BYTES: u64 = 256 << 20;

/// Worst-case memory of one `/measure` job, rounded up from its parts:
///
/// - the decoder's window: at most 16 MiB + 128 KiB past the last complete frame, one more
///   8 KiB read and 1 MiB of finished frames, in one allocation that is never copied, 17.2 MiB;
/// - the PCM pipeline: four buffers of a 65,535-sample, 8-channel, 24-bit frame, 6 MiB;
/// - libFLAC's decoder: output and residual buffers for 8 channels of 65,536 samples, the side
///   channel and the Rice partition tables, about 7 MiB;
/// - the body queue: 16 queued chunks, the one being read and the one being sent, each at most
///   hyper's ~408 KiB read buffer, about 7.3 MiB;
/// - the metadata (64 KiB), two thread stacks and the response.
pub const MEASURE_JOB_BYTES: u64 = 48 << 20;

/// Memory kept for everything but the jobs: the kernel's own allocations, the root file system
/// the image unpacks into memory, the runtime, and up to 256 connections, each with at most a
/// 4 KiB `/attest` body.
const PROCESS_RESERVE_BYTES: u64 = 128 << 20;

/// Largest accepted `/attest` body.
pub const ATTEST_BODY_BYTES: usize = 4 << 10;

/// Deadline for one `/attest` request, body and attestation.
const ATTEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Limits of `/measure`.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Measurements at once; more get HTTP 429.
    pub jobs: usize,
    /// A body that delivers nothing for this long is abandoned.
    pub chunk_timeout: Duration,
    /// Deadline for the whole request, body and measurement: 256 MiB at about 0.5 MB/s.
    pub request_timeout: Duration,
}

impl Limits {
    /// The service's limits, with `jobs` measurements at once.
    pub fn new(jobs: usize) -> Self {
        Self {
            jobs,
            chunk_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(600),
        }
    }
}

/// `/measure` jobs for an enclave with `cpus` vCPUs and `mem_total` bytes of `MemTotal`: one per
/// vCPU, no more than fit after [`PROCESS_RESERVE_BYTES`] at [`MEASURE_JOB_BYTES`] each, and at
/// least one. Unknown memory counts as room for one.
pub fn measure_jobs(cpus: usize, mem_total: Option<u64>) -> usize {
    let by_memory = mem_total.map_or(1, |memory| {
        memory.saturating_sub(PROCESS_RESERVE_BYTES) / MEASURE_JOB_BYTES
    });
    cpus.min(usize::try_from(by_memory).unwrap_or(usize::MAX))
        .max(1)
}

/// `MemTotal` from the text of `/proc/meminfo`, in bytes.
pub fn mem_total(meminfo: &str) -> Option<u64> {
    let value = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?;
    let kib = value.trim().strip_suffix("kB")?.trim_end().parse::<u64>();
    kib.ok()?.checked_mul(1024)
}

/// JSON view of an `AudioPayload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioJson {
    /// Channel count.
    pub channels: u8,
    /// Bits per sample.
    pub bit_depth: u8,
    /// Sample rate in hertz.
    pub sample_rate_hz: u32,
    /// Samples per channel as a decimal string.
    pub samples_per_channel: String,
    /// BLAKE3 PCM digest as hex.
    pub pcm_digest: String,
}

impl From<&AudioPayload> for AudioJson {
    fn from(audio: &AudioPayload) -> Self {
        Self {
            channels: audio.channels,
            bit_depth: audio.bit_depth,
            sample_rate_hz: audio.sample_rate_hz,
            samples_per_channel: audio.samples_per_channel.to_string(),
            pcm_digest: hex::encode(&audio.pcm_digest),
        }
    }
}

/// One signed payload in a response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedJson<T> {
    /// Intent byte.
    pub intent: u8,
    /// Signing time in milliseconds since the Unix epoch, from the enclave clock.
    pub timestamp_ms: u64,
    /// The payload's fields.
    #[serde(flatten)]
    pub data: T,
    /// Ed25519 signature over the BCS intent message, as hex.
    pub signature: String,
}

impl<T> SignedJson<T> {
    fn new<P>(signed: SignedResponse<P>, data: T) -> Self {
        Self {
            intent: signed.response.intent.0,
            timestamp_ms: signed.response.timestamp_ms,
            data,
            signature: signed.signature,
        }
    }
}

/// BCS layout of the file binding signed under [`MASTER_FILE_INTENT`]: the audio facts, as
/// signed under [`AUDIO_INTENT`], and the size and SHA-256 of the exact bytes measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterFilePayload {
    /// The audio facts.
    pub audio: AudioPayload,
    /// Bytes of the file.
    pub file_size: u64,
    /// SHA-256 of the file's bytes.
    pub file_sha256: Vec<u8>,
}

/// JSON view of a `MasterFilePayload`'s own fields; its `audio` is the response's `audio`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileJson {
    /// Bytes of the file as a decimal string.
    pub file_size: String,
    /// SHA-256 of the file as hex.
    pub file_sha256: String,
}

/// `/measure` response body: the audio facts and the file binding, signed with one timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasureResponse {
    /// The audio facts, for `verify_audio`.
    pub audio: SignedJson<AudioJson>,
    /// The file binding, for off-chain verifiers.
    pub master_file: SignedJson<FileJson>,
    /// Enclave Ed25519 public key as hex.
    pub public_key: String,
}

/// Signs the audio facts under [`AUDIO_INTENT`] and the file binding under
/// [`MASTER_FILE_INTENT`], both with `timestamp`, one reading of the enclave clock.
pub fn sign_measurement(
    ctx: &NautilusContext,
    timestamp: Timestamp,
    audio: AudioPayload,
    file: &FileStats,
) -> Result<MeasureResponse, NautilusError> {
    let audio_json = AudioJson::from(&audio);
    let binding = MasterFilePayload {
        audio: audio.clone(),
        file_size: file.len,
        file_sha256: file.sha256.to_vec(),
    };
    let audio = ctx.sign_intent_stamped(AUDIO_INTENT, timestamp, audio)?;
    let binding = ctx.sign_intent_stamped(MASTER_FILE_INTENT, timestamp, binding)?;
    let file = FileJson {
        file_size: file.len.to_string(),
        file_sha256: hex::encode(file.sha256),
    };
    Ok(MeasureResponse {
        audio: SignedJson::new(audio, audio_json),
        master_file: SignedJson::new(binding, file),
        public_key: ctx.public_key_hex(),
    })
}

struct Service {
    ctx: NautilusContext,
    limits: Limits,
    measure_permits: Arc<Semaphore>,
    attest_permit: Arc<Semaphore>,
}

/// Builds the service's router around an injected context. `/attest` runs one at a time.
pub fn app(ctx: NautilusContext, limits: Limits) -> Router {
    let service = Service {
        ctx,
        limits,
        measure_permits: Arc::new(Semaphore::new(limits.jobs)),
        attest_permit: Arc::new(Semaphore::new(1)),
    };
    Router::new()
        .route("/health", get(health))
        .route("/attest", post(attest))
        .route("/measure", post(measure::measure))
        .with_state(Arc::new(service))
        .method_not_allowed_fallback(|| async {
            refuse(ErrorCode::MethodNotAllowed, "method not allowed")
        })
        .fallback(|| async { refuse(ErrorCode::NotFound, "no such route") })
}

/// A JSON error in Nautilus's `{ error, message }` shape.
fn refuse_status(status: StatusCode, error: &str, message: impl Into<String>) -> Response {
    let body = serde_json::json!({ "error": error, "message": message.into() });
    (status, Json(body)).into_response()
}

fn refuse(code: ErrorCode, message: impl Into<String>) -> Response {
    refuse_status(code.status(), code.as_str(), message)
}

fn content_length(request: &Request) -> Option<u64> {
    let value = request.headers().get(header::CONTENT_LENGTH)?;
    value.to_str().ok()?.parse().ok()
}

async fn health(State(service): State<Arc<Service>>) -> Json<HealthCheckBody> {
    Json(HealthCheckBody {
        pk: service.ctx.public_key_hex(),
        address: service.ctx.sui_address(),
    })
}

/// `/attest` request body. Nautilus's optional `user_data` is not accepted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestBody {
    nonce: String,
}

async fn attest(State(service): State<Arc<Service>>, request: Request) -> Response {
    match timeout(ATTEST_TIMEOUT, attest_within_deadline(&service, request)).await {
        Ok(response) => response.into_response(),
        Err(_) => refuse(
            ErrorCode::RequestTimeout,
            format!("the request took longer than {ATTEST_TIMEOUT:?}"),
        ),
    }
}

async fn attest_within_deadline(service: &Service, request: Request) -> Result<Response, Response> {
    let bytes = read_small(request).await?;
    let body: AttestBody = serde_json::from_slice(&bytes).map_err(|error| {
        refuse(
            ErrorCode::InvalidRequest,
            format!("invalid attestation body: {error}"),
        )
    })?;
    let nonce = decode_hex(&body.nonce)
        .map_err(|error| refuse(ErrorCode::InvalidRequest, format!("nonce: {error}")))?;
    if nonce.is_empty() {
        return Err(refuse(ErrorCode::InvalidRequest, "nonce is required"));
    }
    let permit = Arc::clone(&service.attest_permit)
        .try_acquire_owned()
        .map_err(|_| refuse(ErrorCode::Overloaded, "server is at its concurrency limit"))?;
    let ctx = service.ctx.clone();
    // The permit is held until the NSM returns, also when the deadline drops this future.
    let document = spawn_blocking(move || {
        let _permit = permit;
        ctx.attestation(Some(nonce), None)
    })
    .await
    .map_err(|_| refuse(ErrorCode::InternalError, "internal error"))?;
    match document {
        Ok(document) => {
            Ok(Json(serde_json::json!({ "attestation": encode_hex(document) })).into_response())
        }
        Err(error @ NautilusError::Attestation(AttestationError::InvalidRequest(_))) => {
            Err(refuse(ErrorCode::InvalidRequest, error.to_string()))
        }
        Err(error) => {
            eprintln!("[attest] failed: {error}");
            Err(refuse(
                ErrorCode::AttestationUnavailable,
                "attestation is unavailable",
            ))
        }
    }
}

/// Reads a body of at most [`ATTEST_BODY_BYTES`], refusing it as soon as it declares or
/// delivers more.
async fn read_small(request: Request) -> Result<Vec<u8>, Response> {
    let too_large = || {
        refuse(
            ErrorCode::BodyTooLarge,
            format!("the body is over {ATTEST_BODY_BYTES} bytes"),
        )
    };
    if content_length(&request).is_some_and(|declared| declared > ATTEST_BODY_BYTES as u64) {
        return Err(too_large());
    }
    let mut stream = request.into_body().into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            refuse(
                ErrorCode::BodyReadFailed,
                format!("reading the body failed: {error}"),
            )
        })?;
        if bytes.len() + chunk.len() > ATTEST_BODY_BYTES {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn jobs_follow_the_vcpus_unless_memory_is_short() {
        assert_eq!(measure_jobs(2, Some(1900 * MIB)), 2);
        assert_eq!(measure_jobs(4, Some(6144 * MIB)), 4);
        assert_eq!(measure_jobs(32, Some(1024 * MIB)), 18);
        assert_eq!(measure_jobs(64, Some((128 + 48 * 10 - 1) * MIB)), 9);
        assert_eq!(measure_jobs(64, Some((128 + 48 * 10) * MIB)), 10);
        assert_eq!(measure_jobs(8, Some(100 * MIB)), 1);
        assert_eq!(measure_jobs(32, None), 1);
    }

    #[test]
    fn mem_total_is_read_from_meminfo() {
        let meminfo = "MemFree:         1803040 kB\nMemTotal:\t1967392 kB\n";
        assert_eq!(mem_total(meminfo), Some(1_967_392 * 1024));
        assert_eq!(mem_total("MemFree: 10 kB\n"), None);
        assert_eq!(mem_total("MemTotal: 10 MB\n"), None);
    }
}
