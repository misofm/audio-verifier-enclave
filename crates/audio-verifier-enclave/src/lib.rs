mod routes;
mod sizing;
mod stream;

use std::time::Duration;

use audio_verifier::{AudioPayload, FileStats};
use nautilus::{Intent, NautilusContext, NautilusError, ServerConfig, SignedResponse, Timestamp};
use serde::{Deserialize, Serialize};

pub use routes::app;
pub use sizing::{
    MEASURE_JOB_BYTES, PROCESS_RESERVE_BYTES, Resources, measure_concurrency, mem_total,
};
pub use stream::{StreamConfig, measure_routes};

/// Intent of the signed `IntentMessage<AudioPayload>`, verified on chain by
/// `audio_verifier::verify_audio`.
pub const AUDIO_INTENT: Intent = Intent(0);

/// Intent of the signed `IntentMessage<MasterFilePayload>`, verified off chain. Intent 1 was the
/// retired `AudioEncodingPayload` and is not reused.
pub const MASTER_FILE_INTENT: Intent = Intent(2);

/// Default limit on the size of a file sent to `/v1/measure`.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Maximum decoded PCM work per request, including all channels (4 GiB).
pub use audio_verifier::MAX_DECODED_BYTES;

/// Largest accepted `/attestation` body.
pub const ATTESTATION_BODY_BYTES: usize = 4 * 1024;

/// Deadline for one `/attestation` request, body and attestation.
pub const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Open connections, matching the host bridge's 256. Idle ones cost little; a low cap let a few
/// idle connections lock out every request, `/health_check` included, until
/// `HEADER_READ_TIMEOUT` reaped them.
pub const MAX_CONNECTIONS: usize = 256;

/// Deadline for request headers, including a kept-alive connection's next request.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Closes a connection that does no I/O for this long outside a handler.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// A `/v1/measure` body that delivers nothing for this long is abandoned.
pub const MEASURE_CHUNK_TIMEOUT: Duration = Duration::from_secs(30);

/// Deadline for one `/v1/measure` request, body and measurement: 256 MiB at about 0.5 MB/s.
pub const MEASURE_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// Environment variable that overrides the body limit.
pub const MAX_BODY_BYTES_ENV: &str = "AUDIO_VERIFIER_MAX_BODY_BYTES";

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
    fn new<P>(signed: &SignedResponse<P>, data: T) -> Self {
        Self {
            intent: signed.response.intent.0,
            timestamp_ms: signed.response.timestamp_ms,
            data,
            signature: signed.signature.clone(),
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

/// `/v1/measure` response body: the audio facts and the file binding, signed with one timestamp.
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
/// [`MASTER_FILE_INTENT`], both with one reading of the enclave clock.
pub fn sign_measurement(
    ctx: &NautilusContext,
    audio: AudioPayload,
    file: &FileStats,
) -> Result<MeasureResponse, NautilusError> {
    sign_measurement_stamped(ctx, ctx.now()?, audio, file)
}

/// As [`sign_measurement`], with a given reading of the clock: both messages carry `timestamp`.
pub fn sign_measurement_stamped(
    ctx: &NautilusContext,
    timestamp: Timestamp,
    audio: AudioPayload,
    file: &FileStats,
) -> Result<MeasureResponse, NautilusError> {
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
        audio: SignedJson::new(&audio, AudioJson::from(&audio.response.data)),
        master_file: SignedJson::new(&binding, file),
        public_key: ctx.public_key_hex(),
    })
}

/// Connection limits for [`nautilus::serve`], which reads only `max_connections`,
/// `header_read_timeout` and `idle_timeout`; the other fields configure Nautilus's router, which
/// this service does not use.
pub fn server_config() -> ServerConfig {
    ServerConfig {
        max_connections: MAX_CONNECTIONS,
        header_read_timeout: HEADER_READ_TIMEOUT,
        idle_timeout: IDLE_TIMEOUT,
        ..ServerConfig::default()
    }
}

/// Limits of `/v1/measure` for files of up to `max_file_bytes` and `max_concurrent` jobs at once;
/// [`measure_concurrency`] sizes them to the enclave.
pub fn stream_config(max_file_bytes: usize, max_concurrent: usize) -> StreamConfig {
    StreamConfig {
        max_file_bytes: max_file_bytes as u64,
        max_concurrent,
        chunk_timeout: MEASURE_CHUNK_TIMEOUT,
        request_timeout: MEASURE_REQUEST_TIMEOUT,
    }
}

/// Resolves the body limit from `--max-body-bytes`, then the environment, then the default.
pub fn max_body_bytes(args: &[String], env: Option<String>) -> anyhow::Result<usize> {
    let mut flag = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--max-body-bytes" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--max-body-bytes needs a value"))?;
                anyhow::ensure!(
                    flag.is_none(),
                    "--max-body-bytes may only be specified once"
                );
                flag = Some(value.clone());
            }
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    match flag.or(env) {
        Some(value) => {
            let limit = value.trim().parse::<usize>()?;
            anyhow::ensure!(limit > 0, "max body bytes must be greater than zero");
            Ok(limit)
        }
        None => Ok(DEFAULT_MAX_BODY_BYTES),
    }
}
