//! `POST /v1/measure`: the FLAC file as a streamed body, measured as it arrives.
//!
//! The route reads the body itself instead of buffering it. Chunks go through a bounded channel
//! to `measure_reader` on the blocking pool, so a request holds the decoder's window and the
//! channel's chunks, whatever the file's size: about 1 MiB of the file for typical frames, and
//! at most [`crate::MEASURE_JOB_BYTES`] in all. The route has its own concurrency permits and
//! deadlines.

use std::{io, sync::Arc, time::Duration};

use audio_verifier::measure_reader;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use futures_util::StreamExt as _;
use nautilus::{ErrorCode, NautilusContext};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    time::timeout,
};

use crate::{
    routes::{refuse, refuse_with},
    sign_measurement,
};

/// Body chunks queued for the decoder before the route stops reading.
const CHANNEL_DEPTH: usize = 16;

/// Limits of the streaming route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamConfig {
    /// Largest accepted `Content-Length`.
    pub max_file_bytes: u64,
    /// Concurrent measurements; more get HTTP 429.
    pub max_concurrent: usize,
    /// A body that delivers nothing for this long is abandoned.
    pub chunk_timeout: Duration,
    /// Deadline for the whole request, body and measurement.
    pub request_timeout: Duration,
}

struct StreamState {
    ctx: NautilusContext,
    config: StreamConfig,
    permits: Arc<Semaphore>,
}

/// The `/v1/measure` route, which [`crate::app`] mounts.
pub fn measure_routes(ctx: NautilusContext, config: StreamConfig) -> Router {
    let permits = Arc::new(Semaphore::new(
        config.max_concurrent.min(Semaphore::MAX_PERMITS),
    ));
    Router::new()
        .route("/v1/measure", post(measure))
        .with_state(Arc::new(StreamState {
            ctx,
            config,
            permits,
        }))
}

async fn measure(State(state): State<Arc<StreamState>>, request: Request) -> Response {
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let Some(declared) = declared else {
        return refuse(
            StatusCode::LENGTH_REQUIRED,
            "length_required",
            "Content-Length is required",
        );
    };
    if declared > state.config.max_file_bytes {
        return refuse_with(
            ErrorCode::BodyTooLarge,
            format!(
                "the file is {declared} bytes; the limit is {}",
                state.config.max_file_bytes
            ),
        );
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return refuse_with(ErrorCode::Overloaded, "server is at its concurrency limit");
    };
    let deadline = state.config.request_timeout;
    match timeout(deadline, run(&state, permit, request.into_body(), declared)).await {
        Ok(response) => response,
        Err(_) => refuse_with(
            ErrorCode::RequestTimeout,
            format!("the request took longer than {deadline:?}"),
        ),
    }
}

/// Why the body did not arrive whole.
enum Transport {
    Stalled,
    Failed(String),
}

async fn run(
    state: &StreamState,
    permit: OwnedSemaphorePermit,
    body: Body,
    declared: u64,
) -> Response {
    let (sender, receiver) = mpsc::channel(CHANNEL_DEPTH);
    // The permit is held until the decoder stops, also when this future is dropped at the
    // deadline: dropping `sender` ends its input, so it stops soon after.
    let job = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        measure_reader(ChannelReader {
            receiver,
            current: Bytes::new(),
        })
    });
    let delivered = deliver(body, declared, state.config.chunk_timeout, sender).await;
    let measured = job.await;
    match delivered {
        Err(Transport::Stalled) => {
            return refuse_with(
                ErrorCode::BodyReadTimeout,
                format!("the body sent nothing for {:?}", state.config.chunk_timeout),
            );
        }
        Err(Transport::Failed(message)) => return refuse_with(ErrorCode::BodyReadFailed, message),
        Ok(()) => {}
    }
    let Ok(measured) = measured else {
        return refuse_with(ErrorCode::InternalError, "internal error");
    };
    let (audio, file) = match measured {
        Ok(measured) => measured,
        Err(error) => return refuse_with(ErrorCode::ApplicationError, error.to_string()),
    };
    match sign_measurement(&state.ctx, audio, &file) {
        Ok(response) => Json(response).into_response(),
        Err(_) => refuse_with(ErrorCode::InternalError, "internal error"),
    }
}

/// Forwards `body` to the decoder until it ends, the decoder stops, or the body fails: stalls,
/// errors, or delivers other than `declared` bytes. On failure the decoder is sent a read error,
/// so it never accepts a partial or overlong body.
async fn deliver(
    body: Body,
    declared: u64,
    chunk_timeout: Duration,
    sender: mpsc::Sender<io::Result<Bytes>>,
) -> Result<(), Transport> {
    let mut stream = body.into_data_stream();
    let mut received = 0u64;
    let failure = loop {
        let next = tokio::select! {
            next = timeout(chunk_timeout, stream.next()) => next,
            // The decoder has stopped, and its verdict is final: stop reading the body.
            () = sender.closed() => return Ok(()),
        };
        let chunk = match next {
            Err(_) => break Transport::Stalled,
            Ok(None) if received == declared => return Ok(()),
            Ok(None) => {
                break Transport::Failed(format!(
                    "the body ended after {received} of its {declared} bytes"
                ));
            }
            Ok(Some(Err(error))) => {
                break Transport::Failed(format!("reading the body failed: {error}"));
            }
            Ok(Some(Ok(chunk))) => chunk,
        };
        received += chunk.len() as u64;
        if received > declared {
            break Transport::Failed(format!("the body is longer than its {declared} bytes"));
        }
        if sender.send(Ok(chunk)).await.is_err() {
            return Ok(());
        }
    };
    let _ = sender
        .send(Err(io::Error::other("the body did not arrive whole")))
        .await;
    Err(failure)
}

/// The body's chunks, read synchronously by the decoder.
struct ChannelReader {
    receiver: mpsc::Receiver<io::Result<Bytes>>,
    current: Bytes,
}

impl io::Read for ChannelReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.current.is_empty() {
            match self.receiver.blocking_recv() {
                Some(Ok(chunk)) => self.current = chunk,
                Some(Err(error)) => return Err(error),
                None => return Ok(0),
            }
        }
        let count = buffer.len().min(self.current.len());
        buffer[..count].copy_from_slice(&self.current.split_to(count));
        Ok(count)
    }
}
