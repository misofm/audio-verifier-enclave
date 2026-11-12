//! `POST /measure`: the FLAC file as a streamed body, measured as it arrives.
//!
//! Chunks go through a bounded channel to `measure_reader` on the blocking pool, so a request
//! holds the decoder's window and the queued chunks, whatever the file's size: about 1 MiB of
//! the file for typical frames, and at most [`crate::MEASURE_JOB_BYTES`] in all.

use std::{io, sync::Arc, time::Duration};

use audio_verifier::measure_reader;
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt as _;
use nautilus::ErrorCode;
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc},
    task::spawn_blocking,
    time::timeout,
};

use crate::{MAX_FILE_BYTES, Service, content_length, refuse, refuse_status, sign_measurement};

/// Body chunks queued for the decoder before the route stops reading.
const QUEUED_CHUNKS: usize = 16;

pub(crate) async fn measure(State(service): State<Arc<Service>>, request: Request) -> Response {
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
        run(&service, permit, request.into_body(), declared),
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
) -> Response {
    let (sender, receiver) = mpsc::channel(QUEUED_CHUNKS);
    // The permit is held until the decoder stops, also when this future is dropped at the
    // deadline: dropping `sender` ends its input, so it stops soon after.
    let job = spawn_blocking(move || {
        let _permit = permit;
        measure_reader(ChannelReader {
            receiver,
            current: Bytes::new(),
        })
    });
    let delivered = deliver(body, declared, service.limits.chunk_timeout, sender).await;
    let measured = job.await;
    if let Err(refused) = delivered {
        return refused;
    }
    let (audio, file) = match measured {
        Ok(Ok(measured)) => measured,
        Ok(Err(error)) => return refuse(ErrorCode::ApplicationError, error.to_string()),
        Err(_) => return refuse(ErrorCode::InternalError, "internal error"),
    };
    let ctx = &service.ctx;
    match ctx
        .now()
        .and_then(|now| sign_measurement(ctx, now, audio, &file))
    {
        Ok(response) => Json(response).into_response(),
        Err(_) => refuse(ErrorCode::InternalError, "internal error"),
    }
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
