//! The service's router: `/health_check`, `/attestation` and `/v1/measure`, behind one panic
//! catcher and JSON fallbacks. Nautilus's own router is not used: it always mounts
//! `/process_data`, and it buffers bodies whole before checking them.

use std::{panic::AssertUnwindSafe, sync::Arc};

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{FutureExt as _, StreamExt as _};
use nautilus::{
    AttestationError, ErrorCode, HealthCheckBody, NautilusContext, NautilusError, decode_hex,
    encode_hex,
};
use serde::Deserialize;
use tokio::{sync::Semaphore, task::spawn_blocking, time::timeout};

use crate::{ATTESTATION_BODY_BYTES, ATTESTATION_TIMEOUT, measure_routes, stream_config};

struct AttestationState {
    ctx: NautilusContext,
    permits: Arc<Semaphore>,
}

/// `/attestation` request body. Nautilus's optional `user_data` is not accepted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationBody {
    nonce: String,
}

/// Builds the service's router around an injected context. `/v1/measure` accepts files of up to
/// `max_file_bytes` and runs up to `measure_concurrent` jobs at once; `/attestation` runs one at
/// a time.
pub fn app(ctx: NautilusContext, max_file_bytes: usize, measure_concurrent: usize) -> Router {
    let measure = measure_routes(
        ctx.clone(),
        stream_config(max_file_bytes, measure_concurrent),
    );
    let state = Arc::new(AttestationState {
        ctx,
        permits: Arc::new(Semaphore::new(1)),
    });
    Router::new()
        .route("/health_check", get(health_check))
        .route("/attestation", post(attestation))
        .with_state(state)
        .merge(measure)
        .method_not_allowed_fallback(|| async {
            refuse_with(ErrorCode::MethodNotAllowed, "method not allowed")
        })
        .fallback(|| async { refuse_with(ErrorCode::NotFound, "no such route") })
        .layer(middleware::from_fn(catch_panic))
}

/// A JSON error in Nautilus's `{ error, message }` shape.
pub(crate) fn refuse(status: StatusCode, error: &str, message: impl Into<String>) -> Response {
    let body = serde_json::json!({ "error": error, "message": message.into() });
    (status, Json(body)).into_response()
}

pub(crate) fn refuse_with(code: ErrorCode, message: impl Into<String>) -> Response {
    refuse(code.status(), code.as_str(), message)
}

async fn catch_panic(request: Request, next: Next) -> Response {
    match AssertUnwindSafe(next.run(request)).catch_unwind().await {
        Ok(response) => response,
        Err(_) => refuse_with(ErrorCode::InternalError, "internal error"),
    }
}

async fn health_check(State(state): State<Arc<AttestationState>>) -> Json<HealthCheckBody> {
    Json(HealthCheckBody {
        pk: state.ctx.public_key_hex(),
        address: state.ctx.sui_address(),
    })
}

async fn attestation(State(state): State<Arc<AttestationState>>, request: Request) -> Response {
    match timeout(ATTESTATION_TIMEOUT, attest(&state, request)).await {
        Ok(response) => response.unwrap_or_else(|refused| refused),
        Err(_) => refuse_with(
            ErrorCode::RequestTimeout,
            format!("the request took longer than {ATTESTATION_TIMEOUT:?}"),
        ),
    }
}

async fn attest(state: &AttestationState, request: Request) -> Result<Response, Response> {
    let bytes = read_small(request).await?;
    let body: AttestationBody = serde_json::from_slice(&bytes).map_err(|error| {
        refuse_with(
            ErrorCode::InvalidRequest,
            format!("invalid attestation body: {error}"),
        )
    })?;
    let nonce = decode_hex(&body.nonce)
        .map_err(|error| refuse_with(ErrorCode::InvalidRequest, format!("nonce: {error}")))?;
    if nonce.is_empty() {
        return Err(refuse_with(ErrorCode::InvalidRequest, "nonce is required"));
    }
    let permit = Arc::clone(&state.permits)
        .try_acquire_owned()
        .map_err(|_| refuse_with(ErrorCode::Overloaded, "server is at its concurrency limit"))?;
    let ctx = state.ctx.clone();
    let document = spawn_blocking(move || {
        let _permit = permit;
        ctx.attestation(Some(nonce), None)
    })
    .await
    .map_err(|_| refuse_with(ErrorCode::InternalError, "internal error"))?;
    match document {
        Ok(document) => {
            Ok(Json(serde_json::json!({ "attestation": encode_hex(document) })).into_response())
        }
        Err(error @ NautilusError::Attestation(AttestationError::InvalidRequest(_))) => {
            Err(refuse_with(ErrorCode::InvalidRequest, error.to_string()))
        }
        Err(error) => {
            eprintln!("[attestation] failed: {error}");
            Err(refuse_with(
                ErrorCode::AttestationUnavailable,
                "attestation is unavailable",
            ))
        }
    }
}

/// Reads a body of at most [`ATTESTATION_BODY_BYTES`], refusing it as soon as it declares or
/// delivers more.
async fn read_small(request: Request) -> Result<Vec<u8>, Response> {
    let too_large = || {
        refuse_with(
            ErrorCode::BodyTooLarge,
            format!("the body is over {ATTESTATION_BODY_BYTES} bytes"),
        )
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|declared| declared > ATTESTATION_BODY_BYTES as u64) {
        return Err(too_large());
    }
    let mut stream = request.into_body().into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            refuse_with(
                ErrorCode::BodyReadFailed,
                format!("reading the body failed: {error}"),
            )
        })?;
        if bytes.len() + chunk.len() > ATTESTATION_BODY_BYTES {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
