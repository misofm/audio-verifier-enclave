//! The parent instance's gateway to the enclave: `POST /measure` downloads a file from an R2
//! presigned URL, streams it into the enclave's `/measure`, and streams the encrypted master the
//! enclave returns to a Walrus publisher; `POST /attest` and `GET /health` pass through. It
//! keeps no state; callers retry on 429 and 5xx.

mod enclave;
mod policy;
mod walrus;

use std::{
    error::Error,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt as _};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Empty, Full, LengthLimitError, Limited};
use reqwest::{dns::Resolve, redirect};
use serde::Deserialize;
use tokio::{sync::Semaphore, time::timeout};

pub use enclave::Enclave;
pub use policy::{PublicResolver, R2_HOST_SUFFIX, UrlPolicy, is_public};
pub use walrus::{MEASURED_MASTER_TYPE, Publisher};

/// Largest file `/measure` forwards, the enclave's own limit.
pub const MAX_FILE_BYTES: u64 = 256 << 20;

/// Largest accepted `/attest` body, the enclave's own limit.
pub const ATTEST_BODY_BYTES: usize = 4 << 10;

/// Largest accepted `/measure` body, the JSON holding the URL.
const MEASURE_BODY_BYTES: usize = 16 << 10;

/// Deadline for `/attest` and `/health`.
const PASSTHROUGH_TIMEOUT: Duration = Duration::from_secs(60);

/// The gateway's settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// The enclave's HTTP service, through the TCP-to-vsock bridge.
    pub enclave: SocketAddr,
    /// Which download URLs are accepted.
    pub policy: UrlPolicy,
    /// `/measure` requests at once; more get 429 `overloaded`.
    pub max_in_flight: usize,
    /// Deadline for a TCP connection, to the download or the enclave.
    pub connect_timeout: Duration,
    /// A download that delivers nothing for this long fails.
    pub idle_timeout: Duration,
    /// Deadline for `/measure` up to the enclave's answer: the enclave allows 600 s for the body
    /// and measurement. The upload has [`Publisher::timeout`] after it.
    pub request_timeout: Duration,
    /// The Walrus publisher that stores the ciphertexts.
    pub publisher: Publisher,
}

impl Config {
    /// The defaults, with the enclave at `enclave`.
    pub fn new(enclave: SocketAddr) -> Self {
        Self {
            enclave,
            policy: UrlPolicy::default(),
            max_in_flight: 16,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(630),
            publisher: Publisher::default(),
        }
    }
}

/// The download client: no proxy, no redirects, rustls with the bundled web PKI roots, and the
/// config's timeouts, resolving names through `resolver`.
pub fn download_client<R: Resolve + 'static>(
    config: &Config,
    resolver: R,
) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::none())
        .https_only(config.policy.require_https)
        .connect_timeout(config.connect_timeout)
        .read_timeout(config.idle_timeout)
        .dns_resolver(Arc::new(resolver))
        .build()
}

/// The upload client: no proxy, no redirects, rustls with the bundled web PKI roots. The
/// publisher is the operator's choice, so its address is not checked.
pub fn upload_client(config: &Config) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::none())
        .connect_timeout(config.connect_timeout)
        .build()
}

struct Gateway {
    config: Config,
    client: reqwest::Client,
    uploads: reqwest::Client,
    enclave: Enclave,
    in_flight: Arc<Semaphore>,
}

/// Builds the gateway's router: `client` downloads, `uploads` stores on Walrus.
pub fn app(config: Config, client: reqwest::Client, uploads: reqwest::Client) -> Router {
    let gateway = Gateway {
        enclave: Enclave::new(config.enclave, config.connect_timeout),
        uploads,
        in_flight: Arc::new(Semaphore::new(config.max_in_flight)),
        config,
        client,
    };
    let not_found = || async { refuse(StatusCode::NOT_FOUND, "not_found", "no such route") };
    Router::new()
        .route("/measure", post(measure))
        .route("/attest", post(attest))
        .route("/health", get(health))
        .with_state(Arc::new(gateway))
        .method_not_allowed_fallback(not_found)
        .fallback(not_found)
}

/// A JSON error in the enclave's `{ error, message }` shape.
fn refuse(status: StatusCode, error: &str, message: impl Into<String>) -> Response {
    let body = serde_json::json!({ "error": error, "message": message.into() });
    (status, Json(body)).into_response()
}

fn download_failed(message: impl Into<String>) -> Response {
    let message = message.into();
    eprintln!("[measure] download failed: {message}");
    refuse(StatusCode::BAD_GATEWAY, "download_failed", message)
}

fn enclave_unavailable(message: String) -> Response {
    eprintln!("[enclave] {message}");
    refuse(StatusCode::BAD_GATEWAY, "enclave_unavailable", message)
}

/// A download or upload error and its causes, without the URL, whose query holds the presigned
/// signature.
fn describe(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut message = error.to_string();
    let mut source = Error::source(&error);
    while let Some(cause) = source {
        message = format!("{message}: {cause}");
        source = cause.source();
    }
    message
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasureBody {
    url: String,
    /// The Recording's object ID, which the enclave seals the master's key to.
    recording_id: String,
}

/// A 32-byte object ID as hex, with or without `0x`.
fn is_object_id(value: &str) -> bool {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    digits.len() == 64 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn measure(State(gateway): State<Arc<Gateway>>, request: Request) -> Response {
    let Ok(_permit) = Arc::clone(&gateway.in_flight).try_acquire_owned() else {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "overloaded",
            "the gateway is at its concurrency limit",
        );
    };
    let deadline = gateway.config.request_timeout;
    let opened = match timeout(deadline, measure_within_deadline(&gateway, request)).await {
        Ok(Ok(opened)) => opened,
        Ok(Err(response)) => return response,
        Err(_) => {
            return refuse(
                StatusCode::GATEWAY_TIMEOUT,
                "request_timeout",
                format!("the request took longer than {deadline:?}"),
            );
        }
    };
    let content_type = opened.response.headers().get(header::CONTENT_TYPE);
    let measured = opened.response.status() == StatusCode::OK
        && content_type.is_some_and(|value| value.as_bytes() == MEASURED_MASTER_TYPE.as_bytes());
    if !measured {
        return match timeout(PASSTHROUGH_TIMEOUT, enclave::relay(opened)).await {
            Ok(Ok(response)) => response,
            Ok(Err(message)) => enclave_unavailable(message),
            Err(_) => enclave_unavailable("reading the enclave's answer timed out".into()),
        };
    }
    let publisher = &gateway.config.publisher;
    match timeout(
        publisher.timeout,
        walrus::store(&gateway.uploads, publisher, opened),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => refuse(
            StatusCode::GATEWAY_TIMEOUT,
            "request_timeout",
            format!("the upload took longer than {:?}", publisher.timeout),
        ),
    }
}

/// Up to the enclave's answer: the request, the download, and the enclave's response head.
async fn measure_within_deadline(
    gateway: &Gateway,
    request: Request,
) -> Result<enclave::Opened, Response> {
    let bytes = read_small(request, MEASURE_BODY_BYTES).await?;
    let body: MeasureBody = serde_json::from_slice(&bytes).map_err(|error| {
        refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            format!("invalid measure body: {error}"),
        )
    })?;
    if !is_object_id(&body.recording_id) {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "recording_id must be a 32-byte hex object ID",
        ));
    }
    let url = gateway
        .config
        .policy
        .check(&body.url)
        .map_err(|message| refuse(StatusCode::BAD_REQUEST, "url_not_allowed", message))?;
    let download = gateway
        .client
        .get(url)
        .send()
        .await
        .map_err(|error| download_failed(describe(error)))?;
    if !download.status().is_success() {
        return Err(download_failed(format!(
            "the download answered {}",
            download.status()
        )));
    }
    let length = download
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok())
        .ok_or_else(|| download_failed("the download has no Content-Length"))?;
    if length > MAX_FILE_BYTES {
        return Err(refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            format!("the file is {length} bytes, over {MAX_FILE_BYTES}"),
        ));
    }
    let uri = format!("/measure?recording_id={}", body.recording_id);
    let failure = Arc::new(OnceLock::new());
    let body = DownloadBody {
        stream: Box::pin(download.bytes_stream()),
        remaining: length,
        failure: Arc::clone(&failure),
    };
    let request = axum::http::Request::post(uri)
        .header(header::CONTENT_LENGTH, length)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .expect("the request is well formed");
    gateway
        .enclave
        .open(request)
        .await
        .map_err(|message| match failure.get() {
            Some(failure) => download_failed(failure.clone()),
            None => enclave_unavailable(message),
        })
}

async fn attest(State(gateway): State<Arc<Gateway>>, request: Request) -> Response {
    let forward = async {
        let bytes = read_small(request, ATTEST_BODY_BYTES).await?;
        let request = axum::http::Request::post("/attest")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(bytes))
            .expect("the request is well formed");
        gateway
            .enclave
            .send(request)
            .await
            .map_err(enclave_unavailable)
    };
    passthrough(forward).await
}

async fn health(State(gateway): State<Arc<Gateway>>) -> Response {
    let request = axum::http::Request::get("/health")
        .body(Empty::<Bytes>::new())
        .expect("the request is well formed");
    let forward = async {
        gateway
            .enclave
            .send(request)
            .await
            .map_err(enclave_unavailable)
    };
    passthrough(forward).await
}

async fn passthrough(forward: impl Future<Output = Result<Response, Response>>) -> Response {
    match timeout(PASSTHROUGH_TIMEOUT, forward).await {
        Ok(Ok(response) | Err(response)) => response,
        Err(_) => refuse(
            StatusCode::GATEWAY_TIMEOUT,
            "request_timeout",
            format!("the request took longer than {PASSTHROUGH_TIMEOUT:?}"),
        ),
    }
}

/// Reads a body of at most `limit` bytes, refusing it as soon as it declares or delivers more.
async fn read_small(request: Request, limit: usize) -> Result<Bytes, Response> {
    let too_large = || {
        refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            format!("the body is over {limit} bytes"),
        )
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok());
    if declared.is_some_and(|declared| declared > limit as u64) {
        return Err(too_large());
    }
    match Limited::new(request.into_body(), limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.is::<LengthLimitError>() => Err(too_large()),
        Err(error) => Err(refuse(
            StatusCode::BAD_REQUEST,
            "body_read_failed",
            format!("reading the body failed: {error}"),
        )),
    }
}

type ByteStream = Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>;

/// The download as the enclave request's body: exactly `Content-Length` bytes, or an error
/// that is also recorded in `failure`, so that a failed send can be told from a failed enclave.
struct DownloadBody {
    stream: ByteStream,
    remaining: u64,
    failure: Arc<OnceLock<String>>,
}

impl DownloadBody {
    fn fail(&self, message: String) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let _ = self.failure.set(message.clone());
        Poll::Ready(Some(Err(io::Error::other(message))))
    }
}

impl Body for DownloadBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.stream.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                let len = chunk.len() as u64;
                if len > self.remaining {
                    return self.fail("the download is longer than its Content-Length".into());
                }
                self.remaining -= len;
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Poll::Ready(Some(Err(error))) => self.fail(describe(error)),
            Poll::Ready(None) if self.remaining > 0 => {
                self.fail("the download is shorter than its Content-Length".into())
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}
