use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use audio_verifier_host::{
    Config, MEASURED_MASTER_TYPE, UrlPolicy, app, download_client, upload_client,
};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{StreamExt as _, stream};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde_json::{Value, json};
use tokio::{net::TcpListener, time::sleep};

const FILE_LEN: usize = (3 << 20) + 17;
const SLOW_LEN: u64 = 64 << 20;

fn file() -> Vec<u8> {
    (0..FILE_LEN).map(|i| (i * 31 % 251) as u8).collect()
}

async fn serve(router: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

struct FixedResolver(SocketAddr);

impl Resolve for FixedResolver {
    fn resolve(&self, _: Name) -> Resolving {
        let addr = self.0;
        Box::pin(async move { Ok(Box::new(std::iter::once(addr)) as Addrs) })
    }
}

#[derive(Default)]
struct R2 {
    sent: AtomicU64,
    dropped: AtomicBool,
}

struct DropFlag(Arc<R2>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::SeqCst);
    }
}

fn with_length(length: u64, body: Body) -> Response {
    ([(header::CONTENT_LENGTH, length.to_string())], body).into_response()
}

fn fake_r2(state: Arc<R2>) -> Router {
    Router::new()
        .route("/file", get(|| async { file() }))
        .route(
            "/slow",
            get(|State(r2): State<Arc<R2>>| async move {
                let flag = DropFlag(Arc::clone(&r2));
                let chunks = stream::unfold(flag, |flag| async move {
                    sleep(Duration::from_millis(5)).await;
                    flag.0.sent.fetch_add(64 << 10, Ordering::SeqCst);
                    Some((Ok::<_, std::io::Error>(vec![0u8; 64 << 10]), flag))
                });
                with_length(SLOW_LEN, Body::from_stream(chunks.take(1024)))
            }),
        )
        .route(
            "/chunked",
            get(|| async {
                Body::from_stream(stream::iter([Ok::<_, std::io::Error>(vec![1u8; 10])]))
            }),
        )
        .route(
            "/huge",
            get(|| async {
                let never = stream::pending::<Result<Bytes, std::io::Error>>();
                with_length((256 << 20) + 1, Body::from_stream(never))
            }),
        )
        .route(
            "/broken",
            get(|| async {
                let chunks = stream::iter([
                    Ok(vec![2u8; 100 << 10]),
                    Err(std::io::Error::other("upstream broke")),
                ]);
                with_length(1 << 20, Body::from_stream(chunks))
            }),
        )
        .route(
            "/stall",
            get(|| async {
                let first = stream::iter([Ok::<_, std::io::Error>(vec![3u8; 10 << 10])]);
                with_length(1 << 20, Body::from_stream(first.chain(stream::pending())))
            }),
        )
        .route("/hang", get(std::future::pending::<()>))
        .route(
            "/redirect",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/file")]) }),
        )
        .route("/missing", get(|| async { StatusCode::NOT_FOUND }))
        .with_state(state)
}

const RECORDING_ID: &str = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

/// The fake enclave's ciphertext of a file: its bytes reversed, then a 16-byte tail.
fn ciphertext(file: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = file.iter().rev().copied().collect();
    out.extend_from_slice(&[0xee; 16]);
    out
}

/// The blob ID the fake enclave signs, and the fake publisher answers with unless told
/// otherwise.
const BLOB_ID: &str = "956rVqcCzB_6B44jO85CZhUo3hlATKF576dhMV4c3do";

/// A request as received: its `Content-Length`, its query and its body.
type Received = (Option<String>, String, Vec<u8>);

#[derive(Default)]
struct FakeEnclave {
    measured: Mutex<Vec<Received>>,
    attested: Mutex<Vec<Vec<u8>>>,
}

fn fake_enclave(state: Arc<FakeEnclave>, overloaded: bool) -> Router {
    Router::new()
        .route(
            "/measure",
            post(
                move |State(enclave): State<Arc<FakeEnclave>>, request: Request| async move {
                    if overloaded {
                        let body = json!({ "error": "overloaded", "message": "busy" });
                        return (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
                    }
                    let length = request
                        .headers()
                        .get(header::CONTENT_LENGTH)
                        .map(|value| value.to_str().unwrap().to_owned());
                    let query = request.uri().query().unwrap_or_default().to_owned();
                    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX).await;
                    let Ok(bytes) = bytes else {
                        return StatusCode::BAD_REQUEST.into_response();
                    };
                    let len = bytes.len();
                    let ciphertext = ciphertext(&bytes);
                    enclave.measured.lock().unwrap().push((length, query, bytes.to_vec()));
                    let head = json!({
                        "audio": { "len": len, "blob_id": BLOB_ID },
                        "ciphertext_size": ciphertext.len().to_string(),
                        "public_key": "ab",
                    });
                    let mut body = serde_json::to_vec(&head).unwrap();
                    body.push(b'\n');
                    body.extend_from_slice(&ciphertext);
                    // Sent in pieces, the JSON split from its newline.
                    let split = body.len() / 3;
                    let pieces: Vec<Result<Vec<u8>, std::io::Error>> = vec![
                        Ok(body[..10].to_vec()),
                        Ok(body[10..split].to_vec()),
                        Ok(body[split..].to_vec()),
                    ];
                    let length = body.len().to_string();
                    (
                        [
                            (header::CONTENT_TYPE, MEASURED_MASTER_TYPE.to_owned()),
                            (header::CONTENT_LENGTH, length),
                        ],
                        Body::from_stream(stream::iter(pieces)),
                    )
                        .into_response()
                },
            ),
        )
        .route(
            "/attest",
            post(
                |State(enclave): State<Arc<FakeEnclave>>, headers: HeaderMap, body: Bytes| async move {
                    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
                    enclave.attested.lock().unwrap().push(body.to_vec());
                    let body = json!({ "error": "invalid_request", "message": "nonce" });
                    (StatusCode::BAD_REQUEST, Json(body))
                },
            ),
        )
        .route(
            "/health",
            get(|| async { Json(json!({ "pk": "00", "address": "0x0" })) }),
        )
        .with_state(state)
}

/// A Walrus publisher that stores what it is sent and answers with `answer`'s blob ID, or
/// fails with `status`.
#[derive(Default)]
struct FakePublisher {
    stored: Mutex<Vec<Received>>,
    blob_id: Mutex<Option<String>>,
    status: Mutex<Option<StatusCode>>,
}

fn fake_publisher(state: Arc<FakePublisher>) -> Router {
    Router::new()
        .route(
            "/v1/blobs",
            axum::routing::put(
                |State(publisher): State<Arc<FakePublisher>>, request: Request| async move {
                    let query = request.uri().query().unwrap_or_default().to_owned();
                    let length = request
                        .headers()
                        .get(header::CONTENT_LENGTH)
                        .map(|value| value.to_str().unwrap().to_owned());
                    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
                        .await
                        .unwrap();
                    publisher
                        .stored
                        .lock()
                        .unwrap()
                        .push((length, query, bytes.to_vec()));
                    if let Some(status) = *publisher.status.lock().unwrap() {
                        return (status, "no WAL").into_response();
                    }
                    let blob_id = publisher.blob_id.lock().unwrap().clone();
                    let blob_id = blob_id.unwrap_or_else(|| BLOB_ID.into());
                    Json(json!({
                        "newlyCreated": { "blobObject": { "blobId": blob_id, "id": "0x1" } }
                    }))
                    .into_response()
                },
            ),
        )
        .with_state(state)
}

struct Setup {
    gateway: SocketAddr,
    r2: Arc<R2>,
    enclave: Arc<FakeEnclave>,
    publisher: Arc<FakePublisher>,
}

async fn setup_with(overloaded: bool, tune: impl FnOnce(&mut Config)) -> Setup {
    let r2 = Arc::new(R2::default());
    let r2_addr = serve(fake_r2(Arc::clone(&r2))).await;
    let enclave = Arc::new(FakeEnclave::default());
    let enclave_addr = serve(fake_enclave(Arc::clone(&enclave), overloaded)).await;
    let publisher = Arc::new(FakePublisher::default());
    let publisher_addr = serve(fake_publisher(Arc::clone(&publisher))).await;
    let mut config = Config::new(enclave_addr);
    config.policy = UrlPolicy {
        host_suffixes: vec![".r2.test".into()],
        require_https: false,
    };
    config.publisher.url = format!("http://{publisher_addr}").parse().unwrap();
    config.publisher.epochs = 2;
    tune(&mut config);
    let client = download_client(&config, FixedResolver(r2_addr)).unwrap();
    let uploads = upload_client(&config).unwrap();
    let gateway = serve(app(config, client, uploads)).await;
    Setup {
        gateway,
        r2,
        enclave,
        publisher,
    }
}

async fn setup() -> Setup {
    setup_with(false, |_| {}).await
}

impl Setup {
    async fn measure(&self, path: &str) -> (StatusCode, Value) {
        let url = format!("http://account.r2.test{path}");
        let body = json!({ "url": url, "recording_id": RECORDING_ID }).to_string();
        self.post("/measure", body).await
    }

    async fn post(&self, route: &str, body: String) -> (StatusCode, Value) {
        let response = reqwest::Client::new()
            .post(format!("http://{}{route}", self.gateway))
            .body(body)
            .send()
            .await
            .unwrap();
        read(response).await
    }

    async fn get(&self, route: &str) -> (StatusCode, Value) {
        let url = format!("http://{}{route}", self.gateway);
        read(reqwest::get(url).await.unwrap()).await
    }
}

async fn read(response: reqwest::Response) -> (StatusCode, Value) {
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body = response.bytes().await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn measure_streams_the_file_in_and_the_ciphertext_to_walrus() {
    let setup = setup().await;
    let (status, body) = setup.measure("/file").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let size = (FILE_LEN + 16).to_string();
    assert_eq!(
        body,
        json!({
            "audio": { "len": FILE_LEN, "blob_id": BLOB_ID },
            "ciphertext_size": size,
            "public_key": "ab",
            "walrus": { "newlyCreated": { "blobObject": { "blobId": BLOB_ID, "id": "0x1" } } },
        })
    );
    let measured = setup.enclave.measured.lock().unwrap();
    assert_eq!(measured.len(), 1);
    assert_eq!(
        measured[0].0.as_deref(),
        Some(FILE_LEN.to_string().as_str())
    );
    assert_eq!(measured[0].1, format!("recording_id={RECORDING_ID}"));
    assert!(measured[0].2 == file());
    let stored = setup.publisher.stored.lock().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].0.as_deref(), Some(size.as_str()));
    assert_eq!(stored[0].1, "epochs=2&permanent=true");
    assert!(stored[0].2 == ciphertext(&file()));
}

#[tokio::test]
async fn another_stored_blob_id_or_a_failed_upload_is_bad_gateway() {
    let setup = setup().await;
    *setup.publisher.blob_id.lock().unwrap() = Some("other".into());
    let (status, body) = setup.measure("/file").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"], "blob_id_mismatch");
    *setup.publisher.status.lock().unwrap() = Some(StatusCode::INTERNAL_SERVER_ERROR);
    let (status, body) = setup.measure("/file").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"], "upload_failed");
    assert!(body["message"].as_str().unwrap().contains("no WAL"));
}

#[tokio::test]
async fn an_unreachable_publisher_is_bad_gateway() {
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = unused.local_addr().unwrap();
    drop(unused);
    let setup = setup_with(false, |config| {
        config.publisher.url = format!("http://{addr}").parse().unwrap();
    })
    .await;
    let (status, body) = setup.measure("/file").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"], "upload_failed");
}

#[tokio::test]
async fn an_overloaded_enclave_returns_at_once_and_drops_the_download() {
    let setup = setup_with(true, |_| {}).await;
    let start = Instant::now();
    let (status, body) = setup.measure("/slow").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "overloaded");
    assert!(start.elapsed() < Duration::from_secs(2));
    for _ in 0..200 {
        if setup.r2.dropped.load(Ordering::SeqCst) {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(setup.r2.dropped.load(Ordering::SeqCst));
    assert!(setup.r2.sent.load(Ordering::SeqCst) < SLOW_LEN / 2);
}

#[tokio::test]
async fn a_download_without_content_length_is_refused() {
    let setup = setup().await;
    let (status, body) = setup.measure("/chunked").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "download_failed");
    assert!(setup.enclave.measured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_oversized_download_is_refused_before_its_body() {
    let setup = setup().await;
    let (status, body) = setup.measure("/huge").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "body_too_large");
    assert!(setup.enclave.measured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn download_failures_are_bad_gateway() {
    let setup = setup_with(false, |config| {
        config.idle_timeout = Duration::from_millis(500);
    })
    .await;
    for path in ["/broken", "/stall", "/redirect", "/missing"] {
        let (status, body) = setup.measure(path).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{path}: {body}");
        assert_eq!(body["error"], "download_failed", "{path}");
        assert!(
            !body["message"].as_str().unwrap().contains("r2.test"),
            "{path}"
        );
    }
    assert!(setup.enclave.measured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn measure_refuses_bad_requests() {
    let setup = setup().await;
    for url in [
        "http://evil.test/file",
        "http://127.0.0.1/file",
        "ftp://account.r2.test/file",
    ] {
        let body = json!({ "url": url, "recording_id": RECORDING_ID });
        let (status, body) = setup.post("/measure", body.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}");
        assert_eq!(body["error"], "url_not_allowed", "{url}");
    }
    let short = &RECORDING_ID[..64];
    let injected = format!("{RECORDING_ID}&recording_id=0x00");
    for invalid in [
        "",
        "{}",
        "not json",
        r#"{"url":"http://a.r2.test/file"}"#,
        &format!(r#"{{"url":"http://a.r2.test/","recording_id":"{RECORDING_ID}","x":1}}"#),
        &format!(r#"{{"url":"http://a.r2.test/file","recording_id":"{short}"}}"#),
        &format!(r#"{{"url":"http://a.r2.test/file","recording_id":"{injected}"}}"#),
    ] {
        let (status, body) = setup.post("/measure", invalid.into()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
        assert_eq!(body["error"], "invalid_request", "{invalid}");
    }
    let (status, body) = setup.post("/measure", "x".repeat(17 << 10)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "body_too_large");
}

#[tokio::test]
async fn measure_is_bounded_in_flight_and_in_time() {
    let setup = setup_with(false, |config| {
        config.max_in_flight = 1;
        config.request_timeout = Duration::from_secs(1);
    })
    .await;
    let first = tokio::spawn({
        let gateway = setup.gateway;
        async move {
            let setup = Setup {
                gateway,
                r2: Arc::default(),
                enclave: Arc::default(),
                publisher: Arc::default(),
            };
            setup.measure("/hang").await
        }
    });
    sleep(Duration::from_millis(200)).await;
    let (status, body) = setup.measure("/file").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "overloaded");
    let (status, body) = first.await.unwrap();
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body["error"], "request_timeout");
    let (status, _) = setup.measure("/file").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn attest_and_health_pass_through() {
    let setup = setup().await;
    let (status, body) = setup.post("/attest", r#"{"nonce":"00ff"}"#.into()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({ "error": "invalid_request", "message": "nonce" })
    );
    assert_eq!(
        *setup.enclave.attested.lock().unwrap(),
        [br#"{"nonce":"00ff"}"#.to_vec()]
    );
    let (status, body) = setup.post("/attest", "x".repeat((4 << 10) + 1)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "body_too_large");
    assert_eq!(setup.enclave.attested.lock().unwrap().len(), 1);
    let (status, body) = setup.get("/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "pk": "00", "address": "0x0" }));
}

#[tokio::test]
async fn other_routes_are_not_found() {
    let setup = setup().await;
    for (status, body) in [
        setup.get("/measure").await,
        setup.get("/attest").await,
        setup.post("/health", String::new()).await,
        setup.get("/").await,
        setup.post("/process_data", String::new()).await,
    ] {
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");
    }
}

#[tokio::test]
async fn an_unreachable_enclave_is_bad_gateway() {
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = unused.local_addr().unwrap();
    drop(unused);
    let mut config = Config::new(addr);
    config.policy.require_https = false;
    let client = download_client(&config, FixedResolver(addr)).unwrap();
    let uploads = upload_client(&config).unwrap();
    let setup = Setup {
        gateway: serve(app(config, client, uploads)).await,
        r2: Arc::default(),
        enclave: Arc::default(),
        publisher: Arc::default(),
    };
    let (status, body) = setup.get("/health").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "enclave_unavailable");
}
