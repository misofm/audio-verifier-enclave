use std::sync::{Mutex, mpsc};

use audio_verifier_enclave::{
    ATTESTATION_BODY_BYTES, DEFAULT_MAX_BODY_BYTES, app, max_body_bytes, server_config,
};
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, Response, StatusCode, header},
};
use http_body_util::BodyExt as _;
use nautilus::{
    AttestationError, AttestationRequest, Attestor, EnclaveIdentity, NautilusContext,
    testing::FakeAttestor,
};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tower::ServiceExt as _;

fn context() -> NautilusContext {
    NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    )
}

fn router() -> Router {
    app(context(), DEFAULT_MAX_BODY_BYTES, 2)
}

fn request(method: &str, uri: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(body.into())
        .expect("request")
}

async fn json(response: Response<Body>) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, serde_json::from_slice(&bytes).expect("JSON"))
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    json(router.clone().oneshot(request).await.expect("response")).await
}

#[tokio::test]
async fn health_check_reports_the_injected_identity() {
    let ctx = context();
    let router = app(ctx.clone(), DEFAULT_MAX_BODY_BYTES, 2);
    let (status, value) = send(&router, request("GET", "/health_check", Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["pk"], ctx.public_key_hex());
    assert_eq!(value["address"], ctx.sui_address());
}

#[tokio::test]
async fn attestation_binds_the_nonce_and_the_key() {
    let attestor = FakeAttestor::default();
    let ctx = NautilusContext::with_signer(EnclaveIdentity::from_seed([9u8; 32]), attestor.clone());
    let router = app(ctx.clone(), DEFAULT_MAX_BODY_BYTES, 2);
    let body = r#"{ "nonce": "0a0b0c" }"#;
    let (status, value) = send(&router, request("POST", "/attestation", body)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let document = hex::decode(value["attestation"].as_str().expect("hex")).expect("hex");
    let document: serde_json::Value = serde_json::from_slice(&document).expect("fake document");
    assert_eq!(document["nonce"], "0a0b0c");
    assert_eq!(document["public_key"], ctx.public_key_hex());
    let requests = attestor.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].nonce.as_deref(), Some(&[10u8, 11, 12][..]));
    assert_eq!(requests[0].user_data, None);
}

#[tokio::test]
async fn attestation_requires_a_nonce() {
    let router = router();
    for body in [
        "",
        "{}",
        r#"{ "nonce": "" }"#,
        r#"{ "nonce": "zz" }"#,
        r#"{ "nonce": "0a", "user_data": "0b" }"#,
    ] {
        let (status, value) = send(&router, request("POST", "/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {value}");
        assert_eq!(value["error"], "invalid_request", "{body}");
    }
    let oversized = format!(r#"{{ "nonce": "{}" }}"#, "00".repeat(513));
    let (status, value) = send(&router, request("POST", "/attestation", oversized)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = value["message"].as_str().expect("message");
    assert!(message.contains("at most 512 bytes"), "{message}");
}

#[tokio::test]
async fn attestation_body_is_bounded() {
    let router = router();
    let body = format!(
        r#"{{ "nonce": "0a", "pad": "{}" }}"#,
        " ".repeat(ATTESTATION_BODY_BYTES)
    );
    // A declared length over the limit is refused before any of the body is read.
    let declared = Request::builder()
        .method("POST")
        .uri("/attestation")
        .header(header::CONTENT_LENGTH, ATTESTATION_BODY_BYTES + 1)
        .body(Body::from_stream(futures_util::stream::pending::<
            Result<Bytes, std::io::Error>,
        >()))
        .expect("request");
    let (status, value) = send(&router, declared).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value["error"], "body_too_large");

    // Without one, the body is refused once it delivers more than the limit.
    let chunks: Vec<Result<Bytes, std::io::Error>> = body
        .as_bytes()
        .chunks(100)
        .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
        .collect();
    let streamed = Body::from_stream(futures_util::stream::iter(chunks));
    let (status, value) = send(&router, request("POST", "/attestation", streamed)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value["error"], "body_too_large");
}

/// An attestor that reports each attestation and blocks it until released.
struct Gate {
    entered: UnboundedSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Attestor for Gate {
    fn name(&self) -> &'static str {
        "gate"
    }

    fn attest(&self, _request: AttestationRequest) -> Result<Vec<u8>, AttestationError> {
        self.entered.send(()).expect("entered");
        self.release.lock().expect("lock").recv().expect("released");
        Err(AttestationError::Unavailable("closed".into()))
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, AttestationError> {
        Ok(vec![0; len])
    }
}

#[tokio::test]
async fn attestations_run_one_at_a_time() {
    let (entered, mut attesting) = unbounded_channel();
    let (release, gate) = mpsc::channel();
    let gate = Gate {
        entered,
        release: Mutex::new(gate),
    };
    let ctx = NautilusContext::with_signer(EnclaveIdentity::from_seed([9u8; 32]), gate);
    let router = app(ctx, DEFAULT_MAX_BODY_BYTES, 2);
    let body = r#"{ "nonce": "0a" }"#;
    let first = tokio::spawn(
        router
            .clone()
            .oneshot(request("POST", "/attestation", body)),
    );
    attesting.recv().await.expect("attesting");

    let (status, value) = send(&router, request("POST", "/attestation", body)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(value["error"], "overloaded");
    let health = request("GET", "/health_check", Body::empty());
    assert_eq!(send(&router, health).await.0, StatusCode::OK);

    release.send(()).expect("release");
    let (status, value) = json(first.await.expect("task").expect("response")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["error"], "attestation_unavailable");
}

#[tokio::test]
async fn unknown_routes_and_methods_get_json_errors() {
    let router = router();
    for uri in ["/process_data", "/v1/other"] {
        let (status, value) = send(&router, request("POST", uri, Body::empty())).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(value["error"], "not_found");
    }
    for (method, uri) in [
        ("GET", "/attestation"),
        ("GET", "/v1/measure"),
        ("POST", "/health_check"),
    ] {
        let (status, value) = send(&router, request(method, uri, Body::empty())).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {uri}");
        assert_eq!(value["error"], "method_not_allowed");
    }
}

#[test]
fn max_body_bytes_resolution() {
    assert_eq!(
        max_body_bytes(&[], None).expect("default"),
        256 * 1024 * 1024
    );
    assert_eq!(max_body_bytes(&[], Some("1024".into())).expect("env"), 1024);
    let args = ["--max-body-bytes".to_owned(), "2048".to_owned()];
    assert_eq!(
        max_body_bytes(&args, Some("1024".into())).expect("flag"),
        2048
    );
    assert!(max_body_bytes(&["--dev".to_owned()], None).is_err());
    assert!(max_body_bytes(&[], Some("lots".into())).is_err());
}

#[test]
fn ambiguous_or_zero_body_limits_are_rejected() {
    assert!(max_body_bytes(&[], Some("0".into())).is_err());
    let args = ["--max-body-bytes", "1024", "--max-body-bytes", "2048"].map(String::from);
    assert!(max_body_bytes(&args, None).is_err());
}

#[test]
fn server_config_limits_connections() {
    let config = server_config();
    assert_eq!(config.max_connections, 256);
    config.validate().expect("valid");
}
