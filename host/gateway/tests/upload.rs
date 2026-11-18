//! `GET /upload` against a fake enclave and a fake R2: the key, the start and the frames are
//! relayed as records, each frame acknowledged, and the ciphertext stored with a `PUT`.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use audio_verifier_host::{
    Config, MEASURED_MASTER_TYPE, UrlPolicy, app, download_client, upload_client,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post, put},
};
use futures_util::{SinkExt as _, StreamExt as _};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest as _},
};

const RECORDING_ID: &str = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
const FILE_SIZE: u64 = 2500;

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
struct Fakes {
    /// The enclave's `/upload` bodies, as received.
    uploads: Mutex<Vec<Vec<u8>>>,
    /// R2's `PUT`s: their `Content-Length` and body.
    stored: Mutex<Vec<(Option<String>, Vec<u8>)>>,
    /// The enclave refuses every upload after this many bytes of its body.
    refuse_after: Mutex<Option<usize>>,
}

/// Splits `u32be(length) ‖ bytes` records.
fn split_records(mut body: &[u8]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    while !body.is_empty() {
        let length = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
        records.push(body[4..4 + length].to_vec());
        body = &body[4 + length..];
    }
    records
}

fn fake_enclave(fakes: Arc<Fakes>) -> Router {
    Router::new()
        .route(
            "/upload-key",
            get(|| async { Json(json!({ "intent": 3, "x25519_public_key": "aa" })) }),
        )
        .route(
            "/upload",
            post(
                |State(fakes): State<Arc<Fakes>>, request: Request| async move {
                    let mut stream = request.into_body().into_data_stream();
                    let mut body = Vec::new();
                    let refuse_after = *fakes.refuse_after.lock().unwrap();
                    while let Some(Ok(chunk)) = stream.next().await {
                        body.extend_from_slice(&chunk);
                        if refuse_after.is_some_and(|after| body.len() > after) {
                            let refusal =
                                json!({ "error": "upload_rejected", "message": "does not open" });
                            return (StatusCode::BAD_REQUEST, Json(refusal)).into_response();
                        }
                    }
                    fakes.uploads.lock().unwrap().push(body);
                    let head = json!({
                        "audio": { "blob_id": "blob" },
                        "ciphertext_size": "5",
                        "public_key": "ab",
                    });
                    let mut answer = serde_json::to_vec(&head).unwrap();
                    answer.extend_from_slice(b"\nsecre");
                    ([(header::CONTENT_TYPE, MEASURED_MASTER_TYPE)], answer).into_response()
                },
            ),
        )
        .with_state(fakes)
}

fn fake_r2(fakes: Arc<Fakes>) -> Router {
    Router::new()
        .route(
            "/bucket/key",
            put(
                |State(fakes): State<Arc<Fakes>>, request: Request| async move {
                    let length = request
                        .headers()
                        .get(header::CONTENT_LENGTH)
                        .map(|value| value.to_str().unwrap().to_owned());
                    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                        .await
                        .unwrap();
                    fakes.stored.lock().unwrap().push((length, body.to_vec()));
                    StatusCode::OK
                },
            ),
        )
        .with_state(fakes)
}

async fn setup() -> (SocketAddr, Arc<Fakes>) {
    let fakes = Arc::new(Fakes::default());
    let enclave = serve(fake_enclave(Arc::clone(&fakes))).await;
    let r2 = serve(fake_r2(Arc::clone(&fakes))).await;
    let mut config = Config::new(enclave);
    config.policy = UrlPolicy {
        host_suffixes: vec![".r2.test".into()],
        require_https: false,
    };
    let client = download_client(&config, FixedResolver(r2)).unwrap();
    let uploads = upload_client(&config).unwrap();
    (serve(app(config, client, uploads)).await, fakes)
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn open(gateway: SocketAddr, size: u64) -> Socket {
    let mut request = format!("ws://{gateway}/upload")
        .into_client_request()
        .unwrap();
    let headers = request.headers_mut();
    headers.insert("x-miso-recording-id", RECORDING_ID.parse().unwrap());
    headers.insert("x-miso-file-size", size.to_string().parse().unwrap());
    let url = "http://account.r2.test/bucket/key?X-Amz-Signature=ab";
    headers.insert("x-miso-upload-url", url.parse().unwrap());
    connect_async(request).await.unwrap().0
}

async fn text(socket: &mut Socket) -> Value {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

fn start(recording_id: &str, size: u64) -> Message {
    let start = json!({
        "type": "start", "enc": "ee", "recording_id": recording_id,
        "file_size": size.to_string(), "key_expires_ms": "9",
    });
    Message::Text(start.to_string().into())
}

/// A frame of `length` plaintext bytes at `offset`: the offset, then that many bytes and a
/// 16-byte tag's worth.
fn frame(offset: u64, length: usize) -> Vec<u8> {
    let mut frame = offset.to_be_bytes().to_vec();
    frame.extend(std::iter::repeat_n(offset as u8, length + 16));
    frame
}

#[tokio::test]
async fn an_upload_is_relayed_and_its_ciphertext_stored() {
    let (gateway, fakes) = setup().await;
    let mut socket = open(gateway, FILE_SIZE).await;
    let key = text(&mut socket).await;
    assert_eq!(
        key,
        json!({ "type": "upload_key", "key": { "intent": 3, "x25519_public_key": "aa" } })
    );
    socket.send(start(RECORDING_ID, FILE_SIZE)).await.unwrap();
    let frames = [frame(0, 1000), frame(1000, 1000), frame(2000, 500)];
    for (frame, received) in frames.iter().zip([1000, 2000, 2500]) {
        socket
            .send(Message::Binary(Bytes::from(frame.clone())))
            .await
            .unwrap();
        assert_eq!(
            text(&mut socket).await,
            json!({ "type": "ack", "received": received })
        );
    }
    let done = text(&mut socket).await;
    assert_eq!(done["type"], "done", "{done}");
    assert_eq!(done["measured"]["audio"]["blob_id"], "blob");

    let uploads = fakes.uploads.lock().unwrap();
    let records = split_records(&uploads[0]);
    assert_eq!(records.len(), 4);
    let start_record: Value = serde_json::from_slice(&records[0]).unwrap();
    assert_eq!(
        start_record,
        json!({ "enc": "ee", "recording_id": RECORDING_ID, "file_size": "2500", "key_expires_ms": "9" })
    );
    for (record, frame) in records[1..].iter().zip(&frames) {
        assert_eq!(record, frame);
    }
    let stored = fakes.stored.lock().unwrap();
    assert_eq!(stored[0], (Some("5".into()), b"secre".to_vec()));
}

#[tokio::test]
async fn an_upload_of_another_recording_or_size_is_refused() {
    let (gateway, fakes) = setup().await;
    for message in [
        start(
            "0xc1c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
            FILE_SIZE,
        ),
        start(RECORDING_ID, FILE_SIZE + 1),
        Message::Binary(Bytes::from(frame(0, 10))),
    ] {
        let mut socket = open(gateway, FILE_SIZE).await;
        text(&mut socket).await;
        socket.send(message).await.unwrap();
        let error = text(&mut socket).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["error"], "invalid_request", "{error}");
    }
    assert!(fakes.uploads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_frame_out_of_place_is_refused() {
    let (gateway, _) = setup().await;
    for frames in [
        vec![frame(0, 1000), frame(1500, 1000)],
        vec![frame(0, 1000), frame(1000, 1501)],
        vec![b"short".to_vec()],
    ] {
        let mut socket = open(gateway, FILE_SIZE).await;
        text(&mut socket).await;
        socket.send(start(RECORDING_ID, FILE_SIZE)).await.unwrap();
        let mut answer = Value::Null;
        for frame in frames {
            socket
                .send(Message::Binary(Bytes::from(frame)))
                .await
                .unwrap();
            answer = text(&mut socket).await;
            if answer["type"] != "ack" {
                break;
            }
        }
        assert_eq!(answer["type"], "error", "{answer}");
        assert_eq!(answer["error"], "invalid_request");
    }
}

#[tokio::test]
async fn the_enclave_refusal_is_relayed() {
    let (gateway, fakes) = setup().await;
    *fakes.refuse_after.lock().unwrap() = Some(1500);
    let mut socket = open(gateway, FILE_SIZE).await;
    text(&mut socket).await;
    socket.send(start(RECORDING_ID, FILE_SIZE)).await.unwrap();
    let mut answer = Value::Null;
    for frame in [frame(0, 1000), frame(1000, 1000), frame(2000, 500)] {
        if socket
            .send(Message::Binary(Bytes::from(frame)))
            .await
            .is_err()
        {
            break;
        }
        answer = text(&mut socket).await;
        if answer["type"] != "ack" {
            break;
        }
    }
    while answer["type"] == "ack" {
        answer = text(&mut socket).await;
    }
    assert_eq!(answer["type"], "error", "{answer}");
    assert_eq!(answer["error"], "upload_rejected");
    assert_eq!(answer["message"], "does not open");
    assert!(fakes.stored.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_upgrade_without_its_headers_is_refused() {
    let (gateway, _) = setup().await;
    let response = reqwest::Client::new()
        .get(format!("http://{gateway}/upload"))
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "upgrade")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"], "invalid_request");
}
