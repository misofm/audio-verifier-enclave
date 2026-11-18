//! The second half of `/measure`: the enclave's response is its JSON, a newline, then the
//! ciphertext. The JSON is read, the ciphertext is streamed to a Walrus publisher as it arrives,
//! and the caller gets the JSON with the publisher's answer once Walrus's blob ID is the one the
//! enclave signed.

use std::time::Duration;

use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::{StreamExt as _, stream};
use http_body_util::BodyExt as _;
use serde_json::{Map, Value};
use url::Url;

use crate::{enclave::Opened, refuse};

/// The media type of the enclave's `/measure` response.
pub const MEASURED_MASTER_TYPE: &str = "application/vnd.miso.measured-master";

/// Largest JSON before the ciphertext; it is about 2 KiB.
const HEAD_BYTES: usize = 64 << 10;

/// Where and how ciphertexts are stored.
#[derive(Debug, Clone)]
pub struct Publisher {
    /// The publisher's base URL; blobs are `PUT` to `<url>/v1/blobs`.
    pub url: Url,
    /// Epochs to store each blob for.
    pub epochs: u32,
    /// The address the publisher sends the `Blob` object to, if not its own.
    pub send_object_to: Option<String>,
    /// Deadline for one upload, the publisher's answer included.
    pub timeout: Duration,
}

impl Default for Publisher {
    fn default() -> Self {
        Self {
            url: Url::parse("https://publisher.walrus-testnet.walrus.space").expect("a URL"),
            epochs: 53,
            send_object_to: None,
            timeout: Duration::from_secs(600),
        }
    }
}

impl Publisher {
    fn blobs_url(&self) -> Url {
        let mut url = self.url.clone();
        url.path_segments_mut()
            .expect("an http(s) URL has a path")
            .pop_if_empty()
            .extend(["v1", "blobs"]);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("epochs", &self.epochs.to_string());
            query.append_pair("permanent", "true");
            if let Some(address) = &self.send_object_to {
                query.append_pair("send_object_to", address);
            }
        }
        url
    }
}

fn enclave_failed(message: String) -> Response {
    eprintln!("[enclave] {message}");
    refuse(StatusCode::BAD_GATEWAY, "enclave_unavailable", message)
}

fn upload_failed(message: String) -> Response {
    eprintln!("[walrus] upload failed: {message}");
    refuse(StatusCode::BAD_GATEWAY, "upload_failed", message)
}

/// The blob ID Walrus answered with: a new blob's, or one already certified.
fn stored_blob_id(answer: &Value) -> Option<&str> {
    answer
        .pointer("/newlyCreated/blobObject/blobId")
        .or_else(|| answer.pointer("/alreadyCertified/blobId"))?
        .as_str()
}

/// Uploads the ciphertext of `opened`, a measured master, and answers its JSON with `walrus`,
/// the publisher's answer, added; or an error if the upload fails or stores another blob ID.
pub async fn store(client: &reqwest::Client, publisher: &Publisher, opened: Opened) -> Response {
    let Opened {
        response,
        _connection,
    } = opened;
    let mut body = response.into_body().into_data_stream();
    let mut head = Vec::new();
    let rest = loop {
        let chunk = match body.next().await {
            Some(Ok(chunk)) => chunk,
            Some(Err(error)) => {
                return enclave_failed(format!("reading the response failed: {error}"));
            }
            None => return enclave_failed("the response ended before its ciphertext".into()),
        };
        if let Some(newline) = chunk.iter().position(|&byte| byte == b'\n') {
            head.extend_from_slice(&chunk[..newline]);
            break chunk.slice(newline + 1..);
        }
        head.extend_from_slice(&chunk);
        if head.len() > HEAD_BYTES {
            return enclave_failed("the response's JSON is too long".into());
        }
    };
    let parsed: Option<(Map<String, Value>, String, u64)> = (|| {
        let measured: Map<String, Value> = serde_json::from_slice(&head).ok()?;
        let blob_id = measured.get("audio")?.get("blob_id")?.as_str()?.to_owned();
        let size = measured.get("ciphertext_size")?.as_str()?.parse().ok()?;
        Some((measured, blob_id, size))
    })();
    let Some((mut measured, blob_id, size)) = parsed else {
        return enclave_failed("the response's JSON has no blob_id or ciphertext_size".into());
    };
    if rest.len() as u64 > size {
        return enclave_failed("the response is longer than its ciphertext".into());
    }
    let mut remaining = size - rest.len() as u64;
    let ciphertext = stream::once(async move { Ok::<Bytes, std::io::Error>(rest) }).chain(
        body.map(move |chunk| {
            let chunk = chunk.map_err(std::io::Error::other)?;
            remaining = remaining
                .checked_sub(chunk.len() as u64)
                .ok_or_else(|| std::io::Error::other("the ciphertext is too long"))?;
            Ok(chunk)
        }),
    );
    let upload = client
        .put(publisher.blobs_url())
        .header(header::CONTENT_LENGTH, size)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(reqwest::Body::wrap_stream(ciphertext))
        .send()
        .await;
    let answer = match upload {
        Ok(answer) => answer,
        Err(error) => return upload_failed(crate::describe(error)),
    };
    let status = answer.status();
    let text = match answer.text().await {
        Ok(text) => text,
        Err(error) => return upload_failed(crate::describe(error)),
    };
    if !status.is_success() {
        let excerpt: String = text.chars().take(500).collect();
        return upload_failed(format!("the publisher answered {status}: {excerpt}"));
    }
    let Ok(answer) = serde_json::from_str::<Value>(&text) else {
        return upload_failed("the publisher's answer is not JSON".into());
    };
    match stored_blob_id(&answer) {
        Some(stored) if stored == blob_id => {}
        Some(stored) => {
            eprintln!("[walrus] stored {stored}, the enclave signed {blob_id}");
            let message = format!("Walrus stored blob {stored}; the enclave signed {blob_id}");
            return refuse(StatusCode::BAD_GATEWAY, "blob_id_mismatch", message);
        }
        None => return upload_failed("the publisher's answer has no blob ID".into()),
    }
    measured.insert("walrus".into(), answer);
    (StatusCode::OK, Json(Value::Object(measured))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_blobs_url_carries_the_storage_options() {
        let mut publisher = Publisher::default();
        assert_eq!(
            publisher.blobs_url().as_str(),
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=53&permanent=true"
        );
        publisher.url = Url::parse("http://127.0.0.1:8002/").unwrap();
        publisher.epochs = 2;
        publisher.send_object_to = Some("0xab".into());
        assert_eq!(
            publisher.blobs_url().as_str(),
            "http://127.0.0.1:8002/v1/blobs?epochs=2&permanent=true&send_object_to=0xab"
        );
    }

    #[test]
    fn the_blob_id_is_read_from_either_answer() {
        let created = serde_json::json!({ "newlyCreated": { "blobObject": { "blobId": "a" } } });
        let certified = serde_json::json!({ "alreadyCertified": { "blobId": "b" } });
        assert_eq!(stored_blob_id(&created), Some("a"));
        assert_eq!(stored_blob_id(&certified), Some("b"));
        assert_eq!(stored_blob_id(&serde_json::json!({})), None);
    }
}
