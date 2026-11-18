use std::{error::Error, net::SocketAddr, time::Duration};

use axum::{
    body::Body as AxumBody,
    http::{HeaderValue, Request, Response, header},
};
use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt as _, Limited};
use hyper::{body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpStream, task::JoinHandle, time::timeout};

/// Largest enclave response relayed; an attestation document is about 10 KiB of hex.
const RESPONSE_BYTES: usize = 1 << 20;

/// The enclave's HTTP service, through the TCP-to-vsock bridge. Each request has its own
/// connection, closed once its response has been read.
#[derive(Debug, Clone)]
pub struct Enclave {
    addr: SocketAddr,
    host: HeaderValue,
    connect_timeout: Duration,
}

pub(crate) struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An enclave response whose body is still being read, and the connection it arrives on.
pub struct Opened {
    pub response: Response<Incoming>,
    pub(crate) _connection: AbortOnDrop,
}

impl Enclave {
    pub fn new(addr: SocketAddr, connect_timeout: Duration) -> Self {
        let host = HeaderValue::from_str(&addr.to_string()).expect("a socket address is a header");
        Self {
            addr,
            host,
            connect_timeout,
        }
    }

    /// Sends `request` and returns the response as soon as its head has arrived, also while
    /// the request body is still being sent. Dropping it closes the connection, and with it the
    /// request body.
    pub async fn open<B>(&self, mut request: Request<B>) -> Result<Opened, String>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        request
            .headers_mut()
            .insert(header::HOST, self.host.clone());
        let stream = timeout(self.connect_timeout, TcpStream::connect(self.addr))
            .await
            .map_err(|_| "connecting to the enclave timed out".to_string())?
            .map_err(|error| format!("connecting to the enclave failed: {error}"))?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| format!("enclave handshake failed: {error}"))?;
        let connection = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| format!("enclave request failed: {error}"))?;
        Ok(Opened {
            response,
            _connection: connection,
        })
    }

    /// Sends `request` and reads the whole response, as [`Enclave::open`] does.
    pub async fn send<B>(&self, request: Request<B>) -> Result<Response<AxumBody>, String>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        relay(self.open(request).await?).await
    }
}

/// Reads an opened response whole, at most [`RESPONSE_BYTES`], keeping its status and type.
pub async fn relay(opened: Opened) -> Result<Response<AxumBody>, String> {
    let (parts, body) = opened.response.into_parts();
    let bytes = Limited::new(body, RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|error| format!("reading the enclave's response failed: {error}"))?
        .to_bytes();
    let mut relayed = Response::new(AxumBody::from(bytes));
    *relayed.status_mut() = parts.status;
    if let Some(content_type) = parts.headers.get(header::CONTENT_TYPE) {
        relayed
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type.clone());
    }
    Ok(relayed)
}
