//! The service on TCP `127.0.0.1:3000` with a fixed test identity and a fake attestor, for local
//! runs of the gateway: `cargo run --release --example dev_server`. Its signatures verify with
//! no registered enclave, so never expose it. The image's pins are used unchanged.

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr},
};

use audio_verifier_enclave::{Limits, app};
use nautilus::{EnclaveIdentity, NautilusContext, ServerConfig, testing::FakeAttestor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ctx = NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    );
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 3000));
    println!(
        "[dev] public key {}; listening on {addr}",
        ctx.public_key_hex()
    );
    nautilus::serve(addr, app(ctx, Limits::new(2)), ServerConfig::default()).await?;
    Ok(())
}
