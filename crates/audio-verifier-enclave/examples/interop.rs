//! Writes what `interop/` checks with Tink and `@mysten/seal` to `<out-dir>`:
//!
//! - `kat.bin`, `kat.json`: the Tink known answer of [`tink::KNOWN_ANSWER`];
//! - `response.json`, `ciphertext.bin`: `/measure` of `<flac>` for `<recording-id>`, with the
//!   image's pins;
//! - `test_response.json`, `test_ciphertext.bin`, `test_dek.hex`: the same with a key server key
//!   of this example's own, and the DEK it opens.
//!
//! `cargo run --release --example interop -- <out-dir> <flac> <recording-id>`

use std::{env, fs, path::PathBuf};

use audio_verifier_enclave::{
    Limits, MeasureResponse, Pins, app_with_pins, identity, master::MASTER_ASSOCIATED_DATA, tink,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use nautilus::{EnclaveIdentity, NautilusContext, testing::FakeAttestor};
use rand::{SeedableRng as _, rngs::StdRng};
use seal_crypto::{
    EncryptedObject, IBEPublicKeys, IBEUserSecretKeys, create_full_id, ibe, seal_decrypt,
};
use tower::ServiceExt as _;
use walrus_core::BlobId;

async fn measure(pins: Pins, flac: &[u8], recording_id: &str) -> (MeasureResponse, Vec<u8>) {
    let ctx = NautilusContext::with_signer(
        EnclaveIdentity::from_seed([9u8; 32]),
        FakeAttestor::default(),
    );
    let request = Request::builder()
        .method("POST")
        .uri(format!("/measure?recording_id={recording_id}"))
        .header(header::CONTENT_LENGTH, flac.len())
        .body(Body::from(flac.to_vec()))
        .expect("request");
    let response = app_with_pins(ctx, Limits::new(1), pins)
        .oneshot(request)
        .await
        .expect("response");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let newline = bytes
        .iter()
        .position(|&byte| byte == b'\n')
        .expect("measured");
    let body = serde_json::from_slice(&bytes[..newline]).expect("JSON");
    (body, bytes[newline + 1..].to_vec())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let [out, flac, recording_id] = &args[..] else {
        panic!("usage: interop <out-dir> <flac> <recording-id>");
    };
    let out = PathBuf::from(out);
    fs::create_dir_all(&out).expect("out dir");
    let flac = fs::read(flac).expect("flac");

    let (kat, ciphertext) = tink::known_answer();
    fs::write(out.join("kat.bin"), &ciphertext).expect("write");
    fs::write(
        out.join("kat.json"),
        serde_json::to_string_pretty(&kat).unwrap(),
    )
    .expect("write");

    let (body, ciphertext) = measure(Pins::pinned(), &flac, recording_id).await;
    fs::write(
        out.join("response.json"),
        serde_json::to_string_pretty(&body).unwrap(),
    )
    .expect("write");
    fs::write(out.join("ciphertext.bin"), &ciphertext).expect("write");

    let (master_key, pk) = ibe::generate_key_pair(&mut StdRng::seed_from_u64(5));
    let pins = Pins {
        key_server_pk: pk,
        ..Pins::pinned()
    };
    let (body, ciphertext) = measure(pins.clone(), &flac, recording_id).await;
    let sealed = hex::decode(&body.audio.data.sealed_dek).unwrap();
    let object: EncryptedObject = bcs::from_bytes(&sealed).unwrap();
    let recording: [u8; 32] = hex::decode(recording_id.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let blob_id: BlobId = body.audio.data.blob_id.parse().unwrap();
    let full_id = create_full_id(&pins.package.into_inner(), &identity(&recording, &blob_id));
    let keys = IBEUserSecretKeys::BonehFranklinBLS12381(
        [(pins.key_server, ibe::extract(&master_key, &full_id))].into(),
    );
    let public = IBEPublicKeys::BonehFranklinBLS12381(vec![pk]);
    let dek: [u8; 32] = seal_decrypt(&object, &keys, Some(&public))
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        tink::decrypt(&dek, MASTER_ASSOCIATED_DATA, &ciphertext).as_deref(),
        Some(&flac[..])
    );
    fs::write(
        out.join("test_response.json"),
        serde_json::to_string_pretty(&body).unwrap(),
    )
    .expect("write");
    fs::write(out.join("test_ciphertext.bin"), &ciphertext).expect("write");
    fs::write(out.join("test_dek.hex"), hex::encode(dek)).expect("write");
    println!("wrote {}", out.display());
}
