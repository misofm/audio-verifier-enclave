//! `vectors/*.json`: fixed payloads, their BCS, intent messages and signatures from the seed
//! `[7; 32]`, as the route signs them. The Move tests check the audio vector: its payload is
//! the one of `audio_verifier`'s own `vectors.json`, and so are its BCS and signatures.

use std::path::Path;

use audio_verifier::{AudioFacts, FileStats};
use audio_verifier_enclave::{
    AUDIO_INTENT, AudioJson, AudioPayload, FileJson, MASTER_FILE_INTENT, MasterFilePayload,
    sign_measurement,
};
use nautilus::{
    EnclaveIdentity, Intent, NautilusContext, Timestamp, intent_message, testing::FakeAttestor,
};
use serde::Serialize;

const TIMESTAMP_MS: u64 = 1_750_000_000_000;

#[derive(Serialize)]
struct Vector<T> {
    intent: u8,
    timestamp_ms: u64,
    fields: T,
    payload_bcs_hex: String,
    intent_message_hex: String,
    public_key: String,
    signature: String,
    /// The same payload signed under another intent, which a verifier must reject.
    other_intent_signature: String,
}

/// A `MasterFilePayload` as JSON: the audio facts as in `audio_intent.json`, and the file's
/// size and SHA-256 as in the `/measure` response's `master_file`.
#[derive(Serialize)]
struct MasterFileFields {
    audio: AudioJson,
    #[serde(flatten)]
    file: FileJson,
}

fn vector<P: Serialize + Clone, T>(
    ctx: &NautilusContext,
    intent: Intent,
    other_intent: Intent,
    payload: &P,
    fields: T,
) -> Vector<T> {
    let sign = |intent| {
        let signed = ctx.sign_intent_at(intent, TIMESTAMP_MS, payload.clone());
        signed.expect("sign").signature
    };
    let message = intent_message(intent, TIMESTAMP_MS, payload).expect("BCS");
    Vector {
        intent: intent.0,
        timestamp_ms: TIMESTAMP_MS,
        fields,
        payload_bcs_hex: hex::encode(bcs::to_bytes(payload).expect("BCS")),
        intent_message_hex: hex::encode(message),
        public_key: ctx.public_key_hex(),
        signature: sign(intent),
        other_intent_signature: sign(other_intent),
    }
}

/// Fails, after regenerating it for review, if `vectors/{name}` is not `vector`.
fn assert_committed<T: Serialize>(name: &str, vector: &Vector<T>) {
    let rendered = serde_json::to_string_pretty(vector).expect("JSON") + "\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    if std::fs::read_to_string(&path).ok().as_deref() != Some(rendered.as_str()) {
        std::fs::write(&path, &rendered).expect("write vector");
        panic!("vectors/{name} was stale and has been regenerated; review and commit it");
    }
}

#[test]
fn the_route_signs_the_committed_vectors() {
    let ctx = NautilusContext::with_signer(
        EnclaveIdentity::from_seed([7u8; 32]),
        FakeAttestor::default(),
    );
    let facts = AudioFacts {
        channels: 2,
        bit_depth: 24,
        sample_rate_hz: 48_000,
        samples_per_channel: 480_000,
        pcm_digest: vec![0x11; 32],
        channel_layout: vec![0, 1],
    };
    let blob_id: [u8; 32] = std::array::from_fn(|index| 31 - index as u8);
    let audio = AudioPayload::new(facts, blob_id, vec![0x5e; 40]);
    let file = FileStats {
        len: 285_050_717,
        sha256: [0x22; 32],
        peak_held: 0,
    };
    let master_file = MasterFilePayload {
        audio: audio.clone(),
        file_size: file.len,
        file_sha256: file.sha256.to_vec(),
    };
    let timestamp = Timestamp::from_ms(TIMESTAMP_MS);
    let signed =
        sign_measurement(&ctx, timestamp, audio.clone(), &file, 285_053_469).expect("sign");

    let audio_vector = vector(&ctx, AUDIO_INTENT, Intent(1), &audio, signed.audio.data);
    // The Move package's vectors.json, for the same payload.
    assert_eq!(
        audio_vector.payload_bcs_hex,
        "021880bb00000053070000000000201111111111111111111111111111111111111111111111111111111111\
         1111110200011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100285e5e5e5e5e\
         5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
    );
    assert_eq!(
        audio_vector.signature,
        "b8f38b09320690b6fa3e9fdd2a2f95b4820a7a54932a453f152d74dd4f5241b65a09f597dbc950886ff4fab8\
         20a2121fff83fa9deb8d85af832dce613526c407"
    );
    assert_eq!(
        audio_vector.other_intent_signature,
        "36ced283d9b9e97886d8b5f23c17c0232cd4818ac3d9afed81ab6fe5f4e6269edc95f38256e0cec037b0a952\
         bf7d2e7b3cdb4b2ff13f03431b40ca2578a83007"
    );
    assert_eq!(
        audio_vector.fields.blob_id,
        "Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA"
    );
    assert_eq!(signed.audio.intent, audio_vector.intent);
    assert_eq!(signed.audio.timestamp_ms, TIMESTAMP_MS);
    assert_eq!(signed.audio.signature, audio_vector.signature);
    assert_committed("audio_intent.json", &audio_vector);

    let fields = MasterFileFields {
        audio: audio_vector.fields,
        file: signed.master_file.data,
    };
    let master_vector = vector(&ctx, MASTER_FILE_INTENT, AUDIO_INTENT, &master_file, fields);
    assert_eq!(signed.master_file.intent, master_vector.intent);
    assert_eq!(signed.master_file.timestamp_ms, TIMESTAMP_MS);
    assert_eq!(signed.master_file.signature, master_vector.signature);
    assert_committed("master_file_intent.json", &master_vector);
}
