//! The encrypted master: the file under a fresh DEK ([`crate::tink`]), the Walrus blob ID of
//! that ciphertext, and the DEK Seal-encrypted under `recording_master_seal` to the identity of
//! the recording and the blob. Every network parameter is pinned here, so it is part of the
//! image and its PCRs.

use std::num::NonZeroU16;

use fastcrypto::{groups::bls12381::G2Element, serde_helpers::ToFromByteArray as _};
use seal_crypto::{EncryptionInput, IBEPublicKeys, ObjectID, seal_encrypt};
use walrus_core::{
    BlobId, DEFAULT_ENCODING, EncodingType,
    encoding::{EncodingConfig, EncodingFactory as _},
};

use crate::tink::KEY_BYTES;

/// The `recording_master_seal` package on testnet whose `seal_approve` guards every DEK: its
/// original package ID, the namespace of every Seal identity.
pub const RECORDING_MASTER_SEAL_PACKAGE: &str =
    "0xf2452914718b6f8d3cadef6e04d390fb66b496e7e5095de67b254eecbd77b6fb";

/// Walrus testnet's shard count, from the system object
/// `0x6c2547cbbc38025cf3adac45f63cb0a8d12ecf777cdc75a4971612bf97fdf6af` (epoch 585,
/// November 2026).
pub const WALRUS_N_SHARDS: NonZeroU16 = NonZeroU16::new(1000).unwrap();

/// Walrus's encoding type, RedStuff over Reed-Solomon, walrus-core's `DEFAULT_ENCODING`.
pub const WALRUS_ENCODING: EncodingType = EncodingType::RS2;

/// Seal's decentralized testnet key server: one `KeyServer` object whose key a 3-of-5
/// committee holds in shares, so a threshold of 1 asks it once.
pub const SEAL_KEY_SERVER: &str =
    "0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98";

/// That key server's BLS12-381 G2 public key, `KeyServerV2.pk` (version 2).
pub const SEAL_KEY_SERVER_PK: &str = "b8068e916e76791ec188624be83cabe2563719ed991a9732e54e8a04\
    271037bc5f3b35356b2f9e22b3f5aa84856800f219bc7472422ffcaced0c921f43b4f192662deb294c0639dbf0\
    e2d00ade5483bcae7c70b25f9c8a1d3d21130ce441febe";

/// Key servers that must answer for the DEK.
pub const SEAL_THRESHOLD: u8 = 1;

/// The associated data of every master's ciphertext: none. The DEK encrypts one file only, and
/// the blob ID, the natural binding, is a hash of the ciphertext itself.
pub const MASTER_ASSOCIATED_DATA: &[u8] = b"";

/// The pinned parameters, parsed.
#[derive(Debug, Clone)]
pub struct Pins {
    /// The Seal policy package.
    pub package: ObjectID,
    /// The Seal key server.
    pub key_server: ObjectID,
    /// Its public key.
    pub key_server_pk: G2Element,
    /// The Walrus encoding.
    pub walrus: EncodingConfig,
}

fn object_id(hex_id: &str) -> ObjectID {
    let bytes = hex::decode(hex_id.trim_start_matches("0x")).expect("a pinned ID is hex");
    ObjectID::new(bytes.try_into().expect("a pinned ID is 32 bytes"))
}

impl Pins {
    /// The image's pins.
    pub fn pinned() -> Self {
        Self::with_package(RECORDING_MASTER_SEAL_PACKAGE)
    }

    /// The image's pins, with another policy package, for tests.
    pub fn with_package(package: &str) -> Self {
        let pk: [u8; 96] = hex::decode(SEAL_KEY_SERVER_PK)
            .expect("the pinned key is hex")
            .try_into()
            .expect("the pinned key is 96 bytes");
        Self {
            package: object_id(package),
            key_server: object_id(SEAL_KEY_SERVER),
            key_server_pk: G2Element::from_byte_array(&pk).expect("the pinned key is on G2"),
            walrus: EncodingConfig::new(WALRUS_N_SHARDS),
        }
    }

    /// The Walrus blob ID of `blob` at the pinned shard count and encoding.
    pub fn blob_id(&self, blob: &[u8]) -> Result<BlobId, String> {
        debug_assert_eq!(WALRUS_ENCODING, DEFAULT_ENCODING);
        self.walrus
            .get_for_type(WALRUS_ENCODING)
            .compute_blob_id(blob)
            .map_err(|error| error.to_string())
    }

    /// Seal-encrypts `dek` under the policy package, for the key server at the threshold, to
    /// the identity [`identity`] of `recording_id` and `blob_id`: the `EncryptedObject`'s BCS.
    /// The DEK is the AES-256-GCM plaintext with empty associated data, as `@mysten/seal`'s
    /// `encrypt` does by default.
    pub fn seal_dek(
        &self,
        recording_id: &[u8; 32],
        blob_id: &BlobId,
        dek: &[u8; KEY_BYTES],
    ) -> Result<Vec<u8>, String> {
        let (object, _) = seal_encrypt(
            self.package,
            identity(recording_id, blob_id).to_vec(),
            vec![self.key_server],
            &IBEPublicKeys::BonehFranklinBLS12381(vec![self.key_server_pk]),
            SEAL_THRESHOLD,
            EncryptionInput::Aes256Gcm {
                data: dek.to_vec(),
                aad: Some(Vec::new()),
            },
        )
        .map_err(|error| format!("Seal encryption failed: {error}"))?;
        bcs::to_bytes(&object).map_err(|error| error.to_string())
    }
}

/// The Seal identity of a master after the package ID, as `recording_master_seal` checks it:
/// `bcs(recording_id: address) ‖ bcs(blob_id: u256)`, the recording's 32 object ID bytes, then
/// the blob ID's 32 bytes, which are Walrus's own and the little-endian `u256`.
pub fn identity(recording_id: &[u8; 32], blob_id: &BlobId) -> [u8; 64] {
    let mut id = [0; 64];
    id[..32].copy_from_slice(recording_id);
    id[32..].copy_from_slice(&blob_id.0);
    id
}

/// Formats 32 little-endian bytes as a decimal `u256`.
pub fn u256_le_decimal(bytes: &[u8; 32]) -> String {
    let mut limbs: Vec<u8> = bytes.iter().rev().copied().collect();
    let mut digits = Vec::new();
    while limbs.iter().any(|limb| *limb != 0) {
        let mut remainder = 0u16;
        for limb in &mut limbs {
            let value = (remainder << 8) | u16::from(*limb);
            *limb = (value / 10) as u8;
            remainder = value % 10;
        }
        digits.push(b'0' + remainder as u8);
    }
    if digits.is_empty() {
        digits.push(b'0');
    }
    digits.reverse();
    String::from_utf8(digits).expect("ASCII digits")
}

/// Blob IDs at 1,000 shards that the `walrus blob-id --n-shards 1000` CLI printed for three
/// fixtures, committed with this repository's first Walrus encoder.
pub const KNOWN_BLOB_IDS: [(&str, &[u8], &str); 3] = [
    (
        "s16_stereo_44100.flac",
        include_bytes!("../../audio-verifier/tests/fixtures/s16_stereo_44100.flac"),
        "L7_e5aB1GgkP_trnaMES1iktg_BBrF09OMa6_oemifM",
    ),
    (
        "s24_stereo_48000.flac",
        include_bytes!("../../audio-verifier/tests/fixtures/s24_stereo_48000.flac"),
        "7UuQqm0upnQTTclUgYdJwxw2APcE3L8uJuZO1QahDgM",
    ),
    (
        "s16_mono_96000.flac",
        include_bytes!("../../audio-verifier/tests/fixtures/s16_mono_96000.flac"),
        "zxBXsxzcZCNnKrU5nvFnrgqZX1k2zrw5kBktCPsel-0",
    ),
];

#[cfg(test)]
mod tests {
    use seal_crypto::{
        Ciphertext, EncryptedObject, IBEEncryptions, IBEUserSecretKeys, create_full_id, ibe,
        seal_decrypt,
    };

    use super::*;

    #[test]
    fn blob_ids_match_the_walrus_cli() {
        let pins = Pins::pinned();
        for (name, bytes, expected) in KNOWN_BLOB_IDS {
            assert_eq!(
                pins.blob_id(bytes).expect(name).to_string(),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn a_sealed_dek_opens_with_the_identitys_key() {
        let (master_key, pk) = ibe::generate_key_pair(&mut rand::thread_rng());
        let pins = Pins {
            key_server_pk: pk,
            ..Pins::with_package(SEAL_KEY_SERVER)
        };
        let blob_id = BlobId([0x5a; 32]);
        let dek = [9u8; 32];
        let sealed = pins.seal_dek(&[0x77; 32], &blob_id, &dek).expect("seal");
        let object: EncryptedObject = bcs::from_bytes(&sealed).expect("BCS");
        let full_id = create_full_id(&pins.package.into_inner(), &identity(&[0x77; 32], &blob_id));
        let keys = |id: &[u8]| {
            IBEUserSecretKeys::BonehFranklinBLS12381(
                [(pins.key_server, ibe::extract(&master_key, id))].into(),
            )
        };
        let public = IBEPublicKeys::BonehFranklinBLS12381(vec![pk]);
        assert_eq!(
            seal_decrypt(&object, &keys(&full_id), Some(&public)).expect("opens"),
            dek
        );
        // Neither the blob alone nor another recording's identity opens it.
        for other in [blob_id.0.to_vec(), identity(&[0x78; 32], &blob_id).to_vec()] {
            let other = create_full_id(&pins.package.into_inner(), &other);
            assert!(seal_decrypt(&object, &keys(&other), Some(&public)).is_err());
        }
    }

    #[test]
    fn u256_decimal_matches_known_values() {
        assert_eq!(u256_le_decimal(&[0; 32]), "0");
        let mut one = [0; 32];
        one[0] = 1;
        assert_eq!(u256_le_decimal(&one), "1");
        let mut word = [0; 32];
        word[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(u256_le_decimal(&word), u64::MAX.to_string());
        assert_eq!(
            u256_le_decimal(&[0xff; 32]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        let mut high = [0; 32];
        high[31] = 1;
        assert_eq!(
            u256_le_decimal(&high),
            "452312848583266388373324160190187140051835877600158453279131187530910662656"
        );
    }

    #[test]
    fn the_pins_parse() {
        let pins = Pins::pinned();
        assert_eq!(pins.package, object_id(RECORDING_MASTER_SEAL_PACKAGE));
        assert_eq!(pins.walrus.n_shards(), WALRUS_N_SHARDS);
        assert_eq!(WALRUS_ENCODING, DEFAULT_ENCODING);
    }

    /// `seal_identity` of the Move package's `vectors.json`.
    #[test]
    fn the_identity_is_the_recording_then_the_blob() {
        let blob_id: BlobId = "Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA"
            .parse()
            .expect("blob ID");
        assert_eq!(
            hex::encode(identity(&[0xc0; 32], &blob_id)),
            "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0\
             1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        );
    }

    #[test]
    fn the_sealed_dek_names_the_package_identity_server_and_threshold() {
        let package = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let pins = Pins::with_package(package);
        let blob_id = BlobId([0xab; 32]);
        let bytes = pins
            .seal_dek(&[0xcd; 32], &blob_id, &[5; 32])
            .expect("seal");
        let object: EncryptedObject = bcs::from_bytes(&bytes).expect("EncryptedObject");
        assert_eq!(object.version, 0);
        assert_eq!(object.package_id, object_id(package));
        assert_eq!(object.id, [[0xcd; 32], [0xab; 32]].concat());
        assert_eq!(object.services, vec![(object_id(SEAL_KEY_SERVER), 1)]);
        assert_eq!(object.threshold, 1);
        let IBEEncryptions::BonehFranklinBLS12381 {
            encrypted_shares, ..
        } = &object.encrypted_shares;
        assert_eq!(encrypted_shares.len(), 1);
        let Ciphertext::Aes256Gcm { blob, aad } = &object.ciphertext else {
            panic!("AES-256-GCM DEM");
        };
        assert_eq!(blob.len(), 32 + 16);
        assert_eq!(aad.as_deref(), Some(&[][..]));
        assert_ne!(
            pins.seal_dek(&[0xcd; 32], &blob_id, &[5; 32])
                .expect("seal"),
            bytes
        );
    }
}
