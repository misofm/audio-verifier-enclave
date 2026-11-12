mod decode;
mod error;
mod frame_header;
mod self_test;
mod stream;
mod streaminfo;

use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

pub use error::Error;
pub use self_test::self_test;
pub use streaminfo::StreamInfo;

/// Bit depths the enclave attests.
pub const SUPPORTED_BIT_DEPTHS: [u8; 3] = [8, 16, 24];

/// Sample rates the enclave attests: 44.1 and 48 kHz and their doublings.
pub const SUPPORTED_SAMPLE_RATES: [u32; 8] = [
    44_100, 48_000, 88_200, 96_000, 176_400, 192_000, 352_800, 384_000,
];

/// BCS mirror of the Move `audio_verifier::audio_verifier::AudioPayload`, field for field:
/// the facts of the decoded audio, signed under the audio intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioPayload {
    /// Channel count.
    pub channels: u8,
    /// Bits per sample.
    pub bit_depth: u8,
    /// Sample rate in hertz.
    pub sample_rate_hz: u32,
    /// Samples per channel.
    pub samples_per_channel: u64,
    /// BLAKE3 of the decoded PCM, interleaved by sample frame, each sample
    /// signed little-endian in `ceil(bit_depth / 8)` bytes.
    pub pcm_digest: Vec<u8>,
}

/// Most bytes of metadata blocks after STREAMINFO, their 4-byte headers included (64 KiB).
pub const MAX_EXTRA_METADATA_BYTES: u32 = 64 * 1024;

/// Most decoded PCM per file, all channels included (4 GiB), checked from STREAMINFO before
/// decoding: a small compressed file could otherwise expand to terabytes of hashing work.
pub const MAX_DECODED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// What [`measure_reader`] read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStats {
    /// Bytes of the file.
    pub len: u64,
    /// SHA-256 of the file's bytes.
    pub sha256: [u8; 32],
    /// The most input bytes the decoder held at once.
    pub peak_held: usize,
}

/// Measures a FLAC file into its Move-layout `AudioPayload`.
///
/// STREAMINFO must be the first metadata block. PADDING, SEEKTABLE and VORBIS_COMMENT blocks may
/// follow it, up to [`MAX_EXTRA_METADATA_BYTES`] in total, and are ignored: the facts describe
/// the decoded audio only, so tags never change them.
pub fn measure(bytes: &[u8]) -> Result<AudioPayload, Error> {
    let (info, _) = stream::read_head(&mut &*bytes)?;
    info.validate()?;
    let pcm_digest = decode::verify_and_digest(bytes, &info)?;
    Ok(payload(&info, pcm_digest))
}

/// Measures a FLAC file read front to back from `reader`, as [`measure`] does, holding only a
/// bounded window of it. Also returns the file's length and SHA-256.
pub fn measure_reader<R: Read>(reader: R) -> Result<(AudioPayload, FileStats), Error> {
    let mut reader = stream::Hashing::new(reader);
    let (info, head) = stream::read_head(&mut reader)?;
    info.validate()?;
    let input = Cursor::new(head).chain(&mut reader);
    let (pcm_digest, read) = decode::verify_and_digest_reader(input, &info)?;
    let (len, sha256) = reader.finish();
    debug_assert_eq!(len, read.len);
    let stats = FileStats {
        len,
        sha256,
        peak_held: read.peak_held,
    };
    Ok((payload(&info, pcm_digest), stats))
}

fn payload(info: &StreamInfo, pcm_digest: [u8; 32]) -> AudioPayload {
    AudioPayload {
        channels: info.channels,
        bit_depth: info.bit_depth,
        sample_rate_hz: info.sample_rate_hz,
        samples_per_channel: info.total_samples,
        pcm_digest: pcm_digest.to_vec(),
    }
}
