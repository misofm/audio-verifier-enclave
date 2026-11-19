mod decode;
mod error;
mod frame_header;
mod layout;
mod self_test;
mod stream;
mod streaminfo;

use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

pub use error::Error;
pub use layout::{
    CHANNEL_MASK_FIELD, MAX_SPEAKER, UNASSIGNED, channel_layout, default_layout, masked_layout,
};
pub use self_test::self_test;

use streaminfo::StreamInfo;

/// Bit depths the enclave attests.
pub const SUPPORTED_BIT_DEPTHS: [u8; 3] = [8, 16, 24];

/// Sample rates the enclave attests: 44.1 and 48 kHz and their doublings.
pub const SUPPORTED_SAMPLE_RATES: [u32; 8] = [
    44_100, 48_000, 88_200, 96_000, 176_400, 192_000, 352_800, 384_000,
];

/// The facts of the decoded audio: the first fields of the Move
/// `audio_verifier::audio_verifier::AudioFacts`, in its order, and the channel layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioFacts {
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
    /// One speaker position per channel, in channel order: the FLAC default for the channel
    /// count, or the one a `WAVEFORMATEXTENSIBLE_CHANNEL_MASK` Vorbis comment sets.
    pub channel_layout: Vec<u8>,
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
    /// BLAKE3 of the file's bytes.
    pub blake3: [u8; 32],
    /// The most input bytes the decoder held at once.
    pub peak_held: usize,
}

/// Measures a FLAC file read front to back from `reader` into its [`AudioFacts`], holding only a
/// bounded window of it, and returns the file's length and BLAKE3 with them.
///
/// STREAMINFO must be the first metadata block. PADDING, SEEKTABLE and VORBIS_COMMENT blocks may
/// follow it, up to [`MAX_EXTRA_METADATA_BYTES`] in total. Of them only the
/// `WAVEFORMATEXTENSIBLE_CHANNEL_MASK` field of a VORBIS_COMMENT changes the facts, through the
/// channel layout: other tags never do.
pub fn measure_reader<R: Read>(reader: R) -> Result<(AudioFacts, FileStats), Error> {
    let mut reader = stream::Hashing::new(reader);
    let stream::Head {
        info,
        bytes: head,
        channel_mask,
    } = stream::read_head(&mut reader)?;
    info.validate()?;
    let channel_layout = channel_layout(info.channels, channel_mask)?;
    let input = Cursor::new(head).chain(&mut reader);
    let (pcm_digest, summary) = decode::verify_and_digest(input, &info)?;
    let (len, blake3) = reader.finish();
    debug_assert_eq!(len, summary.len);
    let audio = AudioFacts {
        channels: info.channels,
        bit_depth: info.bit_depth,
        sample_rate_hz: info.sample_rate_hz,
        samples_per_channel: info.total_samples,
        pcm_digest: pcm_digest.to_vec(),
        channel_layout,
    };
    let stats = FileStats {
        len,
        blake3,
        peak_held: summary.peak_held,
    };
    Ok((audio, stats))
}

/// [`measure_reader`] over a file in memory, for its audio facts.
pub fn measure(bytes: &[u8]) -> Result<AudioFacts, Error> {
    measure_reader(bytes).map(|(audio, _)| audio)
}
