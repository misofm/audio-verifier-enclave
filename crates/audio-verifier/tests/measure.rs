mod common;

use std::io::{self, Read};

use audio_verifier::{AudioFacts, Error, FileStats, MAX_EXTRA_METADATA_BYTES, measure_reader};
use common::{
    FrameEdit, FrameHeader, Rate, Synth, block_sizes, decoded_samples, ffmpeg_raw_pcm, fixture,
    frame_sizes, has_ffmpeg, scratch_file, set_block_sizes, set_frame_sizes, set_md5,
    set_streaminfo, utf8_number,
};
use sha2::{Digest as _, Sha256};

/// Hands out at most `chunk` bytes per read, as a network body does.
struct Chunked<'a> {
    bytes: &'a [u8],
    at: usize,
    chunk: usize,
}

impl<'a> Chunked<'a> {
    fn new(bytes: &'a [u8], chunk: usize) -> Self {
        Self {
            bytes,
            at: 0,
            chunk,
        }
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer.len().min(self.chunk).min(self.bytes.len() - self.at);
        buffer[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

/// Chunk sizes every case of this suite is also read in: one byte, an odd size, a page and the
/// decoder's release threshold.
const CHUNKS: [usize; 4] = [1, 7, 4096, 1 << 20];

fn measure_streamed(bytes: &[u8], chunk: usize) -> Result<(AudioFacts, FileStats), Error> {
    measure_reader(Chunked::new(bytes, chunk))
}

/// Measures `bytes` read whole, and requires the same verdict, error included, when they are
/// read in each of `CHUNKS`, and on success the file's length and SHA-256.
fn measure(bytes: &[u8]) -> Result<AudioFacts, Error> {
    let result = measure_reader(bytes).map(|(audio, stats)| {
        assert_eq!(stats.len, bytes.len() as u64);
        assert_eq!(stats.sha256, <[u8; 32]>::from(Sha256::digest(bytes)));
        audio
    });
    for chunk in CHUNKS {
        let chunked = measure_streamed(bytes, chunk).map(|(audio, _)| audio);
        assert_eq!(chunked, result, "read in chunks of {chunk} bytes");
    }
    result
}

struct Expected {
    name: &'static str,
    channels: u8,
    bit_depth: u8,
    sample_rate_hz: u32,
    samples_per_channel: u64,
}

const POSITIVE: [Expected; 3] = [
    Expected {
        name: "s16_stereo_44100",
        channels: 2,
        bit_depth: 16,
        sample_rate_hz: 44_100,
        samples_per_channel: 11_025,
    },
    Expected {
        name: "s24_stereo_48000",
        channels: 2,
        bit_depth: 24,
        sample_rate_hz: 48_000,
        samples_per_channel: 12_000,
    },
    Expected {
        name: "s16_mono_96000",
        channels: 1,
        bit_depth: 16,
        sample_rate_hz: 96_000,
        samples_per_channel: 24_000,
    },
];

const ENCODER_OUTPUT: [Expected; 5] = [
    Expected {
        name: "s16_stereo_44100_short",
        channels: 2,
        bit_depth: 16,
        sample_rate_hz: 44_100,
        samples_per_channel: 2_205,
    },
    Expected {
        name: "libflac_s16_stereo_44100",
        channels: 2,
        bit_depth: 16,
        sample_rate_hz: 44_100,
        samples_per_channel: 11_025,
    },
    Expected {
        name: "libflac_s24_stereo_96000",
        channels: 2,
        bit_depth: 24,
        sample_rate_hz: 96_000,
        samples_per_channel: 9_600,
    },
    Expected {
        name: "libflac_s16_mono_48000_short",
        channels: 1,
        bit_depth: 16,
        sample_rate_hz: 48_000,
        samples_per_channel: 10,
    },
    Expected {
        name: "s16_mono_44100",
        channels: 1,
        bit_depth: 16,
        sample_rate_hz: 44_100,
        samples_per_channel: 8_820,
    },
];

const VARIABLE_BLOCKS: [usize; 4] = [1_024, 2_048, 512, 300];

fn flac_name(name: &str) -> String {
    format!("{name}.flac")
}

fn assert_properties(
    audio: &AudioFacts,
    channels: u8,
    bit_depth: u8,
    rate: u32,
    samples_per_channel: u64,
) {
    assert_eq!(audio.channels, channels);
    assert_eq!(audio.bit_depth, bit_depth);
    assert_eq!(audio.sample_rate_hz, rate);
    assert_eq!(audio.samples_per_channel, samples_per_channel);
    assert_eq!(audio.pcm_digest.len(), 32);
}

fn assert_matches_ffmpeg(bytes: &[u8], audio: &AudioFacts, scratch_name: &str) {
    if !has_ffmpeg() {
        eprintln!("ffmpeg unavailable, skipping PCM cross-check for {scratch_name}");
        return;
    }
    let path = scratch_file(scratch_name, bytes);
    let raw = ffmpeg_raw_pcm(&path, audio.bit_depth);
    let frame_bytes = u64::from(audio.channels) * u64::from(audio.bit_depth.div_ceil(8));
    assert_eq!(raw.len() as u64, audio.samples_per_channel * frame_bytes);
    assert_eq!(audio.pcm_digest, blake3::hash(&raw).as_bytes().to_vec());
}

fn rejects(bytes: &[u8]) -> Error {
    measure(bytes).expect_err("must be rejected")
}

#[test]
fn synthesized_8_bit_stereo_and_24_bit_mono_are_measured() {
    for (channels, bit_depth, rate, name) in [
        (2, 8, 44_100, "s8_stereo_44100.flac"),
        (1, 24, 192_000, "s24_mono_192000.flac"),
    ] {
        let bytes = Synth::new(channels, bit_depth, rate).build();
        let audio = measure(&bytes).expect(name);
        assert_properties(&audio, channels, bit_depth, rate, 2_500);
        assert_matches_ffmpeg(&bytes, &audio, name);
    }
}

#[test]
fn frame_rate_encodings_equal_to_streaminfo_are_accepted() {
    for rate in [
        Rate::FromStreamInfo,
        Rate::Khz(48),
        Rate::Hz(48_000),
        Rate::TensOfHz(4_800),
    ] {
        let bytes = Synth::new(2, 16, 48_000)
            .with_header(FrameHeader {
                channels: 2,
                bit_depth: 16,
                rate,
            })
            .build();
        let audio = measure(&bytes).unwrap_or_else(|error| panic!("{rate:?}: {error}"));
        assert_eq!(audio.sample_rate_hz, 48_000);
    }
}

/// `canonical` with `blocks` of `(type, body)` inserted after STREAMINFO.
fn with_metadata(canonical: &[u8], blocks: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = canonical[..42].to_vec();
    out[4] &= 0x7f;
    for (index, (block_type, body)) in blocks.iter().enumerate() {
        let last = if index + 1 == blocks.len() { 0x80 } else { 0 };
        out.push(block_type | last);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
    }
    out.extend_from_slice(&canonical[42..]);
    out
}

/// What `@misofm/codec` and libFLAC write: libFLAC's vendor string and no comments.
fn codec_comment() -> Vec<u8> {
    let vendor = b"reference libFLAC 1.5.0 20250211";
    let mut body = (vendor.len() as u32).to_le_bytes().to_vec();
    body.extend_from_slice(vendor);
    body.extend_from_slice(&0u32.to_le_bytes());
    body
}

fn tagged_comment() -> Vec<u8> {
    let mut body = codec_comment();
    body.truncate(body.len() - 4);
    let comments = [&b"TITLE=Pink noise"[..], b"ARTIST=Nobody"];
    body.extend_from_slice(&(comments.len() as u32).to_le_bytes());
    for comment in comments {
        body.extend_from_slice(&(comment.len() as u32).to_le_bytes());
        body.extend_from_slice(comment);
    }
    body
}

/// Seek points at the first `count` frames: sample number, byte offset, samples.
fn seektable(count: u64) -> Vec<u8> {
    let mut body = Vec::new();
    for point in 0..count {
        body.extend_from_slice(&(point * 1_024).to_be_bytes());
        body.extend_from_slice(&0u64.to_be_bytes());
        body.extend_from_slice(&1_024u16.to_be_bytes());
    }
    body
}

const PADDING: u8 = 1;
const APPLICATION: u8 = 2;
const SEEKTABLE: u8 = 3;
const VORBIS_COMMENT: u8 = 4;
const CUESHEET: u8 = 5;
const PICTURE: u8 = 6;

#[test]
fn tags_padding_and_seektables_do_not_change_the_audio() {
    for name in ["s16_stereo_44100.flac", "libflac_s24_stereo_96000.flac"] {
        let canonical = fixture(name);
        let expected = measure(&canonical).expect("canonical");
        for blocks in [
            vec![(VORBIS_COMMENT, codec_comment())],
            vec![(VORBIS_COMMENT, tagged_comment())],
            vec![(VORBIS_COMMENT, vec![0; 8])],
            vec![(PADDING, vec![0; 4])],
            vec![(PADDING, Vec::new())],
            vec![(SEEKTABLE, seektable(3))],
            vec![
                (SEEKTABLE, seektable(2)),
                (VORBIS_COMMENT, codec_comment()),
                (PADDING, vec![0; 8_192]),
            ],
        ] {
            let tagged = with_metadata(&canonical, &blocks);
            assert_eq!(measure(&tagged), Ok(expected.clone()), "{name}: {blocks:?}");
        }
    }
}

/// `bytes` with every metadata block after STREAMINFO removed.
fn strip_metadata(bytes: &[u8]) -> Vec<u8> {
    let mut offset = 4;
    loop {
        let header = bytes[offset];
        let length =
            u32::from_be_bytes([0, bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
        offset += 4 + length as usize;
        if header & 0x80 != 0 {
            break;
        }
    }
    let mut out = bytes[..42].to_vec();
    out[4] |= 0x80;
    out.extend_from_slice(&bytes[offset..]);
    out
}

#[test]
fn ffmpeg_output_with_its_tags_is_measured_as_without_them() {
    if !has_ffmpeg() {
        eprintln!("ffmpeg unavailable, skipping the tagged ffmpeg file");
        return;
    }
    let path = scratch_file("tagged.flac", &[]);
    let status = std::process::Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
        ])
        .arg("aevalsrc=0.5*sin(2*PI*440*t)|0.4*sin(2*PI*660*t):s=48000:d=0.25")
        .args([
            "-metadata",
            "title=Two tones",
            "-c:a",
            "flac",
            "-sample_fmt",
            "s16",
        ])
        .arg(&path)
        .status()
        .expect("ffmpeg");
    assert!(status.success());
    let tagged = std::fs::read(&path).expect("ffmpeg output");
    assert_eq!(
        tagged[4] & 0x80,
        0,
        "ffmpeg wrote metadata after STREAMINFO"
    );
    let expected = measure(&strip_metadata(&tagged)).expect("stripped");
    assert_eq!(measure(&tagged), Ok(expected));
}

#[test]
fn metadata_may_fill_its_limit_but_not_exceed_it() {
    let canonical = fixture("s16_stereo_44100.flac");
    let expected = measure(&canonical).expect("canonical");
    let limit = MAX_EXTRA_METADATA_BYTES as usize;
    let full = with_metadata(&canonical, &[(PADDING, vec![0; limit - 4])]);
    assert_eq!(measure(&full), Ok(expected.clone()));
    let comment = codec_comment();
    let padding = limit - 8 - comment.len();
    let split = with_metadata(
        &canonical,
        &[(VORBIS_COMMENT, comment), (PADDING, vec![0; padding])],
    );
    assert_eq!(measure(&split), Ok(expected));
    let over = with_metadata(&canonical, &[(PADDING, vec![0; limit - 3])]);
    assert_eq!(rejects(&over), Error::MetadataTooLong);
    let many = with_metadata(&canonical, &vec![(PADDING, vec![0; 1_020]); 65]);
    assert_eq!(rejects(&many), Error::MetadataTooLong);
    // The declared length is checked before the block is read.
    let mut huge = canonical[..42].to_vec();
    huge[4] &= 0x7f;
    huge.extend_from_slice(&[0x81, 0xff, 0xff, 0xff]);
    assert_eq!(rejects(&huge), Error::MetadataTooLong);
    assert!(
        Error::MetadataTooLong
            .to_string()
            .contains(&limit.to_string())
    );
}

#[test]
fn rejects_other_metadata_after_streaminfo() {
    let canonical = fixture("s16_stereo_44100.flac");
    for block_type in [0, APPLICATION, CUESHEET, PICTURE, 7, 126, 127] {
        let bytes = with_metadata(&canonical, &[(block_type, vec![0; 64])]);
        assert_eq!(rejects(&bytes), Error::MetadataBlock(block_type));
        let after_tags = with_metadata(
            &canonical,
            &[(VORBIS_COMMENT, codec_comment()), (block_type, vec![0; 64])],
        );
        assert_eq!(rejects(&after_tags), Error::MetadataBlock(block_type));
    }
    assert!(
        Error::MetadataBlock(PICTURE)
            .to_string()
            .contains("only PADDING, SEEKTABLE and VORBIS_COMMENT")
    );
}

#[test]
fn rejects_malformed_or_truncated_metadata() {
    let canonical = fixture("s16_stereo_44100.flac");
    // A seek table that is not a whole number of 18-byte points.
    let seektable = with_metadata(&canonical, &[(SEEKTABLE, vec![0; 17])]);
    assert_eq!(rejects(&seektable), Error::SeekTableLength(17));
    // The last-block flag is clear, but no block follows: the first frame's sync code is read
    // as a block header of type 127.
    let mut unflagged = canonical.clone();
    unflagged[4] &= 0x7f;
    assert_eq!(rejects(&unflagged), Error::MetadataBlock(127));
    let tagged = with_metadata(&canonical, &[(VORBIS_COMMENT, codec_comment())]);
    let end = 42 + 4 + codec_comment().len();
    for len in [43, 45, 46, 60, end - 1] {
        assert_eq!(
            rejects(&tagged[..len]),
            Error::TooShort(len),
            "length {len}"
        );
    }
}

#[test]
fn rejects_wrong_first_block() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    bytes[4] = 0x00;
    bytes.splice(4..4, [0x01, 0, 0, 4, 0, 0, 0, 0]);
    assert_eq!(rejects(&bytes), Error::WrongFirstBlock(1));
}

#[test]
fn rejects_wrong_streaminfo_length() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    bytes[7] = 33;
    assert_eq!(rejects(&bytes), Error::StreamInfoLength(33));
    bytes[7] = 35;
    assert_eq!(rejects(&bytes), Error::StreamInfoLength(35));
}

#[test]
fn rejects_zero_md5() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    set_md5(&mut bytes, [0; 16]);
    assert_eq!(rejects(&bytes), Error::ZeroMd5);
}

#[test]
fn rejects_md5_mismatch() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    bytes[30] ^= 0x01;
    assert!(matches!(rejects(&bytes), Error::Md5Mismatch { .. }));
}

#[test]
fn rejects_zero_total_samples() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    set_streaminfo(&mut bytes, 44_100, 2, 16, 0);
    assert_eq!(rejects(&bytes), Error::ZeroTotalSamples);
}

#[test]
fn rejects_total_samples_mismatch() {
    for total in [11_024, 11_026, 22_050] {
        let mut bytes = fixture("s16_stereo_44100.flac");
        set_streaminfo(&mut bytes, 44_100, 2, 16, total);
        assert_eq!(
            rejects(&bytes),
            Error::SampleCount {
                expected: total,
                decoded: 11_025
            }
        );
    }
}

#[test]
fn rejects_unsupported_bit_depths() {
    assert_eq!(
        rejects(&fixture("s32_stereo_48000.flac")),
        Error::UnsupportedBitDepth(32)
    );
    let mut bytes = fixture("s16_stereo_44100.flac");
    set_streaminfo(&mut bytes, 44_100, 2, 12, 11_025);
    assert_eq!(rejects(&bytes), Error::UnsupportedBitDepth(12));
}

#[test]
fn rejects_unsupported_sample_rate() {
    assert_eq!(
        rejects(&fixture("s16_stereo_22050.flac")),
        Error::UnsupportedSampleRate(22_050)
    );
}

#[test]
fn rejects_frame_channels_disagreeing_with_streaminfo() {
    let bytes = Synth::new(2, 16, 44_100)
        .with_header(FrameHeader {
            channels: 1,
            bit_depth: 16,
            rate: Rate::standard(44_100),
        })
        .build();
    assert!(matches!(
        rejects(&bytes),
        Error::FrameChannels {
            frame: 0,
            expected: 2,
            found: 1
        }
    ));
}

#[test]
fn rejects_frame_sample_rate_disagreeing_with_streaminfo() {
    for rate in [
        Rate::standard(44_100),
        Rate::Khz(44),
        Rate::Hz(44_100),
        Rate::TensOfHz(4_410),
    ] {
        let bytes = Synth::new(2, 16, 48_000)
            .with_header(FrameHeader {
                channels: 2,
                bit_depth: 16,
                rate,
            })
            .build();
        assert!(
            matches!(
                rejects(&bytes),
                Error::FrameSampleRate {
                    frame: 0,
                    expected: 48_000,
                    ..
                }
            ),
            "{rate:?}"
        );
    }
}

#[test]
fn rejects_frame_bit_depth_disagreeing_with_streaminfo() {
    let bytes = Synth::new(2, 24, 48_000)
        .with_header(FrameHeader {
            channels: 2,
            bit_depth: 16,
            rate: Rate::standard(48_000),
        })
        .build();
    assert!(matches!(
        rejects(&bytes),
        Error::FrameBitDepth {
            frame: 0,
            expected: 24,
            found: 16
        }
    ));
}

#[test]
fn rejects_mismatch_in_a_later_frame() {
    let mut synth = Synth::new(2, 16, 44_100).with_header(FrameHeader {
        channels: 2,
        bit_depth: 16,
        rate: Rate::standard(96_000),
    });
    synth.override_from_block = 2;
    assert!(matches!(
        rejects(&synth.build()),
        Error::FrameSampleRate {
            frame: 2,
            expected: 44_100,
            found: 96_000
        }
    ));
}

#[test]
fn rejects_truncated_file() {
    let bytes = fixture("s16_stereo_44100.flac");
    for len in [41, 42, 100, bytes.len() / 2, bytes.len() - 1] {
        assert!(measure(&bytes[..len]).is_err(), "length {len}");
    }
}

#[test]
fn rejects_trailing_garbage() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    bytes.extend([0u8; 16]);
    assert!(matches!(rejects(&bytes), Error::Decode(_)));
}

#[test]
fn rejects_empty_input() {
    assert_eq!(rejects(&[]), Error::TooShort(0));
}

#[test]
fn rejects_non_flac_input() {
    assert_eq!(rejects(&[0x42; 64]), Error::MissingMagic);
}

fn spec_pcm_digest(samples: &[i32], bit_depth: u8) -> Vec<u8> {
    let width = u32::from(bit_depth.div_ceil(8));
    let modulus = 1i64 << (8 * width);
    let mut pcm = Vec::new();
    for &sample in samples {
        let value = i64::from(sample).rem_euclid(modulus);
        pcm.extend((0..width).map(|byte| (value >> (8 * byte)) as u8));
    }
    blake3::hash(&pcm).as_bytes().to_vec()
}

#[test]
fn pcm_digest_follows_the_audio_spec_at_every_accepted_bit_depth() {
    let cases = [
        (8, Synth::new(2, 8, 44_100).build()),
        (16, fixture("s16_stereo_44100.flac")),
        (24, fixture("s24_stereo_48000.flac")),
        (24, Synth::new(1, 24, 192_000).build()),
    ];
    for (bit_depth, bytes) in cases {
        let audio = measure(&bytes).expect("accepted");
        assert_eq!(audio.bit_depth, bit_depth);
        let samples = decoded_samples(&bytes);
        let bound = 1i32 << (bit_depth - 1);
        assert!(
            samples
                .iter()
                .all(|&sample| (-bound..bound).contains(&sample))
        );
        assert!(
            samples.iter().any(|&sample| sample < 0),
            "{bit_depth}-bit case has no negative sample to check sign extension"
        );
        assert_eq!(audio.pcm_digest, spec_pcm_digest(&samples, bit_depth));
    }
}

#[test]
fn encoder_output_is_measured_with_exact_block_and_frame_sizes() {
    for expected in POSITIVE.iter().chain(&ENCODER_OUTPUT) {
        let name = flac_name(expected.name);
        let bytes = fixture(&name);
        let (min_frame, max_frame) = frame_sizes(&bytes);
        assert!(
            min_frame > 0 && max_frame > 0,
            "{name} leaves frame sizes unknown"
        );
        let audio = measure(&bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_properties(
            &audio,
            expected.channels,
            expected.bit_depth,
            expected.sample_rate_hz,
            expected.samples_per_channel,
        );
        assert_matches_ffmpeg(&bytes, &audio, &name);
    }
}

#[test]
fn single_frame_may_be_shorter_than_both_block_sizes() {
    for (name, block_size) in [
        ("s16_stereo_44100_short.flac", 4_608),
        ("libflac_s16_mono_48000_short.flac", 4_096),
    ] {
        let bytes = fixture(name);
        assert_eq!(block_sizes(&bytes), (block_size, block_size), "{name}");
        measure(&bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn variable_block_sizes_with_a_short_last_block_are_accepted() {
    for blocks in [&VARIABLE_BLOCKS[..], &[64, 10]] {
        let bytes = Synth::new(2, 16, 48_000)
            .with_variable_block_sizes(blocks)
            .build();
        let audio = measure(&bytes).unwrap_or_else(|error| panic!("{blocks:?}: {error}"));
        assert_eq!(
            audio.samples_per_channel,
            blocks.iter().sum::<usize>() as u64
        );
        assert_matches_ffmpeg(&bytes, &audio, "variable_blocks.flac");
    }
}

#[test]
fn unknown_frame_sizes_are_accepted() {
    let honest = fixture("s16_stereo_44100.flac");
    let expected = measure(&honest).expect("fixture");
    let (min, max) = frame_sizes(&honest);
    for (patched_min, patched_max) in [(0, max), (min, 0), (0, 0)] {
        let mut bytes = honest.clone();
        set_frame_sizes(&mut bytes, patched_min, patched_max);
        let audio = measure(&bytes).expect("unknown frame size");
        assert_eq!(audio.pcm_digest, expected.pcm_digest);
    }
}

#[test]
fn rejects_block_sizes_outside_the_streaminfo_bounds() {
    for (min, max) in [(0, 4_608), (15, 4_608), (4_609, 4_608), (16, 15), (0, 0)] {
        let mut bytes = fixture("s16_stereo_44100.flac");
        set_block_sizes(&mut bytes, min, max);
        assert_eq!(
            rejects(&bytes),
            Error::BlockSizeBounds { min, max },
            "{min} to {max}"
        );
    }
}

#[test]
fn rejects_min_block_size_too_low() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    set_block_sizes(&mut bytes, 4_000, 4_608);
    assert_eq!(
        rejects(&bytes),
        Error::MinBlockSize {
            expected: 4_000,
            found: 4_608
        }
    );

    let mut bytes = Synth::new(2, 16, 48_000)
        .with_variable_block_sizes(&VARIABLE_BLOCKS)
        .build();
    set_block_sizes(&mut bytes, 511, 2_048);
    assert_eq!(
        rejects(&bytes),
        Error::MinBlockSize {
            expected: 511,
            found: 512
        }
    );
}

#[test]
fn rejects_min_block_size_too_high() {
    let mut bytes = Synth::new(2, 16, 48_000)
        .with_variable_block_sizes(&VARIABLE_BLOCKS)
        .build();
    set_block_sizes(&mut bytes, 513, 2_048);
    assert_eq!(
        rejects(&bytes),
        Error::FrameBlockSizeBelowMin {
            frame: 2,
            expected: 513,
            found: 512
        }
    );

    let mut bytes = fixture("libflac_s16_stereo_44100.flac");
    set_block_sizes(&mut bytes, 4_097, 4_097);
    assert_eq!(
        rejects(&bytes),
        Error::FrameBlockSizeBelowMin {
            frame: 0,
            expected: 4_097,
            found: 4_096
        }
    );
}

#[test]
fn rejects_max_block_size_too_low() {
    let mut bytes = Synth::new(2, 16, 48_000)
        .with_variable_block_sizes(&VARIABLE_BLOCKS)
        .build();
    set_block_sizes(&mut bytes, 512, 2_047);
    assert_eq!(
        rejects(&bytes),
        Error::FrameBlockSizeAboveMax {
            frame: 1,
            expected: 2_047,
            found: 2_048
        }
    );

    let mut bytes = fixture("s16_stereo_44100_short.flac");
    set_block_sizes(&mut bytes, 2_204, 2_204);
    assert_eq!(
        rejects(&bytes),
        Error::FrameBlockSizeAboveMax {
            frame: 0,
            expected: 2_204,
            found: 2_205
        }
    );
}

#[test]
fn rejects_max_block_size_too_high() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    set_block_sizes(&mut bytes, 4_608, 4_609);
    assert_eq!(
        rejects(&bytes),
        Error::MaxBlockSize {
            expected: 4_609,
            found: 4_608
        }
    );

    let mut bytes = Synth::new(2, 16, 48_000)
        .with_variable_block_sizes(&VARIABLE_BLOCKS)
        .build();
    set_block_sizes(&mut bytes, 512, 2_049);
    assert_eq!(
        rejects(&bytes),
        Error::MaxBlockSize {
            expected: 2_049,
            found: 2_048
        }
    );
}

#[test]
fn rejects_wrong_min_frame_size() {
    for name in ["s16_stereo_44100.flac", "libflac_s24_stereo_96000.flac"] {
        let honest = fixture(name);
        let (min, max) = frame_sizes(&honest);
        for claimed in [1, min - 1, min + 1] {
            let mut bytes = honest.clone();
            set_frame_sizes(&mut bytes, claimed, max);
            assert_eq!(
                rejects(&bytes),
                Error::MinFrameSize {
                    expected: claimed,
                    found: u64::from(min)
                },
                "{name} claiming {claimed}"
            );
        }
    }
}

#[test]
fn rejects_wrong_max_frame_size() {
    for name in ["s16_stereo_44100.flac", "libflac_s24_stereo_96000.flac"] {
        let honest = fixture(name);
        let (min, max) = frame_sizes(&honest);
        for claimed in [max - 1, max + 1, 0x00ff_ffff] {
            let mut bytes = honest.clone();
            set_frame_sizes(&mut bytes, min, claimed);
            assert_eq!(
                rejects(&bytes),
                Error::MaxFrameSize {
                    expected: claimed,
                    found: u64::from(max)
                },
                "{name} claiming {claimed}"
            );
        }
    }
}

fn decode_message(bytes: &[u8]) -> String {
    match rejects(bytes) {
        Error::Decode(message) => message,
        other => panic!("expected a decode error, got {other:?}"),
    }
}

#[test]
fn rejects_wrong_frame_number() {
    // libFLAC itself reports a forward gap as a missing frame.
    let bytes = Synth::new(2, 16, 48_000)
        .with_frame_edit(1, FrameEdit::CodedNumber(utf8_number(2)))
        .build();
    assert_eq!(
        decode_message(&bytes),
        "libFLAC: missing frame in frame 1 at byte 4150"
    );

    // A repeated number is no gap to libFLAC; the frame header check finds it.
    let bytes = Synth::new(2, 16, 48_000)
        .with_frame_edit(1, FrameEdit::CodedNumber(utf8_number(0)))
        .build();
    assert_eq!(decode_message(&bytes), "frame 1 has frame number 0");
}

#[test]
fn rejects_wrong_sample_number() {
    let bytes = Synth::new(2, 16, 48_000)
        .with_variable_block_sizes(&VARIABLE_BLOCKS)
        .with_frame_edit(1, FrameEdit::CodedNumber(utf8_number(0)))
        .build();
    assert_eq!(
        decode_message(&bytes),
        "frame 1 starts at sample 0, expected 1024"
    );
}

#[test]
fn rejects_overlong_coded_number() {
    let bytes = Synth::new(2, 16, 48_000)
        .with_frame_edit(1, FrameEdit::CodedNumber(vec![0xc0, 0x81]))
        .build();
    assert_eq!(
        decode_message(&bytes),
        "frame 1 at byte 4150: overlong coded number"
    );
}

#[test]
fn rejects_blocking_strategy_change() {
    let bytes = Synth::new(2, 16, 48_000)
        .with_variable_block_sizes(&VARIABLE_BLOCKS)
        .with_frame_edit(1, FrameEdit::FlipBlocking)
        .with_frame_edit(1, FrameEdit::CodedNumber(utf8_number(1)))
        .build();
    assert_eq!(
        decode_message(&bytes),
        "frame 1 changes the blocking strategy"
    );
}

#[test]
fn rejects_sample_overrun_on_the_first_frame() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    set_streaminfo(&mut bytes, 44_100, 2, 16, 1);
    match rejects(&bytes) {
        Error::SampleCount { expected, decoded } => {
            assert_eq!(expected, 1);
            assert!(decoded > 1 && decoded < 11_025);
        }
        error => panic!("unexpected error: {error:?}"),
    }
}

#[test]
fn rejects_excessive_decoded_work_before_decoding() {
    let mut bytes = fixture("s16_stereo_44100.flac");
    // Preserve format fields and replace the 36-bit sample count with its maximum.
    bytes[21] |= 0x0f;
    bytes[22..26].fill(0xff);
    assert_eq!(rejects(&bytes), Error::DecodedTooLarge);
    assert!(Error::DecodedTooLarge.to_string().contains("4 GiB"));
    // Rejected from STREAMINFO alone: the frames are never read.
    assert_eq!(rejects(&bytes[..42]), Error::DecodedTooLarge);
}

#[test]
fn streamed_window_stays_bounded() {
    let bytes = fixture("libflac_s24_stereo_96000.flac");
    for chunk in CHUNKS {
        let (_, stats) = measure_streamed(&bytes, chunk).expect("fixture");
        assert!(stats.peak_held <= bytes.len(), "{stats:?}");
    }
    let mut long = Synth::new(2, 24, 96_000);
    long.block_size = 4_096;
    long.frames_per_channel = 200 * 4_096;
    let bytes = long.build();
    assert!(bytes.len() > 3 << 20, "{} bytes", bytes.len());
    let (_, stats) = measure_streamed(&bytes, 65_536).expect("long file");
    assert!(stats.peak_held <= (1 << 20) + (256 << 10), "{stats:?}");
}

#[test]
fn streamed_read_error_is_rejected() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("connection reset"))
        }
    }
    let bytes = fixture("s16_stereo_44100.flac");
    let reader = Chunked::new(&bytes[..bytes.len() / 2], 4096).chain(Failing);
    assert_eq!(
        measure_reader(reader),
        Err(Error::Read("connection reset".into()))
    );
    assert_eq!(
        measure_reader(Failing),
        Err(Error::Read("connection reset".into()))
    );
}

/// A VORBIS_COMMENT body with libFLAC's vendor string and `comments`.
fn comment_with(comments: &[&str]) -> Vec<u8> {
    let mut body = codec_comment();
    body.truncate(body.len() - 4);
    body.extend_from_slice(&(comments.len() as u32).to_le_bytes());
    for comment in comments {
        body.extend_from_slice(&(comment.len() as u32).to_le_bytes());
        body.extend_from_slice(comment.as_bytes());
    }
    body
}

#[test]
fn channel_layouts_default_to_flacs_assignment() {
    for (channels, layout) in [
        (1, vec![2]),
        (2, vec![0, 1]),
        (6, vec![0, 1, 2, 3, 9, 10]),
        (8, vec![0, 1, 2, 3, 4, 5, 9, 10]),
    ] {
        let bytes = Synth::new(channels, 16, 48_000).build();
        let audio = measure(&bytes).expect("synthesized");
        assert_eq!(audio.channels, channels);
        assert_eq!(audio.channel_layout, layout, "{channels} channels");
        let tagged = with_metadata(&bytes, &[(VORBIS_COMMENT, tagged_comment())]);
        assert_eq!(measure(&tagged), Ok(audio), "{channels} channels, tagged");
    }
    for (name, layout) in [
        ("s16_mono_44100.flac", vec![2]),
        ("s16_stereo_44100.flac", vec![0, 1]),
    ] {
        assert_eq!(measure(&fixture(name)).expect(name).channel_layout, layout);
    }
}

#[test]
fn a_channel_mask_overrides_the_default_layout() {
    let six = Synth::new(6, 16, 48_000).build();
    let expected = measure(&six).expect("synthesized");
    let mask = |value: &str| {
        let field = format!("WAVEFORMATEXTENSIBLE_CHANNEL_MASK={value}");
        with_metadata(
            &six,
            &[(VORBIS_COMMENT, comment_with(&["TITLE=x", &field]))],
        )
    };
    for (value, layout) in [
        // 5.1 with back surrounds instead of side ones.
        ("0x3F", vec![0, 1, 2, 3, 4, 5]),
        // Front left and right, then four channels with no speaker position.
        ("0x0003", vec![0, 1, 255, 255, 255, 255]),
        ("0x0", vec![255; 6]),
        // Six top speakers.
        ("0x1f800", vec![11, 12, 13, 14, 15, 16]),
    ] {
        let audio = measure(&mask(value)).expect(value);
        assert_eq!(audio.channel_layout, layout, "{value}");
        assert_eq!(audio.pcm_digest, expected.pcm_digest, "{value}");
    }
    assert_eq!(
        rejects(&mask("0x7f")),
        Error::ChannelMaskChannels {
            mask: 0x7f,
            channels: 6
        }
    );
    assert_eq!(rejects(&mask("0x4003f")), Error::ChannelMaskBits(0x4003f));
    assert_eq!(rejects(&mask("63")), Error::ChannelMaskValue("63".into()));
    let mask_field = "WAVEFORMATEXTENSIBLE_CHANNEL_MASK=0x3f";
    let repeated = with_metadata(
        &six,
        &[
            (VORBIS_COMMENT, comment_with(&[mask_field])),
            (VORBIS_COMMENT, comment_with(&[mask_field])),
        ],
    );
    assert_eq!(rejects(&repeated), Error::ChannelMaskRepeated);
    let mut malformed = comment_with(&[mask_field]);
    malformed.push(0);
    let malformed = with_metadata(&six, &[(VORBIS_COMMENT, malformed)]);
    assert_eq!(rejects(&malformed), Error::VorbisComment);
}

#[test]
fn ffmpeg_layouts_are_read_from_its_files() {
    if !has_ffmpeg() {
        eprintln!("ffmpeg unavailable, skipping ffmpeg's channel layouts");
        return;
    }
    // ffmpeg writes no mask for FLAC's own layouts, and 0x3f for 5.1 with back surrounds.
    for (layout, expected) in [
        ("mono", vec![2]),
        ("5.1", vec![0, 1, 2, 3, 4, 5]),
        ("5.1(side)", vec![0, 1, 2, 3, 9, 10]),
        ("7.1", vec![0, 1, 2, 3, 4, 5, 9, 10]),
    ] {
        let path = scratch_file(&format!("layout_{layout}.flac"), &[]);
        let status = std::process::Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
            ])
            .arg(format!(
                "aevalsrc=0.1*sin(2*PI*440*t):c={layout}:s=48000:d=0.1"
            ))
            .args(["-c:a", "flac", "-sample_fmt", "s16"])
            .arg(&path)
            .status()
            .expect("ffmpeg");
        assert!(status.success());
        let bytes = std::fs::read(&path).expect("ffmpeg output");
        let audio = measure(&bytes).expect(layout);
        assert_eq!(audio.channel_layout, expected, "{layout}");
    }
}
