use thiserror::Error;

/// Reasons a file is not attested.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Input shorter than the FLAC magic plus a STREAMINFO block.
    #[error("input too short for a FLAC header: {0} bytes")]
    TooShort(usize),
    /// Input does not start with `fLaC`.
    #[error("missing fLaC magic")]
    MissingMagic,
    /// First metadata block is not STREAMINFO.
    #[error("first metadata block has type {0}, expected STREAMINFO")]
    WrongFirstBlock(u8),
    /// A metadata block other than PADDING, SEEKTABLE or VORBIS_COMMENT follows STREAMINFO.
    #[error(
        "metadata block type {0} is not accepted: only PADDING, SEEKTABLE and VORBIS_COMMENT \
         may follow STREAMINFO"
    )]
    MetadataBlock(u8),
    /// The metadata blocks after STREAMINFO exceed
    /// [`MAX_EXTRA_METADATA_BYTES`](crate::MAX_EXTRA_METADATA_BYTES).
    #[error("metadata after STREAMINFO exceeds 65536 bytes")]
    MetadataTooLong,
    /// A SEEKTABLE block is not a whole number of 18-byte seek points.
    #[error("SEEKTABLE length is {0}, not a multiple of 18")]
    SeekTableLength(u32),
    /// A VORBIS_COMMENT block's lengths do not add up to the block.
    #[error("VORBIS_COMMENT block is malformed")]
    VorbisComment,
    /// More than one WAVEFORMATEXTENSIBLE_CHANNEL_MASK field.
    #[error("WAVEFORMATEXTENSIBLE_CHANNEL_MASK appears more than once")]
    ChannelMaskRepeated,
    /// A WAVEFORMATEXTENSIBLE_CHANNEL_MASK value that is not `0x` and hexadecimal digits.
    #[error("WAVEFORMATEXTENSIBLE_CHANNEL_MASK value {0:?} is not 0x and at most 8 hex digits")]
    ChannelMaskValue(String),
    /// A channel mask with bits above 17, the last speaker position.
    #[error("channel mask {0:#x} has bits above 17, the last speaker position")]
    ChannelMaskBits(u32),
    /// A channel mask that assigns more speakers than there are channels.
    #[error("channel mask {mask:#x} assigns more speakers than the {channels} channels")]
    ChannelMaskChannels { mask: u32, channels: u8 },
    /// STREAMINFO block length is not 34.
    #[error("STREAMINFO length is {0}, expected 34")]
    StreamInfoLength(u32),
    /// STREAMINFO MD5 is all zero.
    #[error("STREAMINFO MD5 is zero")]
    ZeroMd5,
    /// STREAMINFO total samples is zero.
    #[error("STREAMINFO total samples is zero")]
    ZeroTotalSamples,
    /// Bit depth outside 8, 16 and 24.
    #[error("unsupported bit depth {0}")]
    UnsupportedBitDepth(u8),
    /// Sample rate outside the on-chain list.
    #[error("unsupported sample rate {0} Hz")]
    UnsupportedSampleRate(u32),
    /// STREAMINFO block sizes break `16 <= min_block_size <= max_block_size`.
    #[error("STREAMINFO block sizes {min} to {max} are not within 16 to 65535 in order")]
    BlockSizeBounds { min: u16, max: u16 },
    /// STREAMINFO declares more decoded PCM than [`MAX_DECODED_BYTES`](crate::MAX_DECODED_BYTES).
    #[error("decoded PCM exceeds the 4 GiB service limit")]
    DecodedTooLarge,
    /// Reading a streamed file failed.
    #[error("reading the input failed: {0}")]
    Read(String),
    /// Decoder error.
    #[error("FLAC decode failed: {0}")]
    Decode(String),
    /// Decoder STREAMINFO differs from the parsed one.
    #[error("decoder STREAMINFO disagrees with the parsed STREAMINFO")]
    StreamInfoMismatch,
    /// Frame header channel count differs from STREAMINFO.
    #[error("frame {frame} has {found} channels, STREAMINFO says {expected}")]
    FrameChannels {
        frame: u64,
        expected: u8,
        found: u32,
    },
    /// Frame header sample rate differs from STREAMINFO.
    #[error("frame {frame} has sample rate {found} Hz, STREAMINFO says {expected} Hz")]
    FrameSampleRate {
        frame: u64,
        expected: u32,
        found: u32,
    },
    /// Frame header bits per sample differs from STREAMINFO.
    #[error("frame {frame} has {found} bits per sample, STREAMINFO says {expected}")]
    FrameBitDepth {
        frame: u64,
        expected: u8,
        found: u32,
    },
    /// A frame before the last is shorter than the STREAMINFO minimum block size.
    #[error("frame {frame} has {found} samples, STREAMINFO minimum block size is {expected}")]
    FrameBlockSizeBelowMin {
        frame: u64,
        expected: u16,
        found: u32,
    },
    /// A frame is longer than the STREAMINFO maximum block size.
    #[error("frame {frame} has {found} samples, STREAMINFO maximum block size is {expected}")]
    FrameBlockSizeAboveMax {
        frame: u64,
        expected: u16,
        found: u32,
    },
    /// STREAMINFO minimum block size differs from the smallest block before the last.
    #[error("smallest block before the last has {found} samples, STREAMINFO says {expected}")]
    MinBlockSize { expected: u16, found: u32 },
    /// STREAMINFO maximum block size differs from the largest block.
    #[error("largest block has {found} samples, STREAMINFO says {expected}")]
    MaxBlockSize { expected: u16, found: u32 },
    /// Non-zero STREAMINFO minimum frame size differs from the smallest frame.
    #[error("smallest frame has {found} bytes, STREAMINFO says {expected}")]
    MinFrameSize { expected: u32, found: u64 },
    /// Non-zero STREAMINFO maximum frame size differs from the largest frame.
    #[error("largest frame has {found} bytes, STREAMINFO says {expected}")]
    MaxFrameSize { expected: u32, found: u64 },
    /// Decoded frame count differs from STREAMINFO total samples.
    #[error("decoded {decoded} frames, STREAMINFO says {expected}")]
    SampleCount { expected: u64, decoded: u64 },
    /// Decoded PCM MD5 differs from STREAMINFO.
    #[error("PCM MD5 mismatch: STREAMINFO {expected}, decoded {decoded}")]
    Md5Mismatch { expected: String, decoded: String },
    /// A boot self-test computed a wrong answer.
    #[error("self-test failed: {0}")]
    SelfTest(&'static str),
}
