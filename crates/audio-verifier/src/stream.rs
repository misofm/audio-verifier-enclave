use std::io::{self, Read};

use sha2::{Digest as _, Sha256};

use crate::streaminfo::HEADER_LENGTH;
use crate::{Error, MAX_EXTRA_METADATA_BYTES, StreamInfo};

const PADDING: u8 = 1;
const SEEKTABLE: u8 = 3;
const VORBIS_COMMENT: u8 = 4;

/// Metadata block types that may follow STREAMINFO. None of them can change the decoded audio,
/// and libFLAC reads past them without reporting them.
const SKIPPED_BLOCK_TYPES: [u8; 3] = [PADDING, SEEKTABLE, VORBIS_COMMENT];

const SEEK_POINT_LENGTH: u32 = 18;

/// Counts and hashes every byte read through it.
pub(crate) struct Hashing<R> {
    reader: R,
    len: u64,
    sha256: Sha256,
}

impl<R> Hashing<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            len: 0,
            sha256: Sha256::new(),
        }
    }

    /// The bytes read and their SHA-256.
    pub(crate) fn finish(self) -> (u64, [u8; 32]) {
        (self.len, self.sha256.finalize().into())
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buffer)?;
        self.sha256.update(&buffer[..count]);
        self.len += count as u64;
        Ok(count)
    }
}

/// Reads up to `buffer.len()` bytes, fewer only at the end of the stream.
fn fill(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, Error> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Read(error.to_string())),
        }
    }
    Ok(filled)
}

/// Reads the `fLaC` marker and the metadata, returning STREAMINFO and every byte read.
///
/// STREAMINFO must come first. Blocks of [`SKIPPED_BLOCK_TYPES`] may follow it, up to
/// [`MAX_EXTRA_METADATA_BYTES`] in total with their headers; any other block is rejected.
pub(crate) fn read_head(reader: &mut impl Read) -> Result<(StreamInfo, Vec<u8>), Error> {
    let mut head = vec![0; HEADER_LENGTH];
    let filled = fill(reader, &mut head)?;
    head.truncate(filled);
    let (info, mut last) = StreamInfo::parse(&head)?;
    let mut extra = 0u32;
    while !last {
        let mut header = [0; 4];
        let filled = fill(reader, &mut header)?;
        if filled < header.len() {
            return Err(Error::TooShort(head.len() + filled));
        }
        head.extend_from_slice(&header);
        last = header[0] & 0x80 != 0;
        let block_type = header[0] & 0x7f;
        if !SKIPPED_BLOCK_TYPES.contains(&block_type) {
            return Err(Error::MetadataBlock(block_type));
        }
        let length = u32::from_be_bytes([0, header[1], header[2], header[3]]);
        // libFLAC parses seek tables even when it skips them, and fails on a partial point.
        if block_type == SEEKTABLE && !length.is_multiple_of(SEEK_POINT_LENGTH) {
            return Err(Error::SeekTableLength(length));
        }
        extra += 4 + length;
        if extra > MAX_EXTRA_METADATA_BYTES {
            return Err(Error::MetadataTooLong);
        }
        let start = head.len();
        head.resize(start + length as usize, 0);
        let filled = fill(reader, &mut head[start..])?;
        if filled < length as usize {
            return Err(Error::TooShort(start + filled));
        }
    }
    Ok((info, head))
}
