use std::io::{self, Read};

use sha2::{Digest as _, Sha256};

use crate::streaminfo::HEADER_LENGTH;
use crate::{Error, StreamInfo};

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
pub(crate) fn read_head(reader: &mut impl Read) -> Result<(StreamInfo, Vec<u8>), Error> {
    let mut head = vec![0; HEADER_LENGTH];
    let filled = fill(reader, &mut head)?;
    head.truncate(filled);
    let (info, last) = StreamInfo::parse(&head)?;
    if !last {
        return Err(Error::ExtraMetadata);
    }
    Ok((info, head))
}
