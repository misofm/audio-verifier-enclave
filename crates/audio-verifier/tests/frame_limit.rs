//! Frames over `libflac::MAX_FRAME_BYTES` (2^24 - 1, the most STREAMINFO can declare) are
//! refused however they are read, and a frame that never ends stops the decoder after
//! `MAX_PENDING_BYTES`, instead of holding the whole file.

mod common;

use std::io::{self, Read};

use audio_verifier::{Error, measure, measure_reader};
use common::{BitWriter, crc8, crc16, fixture, pcm_md5, set_md5};
use libflac::{MAX_FRAME_BYTES, MAX_PENDING_BYTES};

const LIMIT_MESSAGE: &str = "frame 0 at byte 42 is over 16777215 bytes";

/// Hands out at most `chunk` bytes per read.
struct Chunked<'a> {
    bytes: &'a [u8],
    at: usize,
    chunk: usize,
}

impl Read for Chunked<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer.len().min(self.chunk).min(self.bytes.len() - self.at);
        buffer[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

/// A valid one-frame, 16-sample, mono, 24-bit, 44.1 kHz file whose frame is exactly
/// `frame_bytes` long: a FIXED order-0 subframe whose residuals are Rice codes with parameter 0
/// and long unary prefixes, up to 2^24 - 1 bits each, which libFLAC does not limit.
fn big_frame_file(frame_bytes: usize) -> Vec<u8> {
    const SAMPLES: usize = 16;
    // 7 header bytes and the CRC-16; then the subframe header (8 bits) and the residual's
    // method, partition order and parameter (10 bits), and one stop bit per residual.
    let zeros = 8 * (frame_bytes - 9) - 18 - SAMPLES;
    let mut prefixes = vec![zeros / SAMPLES; SAMPLES];
    prefixes[0] += zeros % SAMPLES;
    assert!(prefixes.iter().all(|&prefix| prefix < 1 << 24));
    let samples: Vec<i32> = prefixes
        .iter()
        .map(|&prefix| {
            let prefix = prefix as i64;
            (if prefix % 2 == 0 {
                prefix / 2
            } else {
                -(prefix + 1) / 2
            }) as i32
        })
        .collect();

    let mut out = b"fLaC".to_vec();
    out.extend([0x80, 0, 0, 34]);
    out.extend(16u16.to_be_bytes());
    out.extend(16u16.to_be_bytes());
    out.extend([0; 6]);
    let packed: u64 = (44_100 << 44) | (23 << 36) | SAMPLES as u64;
    out.extend(packed.to_be_bytes());
    out.extend([0; 16]);
    set_md5(&mut out, pcm_md5(&samples, 3));

    let mut frame = vec![0xff, 0xf8, 0x69, 0x0c, 0x00, (SAMPLES - 1) as u8];
    frame.push(crc8(&frame));
    let mut bits = BitWriter::default();
    bits.write(0x10, 8); // FIXED, order 0
    bits.write(0, 10); // RICE, partition order 0, parameter 0
    for prefix in prefixes {
        bits.zeros(prefix);
        bits.write(1, 1);
    }
    frame.extend(bits.finish());
    let crc = crc16(&frame);
    frame.extend(crc.to_be_bytes());
    assert_eq!(frame.len(), frame_bytes);
    out.extend(frame);
    out
}

/// STREAMINFO for 4096-sample stereo 16-bit frames of unknown size, one frame header, a FIXED
/// order-0 subframe with Rice parameter 0, then zero bytes: a unary prefix that never ends.
fn unterminated_head() -> Vec<u8> {
    let mut head = fixture("s16_stereo_44100.flac")[..42].to_vec();
    head[4] |= 0x80;
    head[8..10].copy_from_slice(&4096u16.to_be_bytes());
    head[10..12].copy_from_slice(&4096u16.to_be_bytes());
    head[12..18].fill(0);
    let mut frame = vec![0xff, 0xf8, 0xc9, 0x18, 0x00];
    frame.push(crc8(&frame));
    head.extend(frame);
    head.push(0x10);
    head
}

/// [`unterminated_head`] and `zeros` zero bytes, made as they are read.
struct Unterminated {
    head: Vec<u8>,
    zeros: u64,
    sent: u64,
}

impl Read for Unterminated {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let head = self.head.len() as u64;
        let count = if self.sent < head {
            let at = self.sent as usize;
            let count = buffer.len().min(self.head.len() - at);
            buffer[..count].copy_from_slice(&self.head[at..at + count]);
            count
        } else {
            let left = head + self.zeros - self.sent;
            let count = (buffer.len() as u64).min(left) as usize;
            buffer[..count].fill(0);
            count
        };
        self.sent += count as u64;
        Ok(count)
    }
}

#[test]
fn frame_of_the_largest_declarable_size_is_measured() {
    let bytes = big_frame_file(MAX_FRAME_BYTES as usize);
    let audio = measure(&bytes).expect("whole");
    assert_eq!(audio.samples_per_channel, 16);
    for chunk in [4093, 1 << 20] {
        let reader = Chunked {
            bytes: &bytes,
            at: 0,
            chunk,
        };
        let (chunked, stats) = measure_reader(reader).expect("chunked");
        assert_eq!(chunked, audio, "chunks of {chunk}");
        assert_eq!(stats.len, bytes.len() as u64);
        assert!(stats.peak_held as u64 <= MAX_PENDING_BYTES, "{stats:?}");
    }
}

#[test]
fn frame_over_the_largest_declarable_size_is_rejected() {
    let bytes = big_frame_file(MAX_FRAME_BYTES as usize + 1);
    let whole = measure(&bytes);
    assert_eq!(whole, Err(Error::Decode(LIMIT_MESSAGE.into())), "{whole:?}");
    for chunk in [4093, 1 << 20] {
        let reader = Chunked {
            bytes: &bytes,
            at: 0,
            chunk,
        };
        let chunked = measure_reader(reader).map(|(audio, _)| audio);
        assert_eq!(chunked, whole, "chunks of {chunk}");
    }
}

#[test]
fn unterminated_frame_stops_the_reader_after_the_limit() {
    let mut reader = Unterminated {
        head: unterminated_head(),
        zeros: 64 << 20,
        sent: 0,
    };
    let streamed = measure_reader(&mut reader).map(|(audio, _)| audio);
    assert_eq!(streamed, Err(Error::Decode(LIMIT_MESSAGE.into())));
    // At most one 8 KiB read past the limit, which counts from the end of the metadata.
    assert!(reader.sent > MAX_FRAME_BYTES, "{}", reader.sent);
    assert!(
        reader.sent <= 42 + MAX_PENDING_BYTES + 8192,
        "{}",
        reader.sent
    );

    // The same file, read whole, is refused at the same place.
    let mut bytes = unterminated_head();
    bytes.resize(bytes.len() + (20 << 20), 0);
    assert_eq!(measure(&bytes), streamed);
}
