//! Rice codes whose unary prefix exceeds libFLAC's limit (`UINT32_MAX >> parameter`). Vendored
//! libFLAC 1.5.0 checked the limit only when the whole prefix was already in its bit buffer;
//! a prefix that ran into the end of the buffered input took an unchecked path that wrapped
//! `msbs << parameter`, so such a file decoded to PCM other decoders do not produce, and its
//! verdict depended on where libFLAC's reads ended. `patches/0001-rice-tail-unary-limit.patch`
//! adds the check; every read pattern now rejects these files, with the same error.

mod common;

use std::io::{self, Read};

use audio_verifier::{AudioPayload, Error, measure, measure_reader};
use common::{BitWriter, crc8, crc16, fixture, utf8_number};
use md5::{Digest as _, Md5};
use sha2::Sha256;

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

/// Measures `bytes` buffered, then streamed in several chunk sizes and split in two at every
/// `step`-th offset, and requires the same result, error included, from each.
fn same_everywhere(bytes: &[u8], step: usize) -> Result<AudioPayload, Error> {
    let buffered = measure(bytes);
    for chunk in [1, 7, 100, 4096, 9000, usize::MAX] {
        let reader = Chunked {
            bytes,
            at: 0,
            chunk,
        };
        let streamed = measure_reader(reader).map(|(audio, _)| audio);
        assert_eq!(streamed, buffered, "chunks of {chunk}");
    }
    for split in (1..bytes.len()).step_by(step) {
        let (head, tail) = bytes.split_at(split);
        let streamed = measure_reader(head.chain(tail)).map(|(audio, _)| audio);
        assert_eq!(streamed, buffered, "split at {split}");
    }
    buffered
}

/// A one-frame, 16-sample, mono, 16-bit, 44.1 kHz file. Its first residual is a Rice-2 code
/// with parameter 20 and a unary prefix of `zeros` bits, the rest are zero. STREAMINFO's MD5 is
/// that of 16 zero samples, which the unchecked path decoded for 4096 zeros: `4096 << 20` wraps
/// to 0.
fn overlong_rice(zeros: usize) -> Vec<u8> {
    let mut out = b"fLaC".to_vec();
    out.extend([0x80, 0, 0, 34]);
    out.extend(16u16.to_be_bytes());
    out.extend(16u16.to_be_bytes());
    out.extend([0; 6]);
    let packed: u64 = (44_100 << 44) | (15 << 36) | 16;
    out.extend(packed.to_be_bytes());
    out.extend(Md5::digest([0u8; 32]));

    let mut frame = vec![0xff, 0xf8, 0x69, 0x08, 0x00, 15];
    frame.push(crc8(&frame));
    let mut bits = BitWriter::default();
    bits.write(0x10, 8); // FIXED, order 0
    bits.write(0b01, 2); // RICE2
    bits.write(0, 4); // partition order 0
    bits.write(20, 5); // Rice parameter
    bits.zeros(zeros);
    bits.write(1, 1);
    bits.write(0, 20);
    for _ in 1..16 {
        bits.write(1, 1);
        bits.write(0, 20);
    }
    frame.extend(bits.finish());
    let crc = crc16(&frame);
    frame.extend(crc.to_be_bytes());
    out.extend(frame);
    out
}

/// [`overlong_rice`] after a PADDING block of `padding` bytes, so the code sits deeper in the
/// input and, for some paddings, across the buffered path's own 8 KiB refill.
fn padded(padding: usize) -> Vec<u8> {
    let base = overlong_rice(4096);
    let mut out = base[..42].to_vec();
    out[4] &= 0x7f;
    out.push(0x81);
    out.extend(&(padding as u32).to_be_bytes()[1..]);
    out.extend(vec![0u8; padding]);
    out.extend(&base[42..]);
    out
}

/// A canonical file, STREAMINFO alone: `lead` silent VERBATIM frames of 16 samples, then the
/// overlong-Rice frame as frame `lead`. The buffered path of main@595329a accepted this shape
/// for some `lead`.
fn canonical_with_lead(lead: u32) -> Vec<u8> {
    let base = overlong_rice(4096);
    let total = 16 * (u64::from(lead) + 1);
    let mut out = base[..18].to_vec();
    let packed: u64 = (44_100 << 44) | (15 << 36) | total;
    out.extend(packed.to_be_bytes());
    out.extend(Md5::digest(vec![0u8; 2 * total as usize]));
    for number in 0..lead {
        let mut frame = vec![0xff, 0xf8, 0x69, 0x08];
        frame.extend(utf8_number(number));
        frame.push(15);
        frame.push(crc8(&frame));
        frame.push(0x02);
        frame.extend([0u8; 32]);
        let crc = crc16(&frame);
        frame.extend(crc.to_be_bytes());
        out.extend(frame);
    }
    let mut last = vec![0xff, 0xf8, 0x69, 0x08];
    last.extend(utf8_number(lead));
    last.push(15);
    last.push(crc8(&last));
    last.extend(&base[42 + 7..base.len() - 2]);
    let crc = crc16(&last);
    last.extend(crc.to_be_bytes());
    out.extend(last);
    out
}

#[test]
fn the_fixtures_are_the_generated_files() {
    let bytes = overlong_rice(4096);
    assert_eq!(bytes, fixture("overlong_rice.flac"));
    assert_eq!(
        hex::encode(<Sha256 as sha2::Digest>::digest(&bytes)),
        "9ad046faf94c545fb8c122a7e785b352df73a37e72aed24d73e8cfb8960e17f8"
    );
    assert_eq!(
        canonical_with_lead(181),
        fixture("overlong_rice_canonical.flac")
    );
}

#[test]
fn overlong_rice_code_is_rejected_however_it_is_read() {
    let bytes = overlong_rice(4096);
    let error = same_everywhere(&bytes, 1).expect_err("rejected");
    assert!(matches!(error, Error::Decode(_)), "{error:?}");
}

#[test]
fn overlong_rice_code_is_rejected_at_every_buffer_boundary() {
    for padding in (7_000..8_200).step_by(4) {
        let bytes = padded(padding);
        assert!(same_everywhere(&bytes, 997).is_err(), "padding {padding}");
    }
}

#[test]
fn canonical_file_with_an_overlong_rice_code_is_rejected() {
    for lead in 150..260 {
        let bytes = canonical_with_lead(lead);
        assert!(same_everywhere(&bytes, 4093).is_err(), "{lead} lead frames");
    }
    let bytes = fixture("overlong_rice_canonical.flac");
    assert!(same_everywhere(&bytes, 13).is_err());
}

#[test]
fn rice_codes_up_to_the_limit_still_decode() {
    // With no prefix the file is valid: 16 zero samples.
    let audio = same_everywhere(&overlong_rice(0), 1).expect("valid");
    assert_eq!(audio.samples_per_channel, 16);
    // 4095 is the longest prefix parameter 20 allows. It decodes, to a residual too large for
    // 16 bits; one more bit is refused by the Rice reader itself.
    for zeros in [4094, 4095] {
        let error = same_everywhere(&overlong_rice(zeros), 1).expect_err("out of range");
        assert!(
            error.to_string().contains("exceed the bit depth"),
            "{zeros}: {error}"
        );
    }
    let error = same_everywhere(&overlong_rice(4096), 1).expect_err("over the limit");
    assert!(
        !error.to_string().contains("exceed the bit depth"),
        "{error}"
    );
}
