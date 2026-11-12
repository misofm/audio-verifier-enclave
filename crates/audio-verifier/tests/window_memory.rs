//! The streamed decoder's memory is bounded whatever the frame: a 256 MiB frame that never ends
//! once held the whole file. This test is alone in its binary, so the process's peak RSS is its
//! own.

mod common;

use std::io::{self, Read};

use audio_verifier::measure_reader;
use common::{crc8, fixture};

/// STREAMINFO for 4096-sample stereo 16-bit frames of unknown size, one frame header and a FIXED
/// order-0 subframe with Rice parameter 0, then `zeros` zero bytes, made as they are read.
struct Unterminated {
    head: Vec<u8>,
    zeros: u64,
    sent: u64,
}

impl Unterminated {
    fn new(zeros: u64) -> Self {
        let mut head = fixture("s16_stereo_44100.flac")[..42].to_vec();
        head[4] |= 0x80;
        head[8..10].copy_from_slice(&4096u16.to_be_bytes());
        head[10..12].copy_from_slice(&4096u16.to_be_bytes());
        head[12..18].fill(0);
        let mut frame = vec![0xff, 0xf8, 0xc9, 0x18, 0x00];
        frame.push(crc8(&frame));
        head.extend(frame);
        head.push(0x10);
        Self {
            head,
            zeros,
            sent: 0,
        }
    }
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
            let count = (buffer.len() as u64).min(head + self.zeros - self.sent) as usize;
            buffer[..count].fill(0);
            count
        };
        self.sent += count as u64;
        Ok(count)
    }
}

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .expect("status")
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM")
}

#[test]
fn unterminated_frame_holds_at_most_the_window() {
    let before = peak_rss_kib();
    let mut reader = Unterminated::new(256 << 20);
    assert!(measure_reader(&mut reader).is_err());
    let grown = peak_rss_kib().saturating_sub(before);
    eprintln!(
        "read {} of {} bytes; peak RSS grew by {grown} KiB",
        reader.sent,
        reader.head.len() as u64 + reader.zeros
    );
    // About 17 MiB of window and libFLAC's buffers; unbounded, it grew by the whole 256 MiB.
    assert!(grown < 24 << 10, "peak RSS grew by {grown} KiB");
}
