use std::io::{self, Read};
use std::panic;

use libflac::{Error, ErrorStatus, Frame, Handler, StreamInfo, decode};

const FIXTURE: &[u8] =
    include_bytes!("../../audio-verifier/tests/fixtures/libflac_s16_stereo_44100.flac");

/// Records what libFLAC reports and can fail at a chosen frame.
#[derive(Default)]
struct Record {
    info: Option<StreamInfo>,
    frames: Vec<(u64, u64, usize, u32)>,
    fail_at: Option<u64>,
    panic_at: Option<u64>,
}

impl Handler for Record {
    type Error = &'static str;

    fn stream_info(&mut self, info: &StreamInfo) -> Result<(), Self::Error> {
        self.info = Some(*info);
        Ok(())
    }

    fn frame(&mut self, frame: &Frame<'_>) -> Result<(), Self::Error> {
        if self.panic_at == Some(frame.index) {
            panic!("handler panic");
        }
        if self.fail_at == Some(frame.index) {
            return Err("handler error");
        }
        assert_eq!(frame.samples.len(), frame.channels as usize);
        assert!(
            frame
                .samples
                .iter()
                .all(|channel| channel.len() == frame.block_size as usize)
        );
        self.frames.push((
            frame.index,
            frame.offset,
            frame.bytes.len(),
            frame.block_size,
        ));
        Ok(())
    }
}

#[test]
fn frames_tile_the_input_after_streaminfo() {
    let mut record = Record::default();
    let summary = decode(FIXTURE, &mut record).expect("decode");
    let info = record.info.expect("STREAMINFO");
    assert_eq!((info.channels, info.bits_per_sample), (2, 16));
    assert_eq!(summary.end, FIXTURE.len() as u64);
    assert_eq!(summary.len, FIXTURE.len() as u64);

    let mut offset = 42;
    for (index, (frame, start, len, _)) in record.frames.iter().enumerate() {
        assert_eq!(*frame, index as u64);
        assert_eq!(*start, offset);
        assert_eq!(&FIXTURE[*start as usize..][..2], &[0xff, 0xf8]);
        offset += *len as u64;
    }
    assert_eq!(offset, FIXTURE.len() as u64);
    let samples: u64 = record.frames.iter().map(|frame| u64::from(frame.3)).sum();
    assert_eq!(samples, info.total_samples);
}

#[test]
fn handler_error_stops_decoding() {
    let mut record = Record {
        fail_at: Some(1),
        ..Record::default()
    };
    let error = decode(FIXTURE, &mut record).expect_err("handler error");
    assert!(matches!(error, Error::Handler("handler error")));
    assert_eq!(record.frames.len(), 1);
}

#[test]
fn handler_panic_is_resumed_on_the_caller() {
    let mut record = Record {
        panic_at: Some(0),
        ..Record::default()
    };
    let payload = panic::catch_unwind(panic::AssertUnwindSafe(|| decode(FIXTURE, &mut record)))
        .expect_err("handler panic");
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"handler panic"));
}

#[test]
fn truncation_never_reaches_the_end_of_the_input() {
    let mut full = Record::default();
    decode(FIXTURE, &mut full).expect("decode");
    let (_, last_start, _, _) = *full.frames.last().expect("frames");

    // libFLAC reports some cuts as lost sync and stops quietly at others; either
    // way the last complete frame ends before the cut.
    let (mut errors, mut quiet) = (0, 0);
    for len in last_start as usize + 1..FIXTURE.len() {
        match decode(&FIXTURE[..len], &mut Record::default()) {
            Ok(summary) => {
                assert_eq!(summary.end, last_start, "cut at {len}");
                quiet += 1;
            }
            Err(Error::Stream { .. }) => errors += 1,
            Err(other) => panic!("cut at {len}: {other:?}"),
        }
    }
    eprintln!("{errors} cuts reported, {quiet} stopped quietly");
    assert!(quiet > 0, "no quiet stop exercised");
}

#[test]
fn corrupt_frame_is_a_stream_error() {
    let mut bytes = FIXTURE.to_vec();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    let mut record = Record::default();
    let error = decode(&bytes[..], &mut record).expect_err("corrupt frame");
    assert!(
        matches!(
            error,
            Error::Stream {
                status: ErrorStatus::FrameCrcMismatch
                    | ErrorStatus::LostSync
                    | ErrorStatus::BadHeader,
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn trailing_garbage_is_lost_sync() {
    let mut bytes = FIXTURE.to_vec();
    bytes.extend_from_slice(b"TAG trailing bytes");
    let mut record = Record::default();
    let error = decode(&bytes[..], &mut record).expect_err("trailing bytes");
    assert!(
        matches!(
            error,
            Error::Stream {
                status: ErrorStatus::LostSync,
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn input_without_streaminfo_is_rejected() {
    let error = decode(&b"not flac at all"[..], &mut Record::default()).expect_err("not FLAC");
    assert!(!matches!(error, Error::Handler(_)), "{error:?}");
}

/// Hands out at most `chunk` bytes per read, then fails at `fail_at` if set.
struct Chunked<'a> {
    bytes: &'a [u8],
    at: usize,
    chunk: usize,
    fail_at: Option<usize>,
}

impl<'a> Chunked<'a> {
    fn new(bytes: &'a [u8], chunk: usize) -> Self {
        Self {
            bytes,
            at: 0,
            chunk,
            fail_at: None,
        }
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.fail_at.is_some_and(|at| self.at >= at) {
            return Err(io::Error::other("connection reset"));
        }
        let end = self.fail_at.unwrap_or(self.bytes.len());
        let count = buffer.len().min(self.chunk).min(end - self.at);
        buffer[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

#[test]
fn chunked_reads_decode_the_same_frames() {
    let mut whole = Record::default();
    let summary = decode(FIXTURE, &mut whole).expect("decode");
    assert!(summary.peak_held <= FIXTURE.len(), "{summary:?}");
    for chunk in [1, 7, 4096] {
        let mut chunked = Record::default();
        let chunked_summary = decode(Chunked::new(FIXTURE, chunk), &mut chunked).expect("decode");
        assert_eq!(chunked_summary, summary, "chunk {chunk}");
        assert_eq!(chunked.info, whole.info, "chunk {chunk}");
        assert_eq!(chunked.frames, whole.frames, "chunk {chunk}");
    }
}

#[test]
fn chunked_reads_reach_the_same_verdict_on_bad_input() {
    let mut corrupt = FIXTURE.to_vec();
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 0x01;
    let mut trailing = FIXTURE.to_vec();
    trailing.extend_from_slice(b"TAG trailing bytes");
    for input in [&corrupt[..], &trailing[..], &FIXTURE[..FIXTURE.len() - 1]] {
        let whole = format!("{:?}", decode(input, &mut Record::default()));
        let chunked = decode(Chunked::new(input, 7), &mut Record::default());
        assert_eq!(format!("{chunked:?}"), whole);
    }
}

#[test]
fn reader_error_ends_decoding() {
    let mut reader = Chunked::new(FIXTURE, 4096);
    reader.fail_at = Some(FIXTURE.len() / 2);
    let mut record = Record::default();
    let error = decode(reader, &mut record).expect_err("read error");
    assert!(
        matches!(&error, Error::Read(error) if error.to_string() == "connection reset"),
        "{error:?}"
    );
}

#[test]
fn reader_panic_is_a_read_error() {
    struct Panicking<'a>(Chunked<'a>);

    impl Read for Panicking<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.0.at >= self.0.bytes.len() / 2 {
                panic!("reader panic");
            }
            self.0.read(buffer)
        }
    }

    let reader = Panicking(Chunked::new(FIXTURE, 4096));
    let mut record = Record::default();
    let error = decode(reader, &mut record).expect_err("panic");
    assert!(
        matches!(&error, Error::Read(error) if error.to_string() == "the reader panicked"),
        "{error:?}"
    );
    assert!(!record.frames.is_empty());
}

#[test]
fn reader_is_given_zeroed_buffers() {
    /// Fails if the buffer it is handed holds anything but zeros.
    struct Inspecting<'a>(Chunked<'a>);

    impl Read for Inspecting<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.iter().any(|&byte| byte != 0) {
                return Err(io::Error::other("the buffer was not zeroed"));
            }
            self.0.read(buffer)
        }
    }

    for chunk in [1, 4096, usize::MAX] {
        let reader = Inspecting(Chunked::new(FIXTURE, chunk));
        decode(reader, &mut Record::default()).expect("zeroed buffers");
    }
}
