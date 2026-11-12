//! A safe callback interface to libFLAC 1.5.0's stream decoder, compiled from the
//! vendored release sources in `flac-1.5.0/`.
//!
//! [`decode`] runs libFLAC over a [`Read`], front to back, and hands each decoded
//! frame, with its exact byte range, to a [`Handler`]. It holds only a window of the
//! input: from the end of the last complete frame to libFLAC's read position, dropped
//! once 1 MiB of finished frames has accumulated. Unlike libFLAC's default behaviour,
//! decoding is strict: the first error libFLAC reports ends it, so libFLAC never
//! resynchronises, skips bytes or fills missing frames with silence on the handler's
//! behalf.
//!
//! Every read libFLAC gets is filled unless the stream ends, so the verdict never
//! depends on how the reader splits its input: libFLAC's own checks differ with its
//! read boundaries. A frame over [`MAX_FRAME_BYTES`], the most STREAMINFO can declare,
//! is refused, and reading stops once more than [`MAX_PENDING_BYTES`] lie past the
//! last complete frame, so the window holds at most that and 1 MiB of finished frames,
//! about 17 MiB.

mod ffi;

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::ffi::{c_int, c_void};
use std::fmt;
use std::io::{self, Read};
use std::panic::{self, AssertUnwindSafe};
use std::{ptr, slice};

/// The most channels a FLAC frame can have.
const MAX_CHANNELS: usize = 8;

/// STREAMINFO as libFLAC parsed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamInfo {
    pub min_block_size: u32,
    pub max_block_size: u32,
    pub min_frame_size: u32,
    pub max_frame_size: u32,
    pub sample_rate: u32,
    pub channels: u32,
    pub bits_per_sample: u32,
    pub total_samples: u64,
    pub md5: [u8; 16],
}

/// A decoded frame.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Zero-based position of the frame in the stream.
    pub index: u64,
    /// Samples per channel.
    pub block_size: u32,
    pub sample_rate: u32,
    pub channels: u32,
    pub bits_per_sample: u32,
    /// Byte offset of the frame in the input.
    pub offset: u64,
    /// The frame's bytes, from the start of its header through its CRC-16: the
    /// input from the end of the previous frame, or of the metadata, to where
    /// libFLAC finished this one.
    pub bytes: &'a [u8],
    /// Decoded samples, one slice of `block_size` samples per channel.
    pub samples: &'a [&'a [i32]],
}

/// Receives what [`decode`] decodes. An error from either method ends decoding.
pub trait Handler {
    type Error;

    /// Called once, with the stream's STREAMINFO, before any frame.
    fn stream_info(&mut self, info: &StreamInfo) -> Result<(), Self::Error>;

    /// Called for each frame, in order.
    fn frame(&mut self, frame: &Frame<'_>) -> Result<(), Self::Error>;
}

/// An error libFLAC reported through its error callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorStatus {
    LostSync,
    BadHeader,
    FrameCrcMismatch,
    UnparseableStream,
    BadMetadata,
    OutOfBounds,
    MissingFrame,
    Unknown(c_int),
}

impl ErrorStatus {
    fn from_raw(status: c_int) -> Self {
        match status {
            0 => Self::LostSync,
            1 => Self::BadHeader,
            2 => Self::FrameCrcMismatch,
            3 => Self::UnparseableStream,
            4 => Self::BadMetadata,
            5 => Self::OutOfBounds,
            6 => Self::MissingFrame,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for ErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LostSync => f.write_str("lost sync"),
            Self::BadHeader => f.write_str("corrupt frame header"),
            Self::FrameCrcMismatch => f.write_str("frame CRC-16 mismatch"),
            Self::UnparseableStream => f.write_str("reserved field in use"),
            Self::BadMetadata => f.write_str("corrupt metadata"),
            Self::OutOfBounds => f.write_str("decoded samples exceed the bit depth"),
            Self::MissingFrame => f.write_str("missing frame"),
            Self::Unknown(status) => write!(f, "error status {status}"),
        }
    }
}

/// Why [`decode`] stopped.
#[derive(Debug, thiserror::Error)]
pub enum Error<E> {
    /// The handler returned an error.
    #[error("{0}")]
    Handler(E),
    /// libFLAC reported an error in the stream.
    #[error("libFLAC: {status} in frame {frame} at byte {offset}")]
    Stream {
        status: ErrorStatus,
        /// Index of the frame being decoded.
        frame: u64,
        /// End of the last complete frame, or of the metadata.
        offset: u64,
    },
    /// libFLAC finished the metadata without reporting STREAMINFO.
    #[error("libFLAC found no STREAMINFO")]
    MissingStreamInfo,
    /// libFLAC reported STREAMINFO more than once.
    #[error("libFLAC found more than one STREAMINFO")]
    RepeatedStreamInfo,
    /// libFLAC could not report a byte position inside the input.
    #[error("libFLAC could not report its decode position")]
    DecodePosition,
    /// libFLAC could not allocate or initialize a decoder.
    #[error("libFLAC decoder initialization failed with status {0}")]
    Init(c_int),
    /// libFLAC stopped in a state other than end of stream.
    #[error("libFLAC decoder stopped in state {0}")]
    State(c_int),
    /// The reader failed or panicked.
    #[error("reading the input failed: {0}")]
    Read(io::Error),
    /// A frame is, or runs, over [`MAX_FRAME_BYTES`].
    #[error("frame {frame} at byte {offset} is over {MAX_FRAME_BYTES} bytes")]
    FrameTooLarge {
        /// Index of the frame.
        frame: u64,
        /// Byte offset of the frame.
        offset: u64,
    },
}

/// How a successful [`decode`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Byte offset just past the last frame, or past the metadata if there were
    /// no frames. Input after it was not decoded: libFLAC stops quietly at a
    /// truncated final frame, so callers that require the whole input to be
    /// frames must compare this with `len`.
    pub end: u64,
    /// Bytes read, all of the input: decoding ends only at its end.
    pub len: u64,
    /// The most input bytes held at once.
    pub peak_held: usize,
}

/// Bytes of finished frames kept before they are dropped in one move.
const RELEASE_THRESHOLD: usize = 1 << 20;

/// Largest frame decoded, from the start of its header through its CRC-16: STREAMINFO's 24-bit
/// `max_frame_size` cannot declare more.
pub const MAX_FRAME_BYTES: u64 = (1 << 24) - 1;

/// Most input read past the end of the last complete frame, or from the start of the stream
/// before the first: the largest frame, and 128 KiB for metadata (at most 42 bytes and 64 KiB
/// for `audio-verifier`) and libFLAC's 8 KiB of read-ahead. A read beyond it ends decoding with
/// [`Error::FrameTooLarge`].
pub const MAX_PENDING_BYTES: u64 = MAX_FRAME_BYTES + (128 << 10);

/// Room reserved for the window at the start, so that it is never reallocated, and copied: the
/// pending input, one more read and the finished frames not yet dropped. Only the pages it fills
/// take memory.
const WINDOW_CAPACITY: usize = MAX_PENDING_BYTES as usize + (64 << 10) + RELEASE_THRESHOLD;

/// Decodes the stream `reader` gives with libFLAC, front to back, passing STREAMINFO and every
/// frame to `handler`. A panic in `handler` is resumed on the caller's thread after libFLAC
/// returns.
pub fn decode<R: Read, H: Handler>(reader: R, handler: &mut H) -> Result<Summary, Error<H::Error>> {
    let window = Window {
        reader,
        held: Vec::with_capacity(WINDOW_CAPACITY),
        base: 0,
        peak: 0,
    };
    let session = Session {
        input: RefCell::new(window),
        handler: RefCell::new(handler),
        stream_info: Cell::new(false),
        frames: Cell::new(0),
        end: Cell::new(0),
        failure: RefCell::new(None),
        panic: Cell::new(None),
    };
    // Declared after `session`, so the decoder is deleted before the session it
    // points to is dropped.
    let decoder = Decoder::new()?;
    let client_data = ptr::from_ref(&session).cast_mut().cast::<c_void>();
    // SAFETY: `decoder` is a fresh decoder. The callbacks are instantiated for
    // this `R` and `H` and cast `client_data` back to `Session<R, H>`; `session`
    // outlives the decoder and is only accessed through shared references.
    let status = unsafe {
        ffi::FLAC__stream_decoder_init_stream(
            decoder.0,
            Some(read::<R, H>),
            None,
            Some(tell::<R, H>),
            None,
            None,
            Some(write::<R, H>),
            Some(metadata::<R, H>),
            Some(error::<R, H>),
            client_data,
        )
    };
    if status != ffi::INIT_STATUS_OK {
        return Err(Error::Init(status));
    }

    // SAFETY: `decoder` was initialized above.
    unsafe { ffi::FLAC__stream_decoder_process_until_end_of_metadata(decoder.0) };
    session.finish_step()?;
    if !session.stream_info.get() {
        return Err(Error::MissingStreamInfo);
    }
    session
        .end
        .set(decoder.position().ok_or(Error::DecodePosition)?);

    // SAFETY: as above.
    unsafe { ffi::FLAC__stream_decoder_process_until_end_of_stream(decoder.0) };
    session.finish_step()?;
    // SAFETY: as above.
    let state = unsafe { ffi::FLAC__stream_decoder_get_state(decoder.0) };
    if state != ffi::STATE_END_OF_STREAM {
        return Err(Error::State(state));
    }
    drop(decoder);
    let window = session.input.into_inner();
    Ok(Summary {
        end: session.end.get(),
        len: window.position(),
        peak_held: window.peak,
    })
}

/// A forward-only reader that keeps its bytes from the last release to the read position.
struct Window<R> {
    reader: R,
    held: Vec<u8>,
    /// Stream offset of `held[0]`.
    base: u64,
    peak: usize,
}

impl<R: Read> Window<R> {
    /// Fills `buffer` unless the stream ends, whatever reads the reader gives.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut count = 0;
        while count < buffer.len() {
            match self.reader.read(&mut buffer[count..]) {
                Ok(0) => break,
                Ok(read) => count += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        self.held.extend_from_slice(&buffer[..count]);
        self.peak = self.peak.max(self.held.len());
        Ok(count)
    }
}

impl<R> Window<R> {
    /// The stream's bytes `start..end`, if they are still held.
    fn bytes(&self, start: u64, end: u64) -> Option<&[u8]> {
        let start = usize::try_from(start.checked_sub(self.base)?).ok()?;
        let end = usize::try_from(end.checked_sub(self.base)?).ok()?;
        self.held.get(start..end)
    }

    /// Bytes before `offset` will not be asked for again.
    fn release(&mut self, offset: u64) {
        let dead = offset.saturating_sub(self.base).min(self.held.len() as u64) as usize;
        if dead >= RELEASE_THRESHOLD || dead == self.held.len() {
            self.held.drain(..dead);
            self.base += dead as u64;
        }
    }

    /// Bytes read so far.
    fn position(&self) -> u64 {
        self.base + self.held.len() as u64
    }
}

/// Owns a libFLAC decoder.
struct Decoder(*mut ffi::StreamDecoder);

impl Decoder {
    fn new<E>() -> Result<Self, Error<E>> {
        // SAFETY: no preconditions; a null result means allocation failed.
        let decoder = unsafe { ffi::FLAC__stream_decoder_new() };
        if decoder.is_null() {
            return Err(Error::State(ffi::STATE_MEMORY_ALLOCATION_ERROR));
        }
        Ok(Self(decoder))
    }

    fn position(&self) -> Option<u64> {
        position(self.0)
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `FLAC__stream_decoder_new` and is deleted once.
        unsafe { ffi::FLAC__stream_decoder_delete(self.0) };
    }
}

fn position(decoder: *const ffi::StreamDecoder) -> Option<u64> {
    let mut position = 0;
    // SAFETY: `decoder` is a live, initialized decoder and `position` is a valid
    // out-pointer. libFLAC calls `tell`, which only reads `Session::read`.
    let ok = unsafe { ffi::FLAC__stream_decoder_get_decode_position(decoder, &mut position) };
    (ok != 0).then_some(position)
}

/// State shared with the callbacks, which see it only through `&Session`.
struct Session<'a, R, H: Handler> {
    input: RefCell<Window<R>>,
    handler: RefCell<&'a mut H>,
    stream_info: Cell<bool>,
    frames: Cell<u64>,
    /// End of the last complete frame, or of the metadata.
    end: Cell<u64>,
    /// The first failure; once set, every later callback aborts.
    failure: RefCell<Option<Error<H::Error>>>,
    panic: Cell<Option<Box<dyn Any + Send>>>,
}

impl<R, H: Handler> Session<'_, R, H> {
    fn failed(&self) -> bool {
        self.failure.borrow().is_some()
    }

    fn fail(&self, error: Error<H::Error>) {
        let mut failure = self.failure.borrow_mut();
        if failure.is_none() {
            *failure = Some(error);
        }
    }

    /// Runs a handler method, recording an error or a panic as the failure.
    fn call(&self, f: impl FnOnce(&mut H) -> Result<(), H::Error>) -> bool {
        let mut handler = self.handler.borrow_mut();
        match panic::catch_unwind(AssertUnwindSafe(|| f(&mut handler))) {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                drop(handler);
                self.fail(Error::Handler(error));
                false
            }
            Err(payload) => {
                drop(handler);
                self.panic.set(Some(payload));
                // Any recorded failure stops decoding; the panic takes precedence.
                self.fail(Error::State(ffi::STATE_ABORTED));
                false
            }
        }
    }

    /// Resumes a handler panic, or returns the first failure, after libFLAC returns.
    fn finish_step(&self) -> Result<(), Error<H::Error>> {
        if let Some(payload) = self.panic.take() {
            panic::resume_unwind(payload);
        }
        match self.failure.borrow_mut().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// # Safety
///
/// `client_data` must be the `Session<R, H>` passed to `decode`'s `init_stream`.
unsafe fn session<'s, 'a, R, H: Handler>(client_data: *mut c_void) -> &'s Session<'a, R, H> {
    // SAFETY: guaranteed by the caller; the session outlives the decoder.
    unsafe { &*client_data.cast::<Session<'a, R, H>>() }
}

unsafe extern "C" fn read<R: Read, H: Handler>(
    _decoder: *const ffi::StreamDecoder,
    buffer: *mut u8,
    bytes: *mut usize,
    client_data: *mut c_void,
) -> c_int {
    // SAFETY: libFLAC passes back the client data given to `init_stream`.
    let session = unsafe { session::<R, H>(client_data) };
    if session.failed() {
        return ffi::READ_STATUS_ABORT;
    }
    // SAFETY: libFLAC passes a valid in/out byte count.
    let capacity = unsafe { *bytes };
    // SAFETY: `buffer` has room for `capacity` bytes for the callback's duration and overlaps
    // nothing the input holds. libFLAC's buffer starts uninitialized, and a `Read` may not be
    // given uninitialized memory, so it is zeroed first.
    let buffer = unsafe {
        ptr::write_bytes(buffer, 0, capacity);
        slice::from_raw_parts_mut(buffer, capacity)
    };
    // A panic must not unwind into libFLAC; the input is not used again after one.
    let read = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut input = session.input.borrow_mut();
        input.read(buffer).map(|count| (count, input.position()))
    }));
    let (count, position) = match read {
        Ok(Ok(read)) => read,
        Ok(Err(error)) => {
            session.fail(Error::Read(error));
            return ffi::READ_STATUS_ABORT;
        }
        Err(_) => {
            session.fail(Error::Read(io::Error::other("the reader panicked")));
            return ffi::READ_STATUS_ABORT;
        }
    };
    let start = session.end.get();
    if position.saturating_sub(start) > MAX_PENDING_BYTES {
        session.fail(Error::FrameTooLarge {
            frame: session.frames.get(),
            offset: start,
        });
        return ffi::READ_STATUS_ABORT;
    }
    // SAFETY: libFLAC passes a valid in/out byte count.
    unsafe { *bytes = count };
    if count == 0 {
        ffi::READ_STATUS_END_OF_STREAM
    } else {
        ffi::READ_STATUS_CONTINUE
    }
}

unsafe extern "C" fn tell<R, H: Handler>(
    _decoder: *const ffi::StreamDecoder,
    offset: *mut u64,
    client_data: *mut c_void,
) -> c_int {
    // SAFETY: libFLAC passes back the client data given to `init_stream`.
    let session = unsafe { session::<R, H>(client_data) };
    // SAFETY: libFLAC passes a valid out-pointer.
    unsafe { *offset = session.input.borrow().position() };
    ffi::TELL_STATUS_OK
}

unsafe extern "C" fn metadata<R, H: Handler>(
    _decoder: *const ffi::StreamDecoder,
    block: *const ffi::StreamMetadata,
    client_data: *mut c_void,
) {
    // SAFETY: libFLAC passes back the client data given to `init_stream`.
    let session = unsafe { session::<R, H>(client_data) };
    // SAFETY: libFLAC passes a valid metadata block for the callback's duration.
    let block = unsafe { &*block };
    if session.failed() || block.type_ != ffi::METADATA_TYPE_STREAMINFO {
        return;
    }
    if session.stream_info.replace(true) {
        session.fail(Error::RepeatedStreamInfo);
        return;
    }
    let raw = &block.stream_info;
    let info = StreamInfo {
        min_block_size: raw.min_blocksize,
        max_block_size: raw.max_blocksize,
        min_frame_size: raw.min_framesize,
        max_frame_size: raw.max_framesize,
        sample_rate: raw.sample_rate,
        channels: raw.channels,
        bits_per_sample: raw.bits_per_sample,
        total_samples: raw.total_samples,
        md5: raw.md5sum,
    };
    session.call(|handler| handler.stream_info(&info));
}

unsafe extern "C" fn write<R, H: Handler>(
    decoder: *const ffi::StreamDecoder,
    header: *const ffi::FrameHeader,
    buffer: *const *const i32,
    client_data: *mut c_void,
) -> c_int {
    // SAFETY: libFLAC passes back the client data given to `init_stream`.
    let session = unsafe { session::<R, H>(client_data) };
    if session.failed() {
        return ffi::WRITE_STATUS_ABORT;
    }
    // The whole frame, CRC-16 included, has been consumed by now.
    let Some(end) = position(decoder) else {
        session.fail(Error::DecodePosition);
        return ffi::WRITE_STATUS_ABORT;
    };
    let start = session.end.get();
    if end.saturating_sub(start) > MAX_FRAME_BYTES {
        session.fail(Error::FrameTooLarge {
            frame: session.frames.get(),
            offset: start,
        });
        return ffi::WRITE_STATUS_ABORT;
    }
    let input = session.input.borrow();
    let Some(bytes) = input.bytes(start, end) else {
        drop(input);
        session.fail(Error::DecodePosition);
        return ffi::WRITE_STATUS_ABORT;
    };

    // SAFETY: the write callback's frame pointer is valid for its duration, and
    // `FrameHeader` is a prefix of `FLAC__Frame` (checked in layout.c).
    let header = unsafe { &*header };
    let channels = header.channels as usize;
    let block_size = header.blocksize as usize;
    let mut samples: [&[i32]; MAX_CHANNELS] = [&[]; MAX_CHANNELS];
    for (channel, slot) in samples.iter_mut().enumerate().take(channels) {
        // SAFETY: libFLAC passes `channels <= 8` channel pointers, each to
        // `blocksize` samples valid for the callback's duration.
        *slot = unsafe { slice::from_raw_parts(*buffer.add(channel), block_size) };
    }
    let frame = Frame {
        index: session.frames.get(),
        block_size: header.blocksize,
        sample_rate: header.sample_rate,
        channels: header.channels,
        bits_per_sample: header.bits_per_sample,
        offset: start,
        bytes,
        samples: &samples[..channels.min(MAX_CHANNELS)],
    };
    let handled = session.call(|handler| handler.frame(&frame));
    drop(input);
    if !handled {
        return ffi::WRITE_STATUS_ABORT;
    }
    session.input.borrow_mut().release(end);
    session.end.set(end);
    session.frames.set(session.frames.get() + 1);
    ffi::WRITE_STATUS_CONTINUE
}

unsafe extern "C" fn error<R, H: Handler>(
    _decoder: *const ffi::StreamDecoder,
    status: c_int,
    client_data: *mut c_void,
) {
    // SAFETY: libFLAC passes back the client data given to `init_stream`.
    let session = unsafe { session::<R, H>(client_data) };
    session.fail(Error::Stream {
        status: ErrorStatus::from_raw(status),
        frame: session.frames.get(),
        offset: session.end.get(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gives at most `chunk` bytes per call, interrupted every other call.
    struct Trickle {
        bytes: Vec<u8>,
        at: usize,
        chunk: usize,
        interrupt: bool,
    }

    impl Read for Trickle {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = buffer.len().min(self.chunk).min(self.bytes.len() - self.at);
            buffer[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
            self.at += count;
            Ok(count)
        }
    }

    #[test]
    fn window_reads_fill_the_buffer_whatever_the_reader_gives() {
        let bytes: Vec<u8> = (0..20_000).map(|i| i as u8).collect();
        for chunk in [1, 7, 4096, usize::MAX] {
            let reader = Trickle {
                bytes: bytes.clone(),
                at: 0,
                chunk,
                interrupt: false,
            };
            let mut window = Window {
                reader,
                held: Vec::new(),
                base: 0,
                peak: 0,
            };
            let counts: Vec<usize> = [8192, 100, 8192, 8192, 8192]
                .map(|size| window.read(&mut vec![0; size]).expect("read"))
                .to_vec();
            assert_eq!(counts, [8192, 100, 8192, 3516, 0], "chunk {chunk}");
            assert_eq!(window.held, bytes, "chunk {chunk}");
        }
    }
}
