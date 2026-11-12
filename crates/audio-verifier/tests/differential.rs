//! Differential fuzz: every mutated file must get the same result, error included, read whole
//! and read in several chunkings, and on success the stats must cover exactly the file. The
//! seed is fixed; set `FUZZ_ITERATIONS` to run more mutations per base than the default.

mod common;

use std::collections::BTreeMap;
use std::io::{self, Read};

use audio_verifier::{AudioPayload, Error, measure, measure_reader};
use common::{Synth, fixture};
use sha2::{Digest as _, Sha256};

const DEFAULT_ITERATIONS: usize = 150;

/// xorshift64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// Reads of random sizes, at most `max` bytes each.
struct Jittered<'a> {
    bytes: &'a [u8],
    at: usize,
    rng: Rng,
    max: usize,
}

impl Read for Jittered<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let room = buffer.len().min(self.bytes.len() - self.at);
        let count = if room == 0 {
            0
        } else {
            1 + self.rng.below(room.min(self.max))
        };
        buffer[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

fn check(bytes: &[u8], seed: u64) -> Result<AudioPayload, Error> {
    let whole = measure(bytes);
    let mut readers: Vec<(String, Box<dyn Read + '_>)> = vec![
        (
            "jitter-9000".into(),
            Box::new(Jittered {
                bytes,
                at: 0,
                rng: Rng(seed | 1),
                max: 9_000,
            }),
        ),
        (
            "jitter-17".into(),
            Box::new(Jittered {
                bytes,
                at: 0,
                rng: Rng(seed.rotate_left(7) | 1),
                max: 17,
            }),
        ),
    ];
    for split in [42, bytes.len().saturating_sub(1), bytes.len() / 2] {
        let (head, tail) = bytes.split_at(split.min(bytes.len()));
        readers.push((format!("split-{split}"), Box::new(head.chain(tail))));
    }
    for (name, reader) in readers {
        let chunked = measure_reader(reader).map(|(audio, stats)| {
            assert_eq!(stats.len, bytes.len() as u64, "{name}, seed {seed}");
            assert_eq!(stats.sha256, <[u8; 32]>::from(Sha256::digest(bytes)));
            audio
        });
        assert_eq!(chunked, whole, "{name}, seed {seed}, {} bytes", bytes.len());
    }
    whole
}

fn metadata_block(rng: &mut Rng) -> Vec<u8> {
    let block_type = match rng.below(6) {
        0 => 1,
        1 => 3,
        2 => 4,
        3 => rng.below(128) as u8,
        _ => [1u8, 3, 4][rng.below(3)],
    };
    let length = match rng.below(5) {
        0 => rng.below(64),
        1 => 18 * rng.below(8),
        2 => 65_536 - 4 - rng.below(3) + rng.below(3),
        3 => rng.below(70_000),
        _ => rng.below(300),
    };
    let mut block = vec![block_type];
    block.extend(&(length as u32).to_be_bytes()[1..]);
    block.extend((0..length).map(|_| rng.next() as u8));
    block
}

fn mutate(base: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut bytes = base.to_vec();
    for _ in 0..1 + rng.below(3) {
        let len = bytes.len();
        match rng.below(11) {
            0 => {
                let at = rng.below(len);
                bytes[at] ^= 1 << rng.below(8);
            }
            1 => {
                let at = rng.below(64.min(len));
                bytes[at] ^= 1 << rng.below(8);
            }
            2 => {
                let at = rng.below(len);
                bytes[at] = rng.next() as u8;
            }
            3 => bytes.truncate(rng.below(len + 1)),
            4 => {
                let extra = 1 + rng.below(200);
                bytes.extend((0..extra).map(|_| rng.next() as u8));
            }
            5 => {
                bytes.extend(b"TAG");
                bytes.extend([0u8; 125]);
            }
            6 => {
                let at = rng.below(len + 1);
                let extra: Vec<u8> = (0..1 + rng.below(16)).map(|_| rng.next() as u8).collect();
                bytes.splice(at..at, extra);
            }
            7 => {
                let at = rng.below(len);
                let end = (at + 1 + rng.below(64)).min(len);
                bytes.drain(at..end);
            }
            8 | 9 if len >= 42 => {
                // Metadata blocks after STREAMINFO.
                let mut out = bytes[..42].to_vec();
                out[4] &= 0x7f;
                let count = 1 + rng.below(3);
                for index in 0..count {
                    let mut block = metadata_block(rng);
                    if index + 1 == count && rng.below(8) != 0 {
                        block[0] |= 0x80;
                    }
                    out.extend(block);
                }
                out.extend(&bytes[42..]);
                bytes = out;
            }
            _ => {
                // A range of the frames, copied elsewhere among them.
                if len > 100 {
                    let at = 42 + rng.below(len - 42);
                    let end = (at + rng.below(4_096)).min(len);
                    let copy = bytes[at..end].to_vec();
                    let to = 42 + rng.below(len - 42);
                    bytes.splice(to..to, copy);
                }
            }
        }
        if bytes.is_empty() {
            break;
        }
    }
    bytes
}

#[test]
fn whole_and_chunked_reads_agree_on_mutated_files() {
    let iterations = std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS);
    let mut bases: Vec<(String, Vec<u8>)> = [
        "s16_stereo_44100.flac",
        "libflac_s24_stereo_96000.flac",
        "libflac_s16_stereo_44100.flac",
        "s16_mono_44100.flac",
        "libflac_s16_mono_48000_short.flac",
        "s24_stereo_48000.flac",
    ]
    .iter()
    .map(|name| (name.to_string(), fixture(name)))
    .collect();
    let mut long = Synth::new(2, 16, 44_100);
    long.block_size = 4_096;
    long.frames_per_channel = 40 * 4_096;
    bases.push(("synth-long".into(), long.build()));

    let mut verdicts: BTreeMap<String, usize> = BTreeMap::new();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for (name, base) in &bases {
        assert!(check(base, 1).is_ok(), "{name} measures");
        for _ in 0..iterations {
            let seed = rng.next();
            let mutated = mutate(base, &mut Rng(seed | 1));
            let verdict = match check(&mutated, seed) {
                Ok(_) => "ok".to_string(),
                Err(error) => format!("{error:?}")
                    .split(['(', ' ', '{'])
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            };
            *verdicts.entry(verdict).or_default() += 1;
        }
    }
    eprintln!(
        "{} mutations of {} bases: {verdicts:?}",
        iterations * bases.len(),
        bases.len()
    );
    // The corpus must exercise both outcomes, or the comparison proves little.
    assert!(verdicts.get("ok").is_some_and(|&count| count > 0));
    assert!(verdicts.len() > 4, "{verdicts:?}");
}
