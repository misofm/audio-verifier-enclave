//! Tink streaming AEAD `AES256_GCM_HKDF_1MB`, the `AesGcmHkdfStreaming` wire format byte for
//! byte, as app-v2's `src/posts/tink.ts` writes it with 64 KiB segments:
//!
//! - **Key.** The 32-byte DEK is HKDF's input key. The ciphertext's AES-256 key is
//!   HKDF-SHA256(ikm = DEK, salt = the header's salt, info = associated data), 32 bytes.
//! - **Header** (40 bytes): its own length (one byte, 40), a random 32-byte salt and a random
//!   7-byte nonce prefix.
//! - **Segments.** The ciphertext is cut in [`SEGMENT_BYTES`] segments, the header counting in
//!   the first. Each is AES-GCM with a 16-byte tag and no associated data, under the nonce
//!   `prefix ‖ u32be(index) ‖ last` (`last` 1 on the final segment, else 0). The final segment
//!   may be full; an empty plaintext is one empty final segment.

use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{AeadInPlace as _, consts::U12},
};
use hkdf::Hkdf;
use sha2::Sha256;

/// Bytes of the DEK, the HKDF input key.
pub const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = KEY_BYTES;
const NONCE_PREFIX_BYTES: usize = 7;
/// The header: its length byte, the salt and the nonce prefix.
pub const HEADER_BYTES: usize = 1 + SALT_BYTES + NONCE_PREFIX_BYTES;
/// The AES-GCM tag that ends every segment.
pub const TAG_BYTES: usize = 16;
/// A ciphertext segment, the header counted in the first: Tink's `AES256_GCM_HKDF_1MB`.
pub const SEGMENT_BYTES: usize = 1 << 20;
const FIRST_PLAINTEXT: usize = SEGMENT_BYTES - HEADER_BYTES - TAG_BYTES;
const PLAINTEXT: usize = SEGMENT_BYTES - TAG_BYTES;

/// The ciphertext's size for `plaintext` bytes.
pub fn ciphertext_size(plaintext: u64) -> u64 {
    let first = FIRST_PLAINTEXT as u64;
    let segments = if plaintext <= first {
        1
    } else {
        1 + (plaintext - first).div_ceil(PLAINTEXT as u64)
    };
    HEADER_BYTES as u64 + plaintext + segments * TAG_BYTES as u64
}

/// Encrypts a stream into one ciphertext in memory, a segment at a time.
pub struct Encryptor {
    cipher: Aes256Gcm,
    prefix: [u8; NONCE_PREFIX_BYTES],
    index: u32,
    /// The header and the sealed segments, then the plaintext of the open segment.
    out: Vec<u8>,
    /// Where the open segment's plaintext starts in `out`.
    open: usize,
    /// Plaintext bytes taken.
    taken: u64,
}

impl Encryptor {
    /// Starts a ciphertext under `dek` and `associated_data`, with a fresh salt and nonce prefix
    /// from `rng`, its buffer sized for `plaintext` bytes.
    pub fn new(
        dek: &[u8; KEY_BYTES],
        associated_data: &[u8],
        rng: &mut impl rand::RngCore,
        plaintext: u64,
    ) -> Self {
        let mut salt = [0; SALT_BYTES];
        let mut prefix = [0; NONCE_PREFIX_BYTES];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut prefix);
        Self::with_header(dek, associated_data, salt, prefix, plaintext)
    }

    /// [`Encryptor::new`] with a given salt and nonce prefix, for known-answer tests.
    pub fn with_header(
        dek: &[u8; KEY_BYTES],
        associated_data: &[u8],
        salt: [u8; SALT_BYTES],
        prefix: [u8; NONCE_PREFIX_BYTES],
        plaintext: u64,
    ) -> Self {
        let mut key = [0; KEY_BYTES];
        Hkdf::<Sha256>::new(Some(&salt), dek)
            .expand(associated_data, &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 length");
        let capacity = usize::try_from(ciphertext_size(plaintext)).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity);
        out.push(HEADER_BYTES as u8);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&prefix);
        Self {
            cipher: Aes256Gcm::new(&key.into()),
            prefix,
            index: 0,
            open: out.len(),
            out,
            taken: 0,
        }
    }

    fn capacity(&self) -> usize {
        if self.index == 0 {
            FIRST_PLAINTEXT
        } else {
            PLAINTEXT
        }
    }

    fn nonce(&self, last: bool) -> Nonce<U12> {
        let mut nonce = [0; 12];
        nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&self.prefix);
        nonce[NONCE_PREFIX_BYTES..11].copy_from_slice(&self.index.to_be_bytes());
        nonce[11] = u8::from(last);
        nonce.into()
    }

    /// Seals the open segment in place and appends its tag.
    fn seal(&mut self, last: bool) {
        let nonce = self.nonce(last);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, &[], &mut self.out[self.open..])
            .expect("a segment is far below AES-GCM's length limit");
        self.out.extend_from_slice(&tag);
        self.index = self.index.checked_add(1).expect("fewer than 2^32 segments");
        self.open = self.out.len();
    }

    /// Takes the next plaintext bytes. A segment is sealed as soon as a byte arrives after it
    /// is full, so the final segment is known only at [`Encryptor::finish`].
    pub fn update(&mut self, mut data: &[u8]) {
        self.taken += data.len() as u64;
        while !data.is_empty() {
            let held = self.out.len() - self.open;
            if held == self.capacity() {
                self.seal(false);
                continue;
            }
            let count = data.len().min(self.capacity() - held);
            self.out.extend_from_slice(&data[..count]);
            data = &data[count..];
        }
    }

    /// Plaintext bytes taken so far.
    pub fn taken(&self) -> u64 {
        self.taken
    }

    /// Seals the final segment and returns the ciphertext.
    pub fn finish(mut self) -> Vec<u8> {
        self.seal(true);
        self.out
    }
}

/// Decrypts a whole ciphertext, for tests and the self-test.
pub fn decrypt(
    dek: &[u8; KEY_BYTES],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.len() < HEADER_BYTES + TAG_BYTES || usize::from(ciphertext[0]) != HEADER_BYTES {
        return None;
    }
    let salt = &ciphertext[1..1 + SALT_BYTES];
    let prefix: [u8; NONCE_PREFIX_BYTES] = ciphertext[1 + SALT_BYTES..HEADER_BYTES]
        .try_into()
        .expect("7 bytes");
    let mut key = [0; KEY_BYTES];
    Hkdf::<Sha256>::new(Some(salt), dek)
        .expand(associated_data, &mut key)
        .ok()?;
    let cipher = Aes256Gcm::new(&key.into());
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut rest = &ciphertext[HEADER_BYTES..];
    let mut index = 0u32;
    loop {
        let size = if index == 0 {
            SEGMENT_BYTES - HEADER_BYTES
        } else {
            SEGMENT_BYTES
        };
        let last = rest.len() <= size;
        let segment = &rest[..rest.len().min(size)];
        if segment.len() < TAG_BYTES {
            return None;
        }
        let mut nonce = [0; 12];
        nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&prefix);
        nonce[NONCE_PREFIX_BYTES..11].copy_from_slice(&index.to_be_bytes());
        nonce[11] = u8::from(last);
        let (body, tag) = segment.split_at(segment.len() - TAG_BYTES);
        let start = plaintext.len();
        plaintext.extend_from_slice(body);
        cipher
            .decrypt_in_place_detached(&nonce.into(), &[], &mut plaintext[start..], tag.into())
            .ok()?;
        if last {
            return Some(plaintext);
        }
        rest = &rest[size..];
        index += 1;
    }
}

/// SHA-256 of [`known_answer`]'s ciphertext, which Python Tink and app-v2's `tink.ts` decrypt
/// in `interop/`.
pub const KNOWN_ANSWER: &str = "4ea6f631f12e0c6a95652244e18fae271fc1a3da2903c9287e99ba79866c0856";

/// The inputs of the known answer, as `interop/` reads them.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KnownAnswer {
    /// Ciphertext segment bytes.
    pub segment_bytes: usize,
    /// The DEK, hex.
    pub dek: String,
    /// The associated data, hex.
    pub associated_data: String,
    /// Plaintext bytes; byte `i` is `(31 i + 7) mod 251`.
    pub plaintext_len: usize,
    /// SHA-256 of the ciphertext, hex.
    pub ciphertext_sha256: String,
}

fn known_plaintext(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 31 + 7) % 251) as u8)
        .collect()
}

/// A ciphertext of three segments from fixed inputs: the DEK `00 01 .. 1f`, the salt
/// `40 41 .. 5f`, the nonce prefix `80 .. 86`, no associated data.
pub fn known_answer() -> (KnownAnswer, Vec<u8>) {
    let dek: [u8; KEY_BYTES] = std::array::from_fn(|index| index as u8);
    let salt = std::array::from_fn(|index| 0x40 + index as u8);
    let prefix = std::array::from_fn(|index| 0x80 + index as u8);
    let len = 2 * SEGMENT_BYTES + 12_345;
    let mut encryptor = Encryptor::with_header(&dek, b"", salt, prefix, len as u64);
    encryptor.update(&known_plaintext(len));
    let ciphertext = encryptor.finish();
    let answer = KnownAnswer {
        segment_bytes: SEGMENT_BYTES,
        dek: hex::encode(dek),
        associated_data: String::new(),
        plaintext_len: len,
        ciphertext_sha256: hex::encode(<Sha256 as sha2::Digest>::digest(&ciphertext)),
    };
    (answer, ciphertext)
}

/// Checks [`known_answer`] against [`KNOWN_ANSWER`] and decrypts it, so that a build that
/// encrypts wrongly on this CPU can refuse to start.
pub fn self_test() -> Result<(), &'static str> {
    let (answer, ciphertext) = known_answer();
    if answer.ciphertext_sha256 != KNOWN_ANSWER {
        return Err("Tink known answer");
    }
    let dek: [u8; KEY_BYTES] = std::array::from_fn(|index| index as u8);
    if decrypt(&dek, b"", &ciphertext) != Some(known_plaintext(answer.plaintext_len)) {
        return Err("Tink decryption");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_known_answer_holds() {
        assert_eq!(known_answer().0.ciphertext_sha256, KNOWN_ANSWER);
        assert_eq!(self_test(), Ok(()));
    }

    fn encrypt(plaintext: &[u8], chunk: usize) -> Vec<u8> {
        let mut encryptor =
            Encryptor::with_header(&[7; 32], b"ad", [1; 32], [2; 7], plaintext.len() as u64);
        for part in plaintext.chunks(chunk.max(1)) {
            encryptor.update(part);
        }
        assert_eq!(encryptor.taken(), plaintext.len() as u64);
        encryptor.finish()
    }

    #[test]
    fn sizes_and_round_trips_at_segment_edges() {
        let edges = [
            0,
            1,
            FIRST_PLAINTEXT - 1,
            FIRST_PLAINTEXT,
            FIRST_PLAINTEXT + 1,
            FIRST_PLAINTEXT + PLAINTEXT,
            FIRST_PLAINTEXT + PLAINTEXT + 1,
            3 * SEGMENT_BYTES + 12_345,
        ];
        for len in edges {
            let plaintext: Vec<u8> = (0..len).map(|index| (index * 31 % 251) as u8).collect();
            let whole = encrypt(&plaintext, usize::MAX);
            assert_eq!(whole.len() as u64, ciphertext_size(len as u64), "{len}");
            assert_eq!(whole.capacity(), whole.len(), "{len}: sized exactly");
            for chunk in [1usize, 7, 65_536, SEGMENT_BYTES + 3] {
                if len > 200_000 && chunk < 1000 {
                    continue;
                }
                assert_eq!(
                    encrypt(&plaintext, chunk),
                    whole,
                    "{len} in chunks of {chunk}"
                );
            }
            assert_eq!(
                decrypt(&[7; 32], b"ad", &whole).as_deref(),
                Some(&plaintext[..])
            );
            assert_eq!(decrypt(&[8; 32], b"ad", &whole), None);
            assert_eq!(decrypt(&[7; 32], b"", &whole), None);
            assert_eq!(decrypt(&[7; 32], b"ad", &whole[..whole.len() - 1]), None);
        }
    }

    #[test]
    fn a_full_final_segment_is_not_followed_by_an_empty_one() {
        let ciphertext = encrypt(&vec![0; FIRST_PLAINTEXT], 4096);
        assert_eq!(ciphertext.len(), SEGMENT_BYTES);
        let ciphertext = encrypt(&vec![0; FIRST_PLAINTEXT + 1], 4096);
        assert_eq!(ciphertext.len(), SEGMENT_BYTES + 1 + TAG_BYTES);
    }

    #[test]
    fn the_header_is_tinks() {
        let ciphertext = encrypt(b"", 1);
        assert_eq!(ciphertext.len(), HEADER_BYTES + TAG_BYTES);
        assert_eq!(ciphertext[0], 40);
        assert_eq!(&ciphertext[1..33], &[1; 32]);
        assert_eq!(&ciphertext[33..40], &[2; 7]);
    }
}
