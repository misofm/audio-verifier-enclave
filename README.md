# Nautilus Audio Verifier

Measures FLAC audio inside a Nautilus enclave on AWS Nitro and verifies the signed results on Sui. It checks the decoded audio, computes a BLAKE3 PCM digest, and signs the audio's channels, bit depth, sample rate, sample count and PCM digest. Its streaming endpoint also signs, separately, the size and SHA-256 of the file it measured, for off-chain verifiers.

The [`audio_verifier`](https://github.com/misofm/framework/tree/main/audio_verifier) Move package, in `misofm/framework`, verifies the signature and creates the canonical, frozen `Audio<AudioVerifier>` for use by other applications. Files are not on-chain: anyone can check a file against an Audio by decoding it and comparing the BLAKE3 digest of its PCM with `pcm_digest`. This verifies technical properties of the audio; it does not establish authorship or ownership.

## Supported input

The service accepts FLAC files with:

- STREAMINFO as the first metadata block, with a nonzero MD5 and sample count.
- After it, only PADDING, SEEKTABLE and VORBIS_COMMENT blocks, at most 64 KiB in total including their 4-byte headers. Any other block type (APPLICATION, CUESHEET, PICTURE or a reserved type), more metadata, or a SEEKTABLE that is not whole 18-byte seek points is rejected.
- 8-, 16-, or 24-bit samples.
- Sample rates of 44.1, 48, 88.2, 96, 176.4, 192, 352.8, or 384 kHz.
- Metadata and frame contents that agree with the decoded audio, and no bytes after the last frame.

Accepted metadata blocks are ignored: the audio facts describe the decoded PCM only, so a file measures exactly as its copy with tags and padding removed. The file binding (intent 2) does cover them, because it hashes the file's bytes.

Files default to a 256 MiB limit. Decoded PCM is limited to 4 GiB across all channels, checked from STREAMINFO before any frame is decoded. Non-FLAC files and invalid audio are rejected without a signature.

## API

The service serves HTTP: on vsock port 3000 in an enclave, and on `127.0.0.1:3000` in development. Errors are JSON `{ "error": code, "message": text }`, and a rejected file never receives a signature.

| Route | Body | Response |
|---|---|---|
| `POST /v1/measure` | the FLAC file, streamed, with `Content-Length` | `audio` (intent 0), `master_file` (intent 2), `public_key` |
| `POST /process_data` | the FLAC file, buffered in full | `audio` (intent 0), `public_key` |
| `POST /attestation` | `{ "nonce": hex }` | `{ "attestation": hex }`, the NSM document binding `public_key` |
| `GET /health_check` | | `{ "pk", "address" }` |

`/health_check`, `/attestation` and `/process_data` come from Nautilus. `/v1/measure` decodes the file as it arrives, holding about 1 MiB of it whatever its size, and stops reading as soon as the file is rejected. A response from it looks like this:

```json
{
  "audio": {
    "intent": 0, "timestamp_ms": 1794481458259,
    "channels": 2, "bit_depth": 24, "sample_rate_hz": 96000,
    "samples_per_channel": "11520000",
    "pcm_digest": "<64 hex>", "signature": "<128 hex>"
  },
  "master_file": {
    "intent": 2, "timestamp_ms": 1794481458259,
    "file_size": "31100898", "file_sha256": "<64 hex>", "signature": "<128 hex>"
  },
  "public_key": "<64 hex>"
}
```

`samples_per_channel` and `file_size` are decimal strings. Both signatures carry the same `timestamp_ms`, the enclave's clock when it signed. `/process_data` returns the same `audio` and `public_key`, without `master_file`.

Limits and errors:

| | `/v1/measure` | `/process_data` |
|---|---|---|
| File size | `Content-Length` required (411 `length_required`); over the limit, 413 `body_too_large` | over the limit, 413 `body_too_large` |
| Concurrency | 2 measurements, independent of `/process_data`; more get 429 `overloaded` | 1 upload, shared with `/attestation`; more get 429 `overloaded` |
| Body | nothing received for 30 s: 408 `body_read_timeout`; a read error, or other than `Content-Length` bytes: 400 `body_read_failed` | not received within 90 s: 408 `body_read_timeout` |
| Request | 600 s for the body and the measurement: 408 `request_timeout` | 120 s: 408 `request_timeout` |
| Memory per request | about 1 MiB of the file, plus 16 queued body chunks | the whole file |
| Rejected file | 422 `application_error`, the reason in `message` | 422 `application_error`, the reason in `message` |

Set the file size limit, for both routes, with `--max-body-bytes` or `AUDIO_VERIFIER_MAX_BODY_BYTES`; it defaults to 256 MiB. The service also closes connections beyond 256, connections whose request headers take more than 10 s, and idle connections after 30 s.

## What is signed

Each message is Ed25519-signed with the enclave's per-boot key over `bcs(IntentMessage { intent: u8, timestamp_ms: u64, data })`:

```
intent 0, verified on chain by audio_verifier::verify_audio:
  AudioPayload {
    channels: u8, bit_depth: u8, sample_rate_hz: u32, samples_per_channel: u64,
    pcm_digest: vector<u8>,    // 32 bytes, BLAKE3 of the decoded PCM
  }
  message: 1 + 8 + 47 = 56 bytes

intent 2, verified off chain, from /v1/measure only:
  MasterFilePayload {
    audio: AudioPayload,       // the same facts as intent 0, nested
    file_size: u64,            // bytes of the file as received
    file_sha256: vector<u8>,   // 32 bytes, SHA-256 of those bytes
  }
  message: 1 + 8 + 88 = 97 bytes
```

Integers are little-endian, and each `vector<u8>` is prefixed with its ULEB128 length (one byte, `0x20`, for 32 bytes). `pcm_digest` hashes the PCM interleaved by sample frame, each sample signed little-endian in `ceil(bit_depth / 8)` bytes. Intent 1 was a retired payload and is not reused.

No Move package consumes intent 2. An off-chain verifier rebuilds `MasterFilePayload` from the response's `audio` facts and `master_file` fields, checks the signature with `public_key`, checks that the key is registered at the current version of the on-chain enclave policy, and compares `file_size` and `file_sha256` with the file it expects. A future Move consumer would declare the same struct and call `policy.verify_signature(pk, 2, timestamp_ms, payload, &signature)`.

[`vectors/audio_intent.json`](vectors/audio_intent.json) and [`vectors/master_file_intent.json`](vectors/master_file_intent.json) hold fixed payloads, their BCS, intent messages and signatures from the seed `[7; 32]`. The Rust tests regenerate and compare them; the Move tests check the audio vector.

## Run locally

Install Rust using the version in `rust-toolchain.toml` and a C compiler, then start the development service:

```sh
cargo run --locked -p audio-verifier-enclave --features dev
```

This listens on `127.0.0.1:3000` with a fixed development identity. It is for local testing only. Upload a file:

```sh
curl --fail-with-body http://127.0.0.1:3000/v1/measure \
  -H 'Content-Type: audio/flac' \
  --data-binary @audio.flac
```

Pass `--max-body-bytes` after Cargo's `--`.

## Use on Sui

Publish the [`audio_verifier` Move package](https://github.com/misofm/framework/tree/main/audio_verifier), configure its enclave policy, and register an attested enclave. For new audio, pass `audio`'s fields, timestamp and signature to `audio_verifier::audio_verifier::verify_audio`, which checks the signature against the registered enclave, then freeze the returned Audio with `audio.freeze()` in the same transaction.

See its [README](https://github.com/misofm/framework/tree/main/audio_verifier) for the API and policy setup.

## Run in an enclave

The production build requires AWS Nitro's NSM device and serves HTTP on vsock port 3000. The enclave image requires an x86-64 CPU with AVX-512 and GFNI support.

With Docker available, build the image; on a configured Nitro host with `nitro-cli`, run it:

```sh
make eif
make run-eif
```

The image is written to `out/nitro.eif`. The default enclave allocation is four vCPUs and 6144 MiB of memory. Bridge clients to vsock port 3000 through the parent instance, and register the image's PCR measurements through the Move enclave policy before using its signatures on-chain. Never enable the `dev` feature in a production image.

## Test

```sh
cargo test --locked --workspace
```

Every measurement case also runs streamed, in chunks of 1, 7, 4096 and 1 MiB bytes and whole, and must reach the same verdict. Installing `ffmpeg` enables additional decoder cross-checks. The Move package's tests live with it in `misofm/framework`.

## License

[Functional Source License 1.1, ALv2 Future License](LICENSE.md). Vendored libFLAC is [BSD-3-Clause licensed](crates/libflac/flac-1.5.0/COPYING.Xiph); its notice must accompany binary distributions.
