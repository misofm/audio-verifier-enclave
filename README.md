# Nautilus Audio Verifier

Measures FLAC audio inside a Nautilus enclave on AWS Nitro and verifies the signed results on Sui. It decodes and checks the file, and signs the audio's channels, bit depth, sample rate, sample count and BLAKE3 PCM digest, and separately the size and SHA-256 of the file it measured, for off-chain verifiers.

The [`audio_verifier`](https://github.com/misofm/framework/tree/main/audio_verifier) Move package, in `misofm/framework`, verifies the signature and creates the canonical, frozen `Audio<AudioVerifier>` for use by other applications. Files are not on-chain: anyone can check a file against an Audio by decoding it and comparing the BLAKE3 digest of its PCM with `pcm_digest`. This verifies technical properties of the audio; it does not establish authorship or ownership.

## Supported input

The service accepts FLAC files with:

- STREAMINFO as the first metadata block, with a nonzero MD5 and sample count.
- After it, only PADDING, SEEKTABLE and VORBIS_COMMENT blocks, at most 64 KiB in total including their 4-byte headers. Any other block type (APPLICATION, CUESHEET, PICTURE or a reserved type), more metadata, or a SEEKTABLE that is not whole 18-byte seek points is rejected.
- 8-, 16-, or 24-bit samples.
- Sample rates of 44.1, 48, 88.2, 96, 176.4, 192, 352.8, or 384 kHz.
- Frames of at most 16,777,215 bytes (2^24 - 1, the most STREAMINFO's `max_frame_size` can declare).
- Metadata and frame contents that agree with the decoded audio, and no bytes after the last frame.
- At most 256 MiB of file and 4 GiB of decoded PCM across all channels, the latter checked from STREAMINFO before any frame is decoded.

Accepted metadata blocks are ignored: the audio facts describe the decoded PCM only, so a file measures exactly as its copy with tags and padding removed. The file binding (intent 2) does cover them, because it hashes the file's bytes. The blocks are not otherwise checked: a repeated SEEKTABLE or VORBIS_COMMENT is accepted, and so is PADDING that is not zero, which can carry up to 64 KiB of arbitrary bytes. None of it reaches the decoded audio.

## API

The service serves HTTP on vsock port 3000. Errors are JSON `{ "error": code, "message": text }`, and a rejected file never receives a signature.

| Route | Body | Response |
|---|---|---|
| `POST /measure` | the FLAC file, streamed, with `Content-Length` | `audio` (intent 0), `master_file` (intent 2), `public_key` |
| `POST /attest` | `{ "nonce": hex }` | `{ "attestation": hex }`, the NSM document binding `public_key` |
| `GET /health` | | `{ "pk", "address" }` |

`/measure` decodes the file as it arrives and stops reading as soon as it is rejected. A file gets the same verdict and error however its body is chunked. A response looks like this:

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

`samples_per_channel` and `file_size` are decimal strings. Both signatures carry the same `timestamp_ms`, the enclave's clock when it signed.

| `/measure` | |
|---|---|
| File size | `Content-Length` required (411 `length_required`); over 256 MiB, 413 `body_too_large` |
| Concurrency | one measurement per vCPU, fewer if memory is short (see [Sizing](#sizing)); more get 429 `overloaded` |
| Body | nothing received for 30 s: 408 `body_read_timeout`; a read error, or other than `Content-Length` bytes: 400 `body_read_failed` |
| Request | 600 s for the body and the measurement: 408 `request_timeout` |
| Memory | about 1 MiB of the file for typical frames, 2 to 10 MiB in all; at most 48 MiB, whatever the file's size |
| Rejected file | 422 `application_error`, the reason in `message` |

`/attest` requires a non-empty hex `nonce` of at most 512 bytes and accepts no other field (400 `invalid_request`). Its body may be at most 4 KiB (413 `body_too_large`), and the request has 30 s (408 `request_timeout`). It attests one request at a time, after the body has arrived; others get 429 `overloaded`, and a failing attestation provider 503 `attestation_unavailable`.

Unknown routes get 404 `not_found`, other methods 405 `method_not_allowed`. The service closes connections beyond 256, connections whose request headers take more than 10 s, and idle connections after 30 s.

## What is signed

Each message is Ed25519-signed with the enclave's per-boot key over `bcs(IntentMessage { intent: u8, timestamp_ms: u64, data })`:

```
intent 0, verified on chain by audio_verifier::verify_audio:
  AudioPayload {
    channels: u8, bit_depth: u8, sample_rate_hz: u32, samples_per_channel: u64,
    pcm_digest: vector<u8>,    // 32 bytes, BLAKE3 of the decoded PCM
  }
  message: 1 + 8 + 47 = 56 bytes

intent 2, verified off chain:
  MasterFilePayload {
    audio: AudioPayload,       // the same facts as intent 0, nested
    file_size: u64,            // bytes of the file as received
    file_sha256: vector<u8>,   // 32 bytes, SHA-256 of those bytes
  }
  message: 1 + 8 + 88 = 97 bytes
```

Integers are little-endian, and each `vector<u8>` is prefixed with its ULEB128 length (one byte, `0x20`, for 32 bytes). `pcm_digest` hashes the PCM interleaved by sample frame, each sample signed little-endian in `ceil(bit_depth / 8)` bytes. Intent 1 was a retired payload and is not reused.

No Move package consumes intent 2. An off-chain verifier rebuilds `MasterFilePayload` from the response's `audio` facts and `master_file` fields, checks the signature with `public_key`, checks that the key is registered at the current version of the on-chain enclave policy, and compares `file_size` and `file_sha256` with the file it expects. A future Move consumer would declare the same struct and call `policy.verify_signature(pk, 2, timestamp_ms, payload, &signature)`.

[`vectors/audio_intent.json`](vectors/audio_intent.json) and [`vectors/master_file_intent.json`](vectors/master_file_intent.json) hold fixed payloads, their BCS, intent messages and signatures from the seed `[7; 32]`. The Rust tests regenerate them through the route's signing code and compare; the Move tests check the audio vector.

## Use on Sui

Publish the [`audio_verifier` Move package](https://github.com/misofm/framework/tree/main/audio_verifier), configure its enclave policy, and register an attested enclave. For new audio, pass `audio`'s fields, timestamp and signature to `audio_verifier::audio_verifier::verify_audio`, which checks the signature against the registered enclave, then freeze the returned Audio with `audio.freeze()` in the same transaction. See its [README](https://github.com/misofm/framework/tree/main/audio_verifier) for the API and policy setup.

## Run in an enclave

The image requires an x86-64 CPU with AVX-512 and GFNI, and AWS Nitro's NSM device. With Docker available, build it reproducibly; on a configured Nitro host with `nitro-cli`, run it:

```sh
make eif
make run-eif
```

The image is written to `out/nitro.eif`, with its PCRs in `out/nitro.pcrs`. The default allocation is four vCPUs and 6144 MiB (`ENCLAVE_CPUS`, `ENCLAVE_MEMORY`). Register the image's PCRs through the Move enclave policy before using its signatures on-chain. A new version is a new image with new PCRs, so routes are not versioned.

### Parent instance

`host/` sets up an Amazon Linux 2023 parent with enclaves enabled. As root, from a checkout:

```sh
host/setup.sh out/nitro.eif 4 6144
systemctl start audio-verifier-enclave argonaut
```

| Unit | What it runs |
|---|---|
| `audio-verifier-enclave` | `nitro-cli run-enclave` on `/opt/miso/audio-verifier.eif`, CID 16, at boot; vCPUs and memory from `/etc/miso/audio-verifier.env` |
| `argonaut` | [argonaut](https://github.com/miraicloud/argonaut), pinned by commit in `setup.sh`: TCP `127.0.0.1:3000` to the enclave's vsock port 3000, at most 256 connections |

- The service listens only on loopback; whatever exposes it beyond the instance must authenticate its callers.
- Every enclave start, including a reboot or a spot stop and start, creates a new signing key. Register it with a fresh `/attest` document before its signatures verify.
- The vCPU count must be even on instances with SMT, and the allocator reservation in `/etc/nitro_enclaves/allocator.yaml` is written to match.

### Sizing

At boot the service sizes `/measure` to the enclave, from the vCPUs it may run on and `MemTotal` in `/proc/meminfo`, and logs the result:

```
[server] /measure jobs: 4 (4 vCPUs, MemTotal <n> MiB)
```

```
jobs = max(1, min(vCPUs, (MemTotal - 128 MiB) / 48 MiB))
```

128 MiB is kept for the kernel, the in-memory root file system, the runtime and connections; 48 MiB is the worst case of one job (`MEASURE_JOB_BYTES`). If `MemTotal` cannot be read, it counts as room for one job. Neither resource is part of the PCRs (`nitro-cli run-enclave --cpu-count --memory`), so an enclave can be resized without a new image or registration. vCPUs decide whenever memory has 128 MiB plus 48 MiB per vCPU: two vCPUs and 2 GiB run two jobs. Every job runs a decoder and a hasher thread, so give each job its own vCPU.

## Test

```sh
cargo test --locked --workspace
```

Every measurement case also runs in chunks of 1, 7, 4096 and 1 MiB bytes and must reach the same verdict, error included. A differential fuzz (`crates/audio-verifier/tests/differential.rs`, fixed seed) mutates seven files 150 times each and requires the same result from several chunkings of each; set `FUZZ_ITERATIONS` for a longer run. Installing `ffmpeg` enables cross-checks against an independent decoder. The Move package's tests live with it in `misofm/framework`.

## License

[Functional Source License 1.1, ALv2 Future License](LICENSE.md). Vendored libFLAC is [BSD-3-Clause licensed](crates/libflac/flac-1.5.0/COPYING.Xiph); its notice must accompany binary distributions.

`crates/libflac/flac-1.5.0` is the libFLAC 1.5.0 release's stream decoder. `scripts/vendor-libflac.sh` rebuilds it from the release archive, after checking its SHA-256, and applies [`crates/libflac/patches`](crates/libflac/patches) in order. There is one patch: [`0001-rice-tail-unary-limit.patch`](crates/libflac/patches/0001-rice-tail-unary-limit.patch) enforces the Rice decoder's unary-length limit when a code runs into the end of the buffered input, where 1.5.0 skipped it and decoded overlong codes to PCM other decoders do not produce. It is not fixed upstream as of November 2026.
