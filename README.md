# Nautilus Audio Verifier

Measures and encrypts FLAC masters inside a Nautilus enclave on AWS Nitro, and verifies the signed results on Sui. A browser uploads the file encrypted to the enclave (HPKE, to a key made inside it), so its host and everything in front of it carry only ciphertext. The enclave decodes and checks the file, reads its channel layout, encrypts the whole file under a fresh key (the DEK), computes the Walrus blob ID of the ciphertext, and Seal-encrypts the DEK so that only the Recording's owner, and an enclave the owner granted that master to, can get it back. It signs the audio's channels, bit depth, sample rate, sample count, BLAKE3 PCM digest and channel layout with the blob ID and the sealed DEK, and separately the size and BLAKE3 of the file it measured, for off-chain verifiers. The DEK never leaves the enclave unsealed.

The [`audio_verifier`](https://github.com/misofm/framework/tree/main/audio_verifier) Move package, in `misofm/framework`, verifies the signature and returns an `Audio<AudioVerifier, Pcm, ChannelLayout>` whose data is the encrypted Walrus blob, which `recording_master` stores on the Recording. `recording_master_access` is the Seal policy that releases the DEK to the holder of that Recording's admin cap, and to an enclave registered under an `EnclavePolicy` that holds the holder's grant for that master (the transcoder's, through `audio_transcoder::request_transcode`), with exactly the grant's terms. A grant is per master and is pinned to the policy's version when it was made, so a `set_pcrs` that changes the image voids it. `recording_master_seal` is legacy. This verifies technical properties of the audio; it does not establish authorship or ownership.

## Supported input

The service accepts FLAC files with:

- STREAMINFO as the first metadata block, with a nonzero MD5 and sample count.
- After it, only PADDING, SEEKTABLE and VORBIS_COMMENT blocks, at most 64 KiB in total including their 4-byte headers. Any other block type (APPLICATION, CUESHEET, PICTURE or a reserved type), more metadata, or a SEEKTABLE that is not whole 18-byte seek points is rejected.
- 8-, 16-, or 24-bit samples.
- Sample rates of 44.1, 48, 88.2, 96, 176.4, 192, 352.8, or 384 kHz.
- Frames of at most 16,777,215 bytes (2^24 - 1, the most STREAMINFO's `max_frame_size` can declare).
- Metadata and frame contents that agree with the decoded audio, and no bytes after the last frame.
- At most 256 MiB of file and 4 GiB of decoded PCM across all channels, the latter checked from STREAMINFO before any frame is decoded.

Accepted metadata blocks do not change the PCM facts: a file decodes to the same digest as its copy with tags and padding removed. One Vorbis comment field changes the channel layout (see [Channel layout](#channel-layout)), so each VORBIS_COMMENT block must be well formed, its lengths adding up to the block exactly. The file binding (intent 2) covers every block, because it hashes the file's bytes, and so does the encryption, which is of the whole file. The blocks are not otherwise checked: a repeated SEEKTABLE or VORBIS_COMMENT is accepted, and so is PADDING that is not zero, which can carry up to 64 KiB of arbitrary bytes. None of it reaches the decoded audio.

### Channel layout

`channel_layout` names one speaker position per channel, in channel order, by the bit positions of the WAVE channel mask (RFC 9639, section 8.6.2): 0 FL, 1 FR, 2 FC, 3 LFE, 4 BL, 5 BR, 6 FLC, 7 FRC, 8 BC, 9 SL, 10 SR, 11 TC, 12 TFL, 13 TFC, 14 TFR, 15 TBL, 16 TBC, 17 TBR, and 255 for a channel with no position.

| Channels | Default layout | |
|---|---|---|
| 1 | `[2]` | mono is front center |
| 2 | `[0, 1]` | |
| 3 | `[0, 1, 2]` | |
| 4 | `[0, 1, 4, 5]` | |
| 5 | `[0, 1, 2, 9, 10]` | |
| 6 | `[0, 1, 2, 3, 9, 10]` | |
| 7 | `[0, 1, 2, 3, 8, 9, 10]` | |
| 8 | `[0, 1, 2, 3, 4, 5, 9, 10]` | |

The defaults are FLAC's channel assignment (RFC 9639, section 9.1.3) in the speakers libFLAC's reference decoder writes for it (`src/flac/decode.c`, masks `0x4`, `0x3`, `0x7`, `0x33`, `0x607`, `0x60f`, `0x70f`, `0x63f`): the RFC's "back/surround" pair of five and six channels is side left and right, as in ffmpeg's `5.1(side)`, for which ffmpeg writes no mask.

A `WAVEFORMATEXTENSIBLE_CHANNEL_MASK` field in a VORBIS_COMMENT block overrides the default: its set bits, lowest first, are the positions of the channels in order, and channels past them are 255 (a mask of `0x0` assigns none). The field's name and value are compared without regard to case; the value is `0x` and hexadecimal digits, zero padding allowed. A file is rejected (422) if the field appears more than once, its value is not `0x` and at most 8 significant hex digits, the mask has bits above 17, or it has more bits than the file has channels.

## API

The service serves HTTP on vsock port 3000. Errors are JSON `{ "error": code, "message": text }`, and a rejected file never receives a signature.

| Route | Body | Response |
|---|---|---|
| `GET /upload-key` | | the enclave's X25519 upload key, signed (intent 3, see [The encrypted upload](#the-encrypted-upload)) |
| `POST /upload` | the file encrypted to the upload key, as records (see [The encrypted upload](#the-encrypted-upload)) | as `/measure` |
| `POST /measure?recording_id=<hex>` | the FLAC file, streamed, with `Content-Length` | `application/vnd.miso.measured-master`: the JSON below, a newline (`0x0a`), then the ciphertext |
| `POST /attest` | `{ "nonce": hex }` | `{ "attestation": hex }`, the NSM document binding `public_key` |
| `GET /health` | | `{ "pk", "address" }` |

`recording_id` is the object ID of the Recording the master is for, 32 bytes as 64 hex digits with or without `0x`, given once (400 `invalid_request` otherwise). The Recording need not exist yet. `/measure` decodes and encrypts the file as it arrives and stops reading as soon as it is rejected. A file gets the same verdict and error however its body is chunked. A response starts with this JSON, on one line:

```json
{
  "audio": {
    "intent": 0, "timestamp_ms": 1795009433120,
    "channels": 2, "bit_depth": 24, "sample_rate_hz": 48000,
    "samples_per_channel": "12000",
    "pcm_digest": "<64 hex>",
    "channel_layout": [0, 1],
    "blob_id": "c9CahVauOiY5MCqjTME7q0FQWY28henaFQ_fm66g_yc",
    "blob_id_u256": "<decimal>",
    "sealed_dek": "<hex, 347 bytes>",
    "signature": "<128 hex>"
  },
  "master_file": {
    "intent": 2, "timestamp_ms": 1795009433120,
    "file_size": "35201", "file_blake3": "<64 hex>", "signature": "<128 hex>"
  },
  "ciphertext_size": "35257",
  "public_key": "<64 hex>"
}
```

`samples_per_channel`, `file_size` and `ciphertext_size` are decimal strings. `blob_id` is the Walrus blob ID as Walrus prints it (URL-safe base64 of its 32 bytes, without padding), and `blob_id_u256` the same number as the decimal `u256` that `verify_audio` takes. `sealed_dek` is the BCS of the Seal `EncryptedObject`. Both signatures carry the same `timestamp_ms`, the enclave's clock when it signed. After the newline come exactly `ciphertext_size` bytes of ciphertext; the response's `Content-Length` counts both. Errors are JSON as above, with no ciphertext.

| `/measure` | |
|---|---|
| File size | `Content-Length` required (411 `length_required`); over 256 MiB, 413 `body_too_large` |
| Concurrency | one measurement per vCPU, fewer if memory is short (see [Sizing](#sizing)); more get 429 `overloaded` |
| Body | nothing received for 30 s: 408 `body_read_timeout`; a read error, or other than `Content-Length` bytes: 400 `body_read_failed` |
| Request | 600 s for the body, the measurement, the blob ID and the sealing: 408 `request_timeout` |
| Response | the ciphertext is sent within 600 s, and a reader that takes nothing for 30 s is cut off; the job's slot is held until then |
| Memory | decoding holds about 1 MiB of the file for typical frames and at most 48 MiB; the ciphertext is held whole, the file's size plus 16 bytes a MiB, and computing its blob ID takes about 0.6 times as much again: a 252 MiB file's job peaks at 423 MiB, within the 512 MiB budgeted per job |
| Time | a 252 MiB file takes about 3.4 s after its body has arrived (release build, one core) |
| Rejected file | 422 `application_error`, the reason in `message` |
| Internal failure | 500 `internal_error`; a blob ID or Seal failure is logged |

`/attest` requires a non-empty hex `nonce` of at most 512 bytes and accepts no other field (400 `invalid_request`). Its body may be at most 4 KiB (413 `body_too_large`), and the request has 30 s (408 `request_timeout`). It attests one request at a time, after the body has arrived; others get 429 `overloaded`, and a failing attestation provider 503 `attestation_unavailable`.

Unknown routes get 404 `not_found`, other methods 405 `method_not_allowed`. The service closes connections beyond 256, connections whose request headers take more than 10 s, and idle connections after 30 s.

## The encrypted upload

`/upload` takes the file encrypted to the enclave, so the plaintext exists only in the browser and inside the enclave. It is decrypted frame by frame into `/measure`'s pipeline and is never written anywhere; the answer is `/measure`'s, the same facts, ciphertext and signatures as for the same file sent in the clear.

| | |
|---|---|
| Upload key | X25519, made at boot from 32 bytes of the kernel's randomness (`DeriveKeyPair`), held only in the enclave's memory; a new one at every start, as the Ed25519 key |
| `GET /upload-key` | `{ intent: 3, timestamp_ms, context: "miso-master-upload-v1", x25519_public_key, expires_ms, signature, public_key }`: the public key signed with the Ed25519 key, offered until `expires_ms`, 10 minutes after signing (`UPLOAD_KEY_LIFETIME_MS`) |
| HPKE | RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (`hpke` 0.13) |
| `info` | `"miso-master-upload-v1" ‖ policy ‖ recording_id ‖ u64be(file_size) ‖ u64be(key_expires_ms)`, 101 bytes; `policy` is the network's `EnclavePolicy<AUDIO_VERIFIER>` (`AUDIO_VERIFIER_POLICY`, [Network pins](#network-pins)), pinned in the image |
| Frames | `u64be(offset) ‖ seal(chunk)`, 1 to 1,048,576 bytes of the file each (`MAX_FRAME_PLAINTEXT`), in order from offset 0; the nonces are HPKE's sequence numbers and the associated data `u64be(offset) ‖ last`, `last` 1 on the frame that ends the file, else 0 |

A client checks the key before encrypting to it: the signature, under `public_key`, over `bcs(IntentMessage { intent: 3, timestamp_ms, data: UploadKeyPayload { context: vector<u8>, x25519_public_key: vector<u8>, expires_ms: u64 } })`; that `expires_ms` has not passed; and that `public_key` is registered at the current version of the on-chain policy, so it belongs to an enclave whose attestation matched the policy's PCRs (`AudioVerifier.uploadKey` in `@misofm/sdk`). The browser parses no attestation.

`/upload`'s body is records, each `u32be(length) ‖ bytes`, without `Content-Length` (chunked): first the start record, JSON `{ "enc", "recording_id", "file_size", "key_expires_ms" }` (the encapsulated key as hex, the rest as `/measure` takes them, the u64s as decimal strings) of at most 4 KiB, then one record per frame. The enclave builds `info` from the start record, so a start that names another recording, size or expiry than the client encrypted for does not open. A frame is refused (400 `upload_rejected`, and no signature) if it is not at the next offset, runs past `file_size`, is empty or over 1 MiB, or does not open; that covers a reordered, dropped, repeated, altered or moved frame, one marked last too early or too late, and another key. The body must end with the frame that reaches `file_size`, and nothing may follow it. A key whose `key_expires_ms` has passed is 400 `upload_key_expired`; one later than any this enclave signs, 400 `upload_rejected`. A refused body is still read, and thrown away, for up to 30 s after the answer, so a client still sending it gets the answer rather than a reset connection. Otherwise `/upload` answers and limits as `/measure`: it takes one of the same jobs, the decoder's refusals are 422, and its deadlines are the same.

An upload is not resumed. The measurement, the encryption under the DEK and the file's BLAKE3 are one pass over the plaintext, held in one request; resuming would keep a half-measured job, up to 512 MiB of it, for a client that may not return, or move its state out of the enclave. A broken upload starts again from offset 0 with a fresh `/upload-key` and a fresh HPKE context, which costs at most the bytes already sent. The host's acknowledgements say how far it got.

[`vectors/upload_key_intent.json`](vectors/upload_key_intent.json) holds a signed upload key from the seed `[7; 32]`, and [`vectors/upload_hpke.json`](vectors/upload_hpke.json) an upload sealed from fixed key material, which `@hpke/core`, the browser's HPKE, reproduces byte for byte; the boot self-test opens it. Its `policy` is testnet's in both images (`KNOWN_POLICY`): the self-test checks HPKE, not the pin.

## The encrypted master

| | |
|---|---|
| Encryption | Tink streaming AEAD `AES256_GCM_HKDF_1MB` (`AesGcmHkdfStreaming`, 1,048,576-byte ciphertext segments, HKDF-SHA256, 32-byte derived keys), the wire format byte for byte. The DEK is 32 random bytes from the kernel, and is Tink's raw key value. The associated data is empty. |
| Blob ID | walrus-core at `testnet-v1.60.2` (`29c3d1a`, also `mainnet-v1.60.2`), `EncodingType::RS2` at the network's shard count, 1,000 on both |
| Seal | `crypto` from MystenLabs/seal at `seal-v0.6.16` (`54eff6a`): the DEK is the AES-256-GCM plaintext of an `EncryptedObject`, with empty associated data, as `@mysten/seal`'s `encrypt` makes by default |
| Key server | The network's decentralized Seal key server, a committee behind one key, threshold 1, its `KeyServerV2` public key pinned |
| Policy | The network's `recording_master_access` |
| Identity | `bcs(recording_id: address) ‖ bcs(blob_id: u256)`, 64 bytes: the Recording's object ID, then the blob ID's 32 bytes, which are Walrus's raw blob ID bytes and the little-endian `u256` |

### Network pins

| Pin | Testnet | Mainnet |
|---|---|---|
| `recording_master_access` (`RECORDING_MASTER_ACCESS_PACKAGE`) | `0xc370c70e65b1aa16f429b90dc1ee7080fb4090ddb1b3c914adc32b8b430f0270` | `0xe0262111397c8bfbef7ec8b785e249ce6b4eaf03c63cc4caf11b99fb38ebc0ec` |
| `EnclavePolicy<AUDIO_VERIFIER>` (`AUDIO_VERIFIER_POLICY`) | `0xeb9fdb274f4edbda86b322cbb876a4f92aa6b9e58964d6d5953ff0cead49160e` | `0x7d5d2a995a4b243c408c3cf09f8f037211161494c3636f668696c844031fda1e` |
| Walrus shards (`WALRUS_N_SHARDS`) | 1,000 (system object `0x6c2547cb…f6af`, epoch 585) | 1,000 (system object `0x2134d527…ddd2`, epoch 44) |
| Seal key server (`SEAL_KEY_SERVER`) | `0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98`, 3-of-5 | `0x686098f1439237fff9f36b99c7329683c22979d2005c2465cb891acb012a7595`, 5-of-8 |
| Its public key (`SEAL_KEY_SERVER_PK`) | `b8068e91…41febe` | `aa2bc42f…f91198` |
| Threshold (`SEAL_THRESHOLD`) | 1 | 1 |

The pins are constants in [`crates/audio-verifier-enclave/src/master.rs`](crates/audio-verifier-enclave/src/master.rs), `master::testnet` and `master::mainnet`. A build compiles in one set, testnet's unless the crate's `mainnet` feature is on, so the pins are part of the image and its PCRs, and each network's image has its own; changing one is a new image, registered again. At boot the service checks the decoder, a Tink known answer, an HPKE upload and a Walrus blob ID against recorded answers, and parses the pinned key, and refuses to start if any fails.

The ciphertext is app-v2's `src/posts/tink.ts` format with 1 MiB segments in place of 64 KiB ones: its header (one length byte, 40, a 32-byte salt and a 7-byte nonce prefix), its key derivation and its per-segment nonces (`prefix ‖ u32be(index) ‖ last`) are the same. A browser decrypts it with that file once its `SEGMENT_BYTES` is a parameter. [`interop/`](interop) proves both directions of agreement with outside code (see [Test](#test)).

Seal's identity names the Recording as well as the blob: blob IDs are public, so with the blob alone anyone could attach the same blob ID to their own Recording and pass the policy. The Recording ID is not in the signed payload; it is in the sealed DEK's own header, and the policy enforces it.

## What is signed

Each message is Ed25519-signed with the enclave's per-boot key over `bcs(IntentMessage { intent: u8, timestamp_ms: u64, data })`:

```
intent 0, verified on chain by audio_verifier::verify_audio:
  AudioPayload {
    channels: u8, bit_depth: u8, sample_rate_hz: u32, samples_per_channel: u64,
    pcm_digest: vector<u8>,      // 32 bytes, BLAKE3 of the decoded PCM
    channel_layout: vector<u8>,  // one speaker position per channel
    blob_id: u256,               // Walrus blob ID of the ciphertext
    sealed_dek: vector<u8>,      // BCS of the Seal EncryptedObject of the DEK
  }

intent 2, verified off chain:
  MasterFilePayload {
    audio: AudioPayload,         // the same payload as intent 0, nested
    file_size: u64,              // bytes of the file as received
    file_blake3: vector<u8>,     // 32 bytes, BLAKE3 of those bytes
  }

intent 3, the upload key, verified off chain by the client that encrypts to it:
  UploadKeyPayload {
    context: vector<u8>,             // "miso-master-upload-v1"
    x25519_public_key: vector<u8>,   // 32 bytes
    expires_ms: u64,
  }
```

Integers are little-endian, `u256` is 32 bytes with no length prefix, and each `vector<u8>` is prefixed with its ULEB128 length. A `blob_id` of Walrus's raw bytes `b` is the `u256` whose BCS is `b`. `pcm_digest` hashes the PCM interleaved by sample frame, each sample signed little-endian in `ceil(bit_depth / 8)` bytes. Intent 1 was a retired payload and is not reused.

No Move package consumes intent 2. An off-chain verifier rebuilds `MasterFilePayload` from the response's `audio` fields and `master_file` fields, checks the signature with `public_key`, checks that the key is registered at the current version of the on-chain enclave policy, and compares `file_size` and `file_blake3` with the plaintext it expects. A future Move consumer would declare the same structs and call `policy.verify_signature(pk, 2, timestamp_ms, payload, &signature)`.

[`vectors/audio_intent.json`](vectors/audio_intent.json) and [`vectors/master_file_intent.json`](vectors/master_file_intent.json) hold fixed payloads, their BCS, intent messages and signatures from the seed `[7; 32]`. The Rust tests regenerate them through the route's signing code and compare. The audio vector's payload, BCS and signatures are those of the `audio_verifier` Move package's own vector.

## Use on Sui

Publish the [`audio_verifier` Move package](https://github.com/misofm/framework/tree/main/audio_verifier), configure its enclave policy, and register an attested enclave. Store the ciphertext on Walrus (Miso's API does, from R2, checking the blob ID), then pass `audio`'s fields, `blob_id_u256` as the `blob_id`, the timestamp and the signature to `audio_verifier::audio_verifier::verify_audio(policy, channels, bit_depth, sample_rate_hz, samples_per_channel, pcm_digest, channel_layout, blob_id, sealed_dek, pk, timestamp_ms, signature)`, and attach the returned `Audio` to the Recording with `recording_master::add_master` in the same transaction. See its [README](https://github.com/misofm/framework/tree/main/audio_verifier) for the API and policy setup. On testnet, `audio_verifier` is `0x79cb3c048707800ea6219cf5f86ef22993837ccb912bba81035abc337e5454c0` and its `EnclavePolicy` `0xeb9fdb274f4edbda86b322cbb876a4f92aa6b9e58964d6d5953ff0cead49160e`; on mainnet, `0x11f24c8cd2aa5dd42580c6799922a6197b2ef6a93cff2f64b6bb8f86ffdc47e4` and `0x7d5d2a995a4b243c408c3cf09f8f037211161494c3636f668696c844031fda1e`.

## Run in an enclave

The image requires an x86-64 CPU with AVX-512 and GFNI, and AWS Nitro's NSM device. With Docker available, build it reproducibly; on a configured Nitro host with `nitro-cli`, run it:

```sh
make eif
make run-eif
```

The image is written to `out/nitro.eif`, with its PCRs in `out/nitro.pcrs`. That is the testnet image; `make eif NETWORK=mainnet` builds the mainnet one (`--features mainnet`) into `out/mainnet/`, and `make run-eif NETWORK=mainnet` runs it. The two have different PCRs, each registered on its own network's policy. `host/` registers on testnet only: `setup.sh`'s policy, `miso-enclave-register`'s GraphQL endpoint and the gateway's default Walrus publisher are testnet's. The default allocation is four vCPUs and 6144 MiB (`ENCLAVE_CPUS`, `ENCLAVE_MEMORY`). Register the image's PCRs through the Move enclave policy before using its signatures on-chain. A new version is a new image with new PCRs, so routes are not versioned.

### Parent instance

`host/` sets up an Amazon Linux 2023 parent with enclaves enabled. As root, from a checkout:

```sh
host/setup.sh out/nitro.eif 4 6144
systemctl start audio-verifier-enclave argonaut audio-verifier-host
```

| Unit | What it runs |
|---|---|
| `audio-verifier-enclave` | `nitro-cli run-enclave` on `/opt/miso/audio-verifier.eif`, CID 16, named `audio-verifier`, at boot; vCPUs and memory from `/etc/miso/audio-verifier.env`; stopping it terminates only this enclave |
| `argonaut` | [argonaut](https://github.com/miraicloud/argonaut), pinned by commit in `setup.sh`: TCP `127.0.0.1:3000` to the enclave's vsock port 3000, at most 256 connections |
| `audio-verifier-host` | the gateway in [`host/gateway`](host/gateway), built by `setup.sh` with rustup's Rust: HTTP on `127.0.0.1:4000`, the only service callers reach |
| `miso-enclave-register@audio-verifier` | [`host/miso-enclave-register.py`](host/miso-enclave-register.py) after every enclave start: fetches the key and a fresh attestation through the gateway and submits `nitro_attestation::load_nitro_attestation` and `enclave::register` through Sui GraphQL, signed by the operations key `/etc/miso/ops.key`; a key already registered at the policy's version is success, one registered at an older version is removed and registered again; the policy and package come from `/etc/miso/audio-verifier.register.env` |

- Every service listens only on loopback; whatever exposes the gateway beyond the instance, such as a Cloudflare Tunnel, must authenticate its callers.
- The gateway keeps no state and no queue. `GET /upload` is a WebSocket for the encrypted upload. Its caller, Miso's API Worker through a Workers VPC service, checks who uploads and names the upload in the upgrade's headers: `x-miso-recording-id`, `x-miso-file-size` (at most 256 MiB) and `x-miso-upload-url`, a presigned R2 `PUT` for the ciphertext, held to the download URL rules below (400 `invalid_request` or `url_not_allowed`, before the upgrade). Then:
  1. the gateway sends `{ "type": "upload_key", "key": <the enclave's /upload-key> }`;
  2. the client sends `{ "type": "start", "enc", "recording_id", "file_size", "key_expires_ms" }`, whose recording and size must be the headers', within 60 s;
  3. the client sends the frames as binary messages (at most 1 MiB + 24 bytes each), and the gateway, which sees each frame's offset but not its contents, checks that each starts where the last ended and forwards it to the enclave's `/upload` as a record, then answers `{ "type": "ack", "received": <bytes of the file through it> }` once the enclave's request has taken it (at most four records queued); a client that sends nothing for 60 s is cut off;
  4. once the enclave has answered, the gateway streams the ciphertext to the presigned URL with its `Content-Length` and sends `{ "type": "done", "measured": <the enclave's JSON> }`; or, at any point, `{ "type": "error", "error", "message" }`, an enclave refusal's code and message unchanged. Then it closes.
  The gateway never sees the plaintext or a key, and stores nothing on Walrus for uploads: the API moves the ciphertext from R2 to Walrus and checks its blob ID. Uploads count against `--max-in-flight` with `/measure`, and the whole session has the request and upload timeouts together.
- `POST /measure`, for masters uploaded in the clear before the encrypted upload, takes `{ "url": "<presigned R2 GET URL>", "recording_id": "<hex object ID>" }`, downloads the file and streams it into the enclave's `/measure` with the download's `Content-Length`. An enclave error returns unchanged; callers retry on 429 and 5xx. A measured master's ciphertext is streamed, as it arrives, to the Walrus publisher (`PUT /v1/blobs?epochs=<n>&permanent=true`), and the caller gets the enclave's JSON with `walrus`, the publisher's answer, added, once Walrus's blob ID (`newlyCreated.blobObject.blobId` or `alreadyCertified.blobId`) is the one the enclave signed. Another blob ID gets 502 `blob_id_mismatch`, a failed upload 502 `upload_failed`. `POST /attest` (body at most 4 KiB) and `GET /health` pass through; other routes and methods get 404 `not_found`.
- The publisher is `https://publisher.walrus-testnet.walrus.space` unless `--walrus-publisher` names another, storing for 53 epochs (`--walrus-epochs`); `--walrus-send-object-to` sends the `Blob` objects to an address of yours rather than the publisher's. Publishers on the public internet do not authenticate; run your own, funded, for production.
- It sends the enclave request as soon as the download's headers arrive, so an enclave 429 `overloaded` returns at once and the download is dropped. A download without `Content-Length` gets 502 `download_failed`, one over 256 MiB 413 `body_too_large`, before any body is read. A download that fails, redirects, answers other than 2xx, or delivers other than `Content-Length` bytes gets 502 `download_failed`; an unreachable enclave 502 `enclave_unavailable`.
- Download URLs must be `https` on port 443, without credentials, with a host name ending in `.r2.cloudflarestorage.com` (`<account-id>.r2…` or `<account-id>.<jurisdiction>.r2…`); others get 400 `url_not_allowed`. Redirects are not followed and proxies not used. Names resolve only to public addresses: loopback, private, link-local (the `169.254.169.254` metadata service), shared, multicast and reserved ranges are refused, and the connection uses the checked addresses. `--allowed-host-suffix` (repeatable) replaces the suffix.
- At most 16 `/measure` requests at once (`--max-in-flight`), more get 429 `overloaded`; files and ciphertexts are streamed, never buffered. Timeouts: 10 s to connect (`--connect-timeout-secs`), 20 s without download data (`--idle-timeout-secs`), 630 s up to the enclave's answer (`--request-timeout-secs`; the enclave allows 600 s), and 600 s for the upload (`--upload-timeout-secs`), after which it gets 504 `request_timeout`.
- The gateway is its own Cargo workspace with its own `Cargo.lock`, excluded from the root workspace: it changes neither the enclave's `Cargo.lock`, its vendored dependencies, nor its binary.
- Every enclave start, including a reboot or a stop and start, creates a new signing key, which `miso-enclave-register@audio-verifier` registers. The operations key is 32 random bytes made by `setup.sh`, readable only by root and never printed; `miso-enclave-register --address` prints its address, which needs testnet SUI for gas (from a coin, or else its address balance). It simulates the transaction first and sends it only if it would succeed; it waits up to 10 minutes for the enclave to boot, and while the policy's PCRs are not the running image's it checks again every minute, without spending gas, so the key registers as soon as the policy's admin trusts the image.
- The allocator reservation in `/etc/nitro_enclaves/allocator.yaml` is the sum over every `/etc/miso/<name>.env`, so another enclave on the same host (the transcoder) keeps its share when this one is set up again.
- The vCPU count must be even on instances with SMT.

### Sizing

At boot the service sizes `/measure` to the enclave, from the vCPUs it may run on and `MemTotal` in `/proc/meminfo`, and logs the result:

```
[server] /measure jobs: 4 (4 vCPUs, MemTotal <n> MiB)
```

```
jobs = max(1, min(vCPUs, (MemTotal - 128 MiB) / 48 MiB))
```

128 MiB is kept for the kernel, the in-memory root file system, the runtime and connections; 512 MiB is the worst case of one job (`MEASURE_JOB_BYTES`), a 256 MiB file's ciphertext and its blob ID computation. If `MemTotal` cannot be read, it counts as room for one job. Neither resource is part of the PCRs (`nitro-cli run-enclave --cpu-count --memory`), so an enclave can be resized without a new image or registration. vCPUs decide whenever memory has 128 MiB plus 512 MiB per vCPU: four vCPUs and 6 GiB run four jobs. Every job runs a decoder and a hasher thread, so give each job its own vCPU.

## Test

```sh
cargo test --locked --workspace
cargo test --locked --workspace --features audio-verifier-enclave/mainnet
(cd host/gateway && cargo test --locked)
```

Both networks' pins are parsed in either run; the second runs every test, the boot self-test included, with mainnet's compiled in.

`tests/memory_master.rs` runs a 252 MiB file through the route and checks its job's peak memory; it needs ffmpeg and a release build (`cargo test --release -p audio-verifier-enclave --test memory_master`). Every measurement case also runs in chunks of 1, 7, 4096 and 1 MiB bytes and must reach the same verdict, error included.

The interop checks run against outside code. With an app-v2 checkout (for its `tink.ts` and its `@mysten/seal`) and Python's `tink` package (`pip install tink`):

```sh
cargo run --release -p audio-verifier-enclave --example interop -- interop/out <flac> <recording-id>
node interop/check.mjs <app-v2> interop/out <flac> <recording-id>
python3 interop/tink_check.py interop/out <flac>
```

The first writes a Tink known answer and `/measure`'s output, with the image's pins and with a key server key of its own, whose DEK it opens. `check.mjs` decrypts both ciphertexts with app-v2's `tink.ts` at 1 MiB segments, whole and streamed; parses the sealed DEK with `@mysten/seal` and checks its package, identity, key server and threshold; loads the key server from testnet through `@mysten/seal` and checks its public key is the pinned one (testnet's pins only); and has `@mysten/seal` encrypt to the same identity, for an object of the same shape and size. `tink_check.py` decrypts both with Google's Tink, keys built from the raw DEK and the `AES256_GCM_HKDF_1MB` template's parameters. The Walrus blob ID is checked against the CLI's answers for three fixtures in the unit tests and at boot, and against Walrus itself whenever a ciphertext is stored: by Miso's API for encrypted uploads, by the gateway for `/measure`.

`interop/upload.mjs` runs the encrypted upload with `@misofm/sdk`'s code against the dev server below: it checks the signed key, seals a FLAC file in 1 MiB frames, compares the signed BLAKE3 with the file's, and requires reordered, dropped, altered and truncated frames, another recording in the start, another key and an expired key each to be refused (`node interop/upload.mjs <sdk checkout, built> <flac>`).

`cargo run --release -p audio-verifier-enclave --example dev_server` serves the routes on TCP `127.0.0.1:3000` with a fixed test identity, for running the gateway locally. A differential fuzz (`crates/audio-verifier/tests/differential.rs`, fixed seed) mutates seven files 150 times each and requires the same result from several chunkings of each; set `FUZZ_ITERATIONS` for a longer run. Installing `ffmpeg` enables cross-checks against an independent decoder. The Move package's tests live with it in `misofm/framework`.

## License

[Functional Source License 1.1, ALv2 Future License](LICENSE.md). Vendored libFLAC is [BSD-3-Clause licensed](crates/libflac/flac-1.5.0/COPYING.Xiph); its notice must accompany binary distributions.

`crates/libflac/flac-1.5.0` is the libFLAC 1.5.0 release's stream decoder. `scripts/vendor-libflac.sh` rebuilds it from the release archive, after checking its SHA-256, and applies [`crates/libflac/patches`](crates/libflac/patches) in order. There is one patch: [`0001-rice-tail-unary-limit.patch`](crates/libflac/patches/0001-rice-tail-unary-limit.patch) enforces the Rice decoder's unary-length limit when a code runs into the end of the buffered input, where 1.5.0 skipped it and decoded overlong codes to PCM other decoders do not produce. It is not fixed upstream as of November 2026.
