// The encrypted upload with the browser's code: @misofm/sdk (built, `bun run build`) decodes and
// verifies the enclave's signed upload key, seals a FLAC file with HPKE in 1 MiB frames, and
// the enclave's `/upload` measures it; then each kind of tampering must be refused. Run against
// the dev server (`cargo run --release -p audio-verifier-enclave --example dev_server`):
//
//   node interop/upload.mjs <sdk checkout> <flac> [enclave URL, http://127.0.0.1:3000]
//
// with NETWORK=mainnet against a dev server built with `--features mainnet`; testnet by default.
//
// The dev server's key is not registered on chain, so the chain check (`AudioVerifier.uploadKey`)
// is not run here; its signature check is.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [sdkDir, flacPath, enclave = 'http://127.0.0.1:3000'] = process.argv.slice(2);
if (!flacPath) throw new Error('usage: upload.mjs <sdk> <flac> [enclave URL]');
const sdk = await import(pathToFileURL(join(sdkDir, 'dist/index.js')).href);
const { Effect } = await import(pathToFileURL(join(sdkDir, 'node_modules/effect/dist/index.js')).href);
const { blake3 } = await import(pathToFileURL(join(sdkDir, 'node_modules/@noble/hashes/blake3.js')).href);

const POLICIES = {
  testnet: '0xeb9fdb274f4edbda86b322cbb876a4f92aa6b9e58964d6d5953ff0cead49160e',
  mainnet: '0x7d5d2a995a4b243c408c3cf09f8f037211161494c3636f668696c844031fda1e',
};
const NETWORK = process.env.NETWORK || 'testnet';
if (!Object.hasOwn(POLICIES, NETWORK)) throw new Error(`NETWORK must be testnet or mainnet, not ${NETWORK}`);
const POLICY = POLICIES[NETWORK];
const RECORDING = '0x' + 'c0'.repeat(32);
const file = new Uint8Array(readFileSync(flacPath));
const fileBlake3 = Buffer.from(blake3(file)).toString('hex');

const keyJson = await (await fetch(`${enclave}/upload-key`)).json();
const key = await Effect.runPromise(sdk.decodeUploadKey(keyJson));
assert.equal(await sdk.uploadKeySignatureValid(key), true, 'the upload key verifies');
assert.equal(await sdk.uploadKeySignatureValid({ ...key, x25519PublicKey: new Uint8Array(32) }), false);

/** Seals `file` for `recording` into the start record and frames. */
const seal = async ({ recording = RECORDING, expiresMs = key.expiresMs, target = key } = {}) => {
  const sender = await sdk.openUploadSender({ key: { x25519PublicKey: target.x25519PublicKey, expiresMs }, policyId: POLICY, recordingId: recording, fileSize: BigInt(file.length) });
  const frames = [];
  for (let at = 0; at < file.length; at += sdk.MAX_FRAME_PLAINTEXT) frames.push(await sender.seal(file.subarray(at, at + sdk.MAX_FRAME_PLAINTEXT)));
  const { type: _, ...start } = sender.start;
  return { start: new TextEncoder().encode(JSON.stringify(start)), startJson: start, frames };
};

const record = (bytes) => {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
};
/** POSTs the records to `/upload`. A refusal can arrive before the body is sent, so the answer is
 * read even when writing the rest of the body fails. */
const post = (start, frames) =>
  new Promise((resolve, reject) => {
    const body = Buffer.concat([record(start), ...frames.map(record)]);
    const started = performance.now();
    const request = http.request(`${enclave}/upload`, { method: 'POST', headers: { 'content-length': body.length } }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const bytes = Buffer.concat(chunks);
        const seconds = (performance.now() - started) / 1000;
        const newline = bytes.indexOf(10);
        if (response.statusCode === 200) resolve({ status: 200, measured: JSON.parse(bytes.subarray(0, newline).toString()), ciphertext: bytes.length - newline - 1, seconds });
        else resolve({ status: response.statusCode, error: JSON.parse(bytes.toString()) });
      });
    });
    request.on('error', (error) => setTimeout(() => reject(error), 2000));
    request.end(body);
  });

// 1. The upload measures the file: its SHA-256 and size are signed.
const good = await seal();
assert.ok(good.frames.length >= 2, 'the file needs at least two frames');
const done = await post(good.start, good.frames);
assert.equal(done.status, 200, JSON.stringify(done.error));
assert.equal(done.measured.master_file.file_blake3, fileBlake3);
assert.equal(done.measured.master_file.file_size, String(file.length));
assert.equal(done.measured.public_key, keyJson.public_key);
const measurement = await Effect.runPromise(sdk.decodeMeasurement(done.measured));
console.log(`measured ${file.length} bytes in ${good.frames.length} frames in ${done.seconds.toFixed(2)} s: ${measurement.pcm.channels} ch, ${measurement.pcm.bitDepth}-bit, ${measurement.pcm.sampleRateHz} Hz, blake3 ${fileBlake3.slice(0, 16)}…, blob ${done.measured.audio.blob_id}`);

// 2. Tampering is refused.
const swap = (frames, a, b) => frames.map((f, i) => (i === a ? frames[b] : i === b ? frames[a] : f));
const flip = (frames, index, at) => frames.map((f, i) => (i === index ? f.map((byte, j) => (j === at ? byte ^ 1 : byte)) : f));
const otherRecording = new TextEncoder().encode(JSON.stringify({ ...good.startJson, recording_id: '0x' + 'c1'.repeat(32) }));
const expired = await seal({ expiresMs: BigInt(Date.now() - 1000) });
const otherKey = await seal({ target: { x25519PublicKey: crypto.getRandomValues(new Uint8Array(32)) } });
const cases = [
  ['reordered frames', good.start, swap(good.frames, 0, 1), 'upload_rejected'],
  ['a dropped frame', good.start, good.frames.filter((_, i) => i !== 1), 'upload_rejected'],
  ['a changed byte', good.start, flip(good.frames, 1, 40), 'upload_rejected'],
  ['the final frame missing', good.start, good.frames.slice(0, -1), 'upload_rejected'],
  ['another recording ID in info', otherRecording, good.frames, 'upload_rejected'],
  // Refused on the start record, before any frame is read: only the record is sent.
  ['an expired upload key', expired.start, [], 'upload_key_expired'],
  ['another X25519 key', otherKey.start, otherKey.frames, 'upload_rejected'],
];
for (const [name, start, frames, error] of cases) {
  const answer = await post(start, frames);
  assert.equal(answer.status, 400, `${name}: ${answer.status}`);
  assert.equal(answer.error.error, error, `${name}: ${JSON.stringify(answer.error)}`);
  console.log(`refused ${name}: ${answer.error.error}: ${answer.error.message}`);
}
console.log('ok: the SDK and the enclave agree, and every tampering is refused');
