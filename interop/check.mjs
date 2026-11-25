// Checks the enclave's output with the browser's code: app-v2's `src/posts/tink.ts` decrypts the
// ciphertexts, and app-v2's `@mysten/seal` parses the sealed DEK and loads the pinned key server
// from the network. Usage: node interop/check.mjs <app-v2 checkout> <out-dir> <flac> <recording-id>
// with NETWORK=mainnet for output of the mainnet pins (`--features mainnet`); testnet by default.
//
// tink.ts is the app's file with one change: its segment size, 65,536 bytes for posts, is set
// to 1,048,576 (`AES256_GCM_HKDF_1MB`). The script refuses a tink.ts that does not declare it
// exactly once.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [appDir, outDir, flacPath, recordingId] = process.argv.slice(2);
if (!recordingId) throw new Error('usage: check.mjs <app-v2> <out-dir> <flac> <recording-id>');
const read = (name) => readFileSync(join(outDir, name));
const requireApp = createRequire(join(appDir, 'package.json'));
const load = (name) => import(pathToFileURL(requireApp.resolve(name)).href);

const NETWORKS = {
  testnet: {
    SEAL_PACKAGE: '0xc370c70e65b1aa16f429b90dc1ee7080fb4090ddb1b3c914adc32b8b430f0270',
    KEY_SERVER: '0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98',
    AGGREGATOR: 'https://seal-aggregator-testnet.mystenlabs.com',
    PINNED_PK:
      'b8068e916e76791ec188624be83cabe2563719ed991a9732e54e8a04271037bc5f3b35356b2f9e22b3f5aa84856800f2' +
      '19bc7472422ffcaced0c921f43b4f192662deb294c0639dbf0e2d00ade5483bcae7c70b25f9c8a1d3d21130ce441febe',
  },
  mainnet: {
    SEAL_PACKAGE: '0xe0262111397c8bfbef7ec8b785e249ce6b4eaf03c63cc4caf11b99fb38ebc0ec',
    KEY_SERVER: '0x686098f1439237fff9f36b99c7329683c22979d2005c2465cb891acb012a7595',
    AGGREGATOR: 'https://seal-aggregator-mainnet.mystenlabs.com',
    PINNED_PK:
      'aa2bc42ff27451d38d83f491d05ca200b20a0bf5704e48c4b02fdd4d33397556b4e3e8a2467cd129b469ae314879dee8' +
      '17a804590d4aeca548124da68cc8f4d90cc3fdacc3b30936a393938eb4bb2315e91b0dc8ab704ceae22c314c6ef91198',
  },
};
const NETWORK = process.env.NETWORK || 'testnet';
if (!Object.hasOwn(NETWORKS, NETWORK)) throw new Error(`NETWORK must be testnet or mainnet, not ${NETWORK}`);
const { SEAL_PACKAGE, KEY_SERVER, AGGREGATOR, PINNED_PK } = NETWORKS[NETWORK];

// 1. Tink: app-v2's tink.ts at 1 MiB segments.
const source = readFileSync(join(appDir, 'src/posts/tink.ts'), 'utf8');
const declaration = 'export const SEGMENT_BYTES = 65_536;';
assert.equal(source.split(declaration).length, 2, 'tink.ts declares SEGMENT_BYTES once');
const copy = join(mkdtempSync(join(tmpdir(), 'tink-')), 'tink.ts');
writeFileSync(copy, source.replace(declaration, 'export const SEGMENT_BYTES = 1_048_576;'));
const tink = await import(pathToFileURL(copy).href);

const kat = JSON.parse(read('kat.json'));
assert.equal(kat.segment_bytes, 1_048_576);
const katCiphertext = read('kat.bin');
assert.equal(createHash('sha256').update(katCiphertext).digest('hex'), kat.ciphertext_sha256);
const katPlain = await tink.decryptBytes(Buffer.from(kat.dek, 'hex'), new Uint8Array(), katCiphertext);
assert.equal(katPlain.length, kat.plaintext_len);
assert.ok(katPlain.every((byte, index) => byte === (index * 31 + 7) % 251), 'KAT plaintext');
assert.equal(tink.ciphertextSize(kat.plaintext_len), katCiphertext.length);
console.log(`tink.ts: decrypted the ${katCiphertext.length}-byte known answer (3 segments)`);

const flac = readFileSync(flacPath);
const dek = Buffer.from(read('test_dek.hex').toString(), 'hex');
const master = read('test_ciphertext.bin');
const opened = await tink.decryptBytes(dek, new Uint8Array(), master);
assert.deepEqual(Buffer.from(opened), flac);
const streamed = await new Response(new Blob([master]).stream().pipeThrough(tink.decryptStream(dek, new Uint8Array()))).arrayBuffer();
assert.deepEqual(Buffer.from(streamed), flac);
await assert.rejects(tink.decryptBytes(dek, new Uint8Array([1]), master));
console.log(`tink.ts: decrypted the /measure ciphertext of ${flacPath} to the file, whole and streamed`);

// 2. Seal: the sealed DEK as @mysten/seal parses it.
const { EncryptedObject, SealClient } = await load('@mysten/seal');
const { fromHex, toHex } = await load('@mysten/sui/utils');
const { SuiGrpcClient } = await load('@mysten/sui/grpc');
const response = JSON.parse(read('response.json'));
const blobIdBytes = Buffer.from(response.audio.blob_id, 'base64url');
assert.equal(blobIdBytes.length, 32);
const sealed = EncryptedObject.parse(fromHex(response.audio.sealed_dek));
const identity = toHex(fromHex(recordingId)) + toHex(blobIdBytes);
assert.equal(sealed.version, 0);
assert.equal(sealed.packageId, SEAL_PACKAGE);
assert.equal(sealed.id, identity);
assert.equal(sealed.threshold, 1);
assert.deepEqual(sealed.services, [[KEY_SERVER, 1]]);
assert.ok(sealed.ciphertext.Aes256Gcm, 'AES-256-GCM DEM');
assert.equal(sealed.ciphertext.Aes256Gcm.blob.length, 48);
assert.deepEqual([...sealed.ciphertext.Aes256Gcm.aad], []);
console.log(`@mysten/seal: package ${sealed.packageId}, identity ${sealed.id}, server ${sealed.services[0][0]}, threshold ${sealed.threshold}`);
// The u256 decimal is the same number as the base64url bytes read little-endian.
assert.equal(BigInt('0x' + Buffer.from(blobIdBytes).reverse().toString('hex')).toString(), response.audio.blob_id_u256);

// 3. The key server, from the network through @mysten/seal: the pinned key is its key.
const suiClient = new SuiGrpcClient({ network: NETWORK, baseUrl: `https://fullnode.${NETWORK}.sui.io:443` });
const client = new SealClient({ suiClient, serverConfigs: [{ objectId: KEY_SERVER, weight: 1, aggregatorUrl: AGGREGATOR }], verifyKeyServers: false });
const servers = await client.getKeyServers();
const server = servers.get(KEY_SERVER);
assert.equal(toHex(server.pk), PINNED_PK);
console.log(`@mysten/seal: ${NETWORK} key server ${server.name} (${server.serverType}) has the pinned key`);
// And the SDK's own encryption to it has the enclave's shape.
const own = await client.encrypt({ threshold: 1, packageId: SEAL_PACKAGE, id: identity, data: new Uint8Array(32) });
const parsed = EncryptedObject.parse(own.encryptedObject);
assert.equal(own.encryptedObject.length, fromHex(response.audio.sealed_dek).length);
assert.deepEqual(parsed.services, sealed.services);
assert.equal(parsed.id, sealed.id);
console.log(`@mysten/seal: its own EncryptedObject for the same identity is ${own.encryptedObject.length} bytes, as the enclave's`);
