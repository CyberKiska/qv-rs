import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const oracleRoot = path.resolve(repoRoot, '../qv-work/quantum-vault');
const outputRoot = path.resolve(repoRoot, 'fixtures/js-oracle');
const require = createRequire(import.meta.url);

const indexModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/index.js')));
const qencModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/qenc/format.js')));
const qcontModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/qcont/build.js')));
const qcontRestoreModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/qcont/restore.js')));
const manifestModule = await import(
  pathToFileURL(path.join(oracleRoot, 'src/core/crypto/manifest/archive-manifest.js'))
);
const mlkemModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/mlkem.js')));
const kdfModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/kdf.js')));
const aeadModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/aead.js')));

const { encryptFile, hashBytes, CHUNK_SIZE, generateKeyPair } = indexModule;
const { parseQencHeader } = qencModule;
const { buildQcontShards } = qcontModule;
const { parseShard } = qcontRestoreModule;
const { canonicalizeArchiveManifest } = manifestModule;
const { decapsulate } = mlkemModule;
const { deriveKeyWithKmac } = kdfModule;
const { deriveChunkIvFromK } = aeadModule;

function createDeterministicRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = Math.imul(state ^ (state >>> 15), 1 | state);
    value ^= value + Math.imul(value ^ (value >>> 7), 61 | value);
    return ((value ^ (value >>> 14)) >>> 0) & 0xff;
  };
}

function installDeterministicRuntime(randomSeed, isoTimestamp) {
  const nextByte = createDeterministicRandom(randomSeed);
  const fixedNow = new Date(isoTimestamp);
  const randomTrace = [];
  const recordRandom = (target) => {
    for (let i = 0; i < target.length; i += 1) {
      target[i] = nextByte();
    }
    randomTrace.push({
      length: target.length,
      hex: Buffer.from(target).toString('hex'),
    });
    return target;
  };

  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: {
      subtle: webcrypto.subtle,
      getRandomValues(target) {
        return recordRandom(target);
      },
    },
  });

  const nodeCrypto = require('node:crypto');
  nodeCrypto.randomBytes = (length) => {
    const bytes = recordRandom(new Uint8Array(length));
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  };
  syncBuiltinESMExports();

  const csprngPath = require.resolve('shamir-secret-sharing/csprng', {
    paths: [oracleRoot],
  });
  const csprngModule = require(csprngPath);
  csprngModule.getRandomBytes = (length) => recordRandom(new Uint8Array(length));

  class FixedDate extends Date {
    constructor(...args) {
      if (args.length === 0) {
        super(fixedNow.toISOString());
      } else {
        super(...args);
      }
    }

    static now() {
      return fixedNow.getTime();
    }
  }

  Object.defineProperty(globalThis, 'Date', {
    configurable: true,
    value: FixedDate,
  });

  return { randomTrace };
}

async function ensureErasureRuntime() {
  const source = await readFile(path.join(oracleRoot, 'public/third-party/erasure.js'), 'utf8');
  const cjsShim = { exports: {} };
  const evaluate = new Function('module', 'exports', source);
  evaluate(cjsShim, cjsShim.exports);
  globalThis.erasure = cjsShim.exports;
}

function textBytes(value) {
  return new TextEncoder().encode(value);
}

function deterministicBytes(length) {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = (i * 31 + 17) & 0xff;
  }
  return bytes;
}

function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

async function writeBinary(filePath, bytes) {
  await writeFile(filePath, Buffer.from(bytes));
}

async function buildFixture({
  name,
  seedByte,
  randomSeed,
  timestamp,
  payload,
  filename,
  split = null,
}) {
  const runtime = installDeterministicRuntime(randomSeed, timestamp);
  const seed = new Uint8Array(64).fill(seedByte);
  const { publicKey, secretKey } = await generateKeyPair({ customSeed: seed });
  const qencBlob = await encryptFile(payload, publicKey, filename);
  const qencBytes = await blobToBytes(qencBlob);
  const qencHeader = parseQencHeader(qencBytes);
  const sharedSecret = await decapsulate(qencHeader.encapsulatedKey, secretKey);
  const derived = await deriveKeyWithKmac(
    sharedSecret,
    qencHeader.kdfSalt,
    qencHeader.metaBytes,
    qencHeader.metadata.domainStrings
  );

  const fixtureDir = path.join(outputRoot, name);
  await mkdir(fixtureDir, { recursive: true });
  await writeBinary(path.join(fixtureDir, 'public.qkey'), publicKey);
  await writeBinary(path.join(fixtureDir, 'secret.qkey'), secretKey);
  await writeBinary(path.join(fixtureDir, 'payload.bin'), payload);
  await writeBinary(path.join(fixtureDir, 'container.qenc'), qencBytes);

  const expectations = {
    fixtureName: name,
    timestamp,
    payloadLength: payload.length,
    input: {
      originalFilename: filename,
      payloadHash: await hashBytes(payload),
      keygenSeedHex: Buffer.from(seed).toString('hex'),
    },
    qenc: {
      headerLength: qencHeader.offset,
      metadata: qencHeader.metadata,
      metaUtf8: new TextDecoder().decode(qencHeader.metaBytes),
      encapsulatedKeyLength: qencHeader.encapsulatedKey.length,
      encapsulatedKeyHex: Buffer.from(qencHeader.encapsulatedKey).toString('hex'),
      containerNonceHex: Buffer.from(qencHeader.containerNonce).toString('hex'),
      kdfSaltHex: Buffer.from(qencHeader.kdfSalt).toString('hex'),
      keyCommitmentHex: Buffer.from(qencHeader.storedKeyCommitment).toString('hex'),
      sharedSecretHex: Buffer.from(sharedSecret).toString('hex'),
      encapsulationSeedHex: runtime.randomTrace[0]?.hex ?? null,
      krawHex: Buffer.from(derived.Kraw).toString('hex'),
      kencHex: Buffer.from(derived.Kenc).toString('hex'),
      kivHex: Buffer.from(derived.Kiv).toString('hex'),
      qencHash: await hashBytes(qencBytes),
      randomTrace: runtime.randomTrace,
    },
  };

  if (qencHeader.metadata.aead_mode === 'per-chunk-aead') {
    expectations.qenc.firstChunkIvHex = Buffer.from(
      deriveChunkIvFromK(
        derived.Kiv,
        qencHeader.containerNonce,
        0,
        qencHeader.metadata.domainStrings.iv,
        {
          ivStrategy: qencHeader.metadata.iv_strategy,
          chunkCount: qencHeader.metadata.chunkCount,
          maxChunkCount: qencHeader.metadata.maxChunkCount,
          counterBits: qencHeader.metadata.counterBits,
        }
      )
    ).toString('hex');
  }

  if (split) {
    const randomTraceBeforeSplit = runtime.randomTrace.length;
    const built = await buildQcontShards(qencBytes, secretKey, split);
    const splitRandomTrace = runtime.randomTrace.slice(randomTraceBeforeSplit);
    const sssRandomHex = splitRandomTrace.map((entry) => entry.hex).join('');
    const manifestBytes = built.manifestBytes;
    const manifestCanonical = canonicalizeArchiveManifest(built.manifest);
    await writeBinary(path.join(fixtureDir, 'manifest.qvmanifest.json'), manifestBytes);

    const shards = [];
    for (const shard of built.shards) {
      const shardBytes = await blobToBytes(shard.blob);
      const fileName = `${filename}.part${shard.index + 1}-of-${split.n}.qcont`;
      await writeBinary(path.join(fixtureDir, fileName), shardBytes);
      const parsed = parseShard(shardBytes);
      shards.push({
        fileName,
        shardIndex: parsed.shardIndex,
        manifestDigestHex: parsed.manifestDigestHex,
        shareLength: parsed.share.length,
        fragmentsLength: parsed.fragments.length,
        keyCommitmentHex: Buffer.from(parsed.keyCommit).toString('hex'),
      });
    }

    expectations.split = {
      params: split,
      manifest: built.manifest,
      manifestDigestHex: built.manifestDigestHex,
      manifestCanonical: manifestCanonical.canonical,
      manifestHashHex: Buffer.from(manifestCanonical.bytes).toString('hex'),
      sssRandomHex,
      sssRandomTraceLengths: splitRandomTrace.map((entry) => entry.length),
      shardCount: built.shards.length,
      shards,
    };
  }

  await writeFile(
    path.join(fixtureDir, 'expectations.json'),
    JSON.stringify(expectations, null, 2) + '\n',
    'utf8'
  );
}

await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });
await ensureErasureRuntime();

await buildFixture({
  name: 'single-small',
  seedByte: 0x11,
  randomSeed: 0x12345678,
  timestamp: '2026-03-04T22:30:47.000Z',
  payload: textBytes('single-small-fixture'),
  filename: 'single-small.bin',
  split: null,
});

await buildFixture({
  name: 'chunked-large',
  seedByte: 0x22,
  randomSeed: 0x87654321,
  timestamp: '2026-03-04T22:31:11.000Z',
  payload: deterministicBytes(CHUNK_SIZE + 12_345),
  filename: 'chunked-large.bin',
  split: null,
});

await buildFixture({
  name: 'split-5of3',
  seedByte: 0x33,
  randomSeed: 0x2468ace0,
  timestamp: '2026-03-04T22:32:03.000Z',
  payload: textBytes('split-5of3-fixture'),
  filename: 'split-5of3.bin',
  split: { n: 5, k: 3 },
});

await buildFixture({
  name: 'split-7of5-chunked',
  seedByte: 0x44,
  randomSeed: 0x13579bdf,
  timestamp: '2026-03-04T22:33:19.000Z',
  payload: deterministicBytes(CHUNK_SIZE + 50_000),
  filename: 'split-7of5-chunked.bin',
  split: { n: 7, k: 5 },
});
