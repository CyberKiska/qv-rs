import { createPrivateKey, createPublicKey, sign as nodeSign, webcrypto } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const oracleRoot = path.resolve(repoRoot, '../qv-work/quantum-vault');
const outputRoot = path.resolve(repoRoot, 'fixtures/js-oracle');
const require = createRequire(import.meta.url);
const requireFromOracle = createRequire(path.join(oracleRoot, 'package.json'));

const indexModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/index.js')));
const qencModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/qenc/format.js')));
const qcontBuildModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/qcont/build.js')));
const qcontRestoreModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/qcont/restore.js')));
const qcontAttachModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/qcont/attach.js')));
const manifestArchiveModule = await import(
  pathToFileURL(path.join(oracleRoot, 'src/core/crypto/manifest/archive-manifest.js'))
);
const manifestBundleModule = await import(
  pathToFileURL(path.join(oracleRoot, 'src/core/crypto/manifest/manifest-bundle.js'))
);
const mlkemModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/mlkem.js')));
const kdfModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/kdf.js')));
const aeadModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/aead.js')));
const bytesModule = await import(pathToFileURL(path.join(oracleRoot, 'src/core/crypto/bytes.js')));
const { ml_dsa87 } = await import(
  pathToFileURL(requireFromOracle.resolve('@noble/post-quantum/ml-dsa.js'))
);

const { encryptFile, hashBytes, CHUNK_SIZE, generateKeyPair } = indexModule;
const { parseQencHeader } = qencModule;
const { buildQcontShards } = qcontBuildModule;
const { parseShard, restoreFromShards } = qcontRestoreModule;
const { attachManifestBundleToShards } = qcontAttachModule;
const { canonicalizeArchiveManifest } = manifestArchiveModule;
const { canonicalizeManifestBundle } = manifestBundleModule;
const { decapsulate } = mlkemModule;
const { deriveKeyWithKmac } = kdfModule;
const { deriveChunkIvFromK } = aeadModule;
const { asciiBytes, bytesToBase64, digestSha256 } = bytesModule;

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

async function blobToBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

async function writeBinary(filePath, bytes) {
  await writeFile(filePath, Buffer.from(bytes));
}

function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 31];
  }
  while ((out.length % 8) !== 0) out += '=';
  return out;
}

function crc16Xmodem(bytes) {
  let crc = 0x0000;
  for (let i = 0; i < bytes.length; i += 1) {
    crc ^= bytes[i] << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      if ((crc & 0x8000) !== 0) crc = ((crc << 1) ^ 0x1021) & 0xffff;
      else crc = (crc << 1) & 0xffff;
    }
  }
  return crc;
}

function encodeStellarAddress(publicKeyBytes) {
  const version = 6 << 3;
  const payload = Buffer.concat([Buffer.from([version]), Buffer.from(publicKeyBytes)]);
  const crc = crc16Xmodem(payload);
  const checksum = Buffer.from([crc & 0xff, (crc >>> 8) & 0xff]);
  return base32Encode(Buffer.concat([payload, checksum])).replace(/=+$/g, '');
}

function u16le(value) {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, true);
  return out;
}

function u32le(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, true);
  return out;
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j += 1) {
      crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

async function sha3_256(bytes) {
  const mod = await import(pathToFileURL(requireFromOracle.resolve('@noble/hashes/sha3.js')));
  return mod.sha3_256(bytes);
}

async function buildQsigFixture(messageBytes, seedByte) {
  const suiteId = 0x03;
  const seed = new Uint8Array(32).fill(seedByte);
  const keys = ml_dsa87.keygen(seed);
  const fileHashHex = await hashBytes(messageBytes);
  const fileHash = Buffer.from(fileHashHex, 'hex');
  const tbs = Buffer.concat([
    Buffer.from('QSTB'),
    Buffer.from([0x01, 0x00, 0x01, 0x00, suiteId, 0x01, 0x00]),
    fileHash,
  ]);
  const signature = ml_dsa87.sign(tbs, keys.secretKey, { extraEntropy: false });
  const fingerprintRecord = Buffer.concat([
    Buffer.from([0x01]),
    Buffer.from(await sha3_256(keys.publicKey)),
  ]);
  const metaBytes = Buffer.concat([
    Buffer.from([0x10]),
    Buffer.from(u16le(keys.publicKey.length)),
    Buffer.from(keys.publicKey),
    Buffer.from([0x11]),
    Buffer.from(u16le(fingerprintRecord.length)),
    fingerprintRecord,
  ]);
  const qsigBytes = Buffer.concat([
    Buffer.from('PQSG'),
    Buffer.from([0x01, 0x00, suiteId, 0x01]),
    Buffer.from(u16le(0x000f)),
    fileHash,
    Buffer.from([0x00, 0x00]),
    Buffer.from(u16le(metaBytes.length)),
    Buffer.from(u32le(signature.length)),
    metaBytes,
    Buffer.from(signature),
  ]);
  const pqpkPrefix = Buffer.concat([
    Buffer.from('PQPK'),
    Buffer.from([0x01, 0x00, suiteId, 0x00]),
    Buffer.from(u32le(keys.publicKey.length)),
    Buffer.from(keys.publicKey),
  ]);
  const pqpkBytes = Buffer.concat([pqpkPrefix, Buffer.from(u32le(crc32(pqpkPrefix)))]);
  return { qsigBytes: new Uint8Array(qsigBytes), pqpkBytes: new Uint8Array(pqpkBytes) };
}

function pkcs8Ed25519FromSeed(seed) {
  return Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(seed),
  ]);
}

async function buildStellarSignatureFixture(messageBytes, seedByte) {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({ key: pkcs8Ed25519FromSeed(seed), format: 'der', type: 'pkcs8' });
  const publicKeyDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const publicKeyBytes = new Uint8Array(publicKeyDer.subarray(publicKeyDer.length - 32));
  const signer = encodeStellarAddress(publicKeyBytes);
  const hashes = [
    { alg: 'SHA-256', hex: Buffer.from(await digestSha256(messageBytes)).toString('hex') },
    { alg: 'SHA3-512', hex: await hashBytes(messageBytes) },
  ];
  const message = [
    'STELLAR-WSIGN/v1',
    'type=file',
    `size=${messageBytes.length}`,
    'hashes=SHA-256,SHA3-512',
    `sha256=${hashes[0].hex}`,
    `sha3_512=${hashes[1].hex}`,
  ].join('\n');
  const payload = await digestSha256(textBytes(`Stellar Signed Message:\n${message}`));
  const signature = nodeSign(null, Buffer.from(payload), privateKey);
  const doc = {
    schema: 'stellar-file-signature/v1',
    mode: 'sep53',
    input: { type: 'file' },
    signer,
    message,
    hashes,
    signatureB64: bytesToBase64(new Uint8Array(signature)),
  };
  return {
    bytes: textBytes(JSON.stringify(doc)),
    signer,
  };
}

function createLargeDeterministicPayload(length) {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = (i * 29 + 7) & 0xff;
  }
  return bytes;
}

async function buildOtsFixture(stampedBytes, { completeProof = false } = {}) {
  const header = Buffer.concat([
    Buffer.from('\x00OpenTimestamps\x00\x00Proof\x00', 'binary'),
    Buffer.from([0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01, 0x08]),
    Buffer.from(await digestSha256(stampedBytes)),
  ]);
  const tail = completeProof
    ? createLargeDeterministicPayload(1600)
    : createLargeDeterministicPayload(96);
  return new Uint8Array(Buffer.concat([header, Buffer.from(tail)]));
}

async function summarizeShardSet(rootDir, filePrefix, shardBlobs, split) {
  const shards = [];
  for (const shard of shardBlobs) {
    const shardBytes = shard.blob ? await blobToBytes(shard.blob) : shard.bytes;
    const fileName = `${filePrefix}.part${shard.index + 1}-of-${split.n}.qcont`;
    await writeBinary(path.join(rootDir, fileName), shardBytes);
    const parsed = parseShard(shardBytes);
    shards.push({
      fileName,
      shardIndex: parsed.shardIndex,
      manifestDigestHex: parsed.manifestDigestHex,
      bundleDigestHex: parsed.bundleDigestHex,
      shareLength: parsed.share.length,
      fragmentsLength: parsed.fragments.length,
      keyCommitmentHex: Buffer.from(parsed.keyCommit).toString('hex'),
    });
  }
  return shards;
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
    const built = await buildQcontShards(qencBytes, secretKey, { n: split.n, k: split.k }, {
      authPolicyLevel: split.authPolicyLevel,
      minValidSignatures: split.minValidSignatures ?? 1,
    });
    const splitRandomTrace = runtime.randomTrace.slice(randomTraceBeforeSplit);
    const sssRandomHex = splitRandomTrace.map((entry) => entry.hex).join('');
    const manifestCanonical = canonicalizeArchiveManifest(built.manifest);
    const bundleCanonical = canonicalizeManifestBundle(built.bundle);
    await writeBinary(path.join(fixtureDir, 'manifest.qvmanifest.json'), built.manifestBytes);
    await writeBinary(path.join(fixtureDir, 'initial.extended.qvmanifest.json'), built.bundleBytes);

    const shards = await summarizeShardSet(fixtureDir, filename, built.shards, split);

    const splitExpectations = {
      params: { n: split.n, k: split.k },
      authPolicyLevel: split.authPolicyLevel,
      minValidSignatures: split.minValidSignatures ?? 1,
      manifest: built.manifest,
      bundle: built.bundle,
      manifestDigestHex: built.manifestDigestHex,
      bundleDigestHex: built.bundleDigestHex,
      manifestCanonical: manifestCanonical.canonical,
      bundleCanonical: bundleCanonical.canonical,
      sssRandomHex,
      sssRandomTraceLengths: splitRandomTrace.map((entry) => entry.length),
      shardCount: built.shards.length,
      shards,
    };

    if (split.includeSignatures) {
      const qsig = await buildQsigFixture(built.manifestBytes, split.qsigSeedByte ?? 0x61);
      const qsigB = await buildQsigFixture(built.manifestBytes, split.qsigSeedByteB ?? 0x62);
      const stellar = await buildStellarSignatureFixture(
        built.manifestBytes,
        split.stellarSeedByte ?? 0x71
      );
      const otsA = await buildOtsFixture(qsig.qsigBytes, { completeProof: false });
      const otsB = await buildOtsFixture(qsigB.qsigBytes, { completeProof: true });

      await writeBinary(path.join(fixtureDir, 'archive.qsig'), qsig.qsigBytes);
      await writeBinary(path.join(fixtureDir, 'archive.pqpk'), qsig.pqpkBytes);
      await writeBinary(path.join(fixtureDir, 'archive.sig'), stellar.bytes);
      await writeBinary(path.join(fixtureDir, 'archive.qsig.ots'), otsA);
      await writeBinary(path.join(fixtureDir, 'archive-b.qsig'), qsigB.qsigBytes);
      await writeBinary(path.join(fixtureDir, 'archive-b.pqpk'), qsigB.pqpkBytes);
      await writeBinary(path.join(fixtureDir, 'archive-b.qsig.ots'), otsB);

      const parsedBaseShards = [];
      for (const shard of built.shards) {
        parsedBaseShards.push(parseShard(await blobToBytes(shard.blob)));
      }

      const attached = await attachManifestBundleToShards(parsedBaseShards, {
        signatures: [{ name: 'archive.qsig', bytes: qsig.qsigBytes }],
        pqPublicKeyFileBytesList: [qsig.pqpkBytes],
        timestamps: [{ name: 'archive.qsig.ots', bytes: otsA }],
      });
      await writeBinary(
        path.join(fixtureDir, 'attached.extended.qvmanifest.json'),
        attached.bundleBytes
      );
      const attachedShards = await summarizeShardSet(
        fixtureDir,
        `${filename}.attached`,
        attached.shards,
        split
      );

      const attachedTwice = await attachManifestBundleToShards([], {
        bundleBytes: attached.bundleBytes,
        signatures: [{ name: 'archive-b.qsig', bytes: qsigB.qsigBytes }],
        pqPublicKeyFileBytesList: [qsigB.pqpkBytes],
        timestamps: [{ name: 'archive-b.qsig.ots', bytes: otsB }],
        embedIntoShards: false,
      });
      await writeBinary(
        path.join(fixtureDir, 'attached-twice.extended.qvmanifest.json'),
        attachedTwice.bundleBytes
      );

      splitExpectations.signatures = {
        qsigFile: 'archive.qsig',
        pqpkFile: 'archive.pqpk',
        stellarSigFile: 'archive.sig',
        otsFile: 'archive.qsig.ots',
        qsigBFile: 'archive-b.qsig',
        pqpkBFile: 'archive-b.pqpk',
        otsBFile: 'archive-b.qsig.ots',
        stellarSigner: stellar.signer,
      };
      splitExpectations.attached = {
        bundleFile: 'attached.extended.qvmanifest.json',
        bundleDigestHex: attached.bundleDigestHex,
        shardCount: attached.shards.length,
        shards: attachedShards,
      };
      splitExpectations.attachedTwice = {
        bundleFile: 'attached-twice.extended.qvmanifest.json',
        bundleDigestHex: attachedTwice.bundleDigestHex,
      };
    }

    expectations.split = splitExpectations;
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
  split: { n: 5, k: 3, authPolicyLevel: 'integrity-only' },
});

await buildFixture({
  name: 'split-7of5-chunked',
  seedByte: 0x44,
  randomSeed: 0x13579bdf,
  timestamp: '2026-03-04T22:33:19.000Z',
  payload: deterministicBytes(CHUNK_SIZE + 50_000),
  filename: 'split-7of5-chunked.bin',
  split: { n: 7, k: 5, authPolicyLevel: 'integrity-only' },
});

await buildFixture({
  name: 'split-5of3-anysig',
  seedByte: 0x55,
  randomSeed: 0x42424242,
  timestamp: '2026-03-05T10:00:00.000Z',
  payload: textBytes('split-5of3-anysig-fixture'),
  filename: 'split-5of3-anysig.bin',
  split: {
    n: 5,
    k: 3,
    authPolicyLevel: 'any-signature',
    includeSignatures: true,
    qsigSeedByte: 0x51,
    qsigSeedByteB: 0x52,
    stellarSeedByte: 0x53,
  },
});

await buildFixture({
  name: 'split-5of3-strongpq',
  seedByte: 0x66,
  randomSeed: 0x51515151,
  timestamp: '2026-03-05T10:05:00.000Z',
  payload: textBytes('split-5of3-strongpq-fixture'),
  filename: 'split-5of3-strongpq.bin',
  split: {
    n: 5,
    k: 3,
    authPolicyLevel: 'strong-pq-signature',
    includeSignatures: true,
    qsigSeedByte: 0x61,
    qsigSeedByteB: 0x62,
    stellarSeedByte: 0x63,
  },
});
