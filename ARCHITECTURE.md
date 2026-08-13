# qv-rs / qv-cli Architecture

## Purpose

`qv-rs` is the standalone Rust implementation of the current Quantum Vault format family; `qvault-cli` is its executable and `qvault-core` is its reusable library. It is not a new protocol and it has no runtime dependency on the JavaScript Quantum Vault project. Rust implements all supported parsing, cryptography, lifecycle, and recovery operations locally while preserving byte/format interoperability with a pinned JavaScript oracle.

Quantum Vault protects archives by combining:

- post-quantum confidentiality for the encrypted payload
- threshold recoverability through shard cohorts
- byte-stable archive identity through canonical JSON descriptors
- mutable authenticity evidence through lifecycle bundles
- fail-closed restore policy

## Workspace Layout

```text
qv-cli/
├── crates/
│   ├── qvault-core/
│   │   ├── src/
│   │   │   ├── auth/
│   │   │   ├── lifecycle/
│   │   │   ├── manifest/
│   │   │   ├── qcont/
│   │   │   ├── qenc/
│   │   │   └── ...
│   │   └── tests/
│   └── qvault-cli/
│       ├── src/main.rs
│       └── tests/
├── docs/
├── fuzz/
├── tools/
├── ARCHITECTURE.md
├── README.md
└── USAGE.md
```

## Crate Responsibilities

`qvault-core` owns:

- `.qenc` parse/build/encrypt/decrypt
- OS-backed randomness, KEM/KDF/AEAD operations, and PQ signing
- strict JSON and RFC 8785-style canonicalization
- archive-state, cohort-binding, transition-record, source-evidence, and lifecycle-bundle validation
- `QVqcont-7` shard parse/build/restore/attach/reshare logic
- detached signature and timestamp evidence verification
- archive policy evaluation and fail-closed restore decisions

`qvault-cli` owns:

- argument parsing
- local file I/O
- output path and symlink policy
- JSON and text reporting
- stable process exit codes
- atomic local writes and owner-only modes for secret outputs on Unix
- input-size budgets, output collision checks, portable filename policy, and symlink policy

The CLI should stay thin. Wire-format decisions belong in `qvault-core`.

## Core Data Model

### `.qenc`

The confidentiality layer is the current Quantum Vault `.qenc` format:

- ML-KEM-1024 encapsulation
- KMAC256 derivation tree
- AES-256-GCM single-container and per-chunk modes
- mandatory key commitment
- `wrapped-v1` private metadata
- optional `QVB1` multi-file payload bytes

Production encryption draws an ML-KEM encapsulation seed, a 96-bit container nonce, and a KDF salt from the operating-system CSPRNG. The nonce and salt are acquired in one provider call. A bounded in-process replay guard fingerprints the encapsulated key/nonce/salt tuple and rejects repeats. Small payloads use one AES-GCM operation; larger payloads use 8 MiB chunks with KMAC-derived 64-bit IV prefixes and a bounded 32-bit big-endian counter. Metadata/header bytes and chunk geometry are authenticated.

Deterministic QENC and ML-KEM entry points are absent from normal builds. They compile only with the non-default `deterministic-test-vectors` feature for exact frozen interoperability cases.

### Archive-state Descriptor

The archive-state descriptor is the immutable approval target. Its canonical bytes define `stateId = SHA3-512(archiveStateBytes)` and carry the `authPolicyCommitment`.

Archive approval signatures sign these canonical bytes, not lifecycle-bundle bytes.

### Cohort Binding

The cohort binding binds one shard cohort to an archive state. It carries:

- Shamir and Reed-Solomon parameters
- shard body hash commitments
- raw Shamir share commitments
- canonical shard body include/exclude rules

`cohortId` is derived from `archiveId`, `stateId`, and `cohortBindingDigest`; it is not stored inside canonical cohort-binding bytes.

### Lifecycle Bundle

`QV-Lifecycle-Bundle` v1 is mutable evidence. It embeds the current archive-state and cohort-binding objects plus:

- archive policy
- archive-approval signatures
- maintenance signatures
- source-evidence signatures
- signer public keys
- OpenTimestamps proofs
- same-state resharing transition records
- source-evidence objects

Attach and reshare may update lifecycle-bundle bytes, but must not mutate canonical archive-state or cohort-binding bytes.

The bundle is an evidence carrier, not a trust store. Embedded `.pqpk` material and QSIG-embedded keys may establish raw cryptographic validity, but only operator-supplied `VerificationInputs` pins authorize a signer and contribute to archive policy or trusted maintenance/source-evidence status.

### `QVqcont-7`

Each shard embeds:

- canonical archive-state bytes and digest
- canonical cohort-binding bytes and digest
- canonical lifecycle-bundle bytes and digest
- ML-KEM encapsulated key material copied from `.qenc`
- container nonce and KDF salt
- one Shamir share
- Reed-Solomon fragment body
- successor metadata (`artifactFamily = "successor-lifecycle-v1"`)

Restore rejects old shard formats and unknown artifact families.

## Restore Flow

1. Parse shards strictly as `QVqcont-7`.
2. Validate embedded archive-state, cohort-binding, and lifecycle-bundle digests.
3. Group candidates by `archiveId`, `stateId`, `cohortId`, exact archive-state bytes, and exact cohort-binding bytes.
4. Require explicit selection or acknowledgement when multiple lifecycle-bundle variants are present.
5. Verify archive approval, maintenance, source-evidence, signer pins, and timestamp linkage, then enforce archive policy before materializing secrets.
6. Select copied QENC header fields only when their exact header hash matches the archive-state `containerId`; derive geometry from validated QENC metadata, never unauthenticated shard metadata.
7. Verify Shamir-share and fragment-body commitments independently, then reconstruct the ML-KEM secret key and `.qenc` ciphertext.
8. Verify the QENC key commitment, full `.qenc` hash, header identity, and restored key binding; treat redundant `privateKeyHash` shard metadata as diagnostic only.
9. Preserve same-state fork and non-selected-input diagnostics for operator audit.
10. Write outputs only when the restore policy is satisfied or the requested dry-run semantics allow reporting without output.

## Security Posture

- Both crates forbid unsafe Rust.
- Production randomness is obtained through `getrandom`; entropy failure is preserved as a stable coded error and operations fail closed.
- Deterministic seeds, nonces, salts, archive identifiers, and Shamir streams are compile-time isolated from the production feature graph.
- No hidden legacy fallback.
- No best-effort parsing of malformed artifacts.
- No heuristic cohort selection.
- No policy satisfaction from OpenTimestamps alone.
- No signature policy or trusted-status credit for embedded/bundle-carried signer material without an independent operator pin.
- Stable qvCode taxonomy for CLI automation.
- Strict upper bounds on QENC, signed artifact, metadata/key/evidence, individual shard, and aggregate shard inputs.
- Atomic writes, no-clobber defaults, portable basenames, distinct-output checks, and symlink rejection by default.
- Best-effort zeroization for seeds, shared secrets, derived keys, private keys, Shamir state, plaintext, and secret-bearing owner types.
- Release overflow checks and checked arithmetic on hostile lengths.

Release `panic = "abort"` is a final containment behavior, not an input-validation strategy. Production parser/CLI paths return structured errors for recoverable invalid states; malformed-input tests and fuzz targets check that untrusted bytes do not reach panics.

## Dependency Direction

Cryptographic backends are intentionally narrow:

- ML-KEM: `fips203`
- ML-DSA: `fips204`
- SLH-DSA: `fips205`
- AES-GCM: `aes-gcm`
- SHA3/KMAC: `tiny-keccak`
- SHA-256: `sha2`
- Ed25519 verification: `ed25519-dalek`
- zeroization: `zeroize`

Shamir and Reed-Solomon encoding are local compatibility implementations because their byte layout is part of the shard wire format.

The `aes` and `ghash` direct manifest entries are intentional feature anchors: they enable zeroization in transitive AES-GCM state. Duplicate `digest`/`sha2` support families in `Cargo.lock` are currently imposed by the FIPS 203/204/205 crates versus the newer AES-GCM/Ed25519 stack, not redundant application dependencies.

## Public Library Boundary

The simplest library calls are re-exported from `qvault_core`:

- ML-KEM: `generate_key_pair`, `encapsulate`, `decapsulate`
- QENC: `encrypt_qenc`, `decrypt_qenc`, `parse_qenc_header`, `build_qenc_header`
- QVB1: `build_bundle_payload`, `parse_bundle_payload`, `bundle_entry_output_path`
- lifecycle verification: `verify_successor_lifecycle_authenticity`

Specialized operations remain organized under public modules such as `auth`, `lifecycle`, `qcont`, `qenc`, `sss`, `erasure`, `kdf`, and `aead`. The CLI is a policy-preserving adapter around those APIs; it is not required to use the core crate.
