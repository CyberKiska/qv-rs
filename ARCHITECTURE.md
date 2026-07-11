# qv-cli Architecture

## Purpose

`qv-cli` is a Rust implementation of the current Quantum Vault format family. It is not a new protocol. Its job is to track the sibling JavaScript implementation closely enough that Rust can read, write, inspect, verify, and restore current Quantum Vault artifacts without heuristic fallback.

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
├── tools/
└── README.md
```

## Crate Responsibilities

`qvault-core` owns:

- `.qenc` parse/build/encrypt/decrypt
- KEM/KDF/AEAD operations
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

- No hidden legacy fallback.
- No best-effort parsing of malformed artifacts.
- No heuristic cohort selection.
- No policy satisfaction from OpenTimestamps alone.
- No signature policy credit for unpinned self-verifying signer material.
- Stable qvCode taxonomy for CLI automation.
- Best-effort zeroization for temporary secret material.

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
