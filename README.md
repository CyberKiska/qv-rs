# qv-cli

`qv-cli` is a compatibility-first local Rust CLI for the current Quantum Vault container standard.

The neighboring Quantum Vault JS project is the behavior and wire-format oracle. Default builds are successor-only; retired manifest-v2 / manifest-bundle-v1 / `QVqcont-6` code is available only with `--features legacy-mvp`.

## Current Status

Default build status:

- current `.qenc` container primitives remain available
- predecessor split/restore/attach CLI commands are disabled
- successor lifecycle artifacts and `QVqcont-7` are staged but not implemented yet

Implemented in `qvault-core` default builds:

- ML-KEM-1024 key generation via `fips203`
- current KMAC256 derivation tree with customization strings
- AES-256-GCM single-container and per-chunk modes
- current `wrapped-v1` payload wrapping and unwrapping
- current `QVB1` multi-file bundle payload (`.qvpack`) parsing and building
- current `.qenc` header parse/build with mandatory key commitment
- detached signature verification for `.qsig` / `.pqpk` and Stellar `.sig`
- direct Rust mirrors of the pinned JS Shamir and Reed-Solomon behavior used by Quantum Vault

Verified in default tests:

- Rust decrypts current JS-produced `.qenc` fixtures
- Rust reproduces current JS `.qenc` fixture bytes exactly when RNG inputs and timestamps are fixed
- malformed and tampered inputs fail closed in the covered negative cases

Legacy MVP checks are still available explicitly:

```bash
cargo test -p qvault-core --features legacy-mvp
cargo run -p qvault-cli --features legacy-mvp -- --help
```

## Repository Layout

- `crates/qvault-core`: current container crypto plus staged successor migration modules
- `crates/qvault-cli`: thin CLI over `qvault-core`
- `fixtures/legacy-mvp/js-oracle`: retired predecessor fixtures, feature-gated
- `fixtures/successor`: successor fixture root for later stages
- `tools/gen-js-fixtures.mjs`: disabled until rewritten for successor lifecycle modules

## Build And Test

Requirements:

- Rust toolchain compatible with the workspace `Cargo.toml`
- Node.js for fixture regeneration and JS-oracle smoke work

Build:

```bash
cargo build
```

Run the Rust test suite:

```bash
cargo test
```

The old fixture generator is disabled because it targeted removed predecessor JS modules:

```bash
node tools/gen-js-fixtures.mjs
```

## CLI Usage

The binary built by Cargo is `qvault-cli`.

Default CLI builds intentionally refuse predecessor split/restore/attach commands until
the successor CLI is implemented.

For migration-only legacy help:

```bash
cargo run -p qvault-cli --features legacy-mvp -- --help
```

## Compatibility Notes

Current successor target:

- `.qenc`: `QVv1-5-0`
- archive-state descriptor: `quantum-vault-archive-state-descriptor/v1`
- cohort binding: `quantum-vault-cohort-binding/v1`
- lifecycle bundle: `QV-Lifecycle-Bundle` v1
- `.qcont`: `QVqcont-7`
- crypto profile: `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2`
- KDF tree: `QV-KDF-TREE-v2`
- canonical JSON labels: `QV-JSON-RFC8785-v1`, `QV-BUNDLE-JSON-v1`

Important compatibility rules:

- compatibility comes before abstraction
- wire-visible JSON uses explicit structs and canonical serialization
- restore is manifest-and-bundle centric and fail-closed
- no silent format fallback is introduced
- legacy `QVqcont-5` / manifest-v1 inputs are treated as unsupported

Current deliberate restore hardening:

- for `any-signature` and `strong-pq-signature`, Rust only counts signatures whose signer is actually bound through bundle `publicKeyRef` material or an explicit user pin (`--pqpk` / `--expected-ed25519-signer`)
- unpinned signatures may still verify structurally, but they do not satisfy archive policy
- this is a security hardening relative to the current JS restore behavior, not a wire-format change

Current deliberate CLI divergence from JS Pro defaults:

- the library default for new archives matches the JS builder default (`strong-pq-signature`)
- the Rust CLI `split` command currently defaults to `integrity-only`
- this is intentional so the local CLI remains usable without forcing signature material at archive creation time

OpenTimestamps notes:

- OTS evidence is parsed, linked, and reported
- OTS does not satisfy archive signature policy by itself

## Security Notes

- Key commitment is mandatory and is verified before `.qenc` decryption.
- `decrypt` also verifies the inner wrapped-payload file hash after decryption.
- `split` verifies that the provided secret key matches the `.qenc` container before producing shards.
- `restore` validates manifest digest, bundle digest, copied `.qenc` metadata, key commitment, share commitments, and fragment body hashes.
- `restore` blocks when archive policy is not satisfied.
- for non-`integrity-only` archives, restore only counts signatures toward policy when the signer is trusted via bundle key binding or explicit user pinning.
- bundle extraction only writes single-component file names and refuses duplicate or unsafe entry names.
- secret key files written by `keygen` and `restore` are set to owner-only permissions on Unix (`0600`) as a best-effort local safeguard.
- secret zeroization is best-effort. Temporary shared secrets, derived keys, and intermediate buffers are cleared where feasible, but returned plaintext and returned secret-key bytes remain in caller-controlled memory by design.

## Current Limitations / Non-Goals

Not implemented:

- detached signature creation
- `.qcont` signing as part of `split`
- trusted timestamp validation beyond OpenTimestamps structure/link checks
- daemon mode, RPC mode, or network services
- legacy-format fallback

Current practical limits:

- JS-side cross-language verification is smoke-tested locally, but not yet fully automated inside the Rust test harness
- `restore` reconstructs `.qenc` and `.qkey`; it does not automatically decrypt the restored container
- bundle extraction is filesystem-safe rather than browser-like, so unsafe or colliding entry names are rejected instead of auto-renamed

## Relationship To `quantum-vault`

This project follows the current `../qv-work/quantum-vault` implementation, not older drafts or README prose. When the docs here and the JS oracle differ, the JS source is the source of truth for protocol behavior, and this repo should either be updated to match it or document the remaining gap explicitly.

## Near-Term Roadmap

- automate more JS-side interop checks as repeatable repo scripts
- add more malformed/tamper cases from the JS self-test matrix
- expand CLI-level smokes around restore and attach
- continue hardening secret handling and CLI ergonomics without changing the wire format
- keep docs aligned with the current oracle as Quantum Vault evolves
