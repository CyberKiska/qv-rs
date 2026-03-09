# qv-cli

`qv-cli` is a compatibility-first local Rust CLI for the current Quantum Vault container standard.

It is not a protocol redesign. The neighboring `../qv-work/quantum-vault` project is the behavior and wire-format oracle, and this repo aims to match its current `.qenc`, manifest, bundle, `.qcont`, restore, and attach behavior as closely as practical.

## Current Status

Implemented today:

- `keygen`
- `encrypt`
- `decrypt`
- `split`
- `restore`
- `attach`

Implemented in `qvault-core` today:

- ML-KEM-1024 key generation via `fips203`
- current KMAC256 derivation tree with customization strings
- AES-256-GCM single-container and per-chunk modes
- current `wrapped-v1` payload wrapping and unwrapping
- current `QVB1` multi-file bundle payload (`.qvpack`) parsing and building
- current `.qenc` header parse/build with mandatory key commitment
- archive manifest v2 generation and validation
- manifest bundle v1 generation and validation
- current `.qcont` v6 parse/build/restore
- detached signature verification for `.qsig` / `.pqpk` and Stellar `.sig`
- OpenTimestamps linkage and reporting
- bundle attach workflow for extended manifests and embedded shard bundles
- direct Rust mirrors of the pinned JS Shamir and Reed-Solomon behavior used by Quantum Vault

Verified today:

- Rust decrypts current JS-produced `.qenc` fixtures
- Rust reproduces current JS `.qenc` fixture bytes exactly when RNG inputs and timestamps are fixed
- Rust reproduces current JS `.qcont` v6 shard bytes exactly for deterministic integrity-only fixtures
- Rust restores JS-produced integrity-only, `any-signature`, and `strong-pq-signature` shard fixtures when the required signer binding is present through bundled keys or explicit user pins
- Rust attach reproduces the JS attached bundle and attached shard fixtures
- repeated attach cycles preserve the canonical manifest and match the JS bundle fixture
- malformed and tampered inputs fail closed in the covered negative cases

## Repository Layout

- `crates/qvault-core`: wire formats, crypto, manifests, bundle/auth logic, split/restore/attach, validation
- `crates/qvault-cli`: thin CLI over `qvault-core`
- `fixtures/js-oracle`: deterministic JS-produced fixtures checked into the repo
- `tools/gen-js-fixtures.mjs`: fixture exporter driven by the JS oracle

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

Regenerate the JS oracle fixtures:

```bash
node tools/gen-js-fixtures.mjs
```

Note: the chunked `.qcont` parity and restore tests are intentionally heavy and take noticeably longer than the small-container tests.

## CLI Usage

The binary built by Cargo is `qvault-cli`.

Show help:

```bash
cargo run -p qvault-cli -- --help
```

Generate a keypair:

```bash
cargo run -p qvault-cli -- keygen
```

Defaults:

- `keygen` writes `public.qkey` and `secret.qkey`
- `encrypt` reads `public.qkey` by default
- `decrypt` and `split` read `secret.qkey` by default
- `split` writes to `<input-stem>-shards/` by default
- `restore` writes `<shard-base>.qenc` and `<shard-base>.qkey` by default
- `attach` writes to `<base>-attached/` by default

Override paths only when needed:

```bash
cargo run -p qvault-cli -- keygen \
  --public-key favorite-public.qkey \
  --secret-key favorite-secret.qkey
```

Encrypt a single file into `.qenc`:

```bash
cargo run -p qvault-cli -- encrypt \
  --input input.bin
```

Encrypt multiple files into one Quantum Vault bundle container:

```bash
cargo run -p qvault-cli -- encrypt \
  --input a.txt \
  --input b.bin
```

With multiple `--input` values, `qvault-cli` follows the JS oracle and first builds an internal `QVB1` bundle payload with a `.qvpack` original filename, then encrypts that bundle into one `.qenc`.

Decrypt a `.qenc` container:

```bash
cargo run -p qvault-cli -- decrypt \
  --input input.bin.qenc
```

For single-file payloads, the CLI restores the safe `originalFilename` from wrapped metadata when available, otherwise it falls back to the input stem.

For bundle payloads, the CLI automatically extracts the bundled files into a directory derived from the stored `.qvpack` name.

Split a `.qenc` plus matching secret key into `.qcont` shards:

```bash
cargo run -p qvault-cli -- split \
  --input-qenc output.qenc \
  --n 5 \
  --k 3
```

Set a stronger archive policy explicitly:

```bash
cargo run -p qvault-cli -- split \
  --input-qenc output.qenc \
  --n 5 \
  --k 3 \
  --auth-policy-level strong-pq-signature \
  --min-valid-signatures 1
```

Restore from shards using only embedded bundle data:

```bash
cargo run -p qvault-cli -- restore \
  shards/*.qcont
```

Restore an archive that requires a detached PQ signature:

```bash
cargo run -p qvault-cli -- restore \
  --signature archive.qsig \
  --pqpk archive.pqpk \
  shards/*.qcont
```

Restore using an uploaded extended manifest bundle to select a stale shard cohort:

```bash
cargo run -p qvault-cli -- restore \
  --bundle archive.extended.qvmanifest.json \
  shards/*.qcont
```

Attach detached signature material into a bundle and updated shards:

```bash
cargo run -p qvault-cli -- attach \
  --signature archive.qsig \
  --pqpk archive.pqpk \
  --ots archive.qsig.ots \
  shards/*.qcont
```

Write only the extended manifest bundle:

```bash
cargo run -p qvault-cli -- attach \
  --bundle archive.extended.qvmanifest.json \
  --signature archive-b.qsig \
  --pqpk archive-b.pqpk \
  --ots archive-b.qsig.ots \
  --bundle-only
```

## Compatibility Notes

Current compatibility target:

- `.qenc`: `QVv1-5-0`
- archive manifest: `quantum-vault-archive-manifest/v2`
- manifest bundle: `QV-Manifest-Bundle` v1
- `.qcont`: `QVqcont-6`
- crypto profile: `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2`
- KDF tree: `QV-KDF-TREE-v2`
- canonical JSON label: `QV-C14N-v1`

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
