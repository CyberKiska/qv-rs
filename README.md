# qv-rs / qv-cli

`qv-rs` is the standalone Rust implementation of the current Quantum Vault artifact family. The workspace provides the `qvault-core` Rust library and the `qvault-cli` executable for creating, inspecting, signing, attaching evidence to, verifying, resharing, restoring, and decrypting archives.

The Rust implementation does **not** require the JavaScript Quantum Vault project, Node.js, a network service, or a daemon at build time or runtime. It implements the supported formats and cryptographic operations locally. Artifacts are format-compatible with [CyberKiska/quantum-vault](https://github.com/CyberKiska/quantum-vault); a pinned JavaScript revision is used only as an independent interoperability oracle in CI and during intentional fixture refreshes.

Quantum Vault is an archival container format that separates confidentiality, recoverability, and authenticity:

- `.qenc` holds the encrypted payload using ML-KEM-1024, KMAC256, and AES-256-GCM.
- `QVqcont-7` shards split the encrypted payload and the ML-KEM secret key across a recoverable cohort.
- Archive-state descriptors, cohort bindings, and `QV-Lifecycle-Bundle` v1 carry canonical identity, sharding commitments, policy, signatures, timestamp evidence, transition records, and source evidence.
- Archive approval signatures cover canonical archive-state bytes, not mutable lifecycle-bundle bytes.
- Restore is fail-closed: ambiguity, malformed bytes, digest mismatch, failed key binding, or unsatisfied archive policy blocks output.

Start with [USAGE.md](USAGE.md) for the complete command/parameter reference and end-to-end workflows. [ARCHITECTURE.md](ARCHITECTURE.md) describes the trust and data model; [docs/IMPLEMENTATION_NOTES.md](docs/IMPLEMENTATION_NOTES.md) and [docs/successor-conformance.md](docs/successor-conformance.md) define contributor and cross-implementation constraints.

## Current Status


Implemented:

- `.qenc` `QVv1-5-0` parse/build/decrypt/encrypt
- `wrapped-v1` payload metadata and `QVB1` multi-file payloads
- archive-state descriptor v1
- cohort binding v1 with strict canonical `bodyDefinition.excludes`
- transition-record and source-evidence v1 parsing
- `QV-Lifecycle-Bundle` v1 parsing/canonicalization
- `QVqcont-7` split, restore, attach, and same-state reshare
- archive policy evaluation with fail-closed restore gating
- `.qsig`, `.pqpk`, Stellar `.sig`, and OpenTimestamps linkage handling
- Rust-native PQ signing key generation, detached `.qsig` creation, and generic `.qsig` verification
- stable CLI JSON envelopes and JS-aligned `qvCode` exit taxonomy
- OS-backed, fail-closed randomness for ML-KEM, randomized PQ signatures, QENC nonce/salt generation, archive identities, and Shamir sharing
- compile-time isolation of deterministic interoperability inputs behind the non-default `deterministic-test-vectors` feature
- bounded artifact/shard reads, atomic output replacement, symlink rejection by default, and portable recovered-filename validation

Not implemented:

- dedicated CLI `qvpack` pack/extract commands (the core payload format is implemented)
- full OpenTimestamps calendar attestation validation
- network services, daemon mode, or RPC mode

“Format-compatible” means the supported Rust and JavaScript implementations can exchange the listed artifact versions and that frozen byte-level vectors are checked in CI. It does not mean that every command name, optional legacy format, report field, or unfinished feature in one implementation exists in the other.

## Repository Layout

- `crates/qvault-core`: cryptography, canonical JSON, lifecycle artifacts, shard parsing/building, restore/authenticity policy
- `crates/qvault-cli`: CLI argument parsing, file I/O policy, JSON/text reporting
- `crates/qvault-core/tests/data`: self-contained JS oracle fixtures, schema fixtures, corpus cases, and compact examples
- `docs/successor-conformance.md`: conformance boundaries and intentional Rust deviations
- `ARCHITECTURE.md`: current Rust architecture
- `docs/IMPLEMENTATION_NOTES.md`: contributor rules and oracle references

## Build And Test

Requirements:

- Rust 1.97.1 (the toolchain pinned by CI) or a compatible newer stable toolchain
- no Node.js or JavaScript checkout for normal builds, tests, or operation
- optional Node.js and a pinned JavaScript checkout only for live oracle comparison or fixture maintenance

Build:

```bash
cargo build --release -p qvault-cli --locked
```

The production build has no default features. Do not enable `deterministic-test-vectors` in a release: it exposes exact seed/nonce inputs intended only for frozen interoperability tests. CI verifies that the production dependency graph does not enable it.

### Prebuilt binaries (CI)

After a successful run of the **CI** workflow on GitHub, download archives from the run’s **Artifacts** section: open the repository **Actions** tab, select the workflow run, then scroll to **Artifacts** at the bottom of the summary page.

Typical artifact names (one archive per row):

- `qvault-cli-linux-x86_64-gnu` — Linux `x86_64-unknown-linux-gnu` (`.tar.gz`)
- `qvault-cli-windows-x86_64-gnu` — Windows `x86_64-pc-windows-gnu` (`.zip`, includes `qvault-cli.exe`)
- `qvault-cli-macos-aarch64` — macOS Apple Silicon (`aarch64-apple-darwin`, `.tar.gz`)
- `qvault-cli-macos-x86_64` — macOS Intel (`x86_64-apple-darwin`, `.tar.gz`)

Each archive contains the `qvault-cli` binary (or `qvault-cli.exe` on Windows), plus `README.md`, `USAGE.md`, and `LICENSE`.

Run tests:

```bash
cargo test --workspace --all-targets --locked
cargo test --workspace --all-targets --all-features --locked
```

Run focused successor fixtures:

```bash
cargo test -p qvault-core --test lifecycle_schema
cargo test -p qvault-core --test qcont_v7
cargo test -p qvault-cli --test cli_json
```

The default test suite is self-contained. The optional live-oracle test requires `QV_ORACLE_ROOT` and an explicit `--ignored` run; see [the corpus notes](crates/qvault-core/tests/data/corpus/README.md).

## CLI Surface

The Cargo binary is `qvault-cli`.

See [USAGE.md](USAGE.md) for every command, positional argument, option, default, output rule, end-to-end workflow, and automation/error contract. The executable itself is authoritative for the installed version:

```bash
qvault-cli --help
qvault-cli <command> --help
```

Primary commands:

- `keygen`
- `encrypt`
- `decrypt`
- `split`
- `attach`
- `reshare`
- `signer-keygen`
- `sign`
- `sig-verify`
- `verify`
- `restore`
- `inspect`
- `canonicalize`
- `selftest`
- `version`

Global flags include `--json`, `--quiet`, `--allow-symlink`, `--color`, `--no-color`, and the aggregate shard-memory guard `--max-shard-input-bytes` (1 GiB by default, at most 2 GiB by explicit opt-in).

Commands refuse to overwrite existing outputs unless `--force` is supplied. Writes use temporary files and replacement/rename semantics; secret keys, decrypted plaintext, and shard files use owner-only permissions on Unix. Output names recovered from authenticated metadata must be portable basenames, and symlink path components are rejected unless the operator explicitly opts in with `--allow-symlink`.

## Rust Library Surface

`qvault-core` can be used without the CLI. Its top-level re-exports cover the common path:

- `generate_key_pair`, `encapsulate`, and `decapsulate` for ML-KEM-1024
- `encrypt_qenc`, `decrypt_qenc`, `parse_qenc_header`, and `build_qenc_header` for QENC
- `build_bundle_payload`, `parse_bundle_payload`, and `validate_portable_filename` for QVB1 payloads
- `verify_successor_lifecycle_authenticity` plus `AuthPolicy`, `VerificationInputs`, and `AuthenticityReport` for lifecycle verification

The public modules additionally expose strict lifecycle parsers/builders, QVqcont split/restore/attach/reshare operations, PQ key/signature formats, Shamir/Reed–Solomon compatibility functions, KDF/AEAD helpers, and policy constants. APIs return `qvault_core::Result`; coded failures expose `QvError::qv_code()`.

Production callers should use the ordinary random APIs. Seeded ML-KEM/QENC/Shamir helpers and deterministic archive identifiers exist only when the non-default `deterministic-test-vectors` feature is explicitly enabled; they are for tests, never production key or nonce generation.

## Rust-Only Archive Approval Workflow

This workflow creates a current Quantum Vault archive and satisfies a strong PQ archive-approval policy without relying on the JavaScript CLI or network services. It keeps container creation and signing separate: `encrypt` and `split` create the Quantum Vault archive artifacts, while `signer-keygen`, `sign`, and `attach` create and bind detached PQ approval evidence.

```bash
qvault-cli --json keygen --out vault-keys --name archive-2026-

qvault-cli --json encrypt important.pdf \
  --public-key vault-keys/archive-2026-publicKey.qkey \
  --out important.pdf.qenc \
  --filename important.pdf

qvault-cli --json split important.pdf.qenc \
  --private-key vault-keys/archive-2026-privateKey.qkey \
  --n 5 \
  --k 3 \
  --out important-shards \
  --auth-policy-level strong-pq-signature \
  --min-valid-signatures 1

qvault-cli --json signer-keygen \
  --suite mldsa-87 \
  --out signer

qvault-cli --json sign important-shards/important.pdf.archive-state.json \
  --secret-key signer.pqsk \
  --target archive-state \
  --out important.pdf.archive-state.json.qsig

qvault-cli --json attach \
  --shards important-shards/*.qcont \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --sig important.pdf.archive-state.json.qsig \
  --pqpk signer.pqpk \
  --out-bundle important-approved.lifecycle-bundle.json \
  --out-shards important-approved-shards

qvault-cli --json verify important-shards/important.pdf.archive-state.json \
  --bundle important-approved.lifecycle-bundle.json \
  --pqpk signer.pqpk \
  --required-policy-level strong-pq-signature

qvault-cli --json restore important-approved-shards/*.qcont \
  --bundle important-approved.lifecycle-bundle.json \
  --pqpk signer.pqpk \
  --output-qenc restored/important.pdf.qenc \
  --output-secret-key restored/important-privateKey.qkey
```

`sign --target archive-state` signs the exact canonical archive-state descriptor bytes read from `important-shards/important.pdf.archive-state.json`. It does not sign the lifecycle bundle. This distinction is intentional: the archive-state descriptor is the stable archive identity and policy commitment, while the lifecycle bundle is mutable evidence that can later receive signatures, public keys, timestamps, transition records, and source evidence.

The `.qsig` embeds enough public key material for cryptographic self-verification, but embedded keys and lifecycle-bundle `publicKeys[]` entries are mutable evidence, not trust anchors. `attach --sig --pqpk` records the evidence needed for portable verification, but a signature is trusted and may satisfy lifecycle policy only when the operator also supplies the authorized signer independently to `verify` or `restore` with `--pqpk` (or `--expected-ed25519-signer` for Stellar signatures). `sig-verify` verifies arbitrary document bytes and reports whether verification used a supplied `.pqpk` or only the embedded key; it does not evaluate lifecycle policy and should not be used as a substitute for `verify` or `restore`.

## Compatibility Targets

- `.qenc`: `QVv1-5-0`
- `.qcont`: `QVqcont-7`
- shard artifact family: `successor-lifecycle-v1`
- archive-state schema: `quantum-vault-archive-state-descriptor/v1`
- cohort-binding schema: `quantum-vault-cohort-binding/v1`
- lifecycle bundle: `QV-Lifecycle-Bundle` v1
- crypto profile: `QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2`
- KDF tree: `QV-KDF-TREE-v2`
- canonical JSON labels: `QV-JSON-RFC8785-v1`, `QV-BUNDLE-JSON-v1`

## Restore And Authenticity

Restore groups candidates by archive identity and exact canonical bytes:

- `archiveId`
- `stateId`
- `cohortId`
- exact archive-state bytes
- exact cohort-binding bytes

Lifecycle-bundle bytes are mutable evidence and are selected explicitly when multiple bundle digests are present. Archive approval signatures are verified over canonical archive-state bytes. Maintenance signatures target transition-record bytes. Source-evidence signatures target source-evidence bytes.

For `any-signature` and `strong-pq-signature` policies, Rust counts signatures only when the signer is independently authorized by an explicit user pin (`--pqpk` or `--expected-ed25519-signer`). Bundle-carried keys and self-verifying signature material can establish raw cryptographic validity, but they do not establish trust and never produce trusted lifecycle `Verified` status by themselves.

OpenTimestamps evidence is linked to `SHA-256(detached signature bytes)`. OTS evidence does not satisfy archive policy. Completion fields and labels are heuristic reporting only; complete-looking proofs are reported as `OTS proof appears complete (heuristic)`.

## Security Notes

- Both crates use `#![forbid(unsafe_code)]`; release builds enable overflow checks and abort on panic.
- Production randomness comes from the operating system through `getrandom` and fails closed. QENC obtains its container nonce and KDF salt together, ML-KEM seeds remain in zeroizing storage, and randomized PQ signing preserves entropy-failure attribution.
- QENC keeps a bounded in-process replay guard for recent encapsulated-key/nonce/salt tuples and refuses a detected repeat to reduce catastrophic AES-GCM nonce-reuse risk after RNG failure.
- Key commitment is mandatory and checked before `.qenc` decryption.
- QENC authenticates format/policy metadata and either the complete payload or every chunk with injective AAD and a bounded KMAC-derived per-chunk IV counter.
- Decrypt verifies the inner wrapped-payload file hash.
- Split verifies that the provided ML-KEM secret key matches the `.qenc` before producing shards.
- Restore validates embedded archive-state, cohort-binding, lifecycle-bundle, `.qenc` metadata, key commitment, share commitments, fragment body hashes, and policy.
- Artifact reads have format-specific ceilings. QENC plaintext is limited to 1 GiB, QENC containers to that payload plus 1 MiB, generic signed targets to 512 MiB, small metadata/key/signature artifacts to 32 MiB, and aggregate shard input to 1 GiB by default (2 GiB maximum opt-in).
- Secret keys, decrypted plaintext, and `.qcont` shards are written atomically with owner-only permissions on Unix where available. Public outputs use ordinary public-file permissions.
- `.pqsk` signing keys authorize archive approvals; keep them separate from archive storage and publish/pin only `.pqpk` public keys.
- JSON randomness reports identify the OS provider, purpose, deterministic-feature state, and fail-closed mode without exposing seed or secret bytes.
- Secret zeroization is best-effort, not a formal guarantee. Temporary seeds, shared secrets, derived keys, private-key material, shares, plaintext, and intermediate buffers are cleared where ownership permits; values returned to library callers remain caller-controlled memory.

The cryptographic known-answer tests and runtime `selftest` are engineering health checks. They are not a NIST CAVP/CMVP validation claim and do not replace platform, operational, or independent cryptographic review.

## Limitations And Assurance Boundary

- CI checks the frozen corpus byte-for-byte against pinned JavaScript oracle revision `485a51388d0d26ee6cae9cd4785753a12eee9d32`. The default local suite reports the live parity test as ignored rather than silently passing without `QV_ORACLE_ROOT`.
- `split --archive-approval-key <key.pqsk>` supports same-run archive approval; the separate `sign` + `attach` workflow remains useful for offline approval.
- Dedicated CLI `qvpack` pack/extract commands are not yet exposed.
- OTS validation is structural/linkage reporting, not full calendar verification.
- CI now includes 32-bit checking, seeded fuzz smoke coverage, and scheduled sanitizer fuzzing; longer externally recorded fuzz campaigns remain desirable before high-assurance releases.
- QENC and shard workflows are bounded but remain in-memory operations; the current wire format/API is not a streaming encryption or restore interface.
