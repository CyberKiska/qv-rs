# qv-cli

`qv-cli` is the Rust implementation for Quantum Vault artifacts. It is a local CLI and library workspace for creating, inspecting, attaching evidence to, verifying, resharing, and restoring current Quantum Vault archives.

Quantum Vault is an archival container format that separates confidentiality, recoverability, and authenticity:

- `.qenc` holds the encrypted payload using ML-KEM-1024, KMAC256, and AES-256-GCM.
- `QVqcont-7` shards split the encrypted payload and the ML-KEM secret key across a recoverable cohort.
- Archive-state descriptors, cohort bindings, and `QV-Lifecycle-Bundle` v1 carry canonical identity, sharding commitments, policy, signatures, timestamp evidence, transition records, and source evidence.
- Archive approval signatures cover canonical archive-state bytes, not mutable lifecycle-bundle bytes.
- Restore is fail-closed: ambiguity, malformed bytes, digest mismatch, failed key binding, or unsatisfied archive policy blocks output.

The [sibling JavaScript project](https://github.com/CyberKiska/quantum-vault) remains the source-of-truth implementation and normative documentation set. This Rust repository keeps its docs self-contained, but protocol behavior should be checked against the JS source and its `docs/format-spec.md`, `docs/security-model.md`, `docs/trust-and-policy.md`, and schema fixtures when compatibility questions arise.

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
- stable CLI JSON envelopes and JS-aligned `qvCode` exit taxonomy

Not implemented:

- detached signature creation
- automatic signing during `split`
- full OpenTimestamps calendar attestation validation
- network services, daemon mode, or RPC mode

## Repository Layout

- `crates/qvault-core`: cryptography, canonical JSON, lifecycle artifacts, shard parsing/building, restore/authenticity policy
- `crates/qvault-cli`: CLI argument parsing, file I/O policy, JSON/text reporting
- `crates/qvault-core/tests/data`: self-contained JS oracle fixtures, schema fixtures, corpus cases, and compact examples
- `docs/successor-conformance.md`: conformance boundaries and intentional Rust deviations
- `ARCHITECTURE.md`: current Rust architecture
- `IMPLEMENTATION_NOTES.md`: contributor rules and oracle references

## Build And Test

Requirements:

- Rust toolchain compatible with the workspace `Cargo.toml`
- Node.js only when manually comparing or regenerating JS-oracle fixtures

Build:

```bash
cargo build
```

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
cargo test
```

Run focused successor fixtures:

```bash
cargo test -p qvault-core --test lifecycle_schema
cargo test -p qvault-core --test qcont_v7
cargo test -p qvault-cli --test cli_json
```

The old fixture generator in `tools/gen-js-fixtures.mjs` is intentionally disabled until it is rewritten against the successor JS modules.

## CLI Surface

The Cargo binary is `qvault-cli`.

See `USAGE.md` for end-to-end command examples, restore workflows, attach/reshare examples, test commands, and development guidance.

Primary commands:

- `keygen`
- `encrypt`
- `decrypt`
- `split`
- `attach`
- `reshare`
- `verify`
- `restore`
- `inspect`
- `canonicalize`
- `selftest`
- `version`

Global reporting flags include `--json`, `--quiet`, `--allow-symlink`, `--color`, and `--no-color`.

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

For `any-signature` and `strong-pq-signature` policies, Rust counts signatures only when the signer is bound through bundle public-key material or explicit user pins (`--pqpk` or `--expected-ed25519-signer`). Self-verifying signature material can be reported, but it does not satisfy archive policy by itself.

OpenTimestamps evidence is linked to `SHA-256(detached signature bytes)`. OTS evidence does not satisfy archive policy. Completion fields and labels are heuristic reporting only; complete-looking proofs are reported as `OTS proof appears complete (heuristic)`.

## Security Notes

- Key commitment is mandatory and checked before `.qenc` decryption.
- Decrypt verifies the inner wrapped-payload file hash.
- Split verifies that the provided ML-KEM secret key matches the `.qenc` before producing shards.
- Restore validates embedded archive-state, cohort-binding, lifecycle-bundle, `.qenc` metadata, key commitment, share commitments, fragment body hashes, and policy.
- Secret-key files written by `keygen` and `restore` use owner-only permissions on Unix where available.
- Secret zeroization is best-effort. Temporary shared secrets, derived keys, and intermediate buffers are cleared where feasible; returned plaintext and returned secret-key bytes remain caller-controlled memory.

## Remaining Gaps

- No automated end-to-end JS/Rust fixture regeneration harness is checked in yet.
- Detached signature creation is still external to this CLI.
- OTS validation is structural/linkage reporting, not full calendar verification.
- Full workspace CI should continue expanding malformed and cross-implementation cases before production release.
