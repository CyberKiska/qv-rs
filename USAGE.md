# qv-cli Usage

`qv-cli` is a local Rust command-line tool for current Quantum Vault artifacts. It creates encrypted `.qenc` containers, splits them into recoverable `QVqcont-7` shard cohorts, attaches lifecycle evidence, verifies archive authenticity, restores encrypted containers and secret keys from shards, and decrypts restored containers.

Quantum Vault is meant for long-lived archives where three properties matter at the same time:

- confidentiality: the payload is encrypted with ML-KEM-1024, KMAC256, and AES-256-GCM
- recoverability: the encrypted payload and ML-KEM secret key are split across threshold shards
- authenticity: archive approval signatures, maintenance records, source evidence, and timestamp evidence are bound to canonical successor artifacts

The important operational model is: keep enough shards to restore, keep lifecycle evidence with the archive, and treat restore as a policy-gated operation rather than a blind reconstruction.

## Install Or Build

From the repository root:

```bash
cargo build --release -p qvault-cli
```

The built binary is:

```bash
target/release/qvault-cli
```

For examples below, either use that full path or put it on your `PATH`:

```bash
export QV=target/release/qvault-cli
```

On Windows PowerShell:

```powershell
$env:QV = "target\release\qvault-cli.exe"
```

## Global Flags

These flags work with every command:

- `--json`: emit a stable `cliSchemaVersion: 1` JSON envelope
- `--quiet`: suppress non-error text output
- `--allow-symlink`: permit symlink input paths and path components
- `--color` / `--no-color`: accepted for JavaScript CLI parity

Use `--json` for automation:

```bash
$QV --json version
```

By default, the CLI rejects symlink path components for safer local file handling. Use `--allow-symlink` only when you intentionally trust the path tree.

## Typical Archive Flow

This flow creates a keypair, encrypts a file, splits it into successor shards, verifies the resulting lifecycle bundle, performs a dry-run restore, restores the `.qenc` and secret key, and decrypts the restored archive.

### 1. Generate An ML-KEM Keypair

```bash
$QV keygen --out vault-keys --name archive-2026- --json
```

This writes:

- `vault-keys/archive-2026-publicKey.qkey`
- `vault-keys/archive-2026-privateKey.qkey`

The public key is used for encryption. The private key is needed for decrypting `.qenc` containers and for splitting a `.qenc` into shards.

### 2. Encrypt A File

```bash
$QV encrypt important.pdf \
  --public-key vault-keys/archive-2026-publicKey.qkey \
  --out important.pdf.qenc \
  --filename important.pdf \
  --json
```

The output `.qenc` is the encrypted payload container. The `--filename` value is stored inside encrypted wrapped metadata and is used by `decrypt --use-original-filename`.

### 3. Split Into QVqcont-7 Shards

```bash
$QV split important.pdf.qenc \
  --private-key vault-keys/archive-2026-privateKey.qkey \
  --n 5 \
  --k 3 \
  --out important-shards \
  --auth-policy-level strong-pq-signature \
  --min-valid-signatures 1 \
  --json
```

This writes:

- `important-shards/important.pdf.archive-state.json`
- `important-shards/important.pdf.cohort-binding.json`
- `important-shards/important.pdf.lifecycle-bundle.json`
- `important-shards/important.pdf.part1-of-5.qcont` through `part5-of-5.qcont`

The `--n` value is the number of shard files. The `--k` value is the Reed-Solomon data shard count. Under the successor profile, parity is `n - k`, parity must be even, and the Shamir threshold is derived as `k + parity / 2`. For example, `--n 5 --k 3` produces parity `2` and threshold `4`.

### 4. Verify Archive State And Lifecycle Evidence

For an integrity-only archive, verification can succeed without signatures. For a signed archive policy such as `strong-pq-signature`, provide the lifecycle bundle and signer material:

```bash
$QV verify important-shards/important.pdf.archive-state.json \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --pqpk signer.pqpk \
  --sig important.pdf.archive-state.json.qsig \
  --ots important.pdf.archive-state.json.qsig.ots \
  --required-policy-level strong-pq-signature \
  --json
```

Archive approval signatures target canonical archive-state bytes. OpenTimestamps evidence links to `SHA-256(detached signature bytes)` and is reported separately; it does not satisfy archive policy by itself.

### 5. Dry-Run Restore

Dry-run restore checks shard consistency, lifecycle evidence, restored integrity, and archive policy without writing recovered secret material:

```bash
$QV restore important-shards/*.qcont \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --pqpk signer.pqpk \
  --sig important.pdf.archive-state.json.qsig \
  --ots important.pdf.archive-state.json.qsig.ots \
  --dry-run \
  --json
```

Use dry-run before write-mode restore, especially when shards may contain multiple lifecycle-bundle variants.

### 6. Restore The `.qenc` And Secret Key

```bash
$QV restore important-shards/*.qcont \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --pqpk signer.pqpk \
  --sig important.pdf.archive-state.json.qsig \
  --output-qenc restored/important.pdf.qenc \
  --output-secret-key restored/important-privateKey.qkey \
  --json
```

Restore writes the encrypted `.qenc` and the recovered ML-KEM secret key. It does not automatically decrypt the restored container.

If restore reports that lifecycle-bundle variant acknowledgement is required, inspect the JSON report and rerun with `--accept-policy-warnings` only if the operator accepts the residual bundle-variant risk.

### 7. Decrypt A Restored Container

```bash
$QV decrypt restored/important.pdf.qenc \
  --private-key restored/important-privateKey.qkey \
  --out restored/important.pdf \
  --json
```

Or write using encrypted original filename metadata:

```bash
$QV decrypt restored/important.pdf.qenc \
  --private-key restored/important-privateKey.qkey \
  --out-dir restored-files \
  --use-original-filename
```

## Attach Evidence

`attach` updates a lifecycle bundle without changing canonical archive-state or cohort-binding bytes.

Attach archive approval signatures and signer keys:

```bash
$QV attach \
  --shards important-shards/important.pdf.part1-of-5.qcont important-shards/important.pdf.part2-of-5.qcont important-shards/important.pdf.part3-of-5.qcont \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --sig important.pdf.archive-state.json.qsig \
  --pqpk signer.pqpk \
  --ots important.pdf.archive-state.json.qsig.ots \
  --out-bundle important-attached.lifecycle-bundle.json \
  --out-shards important-attached-shards \
  --force \
  --json
```

If you only want a new lifecycle bundle and do not want shard files rewritten:

```bash
$QV attach \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --sig important.pdf.archive-state.json.qsig \
  --pqpk signer.pqpk \
  --out-bundle important-attached.lifecycle-bundle.json \
  --no-embed-into-shards \
  --json
```

Typed signature imports are accepted with `--sig-import` as a JSON object:

```bash
$QV attach \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --sig-import '{"file":"approval.qsig","signatureFamily":"archive-approval"}' \
  --pqpk signer.pqpk \
  --out-bundle important-attached.lifecycle-bundle.json
```

For maintenance and source-evidence signatures, include explicit targets:

```bash
$QV attach \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --maintenance-sig maintenance.qsig \
  --maintenance-target-ref transition:sha3-512:TRANSITION_DIGEST_HEX \
  --pqpk maintainer.pqpk \
  --out-bundle important-maintained.lifecycle-bundle.json
```

```bash
$QV attach \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --source-evidence source-evidence.json \
  --source-evidence-sig source-evidence.qsig \
  --source-evidence-target-ref source-evidence:sha3-512:SOURCE_EVIDENCE_DIGEST_HEX \
  --pqpk evidence-signer.pqpk \
  --out-bundle important-evidence.lifecycle-bundle.json
```

## Same-State Reshare

`reshare` creates a new cohort for the same archive state and emits a maintenance transition record in the lifecycle bundle.

```bash
$QV reshare \
  --shards important-shards/important.pdf.part1-of-5.qcont important-shards/important.pdf.part2-of-5.qcont important-shards/important.pdf.part3-of-5.qcont important-shards/important.pdf.part4-of-5.qcont \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --n 7 \
  --k 5 \
  --reason-code same-state-resharing \
  --operator-role operator \
  --notes "Routine media refresh" \
  --out important-reshared \
  --json
```

If multiple archive, state, cohort, or lifecycle-bundle candidates are present, select explicitly:

```bash
$QV reshare \
  --shards important-shards/*.qcont \
  --archive-id ARCHIVE_ID_HEX \
  --state-id STATE_ID_HEX \
  --cohort-id COHORT_ID_HEX \
  --bundle-digest LIFECYCLE_BUNDLE_DIGEST_HEX \
  --n 7 \
  --k 5 \
  --out important-reshared
```

## Inspect And Canonicalize

Inspect prints a parsed summary and digest information:

```bash
$QV inspect important-shards/important.pdf.part1-of-5.qcont --json
$QV inspect important-shards/important.pdf.archive-state.json --json
$QV inspect important.pdf.qenc --json
```

Canonicalize validates supported JSON artifacts and emits canonical bytes:

```bash
$QV canonicalize important-shards/important.pdf.archive-state.json > archive-state.canonical.json
```

Use canonicalization checks before signing or comparing artifacts.

## Error Codes For Automation

With `--json`, failures emit:

```json
{
  "command": "restore",
  "ok": false,
  "cliSchemaVersion": 1,
  "qvCode": "POLICY_NOT_SATISFIED",
  "error": "..."
}
```

Important qvCodes:

- `USAGE`: invalid CLI usage
- `FORMAT_POLICY_REJECT`: malformed or unsupported artifact
- `KEY_REJECTED`: supplied key is invalid or does not match
- `AEAD_FAILED`: key commitment or AES-GCM authentication failed
- `QUORUM_UNREACHABLE`: not enough valid shards or shard integrity mismatch
- `POLICY_NOT_SATISFIED`: archive policy blocks restore/verify
- `RESTORE_LIFECYCLE_VARIANT_ACK_REQUIRED`: restore needs explicit lifecycle-bundle variant acknowledgement

## Correctness And Safety Practices

- Keep the private `.qkey` separate from the public `.qkey`.
- Store more than the minimum number of shards and test restore periodically.
- Preserve archive-state, cohort-binding, lifecycle-bundle, signature, public-key, and timestamp files alongside shards.
- Use `restore --dry-run --json` before write-mode restore.
- Use explicit `--archive-id`, `--state-id`, `--cohort-id`, or `--bundle-digest` when operating on mixed shard sets.
- Do not use `--allow-symlink` on untrusted paths.
- Treat OpenTimestamps completion labels as heuristic reporting, not full calendar attestation validation.
- Keep detached signing keys and `.pqsk` files outside shared archive storage.

## Tests And Development

Run the default workspace tests:

```bash
cargo test --workspace
```

Run focused test suites:

```bash
cargo test -p qvault-core --test lifecycle_schema
cargo test -p qvault-core --test qcont_v7
cargo test -p qvault-core --test auth_corpus
cargo test -p qvault-cli --test cli_json
```

Run formatting and compilation checks:

```bash
cargo fmt -- --check
cargo check --workspace --locked
cargo build --release -p qvault-cli --locked
```

The JavaScript implementation remains the behavioral oracle. When changing wire-visible behavior, inspect the sibling JS files first and add Rust tests using committed cross-implementation fixtures under `crates/qvault-core/tests/data/`.
