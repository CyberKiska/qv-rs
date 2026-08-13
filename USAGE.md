# qv-rs / qvault-cli Usage

`qvault-cli` is the standalone command-line interface from the `qv-rs` workspace. It creates encrypted `.qenc` containers, splits them into recoverable `QVqcont-7` shard cohorts, signs and attaches lifecycle evidence, verifies archive authenticity, restores encrypted containers and secret keys from shards, and decrypts restored containers.

No JavaScript Quantum Vault checkout, Node.js runtime, server, or network connection is required. The Rust implementation performs the cryptography and format handling itself. Its supported artifacts are byte/format-compatible with the pinned JavaScript Quantum Vault oracle, but the two CLIs are independent products and need not expose identical commands for every feature.

Quantum Vault is meant for long-lived archives where three properties matter at the same time:

- confidentiality: the payload is encrypted with ML-KEM-1024, KMAC256, and AES-256-GCM
- recoverability: the encrypted payload and ML-KEM secret key are split across threshold shards
- authenticity: archive approval signatures, maintenance records, source evidence, and timestamp evidence are bound to canonical successor artifacts

The important operational model is: keep enough shards to restore, keep lifecycle evidence with the archive, and treat restore as a policy-gated operation rather than a blind reconstruction.

## Install Or Build

From the repository root:

```bash
cargo build --release -p qvault-cli --locked
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
- `--allow-symlink`: permit symlink paths and path components
- `--color` / `--no-color`: accepted for JavaScript CLI parity
- `--max-shard-input-bytes <bytes>`: aggregate QVqcont input budget; defaults to 1 GiB and can be raised explicitly to at most 2 GiB

Use `--json` for automation:

```bash
$QV --json version
```

By default, the CLI rejects symlink path components for safer local file handling. Use `--allow-symlink` only when you intentionally trust the path tree.

Global flags may appear before or after the subcommand. `--json` and `--quiet` are normally alternatives: JSON mode prints the machine-readable result, while quiet mode suppresses successful human-readable output. Errors still produce a JSON envelope when `--json` is present.

## Common Output Behavior

- Existing files are not overwritten unless the command accepts and receives `--force`.
- Output paths are preflighted before expensive secret work where practical. Related outputs are checked for path collisions.
- File writes use a temporary file followed by replacement/rename. Secret-key, plaintext, and shard outputs use mode `0600` on Unix; public artifacts use mode `0644`.
- Input and output symlinks are rejected by default, including symlinked parent components. `--allow-symlink` is an explicit trust decision.
- Filenames embedded in or recovered from artifacts must be portable single-component basenames: no separators, control characters, Windows device names, alternate-data-stream colons, trailing spaces/periods, `.`/`..`, or case-colliding QVB1 entries.
- QENC plaintext is limited to 1 GiB. Signed targets are limited to 512 MiB. Metadata, keys, and detached evidence use a 32 MiB small-artifact ceiling. QVqcont inputs are also checked against per-file and aggregate limits.
- Randomized command reports include a `randomness` object in JSON mode. Production reports identify `getrandom`, the purposes served, and `failureMode: "fail-closed"`; secret seeds and RNG output are never reported.

Use `qvault-cli <command> --help` for the exact syntax of the installed version.

## Command Reference

The forms below omit the global flags described above. Options documented as “repeatable” may be passed more than once.

### `keygen`

```text
qvault-cli keygen --out <directory> [--name <prefix>] [--print-public] [--force]
```

- `--out` is required and receives the raw ML-KEM-1024 key files.
- `--name` prepends a validated portable prefix. The default outputs are `publicKey.qkey` and `privateKey.qkey`; `--name archive-` produces `archive-publicKey.qkey` and `archive-privateKey.qkey`.
- `--print-public` prints the public key as Base64 in text mode or adds `publicKeyBase64` in JSON mode. Private-key bytes are never printed.
- `--force` permits replacement of both output files.

### `signer-keygen`

```text
qvault-cli signer-keygen --out <file-prefix> [--suite <suite>] [--force]
```

- `--out signer` writes `signer.pqpk` and `signer.pqsk`; it is a file prefix, not a directory.
- `--suite` defaults to `mldsa-87`. Accepted values are `mldsa-44`, `mldsa-65`, `mldsa-87`, `slhdsa-shake-128s`, `slhdsa-shake-192s`, `slhdsa-shake-256s`, and `slhdsa-shake-256f`.
- Under the current Quantum Vault policy registry, `mldsa-87`, `slhdsa-shake-256s`, and `slhdsa-shake-256f` are classified as `strongPq`; the other supported PQ suites remain valid signatures but do not satisfy `strong-pq-signature` policy.
- `--force` permits replacement of both key files.

### `sign`

```text
qvault-cli sign <input-file> --secret-key <key.pqsk> --out <signature.qsig>
  [--target <bytes|archive-state|transition-record|source-evidence>]
  [--filename <display-name>] [--created-at <RFC3339>] [--force]
```

- The default target is `bytes`, which signs the input exactly as read.
- Lifecycle targets require strict, canonical, valid JSON of the selected type before signing.
- `--filename` and `--created-at` populate display metadata. The filename is unauthenticated QSIG display metadata and must be a portable basename. The timestamp is normalized to UTC millisecond form.
- The target size ceiling is 512 MiB.
- Signing is randomized/hedged with the OS CSPRNG and fails closed if entropy is unavailable.

### `sig-verify`

```text
qvault-cli sig-verify <input-file> --sig <signature.qsig> [--pqpk <signer.pqpk>]
```

- Verifies a detached QSIG over the exact input bytes.
- Without `--pqpk`, the embedded key may establish cryptographic consistency but not an authorized signer identity.
- With `--pqpk`, that file is authoritative for this operation. JSON distinguishes `cryptographicOk`, `trusted`, and `trustSource`.
- This command does not evaluate lifecycle policy and never counts the result toward archive policy.

### `encrypt`

```text
qvault-cli encrypt <input-file> --public-key <publicKey.qkey> --out <file.qenc>
  [--filename <basename>] [--source-evidence-key <signer.pqsk>]
  [--source-evidence-out <file>] [--source-evidence-sig-out <file>]
  [--source-evidence-pqpk-out <file>] [--force]
```

- `--filename` overrides the input basename stored in authenticated encrypted `wrapped-v1` metadata.
- `--source-evidence-key` additionally creates canonical source-evidence JSON, a detached QSIG over it, and the derived signer `.pqpk`. Defaults append `.source-evidence.json`, `.source-evidence.json.qsig`, and `.source-evidence.pqpk` to the QENC output name.
- Any source-evidence output override requires `--source-evidence-key`.
- All coordinated output paths are checked before writing. On a non-force partial write failure, best-effort cleanup removes files from that output set.
- Plaintext must be non-empty and at most 1 GiB. The command selects single-container or 8 MiB per-chunk AES-GCM automatically.

### `decrypt`

```text
qvault-cli decrypt <input.qenc> --private-key <privateKey.qkey>
  [--out <file> | --out-dir <directory> [--use-original-filename]
  | --use-original-filename] [--force]
```

- `--out` writes exactly that path and cannot be combined with `--out-dir` or `--use-original-filename`.
- `--out-dir` writes the authenticated original basename into that directory; `--use-original-filename` may be supplied for clarity but is not required with `--out-dir`.
- `--use-original-filename` without `--out-dir` writes beside the input QENC.
- With none of those options, output defaults to `<input.qenc>.decrypted`.
- If no original filename exists, filename-based modes use `decrypted`. Unsafe or non-portable recovered names are rejected rather than sanitized silently.
- A `QVB1` payload is validated and reported as `payloadKind: "qvpack"`, but the CLI writes the bundle bytes as one file; it does not extract entries.

### `split`

```text
qvault-cli split <input.qenc> --private-key <privateKey.qkey> --n <total> --k <data>
  [--out <directory>] [--auth-policy-level <level>]
  [--min-valid-signatures <count>] [--archive-approval-key <signer.pqsk>]
  [--force]
```

- `--out` defaults to `shards`.
- Cohort geometry must satisfy `2 <= k < n <= 255` and `n - k` must be even. The Shamir threshold is `k + (n - k) / 2`.
- `--auth-policy-level` defaults to `strong-pq-signature`; accepted values are `integrity-only`, `any-signature`, and `strong-pq-signature`.
- `--min-valid-signatures` defaults to `1` and must be positive.
- `--archive-approval-key` creates a same-run randomized PQ archive approval over canonical archive-state bytes and embeds the signature/public-key evidence into the emitted bundle and shards. The key must use a suite capable of satisfying the selected policy if immediate satisfaction is expected.
- Before output, split verifies that the private key decapsulates the QENC and that its key commitment matches.

### `attach`

```text
qvault-cli attach [--shards <shard>...] [--archive-state <archive-state.json>]
  [--bundle <lifecycle-bundle.json>] [evidence options]
  [--out-bundle <file>] [--out-shards <directory>]
  [--no-embed-into-shards] [--force]
```

Evidence options are repeatable unless noted:

- `--sig <file>` imports an archive-approval QSIG or supported Stellar signature.
- `--maintenance-sig <file>` requires one shared `--maintenance-target-ref <targetRef>`.
- `--source-evidence-sig <file>` requires either one `--source-evidence <file>` or `--source-evidence-target-ref <targetRef>`.
- `--source-evidence <file>` and `--source-evidence-bytes <file>` import source-evidence artifacts.
- `--pqpk <file>` imports PQ public-key evidence; it does not turn the mutable bundle into a trust anchor.
- `--ots <file>` imports detached OpenTimestamps evidence.
- `--ed25519-signer <address>` (alias `--expected-ed25519-signer`) supplies the expected Stellar signer during import.
- `--sig-import '<json>'` accepts a typed descriptor with required `file` and `signatureFamily` (`archive-approval`, `maintenance`, or `source-evidence`) and optional `targetType`, `targetRef`, `targetDigest` (hex string or `{ "value": "..." }`), and `sourceEvidence` path.

`--out-bundle` defaults to `lifecycle-bundle.json`; `--out-shards` defaults to `attached-shards`. Shards are rewritten only when shards were supplied and `--no-embed-into-shards` is absent. `--archive-state` is a consistency check, while `--bundle` supplies the existing mutable evidence carrier.

### `reshare`

```text
qvault-cli reshare --shards <shard>... --n <total> --k <data>
  [--bundle <file>] [--archive-id <hex>] [--state-id <hex>]
  [--cohort-id <hex>] [--bundle-digest <hex>]
  [--reason-code <text>] [--operator-role <text>] [--notes <text>]
  [--performed-at <RFC3339>] [--out <directory>] [--force]
  [--maintenance-sig <file>...] [--maintenance-pqpk <file>...]
  [--maintenance-ots <file>...] [--maintenance-ed25519-signer <address>]
```

- Creates a new availability cohort for the same archive state; it does not decrypt plaintext or claim compromise repair/reapproval.
- Uses the same `n`/`k` geometry rules as `split`.
- Selectors are optional only when the input set is unambiguous. Hex selectors must be exact lowercase values of the expected length.
- Defaults: `reason-code=same-state-resharing`, `operator-role=operator`, current UTC millisecond timestamp, and `out=reshared-shards`.
- Same-run maintenance signatures target the newly created transition. `--maintenance-pqpk` and `--maintenance-ots` require at least one `--maintenance-sig`.
- Outputs include canonical archive state, new cohort binding, transition record, lifecycle bundle, and the new shards.

### `inspect`

```text
qvault-cli inspect <artifact-file>
```

Recognizes supported canonical lifecycle JSON, `QVqcont-7`, and QENC. JSON mode reports type/version, digest, and a parsed summary. Unknown non-`.qenc`/`.qcont` input is reported as generic binary; malformed files carrying those extensions are rejected.

### `canonicalize`

```text
qvault-cli canonicalize <artifact-file>
```

Accepts a strict, already canonical archive-state, cohort-binding, lifecycle-bundle, transition-record, or source-evidence document, validates it, and re-emits the canonical representation. It intentionally rejects rather than repairs noncanonical input. Text mode writes only canonical JSON bytes to stdout, suitable for redirection. JSON mode emits a report containing the canonical value/text and SHA3-512 digest. Binary QENC/QVqcont/QSIG/PQ key files are not canonicalization targets.

### `verify`

```text
qvault-cli verify <archive-state.json> --bundle <lifecycle-bundle.json>
  [--sig <file>...] [--pqpk <file>...] [--ots <file>...]
  [--ed25519-signer <address>] [--required-policy-level <level>]
  [--include-detached-summary]
```

- `--bundle` is required even though argument parsing defers that check to command execution.
- Detached evidence is evaluated without rewriting the input bundle.
- Each `--pqpk` is an independent operator trust anchor for this invocation. Bundle-carried and QSIG-embedded keys can prove raw validity but cannot authorize a signer.
- `--required-policy-level` optionally raises the required level to `integrity-only`, `any-signature`, or `strong-pq-signature`; it cannot make the committed archive policy less strict.
- `--include-detached-summary` adds compact per-proof rows to JSON output.
- Unsatisfied policy returns a nonzero status even though the JSON report is still emitted.

### `restore`

```text
qvault-cli restore [<shard>...] [--shards <shard>...]
  [selection and verification options] [--dry-run]
  [--output-qenc <file>] [--output-secret-key <file>] [--out <base>]
  [--accept-policy-warnings] [--force]
```

- Positional shards and repeatable `--shards` inputs are combined; at least one is required.
- Selection options are `--archive-state`, `--bundle` (alias `--lifecycle-bundle`), `--archive-id`, `--state-id`, `--cohort-id`, and `--bundle-digest` (alias `--lifecycle-bundle-digest`). Use them whenever mixed inputs are possible.
- Verification options are repeatable `--sig` (alias `--signature`), `--pqpk`, `--ots`, and optional `--ed25519-signer` (alias `--expected-ed25519-signer`). Explicit PQPK/Ed25519 inputs are trust anchors for this invocation.
- `--dry-run` reconstructs and verifies in memory but writes no recovered QENC or key. In JSON mode, inspect `ok`, `wouldSucceed`, policy, integrity flags, rejected/corrupt/missing indices, non-selected inputs, and warnings.
- Write mode accepts `--output-qenc` (alias `--out-qenc`) and `--output-secret-key` (alias `--out-key`). `--out <base>` supplies defaults `<base>.qenc` and `<base>.qkey`; otherwise the base is derived from the first shard path.
- `--accept-policy-warnings` is required only for specifically acknowledged non-policy warnings such as multiple embedded lifecycle-bundle digests in the selected cohort. It never overrides an unsatisfied policy or integrity failure.

### `selftest`

```text
qvault-cli selftest [--filter <name-or-substring>]
```

Runs runtime health checks named `sha3-256-kat`, `kmac256-kat`, `aes-256-gcm-kat`, `ml-kem-keygen-encaps-decaps`, and `ml-dsa-44-sign-verify`. An empty filter or `crypto` runs all checks; another lowercase substring selects matching checks and must match at least one. ML-KEM and ML-DSA checks use production OS randomness.

### `version`

```text
qvault-cli version
```

Prints the package version. JSON mode also reports the supported `QVqcont-7` and `QV-Lifecycle-Bundle/v1` family.

## Rust-Only Archive Approval Workflow

This flow creates a Quantum Vault archive, signs its canonical archive-state descriptor with a PQ signing key, attaches the signature and public key to lifecycle evidence, verifies policy, restores the archive, and decrypts the restored container. It uses only the Rust CLI.

Container creation and signing are separate operations:

- `keygen`, `encrypt`, and `split` create the encrypted archive and recoverable shard cohort.
- `signer-keygen` creates PQ signing identity files: `signer.pqsk` and `signer.pqpk`.
- `sign --target archive-state` signs the exact canonical archive-state bytes emitted by `split`.
- `attach --sig --pqpk` binds the detached signature and public key into portable lifecycle evidence; policy commands still require the trusted signer to be supplied independently with `--pqpk`.

### 1. Generate An ML-KEM Keypair

```bash
$QV --json keygen --out vault-keys --name archive-2026-
```

This writes:

- `vault-keys/archive-2026-publicKey.qkey`
- `vault-keys/archive-2026-privateKey.qkey`

The public key is used for encryption. The private key is needed for decrypting `.qenc` containers and for splitting a `.qenc` into shards.

### 2. Encrypt A File

```bash
$QV --json encrypt important.pdf \
  --public-key vault-keys/archive-2026-publicKey.qkey \
  --out important.pdf.qenc \
  --filename important.pdf
```

The output `.qenc` is the encrypted payload container. The `--filename` value is stored inside encrypted wrapped metadata and is used by `decrypt --use-original-filename`.

### 3. Split Into QVqcont-7 Shards

```bash
$QV --json split important.pdf.qenc \
  --private-key vault-keys/archive-2026-privateKey.qkey \
  --n 5 \
  --k 3 \
  --out important-shards \
  --auth-policy-level strong-pq-signature \
  --min-valid-signatures 1
```

This writes:

- `important-shards/important.pdf.archive-state.json`
- `important-shards/important.pdf.cohort-binding.json`
- `important-shards/important.pdf.lifecycle-bundle.json`
- `important-shards/important.pdf.part1-of-5.qcont` through `part5-of-5.qcont`

The `--n` value is the number of shard files. The `--k` value is the Reed-Solomon data shard count. Under the successor profile, parity is `n - k`, parity must be even, and the Shamir threshold is derived as `k + parity / 2`. For example, `--n 5 --k 3` produces parity `2` and threshold `4`.

The archive-state JSON file is canonical and stable. It is the approval target in the next step.

### 4. Generate A PQ Signing Keypair

```bash
$QV --json signer-keygen \
  --suite mldsa-87 \
  --out signer
```

This writes:

- `signer.pqsk`: secret PQ signing key, written through the secret-file writer
- `signer.pqpk`: public PQ signing key, safe to distribute as signer identity material

JSON output reports public/audit-safe fields such as suite, public-key path, secret-key path, and signer fingerprint. It never includes secret bytes, secret-key base64, seed material, or secret-key digests.

### 5. Sign The Canonical Archive State

```bash
$QV --json sign important-shards/important.pdf.archive-state.json \
  --secret-key signer.pqsk \
  --target archive-state \
  --out important.pdf.archive-state.json.qsig
```

`sign --target archive-state` signs the exact bytes read from `important-shards/important.pdf.archive-state.json` after verifying that those bytes are a canonical archive-state descriptor. It does not sign `important-shards/important.pdf.lifecycle-bundle.json`.

That distinction matters. Archive-state bytes define the stable archive identity and policy commitment. Lifecycle-bundle bytes are mutable evidence: they can later receive detached signatures, `.pqpk` public keys, OpenTimestamps proofs, transition records, and source evidence without changing what the approval signature covers.

For generic document signing, use the default target:

```bash
$QV --json sign document.pdf \
  --secret-key signer.pqsk \
  --out document.pdf.qsig
```

### 6. Attach The Signature And Public Key

```bash
$QV --json attach \
  --shards important-shards/*.qcont \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --sig important.pdf.archive-state.json.qsig \
  --pqpk signer.pqpk \
  --out-bundle important-approved.lifecycle-bundle.json \
  --out-shards important-approved-shards
```

`attach --sig --pqpk` imports the detached archive approval signature and its signer public key into portable lifecycle evidence. Because the lifecycle bundle is mutable, the imported key is not a trust anchor. `verify` and `restore` count the signature toward `strong-pq-signature` only when the operator independently supplies the authorized signer with `--pqpk`.

A `.qsig` embeds a signer public key for self-contained cryptographic verification, but that embedded key is not a trusted identity by itself. Embedded-only or bundle-key verification proves that the signature is internally consistent; it does not prove that the signer was authorized. Archive policy and trusted maintenance/source-evidence status require an explicit user pin such as `--pqpk`.

### 7. Verify Archive State And Lifecycle Evidence

After attachment, policy verification can use the approved lifecycle bundle directly:

```bash
$QV --json verify important-shards/important.pdf.archive-state.json \
  --bundle important-approved.lifecycle-bundle.json \
  --pqpk signer.pqpk \
  --required-policy-level strong-pq-signature
```

For automation, check:

- `ok`
- `policy.satisfied`
- `status.strongPqSignatureVerified`
- `verification.counts.pinnedValidStrongPq`

Typical successful policy JSON includes these stable fields:

```json
{
  "command": "verify",
  "ok": true,
  "policy": {
    "satisfied": true
  },
  "status": {
    "strongPqSignatureVerified": true
  }
}
```

You can also verify a detached `.qsig` against arbitrary document bytes without lifecycle policy evaluation:

```bash
$QV --json sig-verify important-shards/important.pdf.archive-state.json \
  --sig important.pdf.archive-state.json.qsig \
  --pqpk signer.pqpk
```

`sig-verify` reports cryptographic verification, `trustSource`, and whether a supplied `.pqpk` was used. It does not evaluate archive policy and does not replace `verify` or `restore`.

Typical successful pinned signature JSON includes:

```json
{
  "command": "sig-verify",
  "ok": true,
  "cryptographicOk": true,
  "trusted": true,
  "trustSource": "loaded-pqpk",
  "lifecyclePolicyEvaluated": false,
  "countedForLifecyclePolicy": false
}
```

Archive approval signatures target canonical archive-state bytes. OpenTimestamps evidence, when present, links to `SHA-256(detached signature bytes)` and is reported separately; it does not satisfy archive policy by itself.

### 8. Restore The `.qenc` And Secret Key

Dry-run restore checks shard consistency, lifecycle evidence, restored integrity, and archive policy without writing recovered secret material:

```bash
$QV --json restore important-approved-shards/*.qcont \
  --bundle important-approved.lifecycle-bundle.json \
  --pqpk signer.pqpk \
  --dry-run
```

Use dry-run before write-mode restore, especially when shards may contain multiple lifecycle-bundle variants.

Write-mode restore emits the encrypted `.qenc` and recovered ML-KEM secret key:

```bash
$QV --json restore important-approved-shards/*.qcont \
  --bundle important-approved.lifecycle-bundle.json \
  --pqpk signer.pqpk \
  --output-qenc restored/important.pdf.qenc \
  --output-secret-key restored/important-privateKey.qkey
```

Restore is policy-gated. A strong PQ archive will not restore unless explicit restore inputs authorize enough valid signers to satisfy the archive policy. Signatures and public keys embedded in the lifecycle bundle remain evidence only; pass each trusted PQ signer independently with `--pqpk`.

If restore reports that lifecycle-bundle variant acknowledgement is required, inspect the JSON report and rerun with `--accept-policy-warnings` only if the operator accepts the residual bundle-variant risk.

### 9. Decrypt A Restored Container

```bash
$QV --json decrypt restored/important.pdf.qenc \
  --private-key restored/important-privateKey.qkey \
  --out restored/important.pdf
```

Or write using encrypted original filename metadata:

```bash
$QV decrypt restored/important.pdf.qenc \
  --private-key restored/important-privateKey.qkey \
  --out-dir restored-files \
  --use-original-filename
```

## Alternate Verification Without Attachment

For a one-off policy check, `verify` and `restore` can accept detached signatures and signer pins directly. This does not mutate the lifecycle bundle:

```bash
$QV --json verify important-shards/important.pdf.archive-state.json \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --sig important.pdf.archive-state.json.qsig \
  --pqpk signer.pqpk \
  --required-policy-level strong-pq-signature \
  --include-detached-summary
```

```bash
$QV --json restore important-shards/*.qcont \
  --bundle important-shards/important.pdf.lifecycle-bundle.json \
  --sig important.pdf.archive-state.json.qsig \
  --pqpk signer.pqpk \
  --dry-run
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

Stable qvCodes and process statuses:

| qvCode | Exit | Meaning |
| --- | ---: | --- |
| `UNEXPECTED` | 1 | Verification/internal failure without a more specific public category |
| `POLICY_NOT_SATISFIED` | 1 | Archive policy blocks verify or restore |
| `USAGE` | 2 | Invalid command syntax or incompatible options |
| `ENTROPY_FAILED` | 3 | Required OS cryptographic randomness was unavailable or replay defense rejected a repeat |
| `FORMAT_POLICY_REJECT` | 4 | Malformed, noncanonical, unsupported, or policy-invalid artifact |
| `KEY_REJECTED` | 5 | Supplied key is malformed, wrong-sized, or does not match |
| `AEAD_FAILED` | 6 | Key commitment or AES-GCM authentication failed |
| `QUORUM_UNREACHABLE` | 7 | Not enough valid shards or shard integrity mismatch |
| `SIGNATURE_IMPORT_FAILED` | 8 | Detached lifecycle signature import failed |
| `AMBIGUOUS_INPUTS` | 9 | Archive/cohort/bundle selection is ambiguous or invalid |
| `RESHARE_CONTRACT_VIOLATION` | 10 | Same-state reshare constraints were violated |
| `RESTORED_INTEGRITY_FAILED` | 11 | Reconstructed QENC/key/header/hash binding failed |
| `RESTORE_LIFECYCLE_VARIANT_ACK_REQUIRED` | 12 | Write-mode restore needs explicit lifecycle-bundle variant acknowledgement |

Some JSON commands, notably `verify` and `restore --dry-run`, print a complete unsuccessful report and then exit nonzero without printing a second error envelope. Automation must check both process status and the report’s `ok`/policy fields.

## Correctness And Safety Practices

- Keep the private `.qkey` separate from the public `.qkey`.
- Store more than the minimum number of shards and test restore periodically.
- Preserve archive-state, cohort-binding, lifecycle-bundle, signature, public-key, and timestamp files alongside shards.
- Use `restore --dry-run --json` before write-mode restore.
- Use explicit `--archive-id`, `--state-id`, `--cohort-id`, or `--bundle-digest` when operating on mixed shard sets.
- Keep the default aggregate shard budget unless a reviewed archive requires a larger value; raising `--max-shard-input-bytes` increases peak-memory exposure.
- Do not use `--allow-symlink` on untrusted paths.
- Treat OpenTimestamps completion labels as heuristic reporting, not full calendar attestation validation.
- Keep detached signing keys and `.pqsk` files outside shared archive storage.
- Supply trusted signer identities independently to each `verify`/`restore` operation. Do not treat keys embedded in a QSIG or mutable lifecycle bundle as authorization.
- Never enable `deterministic-test-vectors` in a production build or expose deterministic seeds/nonces as an operational interface.
- Treat `selftest` and known-answer tests as runtime/engineering health checks, not proof of formal cryptographic module validation.

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
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo build --release -p qvault-cli --locked --no-default-features
cargo deny check
```

Normal development and operation are self-contained in Rust. When intentionally changing wire-visible behavior, compare against the pinned JavaScript interoperability oracle and update focused cross-implementation fixtures under `crates/qvault-core/tests/data/`. The JavaScript project is a conformance reference, not a runtime dependency of `qv-rs`.
