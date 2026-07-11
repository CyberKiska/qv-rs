# Successor Conformance Notes

This repository's default build is successor-only for the Quantum Vault archive lifecycle layer.

Accepted production formats:

- `.qenc` `QVv1-5-0`
- archive-state descriptor `quantum-vault-archive-state-descriptor/v1`
- cohort binding `quantum-vault-cohort-binding/v1`
- transition record `quantum-vault-transition-record/v1`
- source evidence `quantum-vault-source-evidence/v1`
- lifecycle bundle `QV-Lifecycle-Bundle` v1
- shard format `QVqcont-7`

Removed predecessor formats such as archive manifest v2, `QV-Manifest-Bundle` v1, and `QVqcont-6` are not accepted except as negative-test inputs.

## Oracle Material

Rust conformance tests use frozen copies of JavaScript oracle material under `crates/qvault-core/tests/data/`:

- `schema/fixtures`: lifecycle schema and semantic fixtures
- `corpus/qcont`: successor shard corpus
- `corpus/qsig`, `corpus/pqpk`, `corpus/ots`: detached signature, public key, and timestamp-linkage corpora
- `qenc_interop`: `.qenc` cross-language vectors
- `examples/single`, `examples/bundle`: compact successor examples

Refresh these fixtures only as part of an intentional oracle update.

## Conformance Rules

Rust must preserve these JS/normative contracts:

- canonical archive-state bytes are the archive approval signature target
- cohort identity is based on archive id, state id, cohort id, and exact canonical bytes
- lifecycle-bundle evidence is mutable and is not the archive approval target
- restore fails closed on ambiguity or policy failure
- detached timestamp evidence links to `SHA-256(detached signature bytes)`
- `apparentlyComplete` and `completeProof` are reporting heuristics only
- CLI errors use JS-aligned `qvCode` strings and exit codes

## Trust And Reporting Rules

Rust follows the current JS signer-identity policy counting rules:

- Archive approval signatures count toward `any-signature` and `strong-pq-signature` only when the signer is bound through lifecycle-bundle public-key material or an explicit user pin.
- Self-verifying `.qsig` material may verify structurally and be reported, but it does not satisfy archive policy on its own.
- Multiple proofs from one verified signer count once; thresholds count distinct stable signer identities.

Rust follows the normative restore-summary label from `format-spec.md` for complete-looking OTS proofs:

- `completionLabel = "OTS proof appears complete (heuristic)"`

The current JS implementation still emits `OTS proof appears complete` in some reporting paths. The Rust label makes the heuristic origin explicit without changing OTS acceptance, linkage, `apparentlyComplete`, `completeProof`, or policy semantics.

Every intentional deviation should have a focused default test.
