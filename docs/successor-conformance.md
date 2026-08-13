# Successor Conformance Notes

This repository's default build is successor-only for the Quantum Vault archive lifecycle layer. It is a standalone Rust implementation: the JavaScript project is not loaded or invoked in production. “Oracle” below means an independently pinned implementation used to prove artifact compatibility in CI.

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

CI compares the mirrored corpus byte-for-byte with `CyberKiska/quantum-vault` revision `485a51388d0d26ee6cae9cd4785753a12eee9d32`. Updating that pin and any fixture bytes is one reviewed conformance change.

## Conformance Rules

Rust must preserve these JS/normative contracts:

- canonical archive-state bytes are the archive approval signature target
- cohort identity is based on archive id, state id, cohort id, and exact canonical bytes
- lifecycle-bundle evidence is mutable and is not the archive approval target
- restore fails closed on ambiguity or policy failure
- detached timestamp evidence links to `SHA-256(detached signature bytes)`
- `apparentlyComplete` and `completeProof` are reporting heuristics only
- CLI errors use JS-aligned `qvCode` strings and exit codes
- production outputs use OS randomness; exact deterministic inputs are test-only and do not define an operational cross-language API

## Trust And Reporting Rules

Rust follows the current JS signer-identity policy counting rules:

- Archive approval signatures count toward `any-signature` and `strong-pq-signature` only when the signer is authorized by an explicit user pin. Lifecycle-bundle public keys are mutable evidence and never act as trust anchors.
- Maintenance and source-evidence signatures are reported as trusted/verified only when an explicit user pin authorizes the signer; raw cryptographic validity remains available separately.
- Self-verifying `.qsig` material may verify structurally and be reported, but it does not satisfy archive policy on its own.
- Multiple proofs from one verified signer count once; thresholds count distinct stable signer identities.

Rust follows the normative restore-summary label from `format-spec.md` for complete-looking OTS proofs:

- `completionLabel = "OTS proof appears complete (heuristic)"`

The current JS implementation still emits `OTS proof appears complete` in some reporting paths. The Rust label makes the heuristic origin explicit without changing OTS acceptance, linkage, `apparentlyComplete`, `completeProof`, or policy semantics.

Every intentional deviation should have a focused default test.

## Runtime And CLI Independence

Conformance applies to accepted/emitted artifact bytes, canonical identities, cryptographic profiles, policy semantics, and stable shared error taxonomy. It does not require either implementation to shell out to the other, share a dependency graph, or expose every command/flag from the other CLI.

The Rust-only workflow covers key generation, QENC encryption/decryption, QVqcont split/restore/attach/reshare, PQ signer key generation, QSIG signing/verification, inspection, and lifecycle canonicalization. Node.js and `QV_ORACLE_ROOT` are optional release/contributor tools used only for explicit live corpus parity.

Deterministic ML-KEM, QENC, Shamir, and archive-identity controls compile only with `deterministic-test-vectors`. Ordinary builds have no deterministic cryptographic input flags or public seeded QENC path. This is an intentional production-safety boundary and does not affect byte-level vector reproduction in all-feature tests.
