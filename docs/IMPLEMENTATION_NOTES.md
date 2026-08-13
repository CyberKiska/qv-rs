# Implementation Notes

These notes describe the current Rust successor tree. Historical predecessor behavior is not a compatibility target.

## Source Of Truth

`qv-rs` is a complete standalone implementation: production builds and runtime operation must not invoke or depend on JavaScript. The repository's Rust code, tests, and local documentation define the shipped behavior.

For cross-implementation format compatibility, the independent oracle is the pinned JavaScript repository at `https://github.com/CyberKiska/quantum-vault/`. Do not infer wire contracts from older Rust code, stale prose, removed predecessor fixtures, or an unpinned JavaScript checkout. Oracle references below are used for reviewed conformance work, not ordinary execution.

Primary JS and normative references:

- `src/core/crypto/qenc/format.js`
- `src/core/crypto/qcont/lifecycle-shard.js`
- `src/core/crypto/qcont/lifecycle-attach.js`
- `src/core/crypto/qcont/restore.js`
- `src/core/crypto/lifecycle/artifacts.js`
- `src/core/crypto/manifest/jcs.js`
- `src/core/crypto/manifest/strict-json.js`
- `src/core/crypto/auth/qsig.js`
- `src/core/crypto/auth/stellar-sig.js`
- `src/core/crypto/auth/opentimestamps.js`
- `src/core/crypto/auth/signature-suites.js`
- `src/core/cli/lib/exit.js`
- `docs/format-spec.md`
- `docs/security-model.md`
- `docs/trust-and-policy.md`
- `docs/schema/`

## Current Boundary

Default Rust builds implement only the current archive lifecycle:

- `.qenc` `QVv1-5-0`
- archive-state descriptor v1
- cohort binding v1
- transition-record and source-evidence v1
- `QV-Lifecycle-Bundle` v1
- `QVqcont-7`

The workspace has no default features. `deterministic-test-vectors` is a non-production feature that exposes exact ML-KEM seeds, QENC nonce/salt tuples, deterministic Shamir input, and fixture identity controls needed for pinned byte vectors. CI must prove that the ordinary `qvault-cli` dependency graph does not enable it.

## Contracts

- Use explicit algorithm, schema, version, and canonicalization labels.
- Parse JSON strictly: reject duplicate keys, malformed strings, unsupported numbers, unknown top-level fields, and non-canonical bytes where canonical bytes are required.
- Canonical bytes must be deterministic and cross-language comparable.
- Archive approval signatures target canonical archive-state bytes.
- Maintenance signatures target canonical transition-record bytes.
- Source-evidence signatures target canonical source-evidence bytes.
- Lifecycle bundles are mutable evidence carriers; archive-state and cohort-binding bytes are identity inputs.
- Restore groups by `archiveId`, `stateId`, `cohortId`, exact archive-state bytes, and exact cohort-binding bytes.
- Restore and verify fail closed on ambiguity, invalid bindings, unsatisfied policy, or missing required acknowledgements.
- OTS links to detached signature bytes via SHA-256 and never satisfies archive policy by itself.
- Mutable bundle-carried or QSIG-embedded public keys are evidence, not authorization. Only externally supplied verification pins contribute trusted status or policy counts.
- Production randomness comes from the OS provider and fails closed. Seeded/deterministic helpers must remain unavailable without the test-vector feature.

## Fixture Layout

Self-contained fixtures live under `crates/qvault-core/tests/data/`:

- `schema/fixtures`: lifecycle JSON fixtures mirrored from the JS docs
- `corpus/qcont`: `QVqcont-7` shard corpus
- `corpus/qsig`, `corpus/pqpk`, `corpus/ots`: detached signature, public key, and timestamp-linkage corpus
- `qenc_interop`: `.qenc` parity vectors
- `examples/single`, `examples/bundle`: compact JS successor examples

Refresh these fixtures only when intentionally moving to a new JS oracle revision. Fixture updates should include a focused Rust test change that proves the new behavior.

The optional live corpus comparison uses `QV_ORACLE_ROOT` and an explicit ignored-test invocation. CI pins the oracle commit; updating that commit and the frozen fixtures is one reviewed conformance change.

`tools/gen-js-fixtures.mjs` is disabled until rewritten against the successor JS modules. A replacement generator would be maintenance tooling only and must not become a Rust build/runtime dependency.

## Coding Rules

1. Keep wire-visible JSON explicit; do not rely on unordered maps for canonical artifacts.
2. Use structured parsers and validators, not string heuristics, for artifact semantics.
3. Do not add hidden format fallback.
4. Do not reintroduce predecessor acceptance in default paths.
5. Map user-visible failures through stable `QvCode` values aligned with JS `exit.js`.
6. Zeroize temporary shared secrets, derived keys, and plaintext buffers where feasible.
7. Avoid `Debug` output that dumps raw secret material.
8. Document any intentional Rust/JS policy deviation in `docs/successor-conformance.md` and add a focused test.
9. Acquire production cryptographic randomness through the centralized OS-backed RNG helpers. Preserve entropy-failure attribution; never fall back to timestamps, process state, deterministic PRNGs, or user-visible seeds.
10. Keep deterministic APIs and CLI fixture controls behind `deterministic-test-vectors`; never make that feature a default or production dependency.
11. Use checked arithmetic and fallible allocation for hostile lengths. Add format-specific bounds before reading or allocating.
12. Treat lifecycle bundle keys as untrusted evidence unless the caller independently supplies an authorized signer pin.
13. Prefer structured errors to `expect`, `unwrap`, or `unreachable` in production paths. Both crates must continue to forbid unsafe code.
