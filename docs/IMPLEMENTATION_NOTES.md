# Implementation Notes

These notes describe the current Rust successor tree. Historical predecessor behavior is not a compatibility target.

## Source Of Truth

Do not infer protocol behavior from older Rust code, stale prose, or removed predecessor fixtures. The oracle is the sibling JavaScript repository at `https://github.com/CyberKiska/quantum-vault/`.

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

## Fixture Layout

Self-contained fixtures live under `crates/qvault-core/tests/data/`:

- `schema/fixtures`: lifecycle JSON fixtures mirrored from the JS docs
- `corpus/qcont`: `QVqcont-7` shard corpus
- `corpus/qsig`, `corpus/pqpk`, `corpus/ots`: detached signature, public key, and timestamp-linkage corpus
- `qenc_interop`: `.qenc` parity vectors
- `examples/single`, `examples/bundle`: compact JS successor examples

Refresh these fixtures only when intentionally moving to a new JS oracle revision. Fixture updates should include a focused Rust test change that proves the new behavior.

`tools/gen-js-fixtures.mjs` is disabled until rewritten against the successor JS modules. A replacement generator should call the lifecycle builders and canonicalizers in `qcont/lifecycle-shard.js`, `qcont/lifecycle-attach.js`, and `lifecycle/artifacts.js`.

## Coding Rules

1. Keep wire-visible JSON explicit; do not rely on unordered maps for canonical artifacts.
2. Use structured parsers and validators, not string heuristics, for artifact semantics.
3. Do not add hidden format fallback.
4. Do not reintroduce predecessor acceptance in default paths.
5. Map user-visible failures through stable `QvCode` values aligned with JS `exit.js`.
6. Zeroize temporary shared secrets, derived keys, and plaintext buffers where feasible.
7. Avoid `Debug` output that dumps raw secret material.
8. Document any intentional Rust/JS policy deviation in `docs/successor-conformance.md` and add a focused test.
