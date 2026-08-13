# Mirrored binary corpus (`docs/schema/corpus`)

These JSON fixtures are a **byte-identical mirror** of the pinned
`quantum-vault/docs/schema/corpus/` interoperability oracle (successor `.qsig`, `.pqpk`, `.ots`, `QVqcont-7`). They are committed so normal Rust builds/tests remain standalone and require neither Node.js nor a JavaScript checkout.

- **Committed bytes are authoritative** (`bytes` base64 + `expectedDigest` SHA3-512).
- Rust tests under `corpus_*` enforce digest, parse/verify behavior, and (optionally) parity with a local oracle checkout.

## Optional: verify mirror has not drifted from `quantum-vault`

With an absolute path to the `quantum-vault` repository root:

```bash
export QV_ORACLE_ROOT=/path/to/quantum-vault
cargo test -p qvault-core --test corpus_oracle_parity -- --ignored
```

The parity test is intentionally ignored by the default suite so a missing oracle checkout cannot be mistaken for a successful comparison.

CI checks against `CyberKiska/quantum-vault` revision `485a51388d0d26ee6cae9cd4785753a12eee9d32`. A manual checkout should use that revision unless the purpose of the change is an explicitly reviewed oracle update.

## JSON Schema grammar layer (oracle only)

The normative JSON Schema files live under `quantum-vault/docs/schema/*.schema.json`.
The JS repo validates fixtures via:

- `npm run schema:fixtures` — canonical JSON fixtures
- `npm run corpus:verify` — this binary corpus

This Rust crate intentionally does **not** add a JSON Schema dependency; semantic validation stays in `qvault-core`, while schema grammar stays anchored in the oracle tooling above.
