# Mirrored binary corpus (`docs/schema/corpus`)

These JSON fixtures are a **byte-identical mirror** of
`quantum-vault/docs/schema/corpus/` (successor `.qsig`, `.pqpk`, `.ots`, `QVqcont-7`).

- **Committed bytes are authoritative** (`bytes` base64 + `expectedDigest` SHA3-512).
- Rust tests under `corpus_*` enforce digest, parse/verify behavior, and (optionally) parity with a local oracle checkout.

## Optional: verify mirror has not drifted from `quantum-vault`

With an absolute path to the `quantum-vault` repository root:

```bash
export QV_ORACLE_ROOT=/path/to/quantum-vault
cargo test -p qvault-core corpus_bytes_match_oracle_when_qv_oracle_root_set
```

## JSON Schema grammar layer (oracle only)

The normative JSON Schema files live under `quantum-vault/docs/schema/*.schema.json`.
The JS repo validates fixtures via:

- `npm run schema:fixtures` — canonical JSON fixtures
- `npm run corpus:verify` — this binary corpus

This Rust crate intentionally does **not** add a JSON Schema dependency; semantic validation stays in `qvault-core`, while schema grammar stays anchored in the oracle tooling above.
