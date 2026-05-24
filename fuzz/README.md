# Quantum Vault Fuzzing

This directory contains `cargo-fuzz` targets for parser and restore-selection surfaces that accept untrusted bytes.

Install the runner outside normal production builds:

```sh
cargo install cargo-fuzz
```

Run short smoke checks from the repository root. On stable Rust, use `--sanitizer none`; ASan-backed fuzzing requires a nightly toolchain.

```sh
cargo fuzz run fuzz_qsig crates/qvault-core/tests/data/corpus/qsig --sanitizer none -- -runs=1
cargo fuzz run fuzz_pqpk crates/qvault-core/tests/data/corpus/pqpk --sanitizer none -- -runs=1
cargo fuzz run fuzz_qenc_header crates/qvault-core/tests/data/qenc_interop/single-small crates/qvault-core/tests/data/qenc_interop/chunked-large --sanitizer none -- -runs=1
cargo fuzz run fuzz_qvqcont7_shard crates/qvault-core/tests/data/corpus/qcont --sanitizer none -- -runs=1
cargo fuzz run fuzz_lifecycle_bundle crates/qvault-core/tests/data/schema/fixtures --sanitizer none -- -runs=1
cargo fuzz run fuzz_restore_selection crates/qvault-core/tests/data/corpus/qcont crates/qvault-core/tests/data/examples/single crates/qvault-core/tests/data/examples/bundle --sanitizer none -- -runs=1
```

For local coverage-guided runs with nightly, omit `--sanitizer none` and replace `-runs=1` with a time budget:

```sh
cargo fuzz run fuzz_qsig crates/qvault-core/tests/data/corpus/qsig -- -max_total_time=60
```

The qsig, pqpk, and qcont targets understand the committed corpus JSON wrapper shape (`encoding = "base64"`, `bytes = ...`) and fuzz both the raw input and decoded artifact bytes. The qenc target also consumes `expectations.json` files by extracting `qenc.metaUtf8`, while raw `.qenc` files exercise the header parser directly.
