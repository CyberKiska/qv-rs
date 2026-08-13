# Quantum Vault Fuzzing

`cargo-fuzz` targets for parser and restore-selection surfaces that accept untrusted bytes.

CI runs all six targets against committed seeds on each change and schedules longer pinned-nightly sanitizer runs weekly. Local long-running campaigns remain important because the per-change job is a harness/seed smoke check rather than a substitute for sustained fuzzing.

Fuzzing is self-contained in Rust and uses the committed corpus; it does not require the JavaScript Quantum Vault checkout. The separate `fuzz/` workspace depends on `qvault-core` with its normal production feature set, so fuzz harnesses exercise the same deterministic-input boundary as the standalone application.

## Install

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run from the **repository root** (`qv-cli/`). The `fuzz/` crate is a separate workspace; `cargo fuzz` discovers it automatically.

## Corpus layout (important)

LibFuzzer **writes new inputs into corpus directories you pass on the command line**. Never use committed test fixtures as the only corpus path — that pollutes `crates/qvault-core/tests/data/`.

Use a **writable** directory under `fuzz/corpus/<target>/` (gitignored) plus **read-only seeds** from `tests/data/`:

```sh
mkdir -p fuzz/corpus/fuzz_qsig
# One-time seed copy (optional; you can also pass seed dirs as extra read-only inputs):
cp -n crates/qvault-core/tests/data/corpus/qsig/* fuzz/corpus/fuzz_qsig/ 2>/dev/null || true
```

**Argument order:** put the writable corpus **first**, then seed directories. New files are merged into the first corpus dir.

If committed seeds were polluted, restore: `git checkout -- crates/qvault-core/tests/data/`.

## One-shot harness check (`-runs=1`)

Confirms each target builds and runs one input per seed (CI / after toolchain changes). Stable, no ASan:

```sh
cargo fuzz run fuzz_qsig fuzz/corpus/fuzz_qsig \
  crates/qvault-core/tests/data/corpus/qsig --sanitizer none -- -runs=1
```

Repeat for other targets, or use the **all-targets** loop below with `FUZZ_FLAGS="-runs=1"`.

## Run tiers

Replace `WRITABLE` and `SEEDS` per target (see table below). LibFuzzer flags go after `--`.

### ~10 s smoke (stable)

```sh
WRITABLE=fuzz/corpus/fuzz_qsig
SEEDS="crates/qvault-core/tests/data/corpus/qsig"
mkdir -p "$WRITABLE"

cargo fuzz run fuzz_qsig "$WRITABLE" $SEEDS --sanitizer none -- \
  -max_total_time=10 -print_final_stats=1
```

### ~10 min local (nightly + ASan)

```sh
RUSTUP_TOOLCHAIN=nightly cargo fuzz run fuzz_qsig "$WRITABLE" $SEEDS -- \
  -max_total_time=600 -timeout=10 -print_final_stats=1
```

### Hours (serious)

```sh
RUSTUP_TOOLCHAIN=nightly cargo fuzz run fuzz_qsig "$WRITABLE" $SEEDS -- \
  -max_total_time=14400 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1
```

Background example:

```sh
nohup env RUSTUP_TOOLCHAIN=nightly cargo fuzz run fuzz_qsig "$WRITABLE" $SEEDS -- \
  -max_total_time=14400 -print_final_stats=1 \
  > fuzz-runs-fuzz_qsig.log 2>&1 &
```

Crashes land in `fuzz/artifacts/<target>/`. Reproduce with the crash file path printed in the log.

## All six targets (seeds)

| Target | Writable corpus | Seed dirs (after writable) |
| --- | --- | --- |
| `fuzz_qsig` | `fuzz/corpus/fuzz_qsig` | `crates/qvault-core/tests/data/corpus/qsig` |
| `fuzz_pqpk` | `fuzz/corpus/fuzz_pqpk` | `crates/qvault-core/tests/data/corpus/pqpk` |
| `fuzz_qenc_header` | `fuzz/corpus/fuzz_qenc_header` | `crates/qvault-core/tests/data/qenc_interop/single-small`, `crates/qvault-core/tests/data/qenc_interop/chunked-large`, `crates/qvault-core/tests/data/split_v7` |
| `fuzz_qvqcont7_shard` | `fuzz/corpus/fuzz_qvqcont7_shard` | `crates/qvault-core/tests/data/corpus/qcont` |
| `fuzz_lifecycle_bundle` | `fuzz/corpus/fuzz_lifecycle_bundle` | `crates/qvault-core/tests/data/schema/fixtures` |
| `fuzz_restore_selection` | `fuzz/corpus/fuzz_restore_selection` | `crates/qvault-core/tests/data/corpus/qcont`, `crates/qvault-core/tests/data/examples/single`, `crates/qvault-core/tests/data/examples/bundle` |

`fuzz_restore_selection` is the heaviest target (builds a 5-of-3 split on some inputs); give it a longer budget or a higher `-timeout`.

### Run all six (copy-paste loop)

From the repository root. Pick one profile, then run the loop.

| Profile | `MAX` | `FUZZ_SAN` | `TOOLCHAIN` | Wall time (6 targets, sequential) |
| --- | --- | --- | --- | --- |
| One-shot | — | `--sanitizer none` | (stable) | <1 min |
| Smoke | `10` | `--sanitizer none` | (stable) | ~1 min |
| Local | `600` | (omit) | `nightly` | ~1 h |
| Serious | `14400` | (omit) | `nightly` | ~24 h |

```sh
# --- pick one profile ---
MAX=10
FUZZ_SAN="--sanitizer none"
TOOLCHAIN=""
FUZZ_FLAGS="-max_total_time=$MAX -timeout=10 -print_final_stats=1"
# One-shot instead: FUZZ_FLAGS="-runs=1" (ignore MAX)

# --- loop (stable smoke: leave TOOLCHAIN empty; local/serious: TOOLCHAIN=nightly) ---
run_one() {
  mkdir -p "fuzz/corpus/$1"
  if [ -n "$TOOLCHAIN" ]; then
    env RUSTUP_TOOLCHAIN="$TOOLCHAIN" cargo fuzz run "$1" "fuzz/corpus/$1" "${@:2}" \
      $FUZZ_SAN -- $FUZZ_FLAGS
  else
    cargo fuzz run "$1" "fuzz/corpus/$1" "${@:2}" $FUZZ_SAN -- $FUZZ_FLAGS
  fi
}

run_one fuzz_qsig              crates/qvault-core/tests/data/corpus/qsig
run_one fuzz_pqpk              crates/qvault-core/tests/data/corpus/pqpk
run_one fuzz_qenc_header       crates/qvault-core/tests/data/qenc_interop/single-small \
                               crates/qvault-core/tests/data/qenc_interop/chunked-large \
                               crates/qvault-core/tests/data/split_v7
run_one fuzz_qvqcont7_shard    crates/qvault-core/tests/data/corpus/qcont
run_one fuzz_lifecycle_bundle  crates/qvault-core/tests/data/schema/fixtures
run_one fuzz_restore_selection crates/qvault-core/tests/data/corpus/qcont \
                               crates/qvault-core/tests/data/examples/single \
                               crates/qvault-core/tests/data/examples/bundle
```

For one-shot, set `FUZZ_FLAGS="-runs=1"` and keep `FUZZ_SAN="--sanitizer none"` (ignore `MAX`). Run targets in parallel terminals to saturate CPU/RAM.

## Corpus helpers

The qsig, pqpk, and qcont targets understand the committed JSON wrapper (`encoding = "base64"`, `bytes = …`) and fuzz both the raw input and decoded artifact bytes.

`fuzz_qenc_header` always parses embedded `split_v7/single-small.qenc`, reads `qenc.metaUtf8` from `expectations.json`, and parses raw `.qenc` from seed dirs.

## `fuzz_restore_selection` input layout

| Byte | Meaning |
| --- | --- |
| `data[0]` | `0x01` archive id, `0x02` state id, `0x04` cohort id, `0x08` lifecycle bundle digest, `0x10` disable policy enforcement, `0x40` bundle example shard (when `0x80` clear), `0x80` use built split_v7 5-of-3 shards |
| `data[1]` | Shard bitmask when `0x80` is set (bits 0–4) |
| `data[2]` | `0x01` override `archive_state_bytes`, `0x02` override `lifecycle_bundle_bytes` (from `data[3..]`) |

When `0x80` is set, only shards from the same `split_v7` archive are combined. Attachment overrides are clamped to 512 KiB.
