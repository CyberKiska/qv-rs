//! Optional byte-for-byte parity between this crate's mirrored corpus and a checkout of
//! `quantum-vault` (`docs/schema/corpus/`).
//!
//! When the environment variable `QV_ORACLE_ROOT` is set to the absolute path of the
//! `quantum-vault` repository root, every `*.json` file under `crates/qvault-core/tests/data/corpus/`
//! must match the file at `{QV_ORACLE_ROOT}/docs/schema/corpus/<same relative path>`.
//!
//! This does **not** pull in a JSON Schema engine; it keeps the committed frozen bytes identical
//! to the oracle corpus. Grammar validation for JSON Schemas remains in the JS repo
//! (`npm run corpus:verify`, `npm run schema:fixtures`).
//!
//! CI example (optional):
//! `QV_ORACLE_ROOT=/path/to/quantum-vault cargo test -p qvault-core corpus_oracle_parity`

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn corpus_json_files_are_valid_json() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/corpus");
    walk_corpus_json(&root, &mut |path| {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap_or_else(|e| panic!("{}: invalid JSON: {e}", path.display()));
    });
}

fn walk_corpus_json(dir: &Path, f: &mut impl FnMut(&Path)) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            walk_corpus_json(&path, f);
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            f(&path);
        }
    }
}

#[test]
#[ignore = "requires QV_ORACLE_ROOT and an explicit --ignored parity run"]
fn corpus_bytes_match_oracle_when_qv_oracle_root_set() {
    let oracle_root = std::env::var("QV_ORACLE_ROOT").expect(
        "QV_ORACLE_ROOT is required; this test must never report parity without an oracle checkout",
    );
    let oracle_root = PathBuf::from(oracle_root);
    let oracle_corpus = oracle_root.join("docs/schema/corpus");
    assert!(
        oracle_corpus.is_dir(),
        "QV_ORACLE_ROOT must point at quantum-vault repo root (missing {}); got QV_ORACLE_ROOT={}",
        oracle_corpus.display(),
        oracle_root.display()
    );

    let mirror_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/corpus");
    walk_corpus_json(&mirror_root, &mut |mirror_path| {
        let rel = mirror_path
            .strip_prefix(&mirror_root)
            .unwrap_or_else(|e| panic!("strip_prefix: {e}"));
        let oracle_path = oracle_corpus.join(rel);
        assert!(
            oracle_path.is_file(),
            "oracle missing file for mirror {} (expected {})",
            mirror_path.display(),
            oracle_path.display()
        );
        let mirror_bytes = fs::read(mirror_path).unwrap();
        let oracle_bytes = fs::read(&oracle_path).unwrap();
        assert_eq!(
            mirror_bytes,
            oracle_bytes,
            "corpus drift: mirror {} differs from oracle {}",
            mirror_path.display(),
            oracle_path.display()
        );
    });
}
