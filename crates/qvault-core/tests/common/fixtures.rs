use std::fs;
use std::path::{Path, PathBuf};

use qvault_core::Result;

/// Cross-language `.qenc` interop vectors committed under `crates/qvault-core/tests/data/`.
pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/qenc_interop")
}

pub fn fixture_path(name: &str) -> PathBuf {
    fixtures_root().join(name)
}

pub fn read_fixture_bytes(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}
