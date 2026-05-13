use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::error::Result;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

pub fn fixtures_root() -> PathBuf {
    repo_root().join("fixtures/legacy-mvp/js-oracle")
}

pub fn fixture_path(name: &str) -> PathBuf {
    fixtures_root().join(name)
}

pub fn read_fixture_bytes(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

pub fn read_fixture_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}
