use std::path::PathBuf;

use anyhow::{Context, Result};
use qvault_core::qcont::{
    build_qcont_shards, parse_qcont_shard, restore_from_shards, QcontBuildOptions,
    QcontBuildParams, QcontShard, RestoreQcontOptions,
};
use qvault_core::qenc::decrypt_qenc;
use qvault_core::test_support::fixtures::{fixture_path, read_fixture_bytes, read_fixture_json};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct FixtureExpectations {
    timestamp: String,
    split: Option<SplitExpectations>,
}

#[derive(Debug, Clone, Deserialize)]
struct SplitExpectations {
    params: SplitParams,
    #[serde(rename = "manifestDigestHex")]
    manifest_digest_hex: String,
    #[serde(rename = "sssRandomHex")]
    sss_random_hex: String,
    #[serde(rename = "shardCount")]
    shard_count: usize,
    shards: Vec<ShardExpectation>,
}

#[derive(Debug, Clone, Deserialize)]
struct SplitParams {
    n: u16,
    k: u16,
}

#[derive(Debug, Clone, Deserialize)]
struct ShardExpectation {
    #[serde(rename = "fileName")]
    file_name: String,
    #[serde(rename = "shardIndex")]
    shard_index: u16,
}

struct LoadedSplitFixture {
    root: PathBuf,
    expectations: FixtureExpectations,
    manifest_bytes: Vec<u8>,
    qenc_bytes: Vec<u8>,
    secret_key: Vec<u8>,
    payload: Vec<u8>,
}

fn load_split_fixture(name: &str) -> Result<LoadedSplitFixture> {
    let root = fixture_path(name);
    let expectations: FixtureExpectations = read_fixture_json(root.join("expectations.json"))?;
    let manifest_bytes = read_fixture_bytes(root.join("manifest.qvmanifest.json"))?;
    let qenc_bytes = read_fixture_bytes(root.join("container.qenc"))?;
    let secret_key = read_fixture_bytes(root.join("secret.qkey"))?;
    let payload = read_fixture_bytes(root.join("payload.bin"))?;

    Ok(LoadedSplitFixture {
        root,
        expectations,
        manifest_bytes,
        qenc_bytes,
        secret_key,
        payload,
    })
}

fn parse_fixture_shards(fixture: &LoadedSplitFixture) -> Result<Vec<QcontShard>> {
    let split = fixture
        .expectations
        .split
        .as_ref()
        .context("fixture is missing split expectations")?;

    split
        .shards
        .iter()
        .map(|shard| {
            let bytes = read_fixture_bytes(fixture.root.join(&shard.file_name))?;
            parse_qcont_shard(&bytes).map_err(Into::into)
        })
        .collect()
}

fn assert_restored_fixture(
    fixture: &LoadedSplitFixture,
    shards: &[QcontShard],
    options: &RestoreQcontOptions,
    expected_source: &str,
) -> Result<()> {
    let restored = restore_from_shards(shards, options)?;
    let split = fixture
        .expectations
        .split
        .as_ref()
        .context("fixture is missing split expectations")?;

    assert!(restored.qenc_ok);
    assert!(restored.qkey_ok);
    assert_eq!(restored.qenc_bytes, fixture.qenc_bytes);
    assert_eq!(restored.priv_key, fixture.secret_key);
    assert_eq!(restored.manifest_bytes, fixture.manifest_bytes);
    assert_eq!(restored.manifest_digest_hex, split.manifest_digest_hex);
    assert_eq!(restored.manifest_source, expected_source);
    assert!(restored
        .warnings
        .iter()
        .any(|warning| warning == "The content is correct, but may not be authentic."));

    let decrypted = decrypt_qenc(&restored.qenc_bytes, &restored.priv_key)?;
    assert_eq!(decrypted.file_bytes, fixture.payload);

    Ok(())
}

fn assert_build_matches_fixture(name: &str) -> Result<()> {
    let fixture = load_split_fixture(name)?;
    let split = fixture
        .expectations
        .split
        .as_ref()
        .context("fixture is missing split expectations")?;

    assert!(
        !split.sss_random_hex.is_empty(),
        "fixture is missing deterministic SSS randomness"
    );
    let built = build_qcont_shards(
        &fixture.qenc_bytes,
        &fixture.secret_key,
        QcontBuildParams {
            n: split.params.n,
            k: split.params.k,
        },
        &QcontBuildOptions {
            timestamp: Some(fixture.expectations.timestamp.clone()),
            sss_random_bytes: Some(hex::decode(&split.sss_random_hex)?),
            ..QcontBuildOptions::default()
        },
    )?;

    assert_eq!(built.manifest_bytes, fixture.manifest_bytes);
    assert_eq!(built.manifest_digest_hex, split.manifest_digest_hex);
    assert_eq!(built.shards.len(), split.shard_count);

    for (index, shard_expectation) in split.shards.iter().enumerate() {
        let expected_bytes = read_fixture_bytes(fixture.root.join(&shard_expectation.file_name))?;
        assert_eq!(built.shards[index].index, shard_expectation.shard_index);
        assert_eq!(
            built.shards[index].bytes, expected_bytes,
            "shard byte mismatch at index {} for fixture {}",
            shard_expectation.shard_index, name
        );
    }

    Ok(())
}

#[test]
fn rust_build_matches_js_split_5of3_fixture() -> Result<()> {
    assert_build_matches_fixture("split-5of3")
}

#[test]
fn rust_build_matches_js_split_7of5_chunked_fixture() -> Result<()> {
    assert_build_matches_fixture("split-7of5-chunked")
}

#[test]
fn rust_restores_js_split_5of3_fixture() -> Result<()> {
    let fixture = load_split_fixture("split-5of3")?;
    let shards = parse_fixture_shards(&fixture)?;
    assert_restored_fixture(
        &fixture,
        &shards,
        &RestoreQcontOptions::default(),
        "embedded",
    )
}

#[test]
fn rust_restores_js_split_7of5_chunked_fixture_subset() -> Result<()> {
    let fixture = load_split_fixture("split-7of5-chunked")?;
    let shards = parse_fixture_shards(&fixture)?;
    assert_restored_fixture(
        &fixture,
        &shards[..6],
        &RestoreQcontOptions::default(),
        "embedded",
    )
}

#[test]
fn rust_restores_with_one_corrupted_shard_within_rs_tolerance() -> Result<()> {
    let fixture = load_split_fixture("split-5of3")?;
    let mut shards = parse_fixture_shards(&fixture)?;
    let last = shards[0]
        .fragments
        .len()
        .checked_sub(1)
        .context("fixture shard has empty fragment stream")?;
    shards[0].fragments[last] ^= 0x01;

    assert_restored_fixture(
        &fixture,
        &shards,
        &RestoreQcontOptions::default(),
        "embedded",
    )
}

#[test]
fn restore_rejects_mixed_manifest_cohorts_without_selector() -> Result<()> {
    let fixture_a = load_split_fixture("split-5of3")?;
    let fixture_b = load_split_fixture("split-7of5-chunked")?;
    let shards_a = parse_fixture_shards(&fixture_a)?;
    let shards_b = parse_fixture_shards(&fixture_b)?;

    let mixed = vec![
        shards_a[0].clone(),
        shards_a[1].clone(),
        shards_a[2].clone(),
        shards_b[0].clone(),
        shards_b[1].clone(),
    ];
    let error = restore_from_shards(&mixed, &RestoreQcontOptions::default()).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("Multiple manifest cohorts detected"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn restore_uses_uploaded_manifest_to_select_correct_cohort() -> Result<()> {
    let fixture_a = load_split_fixture("split-5of3")?;
    let fixture_b = load_split_fixture("split-7of5-chunked")?;
    let shards_a = parse_fixture_shards(&fixture_a)?;
    let shards_b = parse_fixture_shards(&fixture_b)?;

    let mixed = vec![
        shards_a[0].clone(),
        shards_a[1].clone(),
        shards_a[2].clone(),
        shards_a[3].clone(),
        shards_b[0].clone(),
    ];
    let restored = restore_from_shards(
        &mixed,
        &RestoreQcontOptions {
            manifest_bytes: Some(fixture_a.manifest_bytes.clone()),
        },
    )?;

    assert_eq!(restored.manifest_source, "uploaded");
    assert_eq!(restored.qenc_bytes, fixture_a.qenc_bytes);
    assert_eq!(restored.priv_key, fixture_a.secret_key);
    assert_eq!(restored.rejected_shard_indices.len(), 1);
    Ok(())
}

#[test]
fn restore_rejects_duplicate_shard_indices() -> Result<()> {
    let fixture = load_split_fixture("split-5of3")?;
    let shards = parse_fixture_shards(&fixture)?;
    let duplicated = vec![
        shards[0].clone(),
        shards[0].clone(),
        shards[1].clone(),
        shards[2].clone(),
    ];
    let error = restore_from_shards(&duplicated, &RestoreQcontOptions::default()).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("Duplicate shardIndex 0 detected"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn restore_rejects_when_missing_and_corrupted_exceed_rs_tolerance() -> Result<()> {
    let fixture = load_split_fixture("split-5of3")?;
    let mut shards = parse_fixture_shards(&fixture)?;
    shards.truncate(4);
    let last = shards[0]
        .fragments
        .len()
        .checked_sub(1)
        .context("fixture shard has empty fragment stream")?;
    shards[0].fragments[last] ^= 0x01;

    let error = restore_from_shards(&shards, &RestoreQcontOptions::default()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Too many missing/corrupted shards for RS reconstruction"),
        "unexpected error: {error}"
    );
    Ok(())
}
