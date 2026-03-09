use anyhow::{Context, Result};
use qvault_core::test_support::fixtures::{fixture_path, read_fixture_bytes, read_fixture_json};
use qvault_core::{build_qcont_shards, AuthPolicyLevel, QcontBuildOptions, QcontBuildParams};
use serde_json::Value;

struct LoadedSplitFixture {
    qenc_bytes: Vec<u8>,
    secret_key: Vec<u8>,
    params_n: u16,
    params_k: u16,
}

fn load_split_fixture(name: &str) -> Result<LoadedSplitFixture> {
    let root = fixture_path(name);
    let expectations: Value = read_fixture_json(root.join("expectations.json"))?;
    let split = &expectations["split"];
    Ok(LoadedSplitFixture {
        qenc_bytes: read_fixture_bytes(root.join("container.qenc"))?,
        secret_key: read_fixture_bytes(root.join("secret.qkey"))?,
        params_n: split["params"]["n"]
            .as_u64()
            .context("missing split.params.n")? as u16,
        params_k: split["params"]["k"]
            .as_u64()
            .context("missing split.params.k")? as u16,
    })
}

fn integrity_only_options() -> QcontBuildOptions {
    QcontBuildOptions {
        auth_policy_level: Some(AuthPolicyLevel::IntegrityOnly),
        min_valid_signatures: Some(1),
        ..QcontBuildOptions::default()
    }
}

#[test]
fn split_rejects_invalid_rs_params_before_subtraction() -> Result<()> {
    let fixture = load_split_fixture("split-5of3")?;
    let error = build_qcont_shards(
        &fixture.qenc_bytes,
        &fixture.secret_key,
        QcontBuildParams { n: 3, k: 3 },
        &integrity_only_options(),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("Invalid RS parameters: require 2 <= k < n"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn split_rejects_truncated_chunked_qenc_framing() -> Result<()> {
    let fixture = load_split_fixture("split-7of5-chunked")?;
    let mut truncated = fixture.qenc_bytes.clone();
    truncated
        .pop()
        .context("fixture qenc was unexpectedly empty")?;

    let error = build_qcont_shards(
        &truncated,
        &fixture.secret_key,
        QcontBuildParams {
            n: fixture.params_n,
            k: fixture.params_k,
        },
        &integrity_only_options(),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("QENC ciphertext is truncated for declared per-chunk framing"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn split_rejects_extra_chunked_qenc_ciphertext_bytes() -> Result<()> {
    let fixture = load_split_fixture("split-7of5-chunked")?;
    let mut extended = fixture.qenc_bytes.clone();
    extended.push(0);

    let error = build_qcont_shards(
        &extended,
        &fixture.secret_key,
        QcontBuildParams {
            n: fixture.params_n,
            k: fixture.params_k,
        },
        &integrity_only_options(),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("QENC ciphertext length does not match declared per-chunk framing"),
        "unexpected error: {error}"
    );
    Ok(())
}
