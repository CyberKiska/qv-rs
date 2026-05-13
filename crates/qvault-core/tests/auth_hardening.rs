#![cfg(feature = "legacy-mvp")]

use anyhow::{Context, Result};
use qvault_core::legacy::predecessor::{
    parse_qcont_shard, restore_from_shards, QcontShard, RestoreQcontOptions,
};
use qvault_core::test_support::fixtures::{fixture_path, read_fixture_bytes, read_fixture_json};
use qvault_core::{NamedBinaryArtifact, VerificationInputs};
use serde_json::Value;
use std::path::PathBuf;

struct LoadedSplitFixture {
    root: PathBuf,
    expectations: Value,
}

fn load_split_fixture(name: &str) -> Result<LoadedSplitFixture> {
    let root = fixture_path(name);
    Ok(LoadedSplitFixture {
        expectations: read_fixture_json(root.join("expectations.json"))?,
        root,
    })
}

fn parse_base_fixture_shards(fixture: &LoadedSplitFixture) -> Result<Vec<QcontShard>> {
    fixture.expectations["split"]["shards"]
        .as_array()
        .context("expected shard array")?
        .iter()
        .map(|shard| {
            let file_name = shard["fileName"]
                .as_str()
                .context("missing shard fileName")?;
            let bytes = read_fixture_bytes(fixture.root.join(file_name))?;
            parse_qcont_shard(&bytes).map_err(Into::into)
        })
        .collect()
}

fn build_verification_inputs(
    fixture: &LoadedSplitFixture,
    signature_files: &[&str],
    pqpk_file: Option<&str>,
    expected_ed25519_signer: Option<&str>,
) -> Result<VerificationInputs> {
    Ok(VerificationInputs {
        signatures: signature_files
            .iter()
            .map(|file_name| {
                Ok(NamedBinaryArtifact {
                    name: (*file_name).to_string(),
                    bytes: read_fixture_bytes(fixture.root.join(file_name))?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        pinned_pq_public_key_file_bytes: pqpk_file
            .map(|file_name| read_fixture_bytes(fixture.root.join(file_name)))
            .transpose()?,
        timestamps: Vec::new(),
        expected_ed25519_signer: expected_ed25519_signer.map(ToOwned::to_owned),
    })
}

#[test]
fn any_signature_restore_rejects_unpinned_external_qsig() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let shards = parse_base_fixture_shards(&fixture)?;
    let signatures = &fixture.expectations["split"]["signatures"];

    let error = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            verification: build_verification_inputs(
                &fixture,
                &[signatures["qsigFile"].as_str().unwrap()],
                None,
                None,
            )?,
            ..RestoreQcontOptions::default()
        },
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("no valid pinned signature satisfies archive policy"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn any_signature_restore_rejects_unpinned_external_stellar_sig() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let shards = parse_base_fixture_shards(&fixture)?;
    let signatures = &fixture.expectations["split"]["signatures"];

    let error = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            verification: build_verification_inputs(
                &fixture,
                &[signatures["stellarSigFile"].as_str().unwrap()],
                None,
                None,
            )?,
            ..RestoreQcontOptions::default()
        },
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("no valid pinned signature satisfies archive policy"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn strong_pq_restore_rejects_unpinned_external_qsig() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-strongpq")?;
    let shards = parse_base_fixture_shards(&fixture)?;
    let signatures = &fixture.expectations["split"]["signatures"];

    let error = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            verification: build_verification_inputs(
                &fixture,
                &[signatures["qsigFile"].as_str().unwrap()],
                None,
                None,
            )?,
            ..RestoreQcontOptions::default()
        },
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("no valid pinned strong PQ signature satisfies archive policy"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn uploaded_bundle_rejects_qsig_public_key_ref_suite_mismatch() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let shards = parse_base_fixture_shards(&fixture)?;
    let bundle_file = fixture.expectations["split"]["attached"]["bundleFile"]
        .as_str()
        .context("missing attached bundle file")?;
    let mut bundle_json: Value =
        serde_json::from_slice(&read_fixture_bytes(fixture.root.join(bundle_file))?)?;
    bundle_json["attachments"]["publicKeys"][0]["suite"] =
        Value::String("slhdsa-shake-192s".to_string());

    let error = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            bundle_bytes: Some(serde_json::to_vec(&bundle_json)?),
            ..RestoreQcontOptions::default()
        },
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("no valid pinned signature satisfies archive policy"),
        "unexpected error: {error}"
    );
    Ok(())
}
