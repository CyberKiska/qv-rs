use anyhow::{anyhow, Context, Result};
use qvault_core::qenc::decrypt_qenc;
use qvault_core::test_support::fixtures::{fixture_path, read_fixture_bytes, read_fixture_json};
use qvault_core::{
    attach_manifest_bundle_to_shards, build_qcont_shards, parse_qcont_shard, restore_from_shards,
    AttachManifestBundleOptions, AuthPolicyLevel, NamedBinaryArtifact, QcontBuildOptions,
    QcontBuildParams, RestoreQcontOptions, VerificationInputs,
};
use serde_json::Value;
use std::path::PathBuf;

struct LoadedSplitFixture {
    root: PathBuf,
    expectations: Value,
    manifest_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    qenc_bytes: Vec<u8>,
    secret_key: Vec<u8>,
    payload: Vec<u8>,
}

fn load_split_fixture(name: &str) -> Result<LoadedSplitFixture> {
    let root = fixture_path(name);
    Ok(LoadedSplitFixture {
        expectations: read_fixture_json(root.join("expectations.json"))?,
        manifest_bytes: read_fixture_bytes(root.join("manifest.qvmanifest.json"))?,
        bundle_bytes: read_fixture_bytes(root.join("initial.extended.qvmanifest.json"))?,
        qenc_bytes: read_fixture_bytes(root.join("container.qenc"))?,
        secret_key: read_fixture_bytes(root.join("secret.qkey"))?,
        payload: read_fixture_bytes(root.join("payload.bin"))?,
        root,
    })
}

fn split_expectations<'a>(fixture: &'a LoadedSplitFixture) -> &'a Value {
    &fixture.expectations["split"]
}

fn parse_shards_from_value(
    fixture: &LoadedSplitFixture,
    shards_value: &Value,
) -> Result<Vec<qvault_core::QcontShard>> {
    shards_value
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

fn parse_base_fixture_shards(fixture: &LoadedSplitFixture) -> Result<Vec<qvault_core::QcontShard>> {
    parse_shards_from_value(fixture, &split_expectations(fixture)["shards"])
}

fn parse_attached_fixture_shards(
    fixture: &LoadedSplitFixture,
) -> Result<Vec<qvault_core::QcontShard>> {
    parse_shards_from_value(fixture, &split_expectations(fixture)["attached"]["shards"])
}

fn build_verification_inputs(
    fixture: &LoadedSplitFixture,
    signature_files: &[&str],
    pqpk_file: Option<&str>,
    timestamp_files: &[&str],
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
        timestamps: timestamp_files
            .iter()
            .map(|file_name| {
                Ok(NamedBinaryArtifact {
                    name: (*file_name).to_string(),
                    bytes: read_fixture_bytes(fixture.root.join(file_name))?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        expected_ed25519_signer: expected_ed25519_signer.map(ToOwned::to_owned),
    })
}

fn assert_restored_fixture(
    fixture: &LoadedSplitFixture,
    restored: &qvault_core::RestoredQcont,
) -> Result<()> {
    assert!(restored.qenc_ok);
    assert!(restored.qkey_ok);
    assert_eq!(restored.qenc_bytes, fixture.qenc_bytes);
    assert_eq!(restored.priv_key, fixture.secret_key);
    assert_eq!(restored.manifest_bytes, fixture.manifest_bytes);
    let decrypted = decrypt_qenc(&restored.qenc_bytes, &restored.priv_key)?;
    assert_eq!(decrypted.file_bytes, fixture.payload);
    Ok(())
}

#[test]
fn rust_build_matches_js_split_5of3_fixture() -> Result<()> {
    let fixture = load_split_fixture("split-5of3")?;
    let split = split_expectations(&fixture);
    let built = build_qcont_shards(
        &fixture.qenc_bytes,
        &fixture.secret_key,
        QcontBuildParams {
            n: split["params"]["n"].as_u64().unwrap() as u16,
            k: split["params"]["k"].as_u64().unwrap() as u16,
        },
        &QcontBuildOptions {
            timestamp: Some(
                fixture.expectations["timestamp"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
            sss_random_bytes: Some(hex::decode(split["sssRandomHex"].as_str().unwrap())?),
            auth_policy_level: Some(AuthPolicyLevel::IntegrityOnly),
            min_valid_signatures: Some(1),
        },
    )?;

    assert_eq!(built.manifest_bytes, fixture.manifest_bytes);
    assert_eq!(built.bundle_bytes, fixture.bundle_bytes);
    assert_eq!(
        built.manifest_digest_hex,
        split["manifestDigestHex"].as_str().unwrap()
    );
    assert_eq!(
        built.bundle_digest_hex,
        split["bundleDigestHex"].as_str().unwrap()
    );

    for (index, shard_value) in split["shards"].as_array().unwrap().iter().enumerate() {
        let expected_bytes =
            read_fixture_bytes(fixture.root.join(shard_value["fileName"].as_str().unwrap()))?;
        assert_eq!(built.shards[index].bytes, expected_bytes);
    }
    Ok(())
}

#[test]
fn rust_build_matches_js_split_7of5_chunked_fixture() -> Result<()> {
    let fixture = load_split_fixture("split-7of5-chunked")?;
    let split = split_expectations(&fixture);
    let built = build_qcont_shards(
        &fixture.qenc_bytes,
        &fixture.secret_key,
        QcontBuildParams {
            n: split["params"]["n"].as_u64().unwrap() as u16,
            k: split["params"]["k"].as_u64().unwrap() as u16,
        },
        &QcontBuildOptions {
            timestamp: Some(
                fixture.expectations["timestamp"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
            sss_random_bytes: Some(hex::decode(split["sssRandomHex"].as_str().unwrap())?),
            auth_policy_level: Some(AuthPolicyLevel::IntegrityOnly),
            min_valid_signatures: Some(1),
        },
    )?;

    assert_eq!(built.manifest_bytes, fixture.manifest_bytes);
    assert_eq!(built.bundle_bytes, fixture.bundle_bytes);
    for (index, shard_value) in split["shards"].as_array().unwrap().iter().enumerate() {
        let expected_bytes =
            read_fixture_bytes(fixture.root.join(shard_value["fileName"].as_str().unwrap()))?;
        assert_eq!(built.shards[index].bytes, expected_bytes);
    }
    Ok(())
}

#[test]
fn rust_restores_js_integrity_fixture() -> Result<()> {
    let fixture = load_split_fixture("split-5of3")?;
    let shards = parse_base_fixture_shards(&fixture)?;
    let restored = restore_from_shards(&shards, &RestoreQcontOptions::default())?;
    assert_eq!(restored.manifest_source, "embedded");
    assert_eq!(
        restored.authenticity.policy.level,
        AuthPolicyLevel::IntegrityOnly
    );
    assert!(!restored.authenticity.status.signature_verified);
    assert_restored_fixture(&fixture, &restored)
}

#[test]
fn any_signature_fixture_rejects_unsigned_restore() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let shards = parse_base_fixture_shards(&fixture)?;
    let error = restore_from_shards(&shards, &RestoreQcontOptions::default()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no valid pinned signature satisfies archive policy"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn any_signature_fixture_accepts_external_pq_signature() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let split = split_expectations(&fixture);
    let shards = parse_base_fixture_shards(&fixture)?;
    let signatures = &split["signatures"];
    let restored = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            verification: build_verification_inputs(
                &fixture,
                &[signatures["qsigFile"].as_str().unwrap()],
                Some(signatures["pqpkFile"].as_str().unwrap()),
                &[],
                None,
            )?,
            ..RestoreQcontOptions::default()
        },
    )?;
    assert!(restored.authenticity.status.signature_verified);
    assert!(restored.authenticity.status.user_pinned);
    assert_restored_fixture(&fixture, &restored)
}

#[test]
fn any_signature_fixture_accepts_external_stellar_signature() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let split = split_expectations(&fixture);
    let shards = parse_base_fixture_shards(&fixture)?;
    let signatures = &split["signatures"];
    let restored = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            verification: build_verification_inputs(
                &fixture,
                &[signatures["stellarSigFile"].as_str().unwrap()],
                None,
                &[],
                Some(signatures["stellarSigner"].as_str().unwrap()),
            )?,
            ..RestoreQcontOptions::default()
        },
    )?;
    assert!(restored.authenticity.status.signature_verified);
    assert!(!restored.authenticity.status.strong_pq_signature_verified);
    assert_restored_fixture(&fixture, &restored)
}

#[test]
fn strong_pq_fixture_rejects_ed25519_only_signature() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-strongpq")?;
    let split = split_expectations(&fixture);
    let shards = parse_base_fixture_shards(&fixture)?;
    let signatures = &split["signatures"];
    let error = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            verification: build_verification_inputs(
                &fixture,
                &[signatures["stellarSigFile"].as_str().unwrap()],
                None,
                &[],
                Some(signatures["stellarSigner"].as_str().unwrap()),
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
fn strong_pq_fixture_accepts_external_pq_signature() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-strongpq")?;
    let split = split_expectations(&fixture);
    let shards = parse_base_fixture_shards(&fixture)?;
    let signatures = &split["signatures"];
    let restored = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            verification: build_verification_inputs(
                &fixture,
                &[signatures["qsigFile"].as_str().unwrap()],
                Some(signatures["pqpkFile"].as_str().unwrap()),
                &[],
                None,
            )?,
            ..RestoreQcontOptions::default()
        },
    )?;
    assert!(restored.authenticity.status.strong_pq_signature_verified);
    assert_restored_fixture(&fixture, &restored)
}

#[test]
fn rust_attach_matches_js_attached_bundle_and_shards() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let split = split_expectations(&fixture);
    let signatures = &split["signatures"];
    let shards = parse_base_fixture_shards(&fixture)?;
    let attached = attach_manifest_bundle_to_shards(
        &shards,
        &AttachManifestBundleOptions {
            signatures: build_verification_inputs(
                &fixture,
                &[signatures["qsigFile"].as_str().unwrap()],
                None,
                &[],
                None,
            )?
            .signatures,
            pq_public_key_file_bytes_list: vec![read_fixture_bytes(
                fixture.root.join(signatures["pqpkFile"].as_str().unwrap()),
            )?],
            timestamps: build_verification_inputs(
                &fixture,
                &[],
                None,
                &[signatures["otsFile"].as_str().unwrap()],
                None,
            )?
            .timestamps,
            ..AttachManifestBundleOptions::default()
        },
    )?;

    let expected_bundle = read_fixture_bytes(
        fixture
            .root
            .join(split["attached"]["bundleFile"].as_str().unwrap()),
    )?;
    assert_eq!(attached.bundle_bytes, expected_bundle);

    let attached_shard_values = split["attached"]["shards"]
        .as_array()
        .context("missing attached shard array")?;
    for (index, shard_value) in attached_shard_values.iter().enumerate() {
        let expected_bytes =
            read_fixture_bytes(fixture.root.join(shard_value["fileName"].as_str().unwrap()))?;
        assert_eq!(attached.shards[index].bytes, expected_bytes);
    }
    Ok(())
}

#[test]
fn stale_shards_accept_uploaded_attached_bundle() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let split = split_expectations(&fixture);
    let shards = parse_base_fixture_shards(&fixture)?;
    let bundle_bytes = read_fixture_bytes(
        fixture
            .root
            .join(split["attached"]["bundleFile"].as_str().unwrap()),
    )?;
    let restored = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            bundle_bytes: Some(bundle_bytes),
            ..RestoreQcontOptions::default()
        },
    )?;
    assert_eq!(restored.manifest_source, "uploaded-bundle");
    assert!(restored.authenticity.status.signature_verified);
    assert_restored_fixture(&fixture, &restored)
}

#[test]
fn repeated_attach_cycles_match_js_bundle() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let split = split_expectations(&fixture);
    let signatures = &split["signatures"];
    let attached_bundle = read_fixture_bytes(
        fixture
            .root
            .join(split["attached"]["bundleFile"].as_str().unwrap()),
    )?;
    let second_attach = attach_manifest_bundle_to_shards(
        &[],
        &AttachManifestBundleOptions {
            bundle_bytes: Some(attached_bundle),
            signatures: build_verification_inputs(
                &fixture,
                &[signatures["qsigBFile"].as_str().unwrap()],
                None,
                &[],
                None,
            )?
            .signatures,
            pq_public_key_file_bytes_list: vec![read_fixture_bytes(
                fixture.root.join(signatures["pqpkBFile"].as_str().unwrap()),
            )?],
            timestamps: build_verification_inputs(
                &fixture,
                &[],
                None,
                &[signatures["otsBFile"].as_str().unwrap()],
                None,
            )?
            .timestamps,
            embed_into_shards: Some(false),
            ..AttachManifestBundleOptions::default()
        },
    )?;
    let expected_bundle = read_fixture_bytes(
        fixture
            .root
            .join(split["attachedTwice"]["bundleFile"].as_str().unwrap()),
    )?;
    assert_eq!(second_attach.bundle_bytes, expected_bundle);
    assert_eq!(second_attach.manifest_bytes, fixture.manifest_bytes);
    Ok(())
}

#[test]
fn restore_rejects_duplicate_shard_indices() -> Result<()> {
    let fixture = load_split_fixture("split-5of3")?;
    let shards = parse_base_fixture_shards(&fixture)?;
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
    let mut shards = parse_base_fixture_shards(&fixture)?;
    shards.truncate(4);
    let last = shards[0]
        .fragments
        .len()
        .checked_sub(1)
        .ok_or_else(|| anyhow!("fixture shard has empty fragment stream"))?;
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

#[test]
fn attached_shards_restore_without_external_inputs() -> Result<()> {
    let fixture = load_split_fixture("split-5of3-anysig")?;
    let shards = parse_attached_fixture_shards(&fixture)?;
    let restored = restore_from_shards(&shards, &RestoreQcontOptions::default())?;
    assert!(restored.authenticity.status.signature_verified);
    assert_eq!(restored.manifest_source, "embedded");
    assert_restored_fixture(&fixture, &restored)
}
