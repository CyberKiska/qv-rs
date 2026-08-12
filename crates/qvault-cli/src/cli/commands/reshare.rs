use super::super::*;

pub(super) fn run_reshare(args: ReshareArgs, ctx: CliContext) -> Result<()> {
    validate_cohort_cli_params(args.n, args.k)?;
    if !args.maintenance_pq_public_keys.is_empty() && args.maintenance_signatures.is_empty() {
        bail!("--maintenance-pqpk requires at least one --maintenance-sig");
    }
    if !args.maintenance_timestamps.is_empty() && args.maintenance_signatures.is_empty() {
        bail!("--maintenance-ots requires at least one --maintenance-sig");
    }
    let maintenance_signature_imports = load_named_artifacts(&args.maintenance_signatures, ctx)?
        .into_iter()
        .map(|artifact| {
            signature_import(artifact, LifecycleSignatureFamily::Maintenance, None, None)
        })
        .collect::<Vec<_>>();
    let maintenance_pq_public_key_file_bytes_list =
        load_named_artifacts(&args.maintenance_pq_public_keys, ctx)?
            .into_iter()
            .map(|artifact| artifact.bytes)
            .collect::<Vec<_>>();
    let maintenance_timestamps = load_named_artifacts(&args.maintenance_timestamps, ctx)?;
    let predecessor_shards = read_qcont_shards_checked(&args.shards, ctx)?;
    let lifecycle_bundle_bytes = args
        .bundle
        .as_ref()
        .map(|path| read_small_artifact_checked(path, ctx, "Lifecycle bundle"))
        .transpose()
        .with_context(|| "failed to read --bundle")?;
    let reshared = reshare_same_state(
        &predecessor_shards,
        ReshareSameStateParams {
            n: args.n,
            k: args.k,
        },
        &ReshareSameStateOptions {
            selection: RestoreQvqcont7Selection {
                selected_archive_id: args.archive_id.clone(),
                selected_state_id: args.state_id.clone(),
                selected_cohort_id: args.cohort_id.clone(),
                selected_lifecycle_bundle_digest_hex: args.bundle_digest.clone(),
                ..RestoreQvqcont7Selection::default()
            },
            lifecycle_bundle_bytes,
            transition: ReshareTransitionOptions {
                reason_code: args.reason_code.clone(),
                performed_at: args
                    .performed_at
                    .clone()
                    .unwrap_or_else(current_iso8601_utc_millis),
                operator_role: args.operator_role.clone(),
                actor_hints: serde_json::json!({}),
                notes: args.notes.clone(),
            },
            #[cfg(feature = "deterministic-test-vectors")]
            sss_random_bytes: None,
            maintenance_artifacts: Vec::new(),
            maintenance_signature_imports,
            maintenance_pq_public_key_file_bytes_list,
            maintenance_timestamps,
            maintenance_expected_ed25519_signer: normalize_optional_string(
                args.maintenance_ed25519_signer.as_deref(),
            ),
            forbidden_overrides: Vec::new(),
        },
    )?;

    reject_symlink_components(&args.out, ctx.allow_symlink)?;
    fs::create_dir_all(&args.out)
        .with_context(|| format!("failed to create {}", args.out.display()))?;
    let archive_state_path = args.out.join("archive-state.json");
    let cohort_binding_path = args.out.join("cohort-binding.json");
    let transition_record_path = args.out.join("transition-record.json");
    let lifecycle_bundle_path = args.out.join("lifecycle-bundle.json");
    let shard_paths = reshared
        .shards
        .iter()
        .map(|shard| {
            args.out.join(format!(
                "reshared.part{}-of-{}.qcont",
                usize::from(shard.index) + 1,
                reshared.shards.len()
            ))
        })
        .collect::<Vec<_>>();
    let mut output_paths = vec![
        archive_state_path.clone(),
        cohort_binding_path.clone(),
        transition_record_path.clone(),
        lifecycle_bundle_path.clone(),
    ];
    output_paths.extend(shard_paths.iter().cloned());
    preflight_outputs(&output_paths, args.force, ctx)?;
    write_file_checked(
        &archive_state_path,
        &reshared.archive_state_bytes,
        args.force,
        ctx,
    )?;
    write_file_checked(
        &cohort_binding_path,
        &reshared.cohort_binding_bytes,
        args.force,
        ctx,
    )?;
    write_file_checked(
        &transition_record_path,
        &reshared.transition_record_bytes,
        args.force,
        ctx,
    )?;
    write_file_checked(
        &lifecycle_bundle_path,
        &reshared.lifecycle_bundle_bytes,
        args.force,
        ctx,
    )?;
    for (shard, path) in reshared.shards.iter().zip(shard_paths.iter()) {
        write_secret_file_checked(path, &shard.bytes, args.force, ctx)?;
    }

    if ctx.json {
        let report = serde_json::json!({
            "command": "reshare",
            "ok": true,
            "cliSchemaVersion": 1,
            "archiveId": reshared.archive_id,
            "stateId": reshared.state_id,
            "predecessorCohortId": reshared.predecessor_cohort_id,
            "cohortId": reshared.cohort_id,
            "predecessorLifecycleBundleDigestHex": reshared.predecessor_lifecycle_bundle_digest_hex,
            "predecessorLifecycleBundleSource": "embedded-lifecycle-bundle",
            "archiveStateBytesPath": archive_state_path,
            "archiveStateDigestHex": reshared.archive_state_digest_hex,
            "cohortBindingBytesPath": cohort_binding_path,
            "cohortBindingDigestHex": reshared.cohort_binding_digest_hex,
            "transitionRecordPath": transition_record_path,
            "transitionRecordDigestHex": reshared.transition_record_digest_hex,
            "lifecycleBundlePath": lifecycle_bundle_path,
            "lifecycleBundleDigestHex": reshared.lifecycle_bundle_digest_hex,
            "shards": reshared.shards.iter().zip(shard_paths.iter()).map(|(shard, path)| {
                serde_json::json!({
                    "index": shard.index,
                    "path": path,
                    "shardDigestHex": sha3_512_hex(&shard.bytes),
                    "shardSize": shard.bytes.len()
                })
            }).collect::<Vec<_>>(),
            "verificationReport": {
                "invalidShareIndices": reshared.verification_report.invalid_share_indices,
                "corruptedShardIndices": reshared.verification_report.corrupted_shard_indices,
                "missingShardIndices": reshared.verification_report.missing_shard_indices,
                "rejectedShardIndices": reshared.verification_report.rejected_shard_indices,
                "privateKeyHashMatchesMetadata": reshared.verification_report.private_key_hash_matches_metadata
            },
            "maintenanceSignatureCountAdded": reshared.maintenance_signature_count_added,
            "operationalWarnings": reshared.operational_warnings,
            "semantics": {
                "sameStateAvailabilityMaintenance": true,
                "archiveReapprovalPerformed": false,
                "plaintextDecrypted": false,
                "sourceEvidenceCreated": false,
                "compromiseRepairClaimed": false
            },
            "zeroization": { "attempted": true, "privateKeyBytesCleared": true, "shareCopiesCleared": true }
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        println!("Reshared successor cohort.");
        println!("State ID: {}", reshared.state_id);
        println!("New cohort ID: {}", reshared.cohort_id);
        println!("Output directory: {}", args.out.display());
    }
    Ok(())
}
