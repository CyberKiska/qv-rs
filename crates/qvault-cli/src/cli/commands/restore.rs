use super::super::*;

pub(super) fn run_restore(args: RestoreArgs, ctx: CliContext) -> Result<()> {
    let shard_paths = restore_shard_paths(&args)?;
    let archive_state_bytes = args
        .archive_state
        .as_ref()
        .map(|path| read_file_checked(path, ctx))
        .transpose()
        .with_context(|| "failed to read --archive-state")?;
    let lifecycle_bundle_bytes = args
        .lifecycle_bundle
        .as_ref()
        .map(|path| read_file_checked(path, ctx))
        .transpose()
        .with_context(|| "failed to read --lifecycle-bundle")?;
    let signatures = load_named_artifacts(&args.signatures, ctx)?;
    let pq_public_keys = load_named_artifacts(&args.pq_public_keys, ctx)?;
    let timestamps = load_named_artifacts(&args.timestamps, ctx)?;
    let pinned_pq_public_key_file_bytes = select_single_pinned_pqpk(&pq_public_keys)?;

    let shards = shard_paths
        .iter()
        .map(|path| {
            let bytes = read_file_checked(path, ctx)
                .with_context(|| format!("failed to read {}", path.display()))?;
            parse_qvqcont7_shard(&bytes)
                .with_context(|| format!("failed to parse shard {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut restored = restore_qvqcont7_from_shards(
        &shards,
        &RestoreQvqcont7Options {
            selection: RestoreQvqcont7Selection {
                selected_archive_id: args.archive_id.clone(),
                selected_state_id: args.state_id.clone(),
                selected_cohort_id: args.cohort_id.clone(),
                archive_state_bytes,
                lifecycle_bundle_bytes,
                selected_lifecycle_bundle_digest_hex: args.lifecycle_bundle_digest.clone(),
            },
            verification: VerificationInputs {
                signatures,
                pinned_pq_public_key_file_bytes,
                timestamps,
                expected_ed25519_signer: normalize_optional_string(
                    args.expected_ed25519_signer.as_deref(),
                ),
            },
            enforce_policy: true,
        },
    )?;
    let restored_priv_key = Zeroizing::new(std::mem::take(&mut restored.priv_key));

    let variant_ack_required = restored.mixed_lifecycle_bundle_variants_within_selected_cohort;
    let policy_ok = restored.authenticity.policy.satisfied;
    let base_ok = restored.qenc_ok && restored.qkey_ok && policy_ok;
    let variant_ok = !variant_ack_required || args.accept_policy_warnings;
    let would_succeed = base_ok && variant_ok;

    if args.dry_run {
        if ctx.json {
            let report = serde_json::json!({
                "command": "restore",
                "ok": would_succeed,
                "cliSchemaVersion": 1,
                "dryRun": true,
                "wouldSucceed": would_succeed,
                "policyWarningsAcknowledged": args.accept_policy_warnings,
                "lifecycleBundleVariantAcknowledgementRequired": variant_ack_required,
                "embeddedLifecycleBundleDigestsUsed": restored.embedded_lifecycle_bundle_digests_used,
                "archiveId": restored.archive_id,
                "stateId": restored.state_id,
                "cohortId": restored.cohort_id,
                "archiveStateDigestHex": restored.archive_state_digest_hex,
                "cohortBindingDigestHex": restored.cohort_binding_digest_hex,
                "lifecycleBundleDigestHex": restored.lifecycle_bundle_digest_hex,
                "qencOk": restored.qenc_ok,
                "qkeyOk": restored.qkey_ok,
                "rejectedShardIndices": restored.rejected_shard_indices,
                "authenticity": restored.authenticity,
                "warnings": restored.warnings,
                "outputs": Value::Null
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !would_succeed {
                std::process::exit(1);
            }
        } else if !ctx.quiet {
            if would_succeed {
                println!("Restore dry run succeeded.");
            } else {
                eprintln!("Restore dry run completed without success (see warnings and policy).");
            }
            println!("Archive ID: {}", restored.archive_id);
            println!("State ID: {}", restored.state_id);
            println!("Cohort ID: {}", restored.cohort_id);
        }
        if !would_succeed && !ctx.json {
            std::process::exit(1);
        }
        return Ok(());
    }

    if variant_ack_required && !args.accept_policy_warnings {
        return Err(coded(
                QvCode::RestoreLifecycleVariantAckRequired,
                "Restore refused: the selected cohort embeds multiple lifecycle-bundle digests in its shards. Review authenticity.warnings and embeddedLifecycleBundleDigestsUsed, then re-run with --accept-policy-warnings only if the operator accepts residual bundle-variant risk. Archive policy satisfaction alone does not waive this check.",
            )
            .into());
    }

    let default_base = args
        .out
        .clone()
        .unwrap_or_else(|| default_restore_output_base(&shard_paths));
    let output_qenc = args
        .output_qenc
        .clone()
        .unwrap_or_else(|| append_file_name_suffix(&default_base, ".qenc"));
    let output_secret_key = args
        .output_secret_key
        .clone()
        .unwrap_or_else(|| append_file_name_suffix(&default_base, ".qkey"));
    preflight_outputs(
        &[output_qenc.clone(), output_secret_key.clone()],
        args.force,
        ctx,
    )?;
    write_file_checked(&output_qenc, &restored.qenc_bytes, ctx)
        .with_context(|| format!("failed to write {}", output_qenc.display()))?;
    write_secret_file_checked(&output_secret_key, &restored_priv_key, args.force, ctx)
        .with_context(|| format!("failed to write {}", output_secret_key.display()))?;

    if ctx.json {
        let report = serde_json::json!({
            "command": "restore",
            "ok": true,
            "cliSchemaVersion": 1,
            "archiveId": restored.archive_id,
            "stateId": restored.state_id,
            "cohortId": restored.cohort_id,
            "archiveStateDigestHex": restored.archive_state_digest_hex,
            "cohortBindingDigestHex": restored.cohort_binding_digest_hex,
            "lifecycleBundleDigestHex": restored.lifecycle_bundle_digest_hex,
            "containerHashHex": restored.container_hash,
            "containerId": restored.container_id,
            "recoveredQencHashHex": restored.recovered_qenc_hash,
            "recoveredPrivateKeyHashHex": restored.recovered_priv_hash,
            "qencOk": restored.qenc_ok,
            "qkeyOk": restored.qkey_ok,
            "rejectedShardIndices": restored.rejected_shard_indices,
            "outputQenc": output_qenc,
            "outputSecretKey": output_secret_key,
            "authenticity": restored.authenticity,
            "warnings": restored.warnings,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        for warning in &restored.warnings {
            eprintln!("warning: {warning}");
        }
        println!("Restored successor container successfully.");
        println!("Archive ID: {}", restored.archive_id);
        println!("State ID: {}", restored.state_id);
        println!("Cohort ID: {}", restored.cohort_id);
        println!(
            "Lifecycle bundle digest: {}",
            restored.lifecycle_bundle_digest_hex
        );
        println!("Container output: {}", output_qenc.display());
        println!("Secret key output: {}", output_secret_key.display());
    }

    Ok(())
}
