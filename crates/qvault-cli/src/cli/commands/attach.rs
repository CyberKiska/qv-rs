use super::super::*;

pub(super) fn run_attach(args: AttachArgs, ctx: CliContext) -> Result<()> {
    let archive_state_bytes = args
        .archive_state
        .as_ref()
        .map(|path| read_small_artifact_checked(path, ctx, "Archive-state descriptor"))
        .transpose()
        .with_context(|| "failed to read --archive-state")?;
    let lifecycle_bundle_bytes = args
        .bundle
        .as_ref()
        .map(|path| read_small_artifact_checked(path, ctx, "Lifecycle bundle"))
        .transpose()
        .with_context(|| "failed to read --bundle")?;
    let shards = read_qcont_shards_checked(&args.shards, ctx)?;
    let source_evidence = args
        .source_evidence
        .iter()
        .chain(args.source_evidence_bytes.iter())
        .map(|path| {
            Ok(LifecycleSourceEvidenceImport {
                bytes: Some(
                    read_small_artifact_checked(path, ctx, "Source-evidence artifact")
                        .with_context(|| format!("failed to read {}", path.display()))?,
                ),
                value: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let pq_public_key_file_bytes_list = load_named_artifacts(&args.pq_public_keys, ctx)?
        .into_iter()
        .map(|artifact| artifact.bytes)
        .collect::<Vec<_>>();
    let timestamps = load_named_artifacts(&args.timestamps, ctx)?;
    let signature_imports = build_attach_signature_imports(&args, ctx)?;

    let embed_into_shards = !args.no_embed_into_shards && !shards.is_empty();
    let attached = attach_lifecycle_bundle_to_shards(
        &shards,
        &AttachLifecycleOptions {
            archive_state_bytes,
            lifecycle_bundle_bytes,
            signature_imports,
            source_evidence,
            pq_public_key_file_bytes_list,
            timestamps,
            expected_ed25519_signer: normalize_optional_string(
                args.expected_ed25519_signer.as_deref(),
            ),
            embed_into_shards,
            ..AttachLifecycleOptions::default()
        },
    )?;

    let mut output_paths = vec![args.out_bundle.clone()];
    let shard_output_plan = if embed_into_shards {
        reject_symlink_components(&args.out_shards, ctx.allow_symlink)?;
        fs::create_dir_all(&args.out_shards)
            .with_context(|| format!("failed to create {}", args.out_shards.display()))?;
        attached
            .shards
            .iter()
            .enumerate()
            .map(|(index, shard)| {
                let source_name = args
                    .shards
                    .get(index)
                    .and_then(|path| path.file_name())
                    .and_then(|name| name.to_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("shard-{}.qcont", usize::from(shard.index) + 1));
                args.out_shards.join(source_name)
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    output_paths.extend(shard_output_plan.iter().cloned());
    preflight_outputs(&output_paths, args.force, ctx)?;
    if let Some(parent) = args
        .out_bundle
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        reject_symlink_components(parent, ctx.allow_symlink)?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    write_file_checked(
        &args.out_bundle,
        &attached.lifecycle_bundle_bytes,
        args.force,
        ctx,
    )
    .with_context(|| format!("failed to write {}", args.out_bundle.display()))?;
    for (shard, path) in attached.shards.iter().zip(shard_output_plan.iter()) {
        write_secret_file_checked(path, &shard.bytes, args.force, ctx)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }

    if ctx.json {
        let report = serde_json::json!({
            "command": "attach",
            "ok": true,
            "cliSchemaVersion": 1,
            "archiveStateDigestHex": attached.archive_state_digest_hex,
            "stateId": attached.state_id,
            "cohortBindingDigestHex": attached.cohort_binding_digest_hex,
            "lifecycleBundlePath": args.out_bundle,
            "lifecycleBundleDigestHex": attached.lifecycle_bundle_digest_hex,
            "embeddedIntoShards": embed_into_shards,
            "embeddedIntoShardsReason": if args.no_embed_into_shards { "opt-out" } else if shards.is_empty() { "no-shards" } else { "embedded" },
            "shardsRewritten": attached.shards.iter().zip(shard_output_plan.iter()).map(|(shard, path)| {
                serde_json::json!({ "index": shard.index, "path": path })
            }).collect::<Vec<_>>(),
            "embeddedLifecycleBundleDigests": attached.embedded_lifecycle_bundle_digests,
            "mixedEmbeddedLifecycleBundleDigests": attached.mixed_embedded_lifecycle_bundle_digests,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        println!("Attached lifecycle bundle: {}", args.out_bundle.display());
        println!("State ID: {}", attached.state_id);
        println!(
            "Lifecycle bundle digest: {}",
            attached.lifecycle_bundle_digest_hex
        );
        println!(
            "Embedded into shards: {}",
            if embed_into_shards { "yes" } else { "no" }
        );
    }
    Ok(())
}
