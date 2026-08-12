use super::super::*;

pub(super) fn run_split(args: SplitArgs, ctx: CliContext) -> Result<()> {
    validate_cohort_cli_params(args.n, args.k)?;
    validate_deterministic_flags(&args)?;
    if args.archive_id.is_some() && args.archive_id_random.is_some() {
        bail!("split accepts --archive-id or --archive-id-random, not both");
    }
    // Fail closed like the oracle rather than silently clamping 0 up to 1.
    if args.min_valid_signatures < 1 {
        bail!("--min-valid-signatures must be a positive integer");
    }

    let qenc_bytes = read_bounded_file_checked(
        &args.input_qenc,
        ctx,
        MAX_QENC_CONTAINER_SIZE as u64,
        "QENC container",
    )
    .with_context(|| format!("failed to read {}", args.input_qenc.display()))?;
    let private_key = Zeroizing::new(
        read_small_artifact_checked(&args.private_key, ctx, "ML-KEM private key")
            .with_context(|| format!("failed to read {}", args.private_key.display()))?,
    );
    validate_secret_key(&private_key)?;

    let archive_id_random_bytes = match args.archive_id_random.as_deref() {
        Some(hex) => Some(parse_fixed_hex_32(hex, "--archive-id-random")?),
        None => None,
    };
    let built = build_qvqcont7_shards(
        &qenc_bytes,
        &private_key,
        Qvqcont7BuildParams {
            n: args.n,
            k: args.k,
        },
        &Qvqcont7BuildOptions {
            archive_id: args.archive_id.clone(),
            archive_id_random_bytes,
            parent_state_id: args.parent_state_id.clone(),
            state_type: args.state_type.clone(),
            auth_policy_level: Some(args.auth_policy_level.into()),
            min_valid_signatures: Some(args.min_valid_signatures),
            ..Qvqcont7BuildOptions::default()
        },
    )?;

    let out_dir = args.out.clone();
    let base_name = split_base_name(&args.input_qenc)?;
    let archive_state_path = out_dir.join(format!("{base_name}.archive-state.json"));
    let cohort_binding_path = out_dir.join(format!("{base_name}.cohort-binding.json"));
    let lifecycle_bundle_path = out_dir.join(format!("{base_name}.lifecycle-bundle.json"));
    let shard_paths = (0..built.shards.len())
        .map(|index| {
            out_dir.join(format!(
                "{base_name}.part{}-of-{}.qcont",
                index + 1,
                built.shards.len()
            ))
        })
        .collect::<Vec<_>>();

    let mut output_paths = vec![
        archive_state_path.clone(),
        cohort_binding_path.clone(),
        lifecycle_bundle_path.clone(),
    ];
    output_paths.extend(shard_paths.iter().cloned());
    preflight_outputs(&output_paths, args.force, ctx)?;

    let mut lifecycle_bundle_bytes = built.lifecycle_bundle_bytes.clone();
    let mut lifecycle_bundle_digest_hex = built.lifecycle_bundle_digest_hex.clone();
    let mut split_shards = built
        .shards
        .iter()
        .map(|shard| SplitShardOutput {
            index: shard.index,
            bytes: shard.bytes.clone(),
        })
        .collect::<Vec<_>>();
    let archive_approval = match args.archive_approval_key.as_ref() {
        Some(path) => {
            let approval = create_split_archive_approval(path, &built.archive_state_bytes, ctx)?;
            let parsed_shards = built
                .shards
                .iter()
                .map(|shard| parse_qvqcont7_shard(&shard.bytes))
                .collect::<Result<Vec<_>, _>>()?;
            let attached = attach_lifecycle_bundle_to_shards(
                &parsed_shards,
                &AttachLifecycleOptions {
                    archive_state_bytes: Some(built.archive_state_bytes.clone()),
                    lifecycle_bundle_bytes: Some(built.lifecycle_bundle_bytes.clone()),
                    signature_imports: vec![LifecycleSignatureImport {
                        name: format!("{base_name}.archive-state.json.qsig"),
                        bytes: approval.signature_bytes.clone(),
                        signature_family: LifecycleSignatureFamily::ArchiveApproval,
                        target_type: Some("archive-state".to_string()),
                        target_ref: None,
                        target_digest_hex: None,
                        source_evidence_bytes: None,
                        source_evidence_value: None,
                    }],
                    pq_public_key_file_bytes_list: vec![approval.public_key_file_bytes.clone()],
                    embed_into_shards: true,
                    ..AttachLifecycleOptions::default()
                },
            )?;
            lifecycle_bundle_bytes = attached.lifecycle_bundle_bytes;
            lifecycle_bundle_digest_hex = attached.lifecycle_bundle_digest_hex;
            split_shards = attached
                .shards
                .into_iter()
                .map(|mut shard| SplitShardOutput {
                    index: shard.index,
                    bytes: std::mem::take(&mut shard.bytes),
                })
                .collect();
            Some(approval)
        }
        None => None,
    };

    reject_symlink_components(&out_dir, ctx.allow_symlink)?;
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    preflight_outputs(&output_paths, args.force, ctx)?;

    write_file_checked(
        &archive_state_path,
        &built.archive_state_bytes,
        args.force,
        ctx,
    )?;
    write_file_checked(
        &cohort_binding_path,
        &built.cohort_binding_bytes,
        args.force,
        ctx,
    )?;
    write_file_checked(
        &lifecycle_bundle_path,
        &lifecycle_bundle_bytes,
        args.force,
        ctx,
    )?;
    for (shard, path) in split_shards.iter().zip(shard_paths.iter()) {
        write_secret_file_checked(path, &shard.bytes, args.force, ctx)?;
    }

    if ctx.json {
        let archive_approval_json = archive_approval
            .as_ref()
            .map(split_archive_approval_json)
            .transpose()?
            .unwrap_or_else(|| serde_json::json!({ "signed": false }));
        let report = serde_json::json!({
            "command": "split",
            "ok": true,
            "cliSchemaVersion": 1,
            "inputPath": args.input_qenc,
            "outDir": out_dir,
            "archiveId": built.archive_id,
            "stateId": built.state_id,
            "cohortId": built.cohort_id,
            "n": args.n,
            "k": args.k,
            "m": args.n - args.k,
            "t": u64::from(args.k) + (u64::from(args.n - args.k) / 2),
            "rsCodecId": "QV-RS-ErasureCodes-v1",
            "shamir": { "n": args.n, "t": u64::from(args.k) + (u64::from(args.n - args.k) / 2) },
            "authPolicy": {
                "level": AuthPolicyLevel::from(args.auth_policy_level).as_str(),
                "minValidSignatures": args.min_valid_signatures
            },
            "archiveStateBytesPath": archive_state_path,
            "archiveStateDigestHex": built.archive_state_digest_hex,
            "cohortBindingBytesPath": cohort_binding_path,
            "cohortBindingDigestHex": built.cohort_binding_digest_hex,
            "lifecycleBundleBytesPath": lifecycle_bundle_path,
            "lifecycleBundleDigestHex": lifecycle_bundle_digest_hex,
            "unsignedLifecycleBundleDigestHex": built.lifecycle_bundle_digest_hex,
            "archiveApproval": archive_approval_json,
            "shards": split_shards.iter().zip(shard_paths.iter()).map(|(shard, path)| {
                serde_json::json!({
                    "index": shard.index,
                    "path": path,
                    "shardDigestHex": sha3_512_hex(&shard.bytes),
                    "shardSize": shard.bytes.len()
                })
            }).collect::<Vec<_>>(),
            "fmt": built.format_version,
            "containerHashAlg": "SHA3-512",
            "containerHashHex": built.container_hash_hex,
            "containerId": built.container_id,
            "privateKeyHashHex": built.private_key_hash_hex
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        println!(
            "Split container successfully into {} successor shard(s).",
            built.shards.len()
        );
        println!("Archive ID: {}", built.archive_id);
        println!("State ID: {}", built.state_id);
        println!("Cohort ID: {}", built.cohort_id);
        if let Some(approval) = archive_approval.as_ref() {
            println!(
                "Archive approval signature embedded: {}",
                approval.signer_fingerprint_hex
            );
        }
        println!("Output directory: {}", out_dir.display());
    }

    Ok(())
}

fn create_split_archive_approval(
    secret_key_path: &Path,
    archive_state_bytes: &[u8],
    ctx: CliContext,
) -> Result<SplitArchiveApproval> {
    let secret_key_file_bytes = Zeroizing::new(read_small_artifact_checked(
        secret_key_path,
        ctx,
        "PQ signing secret key",
    )?);
    let secret_key_file =
        unpack_secret_key_file(secret_key_file_bytes.as_slice()).map_err(|error| {
            coded(
                QvCode::InvalidFormat,
                format!("invalid archive approval PQ signing key file: {error}"),
            )
        })?;
    let suite = secret_key_file.suite;
    let derived_public_key = public_from_secret(suite, secret_key_file.key_bytes())?;
    let artifact = create_detached_qsig(DetachedSignOptions::new(
        suite,
        secret_key_file.key_bytes(),
        archive_state_bytes,
    ))?;
    if artifact.public_key != derived_public_key {
        return Err(coded(
                QvCode::VerificationFailed,
                "generated split archive approval signature public key did not match derived signer key",
            )
            .into());
    }
    let public_key_file_bytes = pack_public_key_file(suite, &artifact.public_key)?;
    Ok(SplitArchiveApproval {
        suite,
        signer_fingerprint_hex: to_hex(&artifact.signer_fingerprint_record[1..]),
        public_key_digest_hex: sha3_512_hex(&artifact.public_key),
        public_key_file_digest_hex: sha3_512_hex(&public_key_file_bytes),
        signature_digest_hex: sha3_512_hex(&artifact.qsig_bytes),
        signature_bytes: artifact.qsig_bytes,
        public_key_file_bytes,
    })
}

fn split_archive_approval_json(approval: &SplitArchiveApproval) -> Result<Value> {
    let suite_info = get_signature_suite_info(approval.suite.canonical_name())?;
    Ok(serde_json::json!({
        "signed": true,
        "targetType": "archive-state",
        "signatureFormat": "qsig",
        "suite": suite_info.canonical,
        "suiteDisplayName": suite_info.display_name,
        "signatureFamily": suite_info.family,
        "strongPq": suite_info.strong_pq,
        "signerFingerprintAlg": "SHA3-256",
        "signerFingerprintHex": approval.signer_fingerprint_hex,
        "signatureDigestAlg": "SHA3-512",
        "signatureDigestHex": approval.signature_digest_hex,
        "signatureLength": approval.signature_bytes.len(),
        "publicKeyDigestAlg": "SHA3-512",
        "publicKeyDigestHex": approval.public_key_digest_hex,
        "publicKeyFileDigestAlg": "SHA3-512",
        "publicKeyFileDigestHex": approval.public_key_file_digest_hex,
        "publicKeyFileEmbedded": true,
        "signatureEmbedded": true
    }))
}

fn validate_deterministic_flags(args: &SplitArgs) -> Result<()> {
    let has_deterministic = args.archive_id.is_some()
        || args.archive_id_random.is_some()
        || args.parent_state_id.is_some()
        || args.state_type.is_some();
    if has_deterministic && std::env::var("QV_ALLOW_DETERMINISTIC").as_deref() != Ok("1") {
        bail!("split deterministic fixture flags require QV_ALLOW_DETERMINISTIC=1");
    }
    Ok(())
}
