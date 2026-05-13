#[cfg(feature = "legacy-mvp")]
mod legacy_main;

#[cfg(feature = "legacy-mvp")]
fn main() -> anyhow::Result<()> {
    legacy_main::main()
}

#[cfg(not(feature = "legacy-mvp"))]
fn main() {
    if let Err(error) = successor_main::main() {
        eprintln!("Error: {error:#}");
        std::process::exit(successor_main::exit_code(&error));
    }
}

#[cfg(not(feature = "legacy-mvp"))]
mod successor_main {
    use std::fs;
    use std::path::{Path, PathBuf};

    use anyhow::{bail, Context, Result};
    use clap::{Parser, Subcommand, ValueEnum};
    use qvault_core::auth::AuthPolicyLevel;
    use qvault_core::auth::{NamedBinaryArtifact, VerificationInputs};
    use qvault_core::bytes::from_hex;
    use qvault_core::error::{QvCode, QvError};
    use qvault_core::hash::sha3_512_hex;
    use qvault_core::mlkem::validate_secret_key;
    use qvault_core::qcont::{
        attach_lifecycle_bundle_to_shards, build_qvqcont7_shards, parse_qvqcont7_shard,
        restore_qvqcont7_from_shards, AttachLifecycleOptions, LifecycleSignatureFamily,
        LifecycleSignatureImport, LifecycleSourceEvidenceImport, Qvqcont7BuildOptions,
        Qvqcont7BuildParams, RestoreQvqcont7Options, RestoreQvqcont7Selection,
    };

    #[derive(Parser)]
    #[command(name = "qvault-cli")]
    #[command(about = "Quantum Vault successor migration CLI")]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        Split(SplitArgs),
        Restore(RestoreArgs),
        Attach(AttachArgs),
    }

    #[derive(Parser)]
    struct SplitArgs {
        #[arg(help = "Input .qenc container")]
        input_qenc: PathBuf,
        #[arg(long, help = "Matching ML-KEM-1024 private key")]
        private_key: PathBuf,
        #[arg(long)]
        n: u16,
        #[arg(long)]
        k: u16,
        #[arg(long, default_value = "shards")]
        out: PathBuf,
        #[arg(long, value_enum, default_value = "strong-pq-signature")]
        auth_policy_level: AuthPolicyLevelArg,
        #[arg(long, default_value_t = 1)]
        min_valid_signatures: u64,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, hide = true)]
        archive_id: Option<String>,
        #[arg(long, hide = true)]
        archive_id_random: Option<String>,
        #[arg(long, hide = true)]
        parent_state_id: Option<String>,
        #[arg(long, hide = true)]
        state_type: Option<String>,
    }

    #[derive(Parser)]
    struct RestoreArgs {
        #[arg(long, help = "Reconstructed .qenc output path")]
        output_qenc: Option<PathBuf>,
        #[arg(long, help = "Reconstructed ML-KEM private key output path")]
        output_secret_key: Option<PathBuf>,
        #[arg(
            long,
            help = "Canonical archive-state JSON bytes used as a selection filter"
        )]
        archive_state: Option<PathBuf>,
        #[arg(
            long,
            help = "Canonical lifecycle bundle JSON bytes used as a selection filter"
        )]
        lifecycle_bundle: Option<PathBuf>,
        #[arg(long, help = "Explicit archiveId selection filter")]
        archive_id: Option<String>,
        #[arg(long, help = "Explicit stateId selection filter")]
        state_id: Option<String>,
        #[arg(long, help = "Explicit cohortId selection filter")]
        cohort_id: Option<String>,
        #[arg(long, help = "Explicit lifecycle bundle digest selection filter")]
        lifecycle_bundle_digest: Option<String>,
        #[arg(long = "signature", help = "Detached archive-approval signature file")]
        signatures: Vec<PathBuf>,
        #[arg(long = "pqpk", help = "Pinned PQ signer key (.pqpk)")]
        pq_public_keys: Vec<PathBuf>,
        #[arg(long = "ots", help = "Detached OpenTimestamps proof file")]
        timestamps: Vec<PathBuf>,
        #[arg(long, help = "Expected Stellar signer address for Ed25519 signatures")]
        expected_ed25519_signer: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(required = true, help = "Input QVqcont-7 shard files")]
        shards: Vec<PathBuf>,
    }

    #[derive(Parser)]
    struct AttachArgs {
        #[arg(long = "shards", num_args = 1.., help = "Input QVqcont-7 shard files")]
        shards: Vec<PathBuf>,
        #[arg(
            long,
            help = "Canonical archive-state JSON bytes used as a consistency check"
        )]
        archive_state: Option<PathBuf>,
        #[arg(long, help = "Existing lifecycle bundle JSON bytes")]
        bundle: Option<PathBuf>,
        #[arg(
            long = "archive-approval-sig",
            help = "Detached archive-approval signature file"
        )]
        archive_approval_signatures: Vec<PathBuf>,
        #[arg(long = "maintenance-sig", help = "Detached maintenance signature file")]
        maintenance_signatures: Vec<PathBuf>,
        #[arg(long, help = "Explicit targetRef for all --maintenance-sig files")]
        maintenance_target_ref: Option<String>,
        #[arg(
            long = "source-evidence-sig",
            help = "Detached source-evidence signature file"
        )]
        source_evidence_signatures: Vec<PathBuf>,
        #[arg(long, help = "Explicit targetRef for all --source-evidence-sig files")]
        source_evidence_target_ref: Option<String>,
        #[arg(long = "source-evidence", help = "Source-evidence JSON file")]
        source_evidence: Vec<PathBuf>,
        #[arg(long = "pqpk", help = "Pinned PQ signer key (.pqpk)")]
        pq_public_keys: Vec<PathBuf>,
        #[arg(long = "ots", help = "Detached OpenTimestamps proof file")]
        timestamps: Vec<PathBuf>,
        #[arg(long, help = "Expected Stellar signer address for Ed25519 signatures")]
        expected_ed25519_signer: Option<String>,
        #[arg(long, default_value = "lifecycle-bundle.json")]
        out_bundle: PathBuf,
        #[arg(long, default_value = "attached-shards")]
        out_shards: PathBuf,
        #[arg(long)]
        no_embed_into_shards: bool,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    }

    #[derive(Clone, Copy, Debug, ValueEnum)]
    enum AuthPolicyLevelArg {
        #[value(name = "integrity-only")]
        IntegrityOnly,
        #[value(name = "any-signature")]
        AnySignature,
        #[value(name = "strong-pq-signature")]
        StrongPqSignature,
    }

    impl From<AuthPolicyLevelArg> for AuthPolicyLevel {
        fn from(value: AuthPolicyLevelArg) -> Self {
            match value {
                AuthPolicyLevelArg::IntegrityOnly => AuthPolicyLevel::IntegrityOnly,
                AuthPolicyLevelArg::AnySignature => AuthPolicyLevel::AnySignature,
                AuthPolicyLevelArg::StrongPqSignature => AuthPolicyLevel::StrongPqSignature,
            }
        }
    }

    pub fn main() -> Result<()> {
        let cli = Cli::parse();
        match cli.command {
            Command::Split(args) => run_split(args),
            Command::Restore(args) => run_restore(args),
            Command::Attach(args) => run_attach(args),
        }
    }

    pub fn exit_code(error: &anyhow::Error) -> i32 {
        for cause in error.chain() {
            if let Some(qv_error) = cause.downcast_ref::<QvError>() {
                return match qv_error.qv_code() {
                    Some(
                        QvCode::InvalidFormat
                        | QvCode::InvalidSelection
                        | QvCode::UnsupportedFormat,
                    ) => 2,
                    Some(QvCode::AmbiguousInputs) => 3,
                    Some(
                        QvCode::NotEnoughShards | QvCode::IntegrityMismatch | QvCode::RestoreFailed,
                    ) => 4,
                    Some(QvCode::VerificationFailed | QvCode::PolicyNotSatisfied) => 5,
                    None => 1,
                };
            }
        }
        1
    }

    fn run_split(args: SplitArgs) -> Result<()> {
        validate_deterministic_flags(&args)?;
        if args.archive_id.is_some() && args.archive_id_random.is_some() {
            bail!("split accepts --archive-id or --archive-id-random, not both");
        }

        let mut qenc_bytes = fs::read(&args.input_qenc)
            .with_context(|| format!("failed to read {}", args.input_qenc.display()))?;
        let mut private_key = fs::read(&args.private_key)
            .with_context(|| format!("failed to read {}", args.private_key.display()))?;
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
                min_valid_signatures: Some(args.min_valid_signatures.max(1)),
                ..Qvqcont7BuildOptions::default()
            },
        )?;

        let out_dir = args.out.clone();
        fs::create_dir_all(&out_dir)
            .with_context(|| format!("failed to create {}", out_dir.display()))?;
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
        if !args.force {
            for path in &output_paths {
                if path.exists() {
                    bail!("Refusing to overwrite existing file: {}", path.display());
                }
            }
        }

        fs::write(&archive_state_path, &built.archive_state_bytes)?;
        fs::write(&cohort_binding_path, &built.cohort_binding_bytes)?;
        fs::write(&lifecycle_bundle_path, &built.lifecycle_bundle_bytes)?;
        for (shard, path) in built.shards.iter().zip(shard_paths.iter()) {
            fs::write(path, &shard.bytes)?;
        }

        if args.json {
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
                    "minValidSignatures": args.min_valid_signatures.max(1)
                },
                "archiveStateBytesPath": archive_state_path,
                "archiveStateDigestHex": built.archive_state_digest_hex,
                "cohortBindingBytesPath": cohort_binding_path,
                "cohortBindingDigestHex": built.cohort_binding_digest_hex,
                "lifecycleBundleBytesPath": lifecycle_bundle_path,
                "lifecycleBundleDigestHex": built.lifecycle_bundle_digest_hex,
                "shards": built.shards.iter().zip(shard_paths.iter()).map(|(shard, path)| {
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
        } else {
            println!(
                "Split container successfully into {} successor shard(s).",
                built.shards.len()
            );
            println!("Archive ID: {}", built.archive_id);
            println!("State ID: {}", built.state_id);
            println!("Cohort ID: {}", built.cohort_id);
            println!("Output directory: {}", out_dir.display());
        }

        qenc_bytes.fill(0);
        private_key.fill(0);
        Ok(())
    }

    fn run_attach(args: AttachArgs) -> Result<()> {
        let archive_state_bytes = args
            .archive_state
            .as_ref()
            .map(fs::read)
            .transpose()
            .with_context(|| "failed to read --archive-state")?;
        let lifecycle_bundle_bytes = args
            .bundle
            .as_ref()
            .map(fs::read)
            .transpose()
            .with_context(|| "failed to read --bundle")?;
        let shards = args
            .shards
            .iter()
            .map(|path| {
                let bytes =
                    fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
                parse_qvqcont7_shard(&bytes)
                    .with_context(|| format!("failed to parse shard {}", path.display()))
            })
            .collect::<Result<Vec<_>>>()?;
        let source_evidence = args
            .source_evidence
            .iter()
            .map(|path| {
                Ok(LifecycleSourceEvidenceImport {
                    bytes: Some(
                        fs::read(path)
                            .with_context(|| format!("failed to read {}", path.display()))?,
                    ),
                    value: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let pq_public_key_file_bytes_list = load_named_artifacts(&args.pq_public_keys)?
            .into_iter()
            .map(|artifact| artifact.bytes)
            .collect::<Vec<_>>();
        let timestamps = load_named_artifacts(&args.timestamps)?;
        let signature_imports = build_attach_signature_imports(&args)?;

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
        if !args.force {
            for path in &output_paths {
                if path.exists() {
                    bail!("Refusing to overwrite existing file: {}", path.display());
                }
            }
        }
        if let Some(parent) = args
            .out_bundle
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&args.out_bundle, &attached.lifecycle_bundle_bytes)
            .with_context(|| format!("failed to write {}", args.out_bundle.display()))?;
        for (shard, path) in attached.shards.iter().zip(shard_output_plan.iter()) {
            fs::write(path, &shard.bytes)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }

        if args.json {
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
        } else {
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

    fn run_restore(args: RestoreArgs) -> Result<()> {
        let archive_state_bytes = args
            .archive_state
            .as_ref()
            .map(fs::read)
            .transpose()
            .with_context(|| "failed to read --archive-state")?;
        let lifecycle_bundle_bytes = args
            .lifecycle_bundle
            .as_ref()
            .map(fs::read)
            .transpose()
            .with_context(|| "failed to read --lifecycle-bundle")?;
        let signatures = load_named_artifacts(&args.signatures)?;
        let pq_public_keys = load_named_artifacts(&args.pq_public_keys)?;
        let timestamps = load_named_artifacts(&args.timestamps)?;
        let pinned_pq_public_key_file_bytes = select_single_pinned_pqpk(&pq_public_keys)?;

        let shards = args
            .shards
            .iter()
            .map(|path| {
                let bytes =
                    fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
                parse_qvqcont7_shard(&bytes)
                    .with_context(|| format!("failed to parse shard {}", path.display()))
            })
            .collect::<Result<Vec<_>>>()?;

        let restored = match restore_qvqcont7_from_shards(
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
        ) {
            Ok(restored) => restored,
            Err(error) if args.json => {
                let report = restore_error_json(&error);
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };

        let default_base = default_restore_output_base(&args.shards);
        let output_qenc = args
            .output_qenc
            .clone()
            .unwrap_or_else(|| append_file_name_suffix(&default_base, ".qenc"));
        let output_secret_key = args
            .output_secret_key
            .clone()
            .unwrap_or_else(|| append_file_name_suffix(&default_base, ".qkey"));
        fs::write(&output_qenc, &restored.qenc_bytes)
            .with_context(|| format!("failed to write {}", output_qenc.display()))?;
        fs::write(&output_secret_key, &restored.priv_key)
            .with_context(|| format!("failed to write {}", output_secret_key.display()))?;

        if args.json {
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
        } else {
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

    fn parse_fixed_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
        let bytes = from_hex(value).map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{field} must decode to exactly 32 bytes"))
    }

    fn split_base_name(input_path: &Path) -> Result<String> {
        let file_name = input_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("split input filename must produce a safe output basename")?;
        let base = file_name
            .strip_suffix(".qenc")
            .or_else(|| file_name.strip_suffix(".QENC"))
            .unwrap_or(file_name);
        if base.is_empty() || base == "." || base == ".." || base.contains(['/', '\\', '\0']) {
            bail!("split input filename must produce a safe output basename");
        }
        Ok(base.to_string())
    }

    fn load_named_artifacts(paths: &[PathBuf]) -> Result<Vec<NamedBinaryArtifact>> {
        paths
            .iter()
            .map(|path| {
                let bytes =
                    fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
                Ok(NamedBinaryArtifact {
                    name: path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("artifact")
                        .to_string(),
                    bytes,
                })
            })
            .collect()
    }

    fn build_attach_signature_imports(args: &AttachArgs) -> Result<Vec<LifecycleSignatureImport>> {
        let mut imports = Vec::new();
        for artifact in load_named_artifacts(&args.archive_approval_signatures)? {
            imports.push(signature_import(
                artifact,
                LifecycleSignatureFamily::ArchiveApproval,
                None,
                None,
            ));
        }
        for artifact in load_named_artifacts(&args.maintenance_signatures)? {
            imports.push(signature_import(
                artifact,
                LifecycleSignatureFamily::Maintenance,
                args.maintenance_target_ref.clone(),
                None,
            ));
        }
        let source_evidence_bytes = match args.source_evidence.as_slice() {
            [single] => Some(fs::read(single).with_context(|| {
                format!("failed to read source-evidence {}", single.display())
            })?),
            [] => None,
            _ if args.source_evidence_signatures.is_empty() => None,
            _ => bail!("--source-evidence-sig requires exactly one --source-evidence when no explicit per-signature target is available"),
        };
        for artifact in load_named_artifacts(&args.source_evidence_signatures)? {
            let import = signature_import(
                artifact,
                LifecycleSignatureFamily::SourceEvidence,
                args.source_evidence_target_ref.clone(),
                source_evidence_bytes.clone(),
            );
            if import.source_evidence_bytes.is_none() && import.target_ref.is_none() {
                bail!("--source-evidence-sig requires --source-evidence or --source-evidence-target-ref");
            }
            imports.push(import);
        }
        Ok(imports)
    }

    fn signature_import(
        artifact: NamedBinaryArtifact,
        family: LifecycleSignatureFamily,
        target_ref: Option<String>,
        source_evidence_bytes: Option<Vec<u8>>,
    ) -> LifecycleSignatureImport {
        LifecycleSignatureImport {
            name: artifact.name,
            bytes: artifact.bytes,
            signature_family: family,
            target_type: Some(family.target_type().to_string()),
            target_ref,
            target_digest_hex: None,
            source_evidence_bytes,
            source_evidence_value: None,
        }
    }

    fn select_single_pinned_pqpk(public_keys: &[NamedBinaryArtifact]) -> Result<Option<Vec<u8>>> {
        let Some(first) = public_keys.first() else {
            return Ok(None);
        };
        for key in public_keys.iter().skip(1) {
            if key.bytes != first.bytes {
                bail!("restore accepts at most one distinct --pqpk pinned PQ signer key");
            }
        }
        Ok(Some(first.bytes.clone()))
    }

    fn normalize_optional_string(value: Option<&str>) -> Option<String> {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    fn default_restore_output_base(shards: &[PathBuf]) -> PathBuf {
        let Some(first) = shards.first() else {
            return PathBuf::from("restored");
        };
        let parent = first.parent().unwrap_or_else(|| Path::new(""));
        let file_name = first
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("restored");
        let base = file_name
            .split(".part")
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or("restored");
        parent.join(base)
    }

    fn append_file_name_suffix(path: &Path, suffix: &str) -> PathBuf {
        let mut file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("restored")
            .to_string();
        file_name.push_str(suffix);
        path.parent()
            .map(|parent| parent.join(&file_name))
            .unwrap_or_else(|| PathBuf::from(file_name))
    }

    fn restore_error_json(error: &QvError) -> serde_json::Value {
        serde_json::json!({
            "command": "restore",
            "ok": false,
            "cliSchemaVersion": 1,
            "qvCode": error.qv_code().map(|code| code.as_str()).unwrap_or("QV_ERROR"),
            "error": error.to_string()
        })
    }
}
