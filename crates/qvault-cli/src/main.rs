#[cfg(feature = "legacy-mvp")]
mod legacy_main;

#[cfg(feature = "legacy-mvp")]
fn main() -> anyhow::Result<()> {
    legacy_main::main()
}

#[cfg(not(feature = "legacy-mvp"))]
fn main() -> anyhow::Result<()> {
    successor_main::main()
}

#[cfg(not(feature = "legacy-mvp"))]
mod successor_main {
    use std::fs;
    use std::path::{Path, PathBuf};

    use anyhow::{bail, Context, Result};
    use clap::{Parser, Subcommand, ValueEnum};
    use qvault_core::auth::AuthPolicyLevel;
    use qvault_core::bytes::from_hex;
    use qvault_core::hash::sha3_512_hex;
    use qvault_core::mlkem::validate_secret_key;
    use qvault_core::qcont::{build_qvqcont7_shards, Qvqcont7BuildOptions, Qvqcont7BuildParams};

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
        }
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
}
