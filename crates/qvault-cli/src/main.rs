fn main() {
    if let Err(error) = successor_main::main() {
        successor_main::emit_error(&error);
        std::process::exit(successor_main::exit_code(&error));
    }
}

mod successor_main {
    use std::env;
    use std::fs;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};

    use anyhow::{bail, Context, Result};
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use clap::{Parser, Subcommand, ValueEnum};
    use qvault_core::auth::AuthPolicyLevel;
    use qvault_core::auth::{AuthenticityReport, NamedBinaryArtifact, VerificationInputs};
    use qvault_core::bytes::from_hex;
    use qvault_core::error::{coded, QvCode, QvError};
    use qvault_core::hash::sha3_512_hex;
    use qvault_core::lifecycle::{
        parse_archive_state_descriptor_bytes, parse_cohort_binding_bytes,
        parse_lifecycle_bundle_bytes, parse_source_evidence_bytes, parse_transition_record_bytes,
    };
    use qvault_core::mlkem::{
        validate_public_key, validate_secret_key, ML_KEM_1024_PUBLIC_KEY_SIZE,
        ML_KEM_1024_SECRET_KEY_SIZE,
    };
    use qvault_core::qcont::{
        attach_lifecycle_bundle_to_shards, build_qvqcont7_shards, parse_qvqcont7_shard,
        reshare_same_state, restore_qvqcont7_from_shards, verify_successor_lifecycle_authenticity,
        AttachLifecycleOptions, LifecycleSignatureFamily, LifecycleSignatureImport,
        LifecycleSourceEvidenceImport, Qvqcont7BuildOptions, Qvqcont7BuildParams,
        ReshareSameStateOptions, ReshareSameStateParams, ReshareTransitionOptions,
        RestoreQvqcont7Options, RestoreQvqcont7Selection,
    };
    use qvault_core::{
        current_iso8601_utc_millis, decrypt_qenc, encrypt_qenc, generate_key_pair,
        parse_qenc_header, EncryptQencOptions,
    };
    use serde_json::Value;

    #[derive(Parser)]
    #[command(name = "qvault-cli")]
    #[command(about = "Quantum Vault successor migration CLI")]
    struct Cli {
        #[arg(long, global = true, help = "Emit cliSchemaVersion:1 JSON")]
        json: bool,
        #[arg(long, global = true, help = "Suppress non-error text output")]
        quiet: bool,
        #[arg(
            long,
            global = true,
            help = "Permit symlink input paths and path components"
        )]
        allow_symlink: bool,
        #[arg(
            long = "no-color",
            global = true,
            help = "Accept plain-output color opt-out"
        )]
        no_color: bool,
        #[arg(long, global = true, help = "Accept color opt-in for JS CLI parity")]
        color: bool,
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        Keygen(KeygenArgs),
        Encrypt(EncryptArgs),
        Decrypt(DecryptArgs),
        Split(SplitArgs),
        Attach(AttachArgs),
        Reshare(ReshareArgs),
        Inspect(InspectArgs),
        Canonicalize(CanonicalizeArgs),
        Verify(VerifyArgs),
        Restore(RestoreArgs),
        Selftest(SelftestArgs),
        Version(VersionArgs),
    }

    #[derive(Clone, Copy)]
    struct CliContext {
        json: bool,
        quiet: bool,
        allow_symlink: bool,
    }

    #[derive(Parser)]
    struct KeygenArgs {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        print_public: bool,
    }

    #[derive(Parser)]
    struct EncryptArgs {
        #[arg(help = "Input plaintext file")]
        input_file: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        filename: Option<String>,
        #[arg(long)]
        force: bool,
    }

    #[derive(Parser)]
    struct DecryptArgs {
        #[arg(help = "Input .qenc container")]
        input_qenc: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long)]
        use_original_filename: bool,
        #[arg(long)]
        force: bool,
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
        #[arg(long, alias = "out-qenc", help = "Reconstructed .qenc output path")]
        output_qenc: Option<PathBuf>,
        #[arg(
            long,
            alias = "out-key",
            help = "Reconstructed ML-KEM private key output path"
        )]
        output_secret_key: Option<PathBuf>,
        #[arg(
            long,
            help = "Canonical archive-state JSON bytes used as a selection filter"
        )]
        archive_state: Option<PathBuf>,
        #[arg(
            long = "bundle",
            alias = "lifecycle-bundle",
            help = "Canonical lifecycle bundle JSON bytes used as a selection filter"
        )]
        lifecycle_bundle: Option<PathBuf>,
        #[arg(long, help = "Explicit archiveId selection filter")]
        archive_id: Option<String>,
        #[arg(long, help = "Explicit stateId selection filter")]
        state_id: Option<String>,
        #[arg(long, help = "Explicit cohortId selection filter")]
        cohort_id: Option<String>,
        #[arg(
            long = "bundle-digest",
            alias = "lifecycle-bundle-digest",
            help = "Explicit lifecycle bundle digest selection filter"
        )]
        lifecycle_bundle_digest: Option<String>,
        #[arg(
            long = "sig",
            alias = "signature",
            help = "Detached archive-approval signature file"
        )]
        signatures: Vec<PathBuf>,
        #[arg(long = "pqpk", help = "Pinned PQ signer key (.pqpk)")]
        pq_public_keys: Vec<PathBuf>,
        #[arg(long = "ots", help = "Detached OpenTimestamps proof file")]
        timestamps: Vec<PathBuf>,
        #[arg(
            long = "ed25519-signer",
            alias = "expected-ed25519-signer",
            help = "Expected Stellar signer address for Ed25519 signatures"
        )]
        expected_ed25519_signer: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(
            long,
            help = "Acknowledge restore warnings that do not change policy.satisfied (e.g. multiple embedded lifecycle-bundle digests in the selected cohort); required before write-mode restore in that case"
        )]
        accept_policy_warnings: bool,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long = "shards", num_args = 1.., help = "Input QVqcont-7 shard files")]
        shard_inputs: Vec<PathBuf>,
        #[arg(help = "Input QVqcont-7 shard files")]
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
            long = "sig",
            alias = "archive-approval-sig",
            help = "Detached archive-approval signature file"
        )]
        archive_approval_signatures: Vec<PathBuf>,
        #[arg(long = "sig-import", help = "Typed JSON signature import descriptor")]
        sig_imports: Vec<String>,
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
        #[arg(long = "source-evidence-bytes", help = "Source-evidence bytes file")]
        source_evidence_bytes: Vec<PathBuf>,
        #[arg(long = "pqpk", help = "Pinned PQ signer key (.pqpk)")]
        pq_public_keys: Vec<PathBuf>,
        #[arg(long = "ots", help = "Detached OpenTimestamps proof file")]
        timestamps: Vec<PathBuf>,
        #[arg(
            long = "ed25519-signer",
            alias = "expected-ed25519-signer",
            help = "Expected Stellar signer address for Ed25519 signatures"
        )]
        expected_ed25519_signer: Option<String>,
        #[arg(long, default_value = "lifecycle-bundle.json")]
        out_bundle: PathBuf,
        #[arg(long, default_value = "attached-shards")]
        out_shards: PathBuf,
        #[arg(long)]
        no_embed_into_shards: bool,
        #[arg(long)]
        force: bool,
    }

    #[derive(Parser)]
    struct ReshareArgs {
        #[arg(long = "shards", num_args = 1.., required = true)]
        shards: Vec<PathBuf>,
        #[arg(long)]
        n: u16,
        #[arg(long)]
        k: u16,
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(long)]
        archive_id: Option<String>,
        #[arg(long)]
        state_id: Option<String>,
        #[arg(long)]
        cohort_id: Option<String>,
        #[arg(long = "bundle-digest")]
        bundle_digest: Option<String>,
        #[arg(long, default_value = "same-state-resharing")]
        reason_code: String,
        #[arg(long, default_value = "operator")]
        operator_role: String,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        performed_at: Option<String>,
        #[arg(long, default_value = "reshared-shards")]
        out: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long = "maintenance-sig")]
        maintenance_signatures: Vec<PathBuf>,
        #[arg(long = "maintenance-pqpk")]
        maintenance_pq_public_keys: Vec<PathBuf>,
        #[arg(long = "maintenance-ots")]
        maintenance_timestamps: Vec<PathBuf>,
        #[arg(
            long = "maintenance-ed25519-signer",
            help = "Expected Stellar signer for maintenance detached .sig imports (reshare same-run)"
        )]
        maintenance_ed25519_signer: Option<String>,
    }

    #[derive(Parser)]
    struct InspectArgs {
        artifact_file: PathBuf,
    }

    #[derive(Parser)]
    struct CanonicalizeArgs {
        artifact_file: PathBuf,
    }

    #[derive(Parser)]
    struct VerifyArgs {
        archive_state: PathBuf,
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(long = "sig")]
        signatures: Vec<PathBuf>,
        #[arg(long = "pqpk")]
        pq_public_keys: Vec<PathBuf>,
        #[arg(long = "ots")]
        timestamps: Vec<PathBuf>,
        #[arg(long = "ed25519-signer")]
        expected_ed25519_signer: Option<String>,
        #[arg(long)]
        include_detached_summary: bool,
        #[arg(long, value_enum)]
        required_policy_level: Option<AuthPolicyLevelArg>,
    }

    #[derive(Parser)]
    struct SelftestArgs {
        #[arg(long)]
        filter: Option<String>,
    }

    #[derive(Parser)]
    struct VersionArgs {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
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
        let cli = match Cli::try_parse() {
            Ok(cli) => cli,
            Err(error) => {
                if json_requested() {
                    let report = serde_json::json!({
                        "command": command_name_from_args(),
                        "ok": false,
                        "cliSchemaVersion": 1,
                        "qvCode": "USAGE",
                        "error": error.to_string()
                    });
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    std::process::exit(error.exit_code());
                }
                error.exit();
            }
        };
        let ctx = CliContext {
            json: cli.json,
            quiet: cli.quiet,
            allow_symlink: cli.allow_symlink,
        };
        let _color_flags_accepted = (cli.color, cli.no_color);
        match cli.command {
            Command::Keygen(args) => run_keygen(args, ctx),
            Command::Encrypt(args) => run_encrypt(args, ctx),
            Command::Decrypt(args) => run_decrypt(args, ctx),
            Command::Split(args) => run_split(args, ctx),
            Command::Attach(args) => run_attach(args, ctx),
            Command::Reshare(args) => run_reshare(args, ctx),
            Command::Inspect(args) => run_inspect(args, ctx),
            Command::Canonicalize(args) => run_canonicalize(args, ctx),
            Command::Verify(args) => run_verify(args, ctx),
            Command::Restore(args) => run_restore(args, ctx),
            Command::Selftest(args) => run_selftest(args, ctx),
            Command::Version(args) => run_version(args, ctx),
        }
    }

    pub fn emit_error(error: &anyhow::Error) {
        if json_requested() {
            let report = serde_json::json!({
                "command": command_name_from_args(),
                "ok": false,
                "cliSchemaVersion": 1,
                "qvCode": qv_code_string(error),
                "error": error.to_string()
            });
            match serde_json::to_string_pretty(&report) {
                Ok(text) => println!("{text}"),
                Err(_) => println!(
                    r#"{{"command":null,"ok":false,"cliSchemaVersion":1,"qvCode":"UNEXPECTED","error":"failed to serialize error"}}"#
                ),
            }
        } else {
            eprintln!("Error: {error:#}");
        }
    }

    /// Maps `QvCode` to process exit status per `quantum-vault/src/core/cli/lib/exit.js` (`QV_CODE_TO_EXIT`).
    fn map_qv_code_to_exit(code: QvCode) -> i32 {
        match code {
            QvCode::PolicyNotSatisfied | QvCode::VerificationFailed | QvCode::RestoreFailed => 1,
            QvCode::InvalidFormat | QvCode::UnsupportedFormat => 4,
            QvCode::NotEnoughShards | QvCode::IntegrityMismatch => 7,
            QvCode::InvalidSelection | QvCode::AmbiguousInputs => 9,
            QvCode::ReshareContractViolation => 10,
            QvCode::RestoredIntegrityFailed => 11,
            QvCode::RestoreLifecycleVariantAckRequired => 12,
        }
    }

    pub fn exit_code(error: &anyhow::Error) -> i32 {
        for cause in error.chain() {
            if let Some(qv_error) = cause.downcast_ref::<QvError>() {
                return qv_error.qv_code().map(map_qv_code_to_exit).unwrap_or(1);
            }
        }
        1
    }

    fn run_keygen(args: KeygenArgs, ctx: CliContext) -> Result<()> {
        if let Some(prefix) = args.name.as_deref() {
            validate_safe_name_prefix(prefix)?;
        }
        reject_symlink_components(&args.out, ctx.allow_symlink)?;
        fs::create_dir_all(&args.out)
            .with_context(|| format!("failed to create {}", args.out.display()))?;
        let prefix = args.name.as_deref().unwrap_or("");
        let public_key_path = args.out.join(format!("{prefix}publicKey.qkey"));
        let private_key_path = args.out.join(format!("{prefix}privateKey.qkey"));
        preflight_outputs(
            &[public_key_path.clone(), private_key_path.clone()],
            args.force,
            ctx,
        )?;

        let (public_key, mut private_key) = generate_key_pair(None)?;
        write_file_checked(&public_key_path, &public_key, ctx)?;
        write_file_checked(&private_key_path, &private_key, ctx)?;

        if ctx.json {
            let mut report = serde_json::json!({
                "command": "keygen",
                "ok": true,
                "cliSchemaVersion": 1,
                "alg": { "KEM": "ML-KEM-1024" },
                "publicKeyPath": public_key_path,
                "privateKeyPath": private_key_path,
                "publicKeyDigestHex": sha3_512_hex(&public_key),
                "privateKeyDigestHex": sha3_512_hex(&private_key),
                "publicKeyLength": ML_KEM_1024_PUBLIC_KEY_SIZE,
                "privateKeyLength": ML_KEM_1024_SECRET_KEY_SIZE,
                "seed": { "source": "secure-random" }
            });
            if args.print_public {
                report["publicKeyBase64"] = Value::String(BASE64_STANDARD.encode(&public_key));
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else if !ctx.quiet {
            println!("Generated ML-KEM-1024 keypair.");
            println!("Public key: {}", public_key_path.display());
            println!("Private key: {}", private_key_path.display());
            if args.print_public {
                println!("{}", BASE64_STANDARD.encode(&public_key));
            }
        }
        private_key.fill(0);
        Ok(())
    }

    fn run_encrypt(args: EncryptArgs, ctx: CliContext) -> Result<()> {
        validate_optional_filename(args.filename.as_deref())?;
        let mut plaintext = read_file_checked(&args.input_file, ctx)
            .with_context(|| format!("failed to read {}", args.input_file.display()))?;
        let public_key = read_file_checked(&args.public_key, ctx)
            .with_context(|| format!("failed to read {}", args.public_key.display()))?;
        validate_public_key(&public_key)?;
        preflight_outputs(std::slice::from_ref(&args.out), args.force, ctx)?;

        let original_filename = match args.filename.clone() {
            Some(filename) => Some(filename),
            None => args
                .input_file
                .file_name()
                .and_then(|value| value.to_str())
                .map(str::to_string),
        };
        let qenc_bytes = encrypt_qenc(
            &plaintext,
            &public_key,
            &EncryptQencOptions {
                original_filename: original_filename.clone(),
                ..EncryptQencOptions::default()
            },
        )?;
        let header = parse_qenc_header(&qenc_bytes)?;
        write_file_checked(&args.out, &qenc_bytes, ctx)?;

        if ctx.json {
            let report = serde_json::json!({
                "command": "encrypt",
                "ok": true,
                "cliSchemaVersion": 1,
                "alg": { "KEM": "ML-KEM-1024", "KDF": "KMAC256", "AEAD": "AES-256-GCM" },
                "inputPath": args.input_file,
                "inputPaths": [args.input_file],
                "outputPath": args.out,
                "publicKeyPath": args.public_key,
                "fmt": "QVv1-5-0",
                "aeadMode": header.metadata.aead_mode,
                "chunkSize": header.metadata.chunk_size,
                "chunkCount": header.metadata.chunk_count,
                "payloadLength": header.metadata.payload_length,
                "plaintextLength": plaintext.len(),
                "inputLength": plaintext.len(),
                "containerHashAlg": "SHA3-512",
                "containerHashHex": sha3_512_hex(&qenc_bytes),
                "containerId": Value::Null,
                "fileHashHex": sha3_512_hex(&plaintext),
                "originalFilename": original_filename,
                "payloadKind": "file",
                "fileCount": 1
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else if !ctx.quiet {
            println!("Encrypted file: {}", args.out.display());
        }
        plaintext.fill(0);
        Ok(())
    }

    fn run_decrypt(args: DecryptArgs, ctx: CliContext) -> Result<()> {
        if args.out.is_some() && (args.out_dir.is_some() || args.use_original_filename) {
            bail!("decrypt accepts --out or --out-dir/--use-original-filename, not both");
        }
        let qenc_bytes = read_file_checked(&args.input_qenc, ctx)
            .with_context(|| format!("failed to read {}", args.input_qenc.display()))?;
        let mut private_key = read_file_checked(&args.private_key, ctx)
            .with_context(|| format!("failed to read {}", args.private_key.display()))?;
        validate_secret_key(&private_key)?;
        let header = parse_qenc_header(&qenc_bytes)?;
        let mut decrypted = decrypt_qenc(&qenc_bytes, &private_key)?;
        let output_path =
            decrypt_output_path(&args, &decrypted.private_metadata.original_filename)?;
        preflight_outputs(std::slice::from_ref(&output_path), args.force, ctx)?;
        write_file_checked(&output_path, &decrypted.file_bytes, ctx)?;

        if ctx.json {
            let report = serde_json::json!({
                "command": "decrypt",
                "ok": true,
                "cliSchemaVersion": 1,
                "inputPath": args.input_qenc,
                "outputPath": output_path,
                "outputPaths": [output_path],
                "alg": { "KEM": "ML-KEM-1024", "KDF": "KMAC256", "AEAD": "AES-256-GCM" },
                "fmt": "QVv1-5-0",
                "aeadMode": header.metadata.aead_mode,
                "chunkSize": header.metadata.chunk_size,
                "chunkCount": header.metadata.chunk_count,
                "payloadLength": header.metadata.payload_length,
                "plaintextLength": decrypted.file_bytes.len(),
                "originalFilename": decrypted.private_metadata.original_filename,
                "fileHashHex": decrypted.private_metadata.file_hash,
                "containerHashAlg": "SHA3-512",
                "containerHashHex": sha3_512_hex(&qenc_bytes),
                "containerId": Value::Null,
                "payloadKind": if decrypted.file_bytes.starts_with(b"QVB1") { "qvpack" } else { "file" },
                "fileCount": 1,
                "qvpackExtracted": false,
                "qvpackEntries": []
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else if !ctx.quiet {
            println!("Decrypted file: {}", output_path.display());
        }
        private_key.fill(0);
        decrypted.file_bytes.fill(0);
        Ok(())
    }

    fn run_split(args: SplitArgs, ctx: CliContext) -> Result<()> {
        validate_deterministic_flags(&args)?;
        if args.archive_id.is_some() && args.archive_id_random.is_some() {
            bail!("split accepts --archive-id or --archive-id-random, not both");
        }

        let mut qenc_bytes = read_file_checked(&args.input_qenc, ctx)
            .with_context(|| format!("failed to read {}", args.input_qenc.display()))?;
        let mut private_key = read_file_checked(&args.private_key, ctx)
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
        reject_symlink_components(&out_dir, ctx.allow_symlink)?;
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
        preflight_outputs(&output_paths, args.force, ctx)?;

        write_file_checked(&archive_state_path, &built.archive_state_bytes, ctx)?;
        write_file_checked(&cohort_binding_path, &built.cohort_binding_bytes, ctx)?;
        write_file_checked(&lifecycle_bundle_path, &built.lifecycle_bundle_bytes, ctx)?;
        for (shard, path) in built.shards.iter().zip(shard_paths.iter()) {
            write_file_checked(path, &shard.bytes, ctx)?;
        }

        if ctx.json {
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
        } else if !ctx.quiet {
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

    fn run_attach(args: AttachArgs, ctx: CliContext) -> Result<()> {
        let archive_state_bytes = args
            .archive_state
            .as_ref()
            .map(|path| read_file_checked(path, ctx))
            .transpose()
            .with_context(|| "failed to read --archive-state")?;
        let lifecycle_bundle_bytes = args
            .bundle
            .as_ref()
            .map(|path| read_file_checked(path, ctx))
            .transpose()
            .with_context(|| "failed to read --bundle")?;
        let shards = args
            .shards
            .iter()
            .map(|path| {
                let bytes = read_file_checked(path, ctx)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                parse_qvqcont7_shard(&bytes)
                    .with_context(|| format!("failed to parse shard {}", path.display()))
            })
            .collect::<Result<Vec<_>>>()?;
        let source_evidence = args
            .source_evidence
            .iter()
            .chain(args.source_evidence_bytes.iter())
            .map(|path| {
                Ok(LifecycleSourceEvidenceImport {
                    bytes: Some(
                        read_file_checked(path, ctx)
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
        write_file_checked(&args.out_bundle, &attached.lifecycle_bundle_bytes, ctx)
            .with_context(|| format!("failed to write {}", args.out_bundle.display()))?;
        for (shard, path) in attached.shards.iter().zip(shard_output_plan.iter()) {
            write_file_checked(path, &shard.bytes, ctx)
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

    fn run_restore(args: RestoreArgs, ctx: CliContext) -> Result<()> {
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
            Err(error) => return Err(error.into()),
        };

        let variant_ack_required =
            restored.mixed_lifecycle_bundle_variants_within_selected_cohort;
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
        write_file_checked(&output_secret_key, &restored.priv_key, ctx)
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

    fn run_reshare(args: ReshareArgs, ctx: CliContext) -> Result<()> {
        if !args.maintenance_pq_public_keys.is_empty() && args.maintenance_signatures.is_empty() {
            bail!("--maintenance-pqpk requires at least one --maintenance-sig");
        }
        if !args.maintenance_timestamps.is_empty() && args.maintenance_signatures.is_empty() {
            bail!("--maintenance-ots requires at least one --maintenance-sig");
        }
        let maintenance_signature_imports = load_named_artifacts(&args.maintenance_signatures, ctx)?
            .into_iter()
            .map(|artifact| {
                signature_import(
                    artifact,
                    LifecycleSignatureFamily::Maintenance,
                    None,
                    None,
                )
            })
            .collect::<Vec<_>>();
        let maintenance_pq_public_key_file_bytes_list =
            load_named_artifacts(&args.maintenance_pq_public_keys, ctx)?
                .into_iter()
                .map(|artifact| artifact.bytes)
                .collect::<Vec<_>>();
        let maintenance_timestamps =
            load_named_artifacts(&args.maintenance_timestamps, ctx)?;
        let predecessor_shards = args
            .shards
            .iter()
            .map(|path| {
                let bytes = read_file_checked(path, ctx)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                parse_qvqcont7_shard(&bytes)
                    .with_context(|| format!("failed to parse shard {}", path.display()))
            })
            .collect::<Result<Vec<_>>>()?;
        let lifecycle_bundle_bytes = args
            .bundle
            .as_ref()
            .map(|path| read_file_checked(path, ctx))
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
        write_file_checked(&archive_state_path, &reshared.archive_state_bytes, ctx)?;
        write_file_checked(&cohort_binding_path, &reshared.cohort_binding_bytes, ctx)?;
        write_file_checked(
            &transition_record_path,
            &reshared.transition_record_bytes,
            ctx,
        )?;
        write_file_checked(
            &lifecycle_bundle_path,
            &reshared.lifecycle_bundle_bytes,
            ctx,
        )?;
        for (shard, path) in reshared.shards.iter().zip(shard_paths.iter()) {
            write_file_checked(path, &shard.bytes, ctx)?;
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
                    "invalidShareIndices": [],
                    "corruptedShardIndices": reshared.verification_report.rejected_shard_indices,
                    "missingShardIndices": [],
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

    fn run_inspect(args: InspectArgs, ctx: CliContext) -> Result<()> {
        let bytes = read_file_checked(&args.artifact_file, ctx)?;
        let inspected = inspect_artifact(&args.artifact_file, &bytes)?;
        if ctx.json {
            println!("{}", serde_json::to_string_pretty(&inspected)?);
        } else if !ctx.quiet {
            println!("Artifact: {}", args.artifact_file.display());
            println!(
                "Type: {}",
                inspected["artifactType"].as_str().unwrap_or("unknown")
            );
            println!("Digest: {}", inspected["digestHex"].as_str().unwrap_or(""));
            if let Some(text) = inspected.get("canonicalJsonText").and_then(Value::as_str) {
                println!("{text}");
            }
        }
        Ok(())
    }

    fn run_canonicalize(args: CanonicalizeArgs, ctx: CliContext) -> Result<()> {
        let bytes = read_file_checked(&args.artifact_file, ctx)?;
        let canonical = canonicalize_artifact(&bytes)?;
        if ctx.json {
            let report = serde_json::json!({
                "command": "canonicalize",
                "ok": true,
                "cliSchemaVersion": 1,
                "file": args.artifact_file,
                "artifactType": canonical.artifact_type,
                "artifactVersion": canonical.artifact_version,
                "digestAlg": "SHA3-512",
                "digestHex": sha3_512_hex(&canonical.bytes),
                "canonicalJson": canonical.value,
                "canonicalJsonText": canonical.text
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            io::stdout().write_all(&canonical.bytes)?;
        }
        Ok(())
    }

    fn run_verify(args: VerifyArgs, ctx: CliContext) -> Result<()> {
        let archive_state_bytes = read_file_checked(&args.archive_state, ctx)?;
        let archive_state = parse_archive_state_descriptor_bytes(&archive_state_bytes)?;
        let lifecycle_bundle_bytes = match &args.bundle {
            Some(path) => read_file_checked(path, ctx)?,
            None => bail!("verify requires --bundle with canonical lifecycle bundle bytes"),
        };
        let signatures = load_named_artifacts(&args.signatures, ctx)?;
        let pq_public_keys = load_named_artifacts(&args.pq_public_keys, ctx)?;
        let timestamps = load_named_artifacts(&args.timestamps, ctx)?;
        let pinned_pq_public_key_file_bytes = select_single_pinned_pqpk(&pq_public_keys)?;
        let pq_public_key_file_bytes_list = pq_public_keys
            .iter()
            .map(|artifact| artifact.bytes.clone())
            .collect::<Vec<_>>();
        let attached = attach_lifecycle_bundle_to_shards(
            &[],
            &AttachLifecycleOptions {
                archive_state_bytes: Some(archive_state.bytes.clone()),
                lifecycle_bundle_bytes: Some(lifecycle_bundle_bytes.clone()),
                signature_imports: signatures
                    .into_iter()
                    .map(|artifact| {
                        signature_import(
                            artifact,
                            LifecycleSignatureFamily::ArchiveApproval,
                            None,
                            None,
                        )
                    })
                    .collect(),
                pq_public_key_file_bytes_list,
                timestamps,
                expected_ed25519_signer: normalize_optional_string(
                    args.expected_ed25519_signer.as_deref(),
                ),
                embed_into_shards: false,
                ..AttachLifecycleOptions::default()
            },
        )?;

        let authenticity = verify_successor_lifecycle_authenticity(
            &archive_state.bytes,
            &attached.lifecycle_bundle_bytes,
            &VerificationInputs {
                signatures: vec![],
                pinned_pq_public_key_file_bytes,
                timestamps: vec![],
                expected_ed25519_signer: normalize_optional_string(
                    args.expected_ed25519_signer.as_deref(),
                ),
            },
        )?;

        let required_policy = build_required_policy_report(&authenticity, args.required_policy_level);
        let verify_ok = verify_cli_report_satisfied(&authenticity, required_policy.as_ref());

        let detached_summary = if args.include_detached_summary {
            let rows: Vec<Value> = authenticity
                .verification
                .results
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "artifactId": row.artifact_id,
                        "name": row.name,
                        "source": row.source,
                        "format": row.format,
                        "ok": row.ok,
                        "proofIdentityDigestAlg": row.proof_identity_digest_alg,
                        "proofIdentityDigestHex": row.proof_identity_digest_hex,
                    })
                })
                .collect();
            Value::Array(rows)
        } else {
            Value::Null
        };

        if ctx.json {
            let mut report = serde_json::json!({
                "command": "verify",
                "ok": verify_ok,
                "cliSchemaVersion": 1,
                "verification": serde_json::to_value(&authenticity.verification)?,
                "policy": serde_json::to_value(&authenticity.policy)?,
                "timestampEvidence": serde_json::to_value(&authenticity.timestamp_evidence)?,
                "transitionReport": {},
                "sourceEvidenceReport": {},
                "warnings": authenticity.warnings,
                "status": serde_json::to_value(&authenticity.status)?,
                "detachedSummary": detached_summary,
            });
            if let Some(ref req) = required_policy {
                report["requiredPolicy"] = req.clone();
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !verify_ok {
                std::process::exit(map_qv_code_to_exit(QvCode::PolicyNotSatisfied));
            }
            return Ok(());
        }

        if !verify_ok {
            let reason = required_policy
                .as_ref()
                .and_then(|value| value.get("reason").and_then(Value::as_str))
                .map(str::to_string)
                .unwrap_or_else(|| authenticity.policy.reason.clone());
            return Err(coded(QvCode::PolicyNotSatisfied, reason).into());
        }

        if !ctx.quiet {
            println!("Lifecycle verification succeeded.");
            println!("State ID: {}", archive_state.state_id);
        }
        Ok(())
    }

    fn run_selftest(args: SelftestArgs, ctx: CliContext) -> Result<()> {
        let filter = args.filter.unwrap_or_default();
        let include_crypto =
            filter.is_empty() || "crypto".contains(&filter) || filter.contains("crypto");
        let mut checks = Vec::new();
        if include_crypto {
            let (public_key, private_key) = generate_key_pair(None)?;
            validate_public_key(&public_key)?;
            validate_secret_key(&private_key)?;
            checks.push(serde_json::json!({ "name": "ml-kem-keygen", "ok": true }));
        }
        if ctx.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "command": "selftest",
                    "ok": true,
                    "cliSchemaVersion": 1,
                    "checks": checks
                }))?
            );
        } else if !ctx.quiet {
            println!("Selftest passed.");
        }
        Ok(())
    }

    fn run_version(_args: VersionArgs, ctx: CliContext) -> Result<()> {
        if ctx.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "command": "version",
                    "ok": true,
                    "cliSchemaVersion": 1,
                    "name": "qvault-cli",
                    "version": env!("CARGO_PKG_VERSION"),
                    "format": { "qcont": "QVqcont-7", "lifecycleBundle": "QV-Lifecycle-Bundle/v1" }
                }))?
            );
        } else if !ctx.quiet {
            println!("qvault-cli {}", env!("CARGO_PKG_VERSION"));
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

    fn load_named_artifacts(
        paths: &[PathBuf],
        ctx: CliContext,
    ) -> Result<Vec<NamedBinaryArtifact>> {
        paths
            .iter()
            .map(|path| {
                let bytes = read_file_checked(path, ctx)
                    .with_context(|| format!("failed to read {}", path.display()))?;
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

    fn build_attach_signature_imports(
        args: &AttachArgs,
        ctx: CliContext,
    ) -> Result<Vec<LifecycleSignatureImport>> {
        let mut imports = Vec::new();
        for artifact in load_named_artifacts(&args.archive_approval_signatures, ctx)? {
            imports.push(signature_import(
                artifact,
                LifecycleSignatureFamily::ArchiveApproval,
                None,
                None,
            ));
        }
        for artifact in load_named_artifacts(&args.maintenance_signatures, ctx)? {
            imports.push(signature_import(
                artifact,
                LifecycleSignatureFamily::Maintenance,
                args.maintenance_target_ref.clone(),
                None,
            ));
        }
        let source_evidence_bytes = match args.source_evidence.as_slice() {
            [single] => Some(read_file_checked(single, ctx).with_context(|| {
                format!("failed to read source-evidence {}", single.display())
            })?),
            [] => None,
            _ if args.source_evidence_signatures.is_empty() => None,
            _ => bail!("--source-evidence-sig requires exactly one --source-evidence when no explicit per-signature target is available"),
        };
        for artifact in load_named_artifacts(&args.source_evidence_signatures, ctx)? {
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
        for spec in &args.sig_imports {
            imports.push(parse_sig_import_spec(spec, ctx)?);
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

    fn parse_sig_import_spec(spec: &str, ctx: CliContext) -> Result<LifecycleSignatureImport> {
        let value: Value =
            serde_json::from_str(spec).context("--sig-import must be a JSON object")?;
        let object = value
            .as_object()
            .context("--sig-import must be a JSON object")?;
        let file = object
            .get("file")
            .and_then(Value::as_str)
            .context("--sig-import.file is required")?;
        let family = match object
            .get("signatureFamily")
            .and_then(Value::as_str)
            .context("--sig-import.signatureFamily is required")?
        {
            "archive-approval" => LifecycleSignatureFamily::ArchiveApproval,
            "maintenance" => LifecycleSignatureFamily::Maintenance,
            "source-evidence" => LifecycleSignatureFamily::SourceEvidence,
            other => bail!("unsupported --sig-import.signatureFamily: {other}"),
        };
        let path = PathBuf::from(file);
        let bytes = read_file_checked(&path, ctx)
            .with_context(|| format!("failed to read --sig-import file {}", path.display()))?;
        let source_evidence_bytes = object
            .get("sourceEvidence")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .map(|path| read_file_checked(&path, ctx))
            .transpose()?;
        let target_digest_hex = match object.get("targetDigest") {
            Some(Value::String(value)) => Some(value.clone()),
            Some(Value::Object(map)) => {
                map.get("value").and_then(Value::as_str).map(str::to_string)
            }
            Some(_) => bail!("--sig-import.targetDigest must be a hex string or digest object"),
            None => None,
        };
        Ok(LifecycleSignatureImport {
            name: path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("signature")
                .to_string(),
            bytes,
            signature_family: family,
            target_type: object
                .get("targetType")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| Some(family.target_type().to_string())),
            target_ref: object
                .get("targetRef")
                .and_then(Value::as_str)
                .map(str::to_string),
            target_digest_hex,
            source_evidence_bytes,
            source_evidence_value: None,
        })
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

    fn read_file_checked(path: &Path, ctx: CliContext) -> Result<Vec<u8>> {
        reject_symlink_components(path, ctx.allow_symlink)?;
        fs::read(path).with_context(|| format!("failed to read {}", path.display()))
    }

    fn write_file_checked(path: &Path, bytes: &[u8], ctx: CliContext) -> Result<()> {
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            reject_symlink_components(parent, ctx.allow_symlink)?;
        }
        if path.exists() {
            reject_symlink_components(path, ctx.allow_symlink)?;
        }
        fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
    }

    fn preflight_outputs(paths: &[PathBuf], force: bool, ctx: CliContext) -> Result<()> {
        for path in paths {
            if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
                reject_symlink_components(parent, ctx.allow_symlink)?;
            }
            if path.exists() {
                reject_symlink_components(path, ctx.allow_symlink)?;
                if !force {
                    bail!("Refusing to overwrite existing file: {}", path.display());
                }
            }
        }
        Ok(())
    }

    fn reject_symlink_components(path: &Path, allow_symlink: bool) -> Result<()> {
        if allow_symlink {
            return Ok(());
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()?.join(path)
        };
        let mut current = PathBuf::new();
        for component in absolute.components() {
            current.push(component.as_os_str());
            let Ok(metadata) = fs::symlink_metadata(&current) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                bail!(
                    "Refusing symlink path component without --allow-symlink: {}",
                    current.display()
                );
            }
        }
        Ok(())
    }

    fn validate_safe_name_prefix(prefix: &str) -> Result<()> {
        if prefix.contains(['/', '\\', '\0']) {
            bail!("--name must not contain path separators or NUL");
        }
        Ok(())
    }

    fn validate_optional_filename(filename: Option<&str>) -> Result<()> {
        if let Some(filename) = filename {
            if filename.is_empty() || filename.contains(['/', '\\', '\0']) {
                bail!("--filename must be a safe basename");
            }
        }
        Ok(())
    }

    fn safe_recovered_filename(filename: Option<&str>) -> Result<String> {
        let filename = filename.unwrap_or("decrypted");
        if filename.is_empty()
            || filename == "."
            || filename == ".."
            || filename.starts_with('.')
            || filename.contains(['/', '\\', '\0'])
            || filename.chars().any(char::is_control)
        {
            bail!("recovered original filename is unsafe");
        }
        Ok(filename.to_string())
    }

    fn decrypt_output_path(
        args: &DecryptArgs,
        original_filename: &Option<String>,
    ) -> Result<PathBuf> {
        if let Some(out) = &args.out {
            return Ok(out.clone());
        }
        if let Some(out_dir) = &args.out_dir {
            return Ok(out_dir.join(safe_recovered_filename(original_filename.as_deref())?));
        }
        if args.use_original_filename {
            let parent = args.input_qenc.parent().unwrap_or_else(|| Path::new(""));
            return Ok(parent.join(safe_recovered_filename(original_filename.as_deref())?));
        }
        Ok(append_file_name_suffix(&args.input_qenc, ".decrypted"))
    }

    fn restore_shard_paths(args: &RestoreArgs) -> Result<Vec<PathBuf>> {
        let mut shards = args.shard_inputs.clone();
        shards.extend(args.shards.iter().cloned());
        if shards.is_empty() {
            bail!("restore requires at least one --shards path or positional shard path");
        }
        Ok(shards)
    }

    #[derive(Clone)]
    struct CanonicalizedArtifact {
        artifact_type: &'static str,
        artifact_version: String,
        value: Value,
        text: String,
        bytes: Vec<u8>,
        canonical_input: bool,
    }

    fn canonicalize_artifact(bytes: &[u8]) -> Result<CanonicalizedArtifact> {
        if let Ok(parsed) = parse_archive_state_descriptor_bytes(bytes) {
            return Ok(CanonicalizedArtifact {
                artifact_type: "archive-state",
                artifact_version: "1".to_string(),
                value: parsed.archive_state.value,
                text: parsed.canonical,
                canonical_input: parsed.bytes == bytes,
                bytes: parsed.bytes,
            });
        }
        if let Ok(parsed) = parse_cohort_binding_bytes(bytes) {
            return Ok(CanonicalizedArtifact {
                artifact_type: "cohort-binding",
                artifact_version: "1".to_string(),
                value: parsed.cohort_binding.value,
                text: parsed.canonical,
                canonical_input: parsed.bytes == bytes,
                bytes: parsed.bytes,
            });
        }
        if let Ok(parsed) = parse_lifecycle_bundle_bytes(bytes) {
            return Ok(CanonicalizedArtifact {
                artifact_type: "lifecycle-bundle",
                artifact_version: "1".to_string(),
                value: parsed.lifecycle_bundle.value,
                text: parsed.canonical,
                canonical_input: parsed.bytes == bytes,
                bytes: parsed.bytes,
            });
        }
        if let Ok(parsed) = parse_transition_record_bytes(bytes) {
            return Ok(CanonicalizedArtifact {
                artifact_type: "transition-record",
                artifact_version: "1".to_string(),
                value: parsed.transition_record.value,
                text: parsed.canonical,
                canonical_input: parsed.bytes == bytes,
                bytes: parsed.bytes,
            });
        }
        if let Ok(parsed) = parse_source_evidence_bytes(bytes) {
            return Ok(CanonicalizedArtifact {
                artifact_type: "source-evidence",
                artifact_version: "1".to_string(),
                value: parsed.source_evidence.value,
                text: parsed.canonical,
                canonical_input: parsed.bytes == bytes,
                bytes: parsed.bytes,
            });
        }
        bail!("artifact is not a canonicalizable lifecycle JSON artifact");
    }

    fn inspect_artifact(path: &Path, bytes: &[u8]) -> Result<Value> {
        if let Ok(canonical) = canonicalize_artifact(bytes) {
            return Ok(serde_json::json!({
                "command": "inspect",
                "ok": true,
                "cliSchemaVersion": 1,
                "file": path,
                "artifactType": canonical.artifact_type,
                "artifactVersion": canonical.artifact_version,
                "encoding": "json",
                "digestAlg": "SHA3-512",
                "digestHex": sha3_512_hex(&canonical.bytes),
                "inputDigestHex": sha3_512_hex(bytes),
                "canonicalInput": canonical.canonical_input,
                "canonicalJson": canonical.value,
                "canonicalJsonText": canonical.text,
                "parsedSummary": {}
            }));
        }
        if let Ok(shard) = parse_qvqcont7_shard(bytes) {
            return Ok(serde_json::json!({
                "command": "inspect",
                "ok": true,
                "cliSchemaVersion": 1,
                "file": path,
                "artifactType": "qcont",
                "artifactVersion": "QVqcont-7",
                "encoding": "binary",
                "digestAlg": "SHA3-512",
                "digestHex": sha3_512_hex(bytes),
                "canonicalJson": shard.meta_json,
                "canonicalJsonText": String::from_utf8_lossy(&shard.meta_bytes),
                "parsedSummary": {
                    "stateId": shard.state_id,
                    "cohortId": shard.cohort_id,
                    "shardIndex": shard.shard_index,
                    "archiveStateDigestHex": shard.archive_state_digest_hex,
                    "cohortBindingDigestHex": shard.cohort_binding_digest_hex,
                    "lifecycleBundleDigestHex": shard.lifecycle_bundle_digest_hex
                }
            }));
        }
        Ok(serde_json::json!({
            "command": "inspect",
            "ok": true,
            "cliSchemaVersion": 1,
            "file": path,
            "artifactType": "binary",
            "artifactVersion": "unknown",
            "encoding": "binary",
            "digestAlg": "SHA3-512",
            "digestHex": sha3_512_hex(bytes),
            "parsedSummary": {}
        }))
    }

    fn qv_code_string(error: &anyhow::Error) -> String {
        for cause in error.chain() {
            if let Some(qv_error) = cause.downcast_ref::<QvError>() {
                return qv_error
                    .qv_code()
                    .map(|code| code.as_str().to_string())
                    .unwrap_or_else(|| "UNEXPECTED".to_string());
            }
        }
        let text = error.to_string();
        if text.contains("Refusing")
            || text.contains("requires")
            || text.contains("must")
            || text.contains("not wired")
        {
            "USAGE".to_string()
        } else {
            "UNEXPECTED".to_string()
        }
    }

    fn build_required_policy_report(
        authenticity: &AuthenticityReport,
        required_level: Option<AuthPolicyLevelArg>,
    ) -> Option<Value> {
        let required = required_level?;
        let declared_level = authenticity.policy.level.as_str();
        let declared_strength = policy_strength(declared_level);
        let required_strength = policy_strength(AuthPolicyLevel::from(required).as_str());
        let declared_at_least = declared_strength >= required_strength;
        let archive_policy_satisfied = authenticity.policy.satisfied;
        let satisfied = archive_policy_satisfied && declared_at_least;
        let required_level_str = AuthPolicyLevel::from(required).as_str();
        let reason = if satisfied {
            format!("Archive policy satisfies required policy level {required_level_str}.")
        } else if archive_policy_satisfied {
            format!(
                "Archive policy level {declared_level} is weaker than required policy level {required_level_str}."
            )
        } else {
            format!("Archive policy did not satisfy its declared level {declared_level}.")
        };
        Some(serde_json::json!({
            "level": required_level_str,
            "declaredPolicyLevel": declared_level,
            "declaredPolicySatisfiesRequired": declared_at_least,
            "archivePolicySatisfied": archive_policy_satisfied,
            "satisfied": satisfied,
            "reason": reason,
        }))
    }

    fn verify_cli_report_satisfied(
        authenticity: &AuthenticityReport,
        required_policy: Option<&Value>,
    ) -> bool {
        if authenticity.policy.satisfied != true {
            return false;
        }
        let Some(req) = required_policy else {
            return true;
        };
        req.get("satisfied").and_then(Value::as_bool) == Some(true)
    }

    fn policy_strength(level: &str) -> u8 {
        match level {
            "integrity-only" => 1,
            "any-signature" => 2,
            "strong-pq-signature" => 3,
            _ => 0,
        }
    }

    fn json_requested() -> bool {
        env::args_os().any(|arg| arg == "--json")
    }

    fn command_name_from_args() -> Value {
        let commands = [
            "keygen",
            "encrypt",
            "decrypt",
            "split",
            "attach",
            "reshare",
            "inspect",
            "canonicalize",
            "verify",
            "restore",
            "selftest",
            "version",
        ];
        env::args()
            .skip(1)
            .find(|arg| commands.contains(&arg.as_str()))
            .map(Value::String)
            .unwrap_or(Value::Null)
    }
}
