use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use qvault_core::{
    attach_manifest_bundle_to_shards, build_bundle_payload, build_qcont_shards,
    current_bundle_filename, decrypt_qenc, encrypt_qenc, generate_key_pair, is_bundle_payload,
    parse_bundle_payload, parse_qcont_shard, restore_from_shards, AttachManifestBundleOptions,
    AuthPolicyLevel, AuthenticityReport, BundleEntryRef, EncryptQencOptions, NamedBinaryArtifact,
    QcontBuildOptions, QcontBuildParams, RestoreQcontOptions, VerificationInputs,
};

#[derive(Debug, Parser)]
#[command(
    name = "qvault-cli",
    version,
    about = "Compatibility-first local CLI for Quantum Vault containers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Keygen(KeygenArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Split(SplitArgs),
    Restore(RestoreArgs),
    Attach(AttachArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
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

#[derive(Debug, Args)]
struct KeygenArgs {
    #[arg(long, default_value = "public.qkey", help = "Public key output path")]
    public_key: PathBuf,
    #[arg(long, default_value = "secret.qkey", help = "Secret key output path")]
    secret_key: PathBuf,
}

#[derive(Debug, Args)]
struct EncryptArgs {
    #[arg(
        long = "input",
        required = true,
        help = "Input file. Repeat to encrypt multiple files into one bundled container"
    )]
    inputs: Vec<PathBuf>,
    #[arg(
        long,
        default_value = "public.qkey",
        help = "Quantum Vault public key path"
    )]
    public_key: PathBuf,
    #[arg(
        long,
        help = "Output .qenc path. Defaults to <input>.qenc or <bundle>.qvpack.qenc"
    )]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DecryptArgs {
    #[arg(long, help = "Input .qenc container path")]
    input: PathBuf,
    #[arg(
        long,
        default_value = "secret.qkey",
        help = "Quantum Vault secret key path"
    )]
    secret_key: PathBuf,
    #[arg(
        long,
        help = "Output file path, or extraction directory for bundled payloads"
    )]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SplitArgs {
    #[arg(long, help = "Input .qenc container path")]
    input_qenc: PathBuf,
    #[arg(
        long,
        default_value = "secret.qkey",
        help = "Matching Quantum Vault secret key path"
    )]
    secret_key: PathBuf,
    #[arg(long, help = "Total shard count")]
    n: u16,
    #[arg(long, help = "Data shard count")]
    k: u16,
    #[arg(long, help = "Output directory. Defaults to <input-stem>-shards")]
    out_dir: Option<PathBuf>,
    #[arg(
        long,
        value_enum,
        default_value = "integrity-only",
        help = "Archive authenticity policy for new shards"
    )]
    auth_policy_level: AuthPolicyLevelArg,
    #[arg(
        long,
        default_value_t = 1,
        help = "Minimum valid signatures required by the archive policy"
    )]
    min_valid_signatures: u64,
}

#[derive(Debug, Args)]
struct RestoreArgs {
    #[arg(
        long,
        help = "Reconstructed .qenc output path. Defaults from the shard base name"
    )]
    output_qenc: Option<PathBuf>,
    #[arg(
        long,
        help = "Reconstructed secret key output path. Defaults from the shard base name"
    )]
    output_secret_key: Option<PathBuf>,
    #[arg(long, help = "Uploaded canonical manifest to select a shard cohort")]
    manifest: Option<PathBuf>,
    #[arg(
        long,
        help = "Uploaded extended manifest bundle to select a shard cohort"
    )]
    bundle: Option<PathBuf>,
    #[arg(long = "signature", help = "Detached signature file (.qsig or .sig)")]
    signatures: Vec<PathBuf>,
    #[arg(
        long = "pqpk",
        help = "Pinned PQ signer key (.pqpk). Repeating is allowed only for identical files"
    )]
    pq_public_keys: Vec<PathBuf>,
    #[arg(long = "ots", help = "Detached OpenTimestamps proof file (.ots)")]
    timestamps: Vec<PathBuf>,
    #[arg(long, help = "Expected Stellar signer address for Ed25519 signatures")]
    expected_ed25519_signer: Option<String>,
    #[arg(required = true, help = "Input .qcont shard files")]
    shards: Vec<PathBuf>,
}

#[derive(Debug, Args)]
struct AttachArgs {
    #[arg(long, help = "Canonical manifest file (.qvmanifest.json)")]
    manifest: Option<PathBuf>,
    #[arg(
        long,
        help = "Existing extended manifest bundle (.extended.qvmanifest.json)"
    )]
    bundle: Option<PathBuf>,
    #[arg(long = "signature", help = "Detached signature file (.qsig or .sig)")]
    signatures: Vec<PathBuf>,
    #[arg(long = "pqpk", help = "Detached PQ signer key file (.pqpk)")]
    pq_public_keys: Vec<PathBuf>,
    #[arg(long = "ots", help = "Detached OpenTimestamps proof (.ots)")]
    timestamps: Vec<PathBuf>,
    #[arg(long, help = "Expected Stellar signer address for Ed25519 signatures")]
    expected_ed25519_signer: Option<String>,
    #[arg(
        long,
        help = "Write only the extended manifest bundle, not updated shards"
    )]
    bundle_only: bool,
    #[arg(long, help = "Output directory. Defaults to <base>-attached")]
    out_dir: Option<PathBuf>,
    #[arg(help = "Optional .qcont shard files to update with the embedded bundle")]
    shards: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => run_keygen(args),
        Command::Encrypt(args) => run_encrypt(args),
        Command::Decrypt(args) => run_decrypt(args),
        Command::Split(args) => run_split(args),
        Command::Restore(args) => run_restore(args),
        Command::Attach(args) => run_attach(args),
    }
}

fn run_keygen(args: KeygenArgs) -> Result<()> {
    let (public_key, secret_key) = generate_key_pair(None)?;
    fs::write(&args.public_key, public_key)
        .with_context(|| format!("Failed to write {}", args.public_key.display()))?;
    write_secret_file(&args.secret_key, &secret_key)?;
    println!("Generated ML-KEM-1024 keypair.");
    println!("Public key: {}", args.public_key.display());
    println!("Secret key: {}", args.secret_key.display());
    Ok(())
}

fn run_encrypt(args: EncryptArgs) -> Result<()> {
    let public_key = fs::read(&args.public_key)
        .with_context(|| format!("Failed to read {}", args.public_key.display()))?;

    let sources = args
        .inputs
        .iter()
        .map(|path| read_named_input_file(path))
        .collect::<Result<Vec<_>>>()?;
    if sources.len() == 1 {
        let source = &sources[0];
        let output_path = args
            .output
            .unwrap_or_else(|| default_encrypt_output_path(&source.path));
        let container = encrypt_qenc(
            &source.bytes,
            &public_key,
            &EncryptQencOptions {
                original_filename: Some(source.file_name.clone()),
                ..EncryptQencOptions::default()
            },
        )?;
        fs::write(&output_path, container)
            .with_context(|| format!("Failed to write {}", output_path.display()))?;
        println!("Encrypted file successfully.");
        println!("Input: {}", source.path.display());
        println!("Output: {}", output_path.display());
        return Ok(());
    }

    let bundle_name = current_bundle_filename();
    let output_path = args
        .output
        .unwrap_or_else(|| default_bundle_output_path(&args.inputs, &bundle_name));
    let bundle_entries = sources
        .iter()
        .map(|source| BundleEntryRef {
            name: source.file_name.as_str(),
            bytes: source.bytes.as_slice(),
        })
        .collect::<Vec<_>>();
    let bundle_bytes = build_bundle_payload(&bundle_entries)?;
    let container = encrypt_qenc(
        &bundle_bytes,
        &public_key,
        &EncryptQencOptions {
            original_filename: Some(bundle_name.clone()),
            ..EncryptQencOptions::default()
        },
    )?;
    fs::write(&output_path, container)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;
    println!("Bundled {} files into {}.", sources.len(), bundle_name);
    println!("Encrypted bundle successfully.");
    println!("Output: {}", output_path.display());
    Ok(())
}

fn run_decrypt(args: DecryptArgs) -> Result<()> {
    let container = fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;
    let secret_key = fs::read(&args.secret_key)
        .with_context(|| format!("Failed to read {}", args.secret_key.display()))?;
    let decrypted = decrypt_qenc(&container, &secret_key)?;

    if is_bundle_payload(&decrypted.file_bytes) {
        let (output_dir, warning) = resolve_bundle_output_dir(
            args.output.as_deref(),
            &args.input,
            decrypted.private_metadata.original_filename.as_deref(),
        )?;
        if let Some(warning) = warning {
            eprintln!("warning: {warning}");
        }
        let written_paths = extract_bundle_payload(&decrypted.file_bytes, &output_dir)?;
        println!("Decrypted bundle successfully.");
        println!("Integrity verified against wrapped payload SHA3-512.");
        println!(
            "Extracted {} file(s) to {}.",
            written_paths.len(),
            output_dir.display()
        );
    } else {
        let (output_path, warning) = resolve_single_file_output_path(
            args.output.as_deref(),
            &args.input,
            decrypted.private_metadata.original_filename.as_deref(),
        );
        if let Some(warning) = warning {
            eprintln!("warning: {warning}");
        }
        fs::write(&output_path, decrypted.file_bytes)
            .with_context(|| format!("Failed to write {}", output_path.display()))?;
        println!("Decrypted container successfully.");
        println!("Integrity verified against wrapped payload SHA3-512.");
        println!("Output: {}", output_path.display());
    }
    Ok(())
}

fn run_split(args: SplitArgs) -> Result<()> {
    let qenc_bytes = fs::read(&args.input_qenc)
        .with_context(|| format!("Failed to read {}", args.input_qenc.display()))?;
    let secret_key = fs::read(&args.secret_key)
        .with_context(|| format!("Failed to read {}", args.secret_key.display()))?;
    let built = build_qcont_shards(
        &qenc_bytes,
        &secret_key,
        QcontBuildParams {
            n: args.n,
            k: args.k,
        },
        &QcontBuildOptions {
            auth_policy_level: Some(args.auth_policy_level.into()),
            min_valid_signatures: Some(args.min_valid_signatures),
            ..QcontBuildOptions::default()
        },
    )?;

    let out_dir = args
        .out_dir
        .unwrap_or_else(|| default_split_out_dir(&args.input_qenc));
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("Failed to create {}", out_dir.display()))?;

    let base_name = output_base_name(&args.input_qenc);
    let manifest_path = out_dir.join(format!("{base_name}.qvmanifest.json"));
    fs::write(&manifest_path, &built.manifest_bytes)
        .with_context(|| format!("Failed to write {}", manifest_path.display()))?;

    let shard_count = built.shards.len();
    let threshold = args.k + ((args.n - args.k) / 2);
    for shard in built.shards {
        let part_number = usize::from(shard.index) + 1;
        let shard_path = out_dir.join(format!("{base_name}.part{part_number}-of-{}.qcont", args.n));
        fs::write(&shard_path, shard.bytes)
            .with_context(|| format!("Failed to write {}", shard_path.display()))?;
    }

    println!(
        "Split container successfully into {shard_count} shard(s) with threshold {threshold}."
    );
    println!(
        "Archive policy: {} (min valid signatures: {}).",
        built.bundle.auth_policy.level.as_str(),
        built.bundle.auth_policy.min_valid_signatures
    );
    println!("Manifest: {}", manifest_path.display());
    println!("Shard directory: {}", out_dir.display());
    Ok(())
}

fn run_restore(args: RestoreArgs) -> Result<()> {
    let manifest_bytes = args
        .manifest
        .as_ref()
        .map(|path| read_file(path))
        .transpose()?;
    let bundle_bytes = args
        .bundle
        .as_ref()
        .map(|path| read_file(path))
        .transpose()?;
    let signatures = load_named_artifacts(&args.signatures)?;
    let pq_public_keys = load_named_artifacts(&args.pq_public_keys)?;
    let timestamps = load_named_artifacts(&args.timestamps)?;
    let pinned_pq_public_key_file_bytes = select_single_pinned_pqpk(&pq_public_keys)?;

    let shards = args
        .shards
        .iter()
        .map(|path| {
            let bytes = read_file(path)?;
            parse_qcont_shard(&bytes)
                .with_context(|| format!("Failed to parse shard {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    let restored = restore_from_shards(
        &shards,
        &RestoreQcontOptions {
            manifest_bytes,
            bundle_bytes,
            verification: VerificationInputs {
                signatures,
                pinned_pq_public_key_file_bytes,
                timestamps,
                expected_ed25519_signer: normalize_optional_string(
                    args.expected_ed25519_signer.as_deref(),
                ),
            },
            strict: true,
        },
    )?;
    let default_base = default_restore_output_base(&args.shards);
    let output_qenc = args
        .output_qenc
        .unwrap_or_else(|| append_file_name_suffix(&default_base, ".qenc"));
    let output_secret_key = args
        .output_secret_key
        .unwrap_or_else(|| append_file_name_suffix(&default_base, ".qkey"));
    fs::write(&output_qenc, &restored.qenc_bytes)
        .with_context(|| format!("Failed to write {}", output_qenc.display()))?;
    write_secret_file(&output_secret_key, &restored.priv_key)?;

    print_authenticity_summary(&restored.authenticity, &restored.manifest_source);
    emit_restore_warnings(&restored);
    println!("Restored container successfully.");
    println!("Selected manifest digest: {}", restored.manifest_digest_hex);
    println!("Selected bundle digest: {}", restored.bundle_digest_hex);
    println!("Reconstructed .qenc hash verified.");
    if restored.qkey_ok {
        println!("Recovered secret key hash verified.");
    } else {
        eprintln!("warning: Recovered secret key hash does not match shard metadata.");
    }
    println!("Container output: {}", output_qenc.display());
    println!("Secret key output: {}", output_secret_key.display());

    Ok(())
}

fn run_attach(args: AttachArgs) -> Result<()> {
    let manifest_bytes = args
        .manifest
        .as_ref()
        .map(|path| read_file(path))
        .transpose()?;
    let bundle_bytes = args
        .bundle
        .as_ref()
        .map(|path| read_file(path))
        .transpose()?;
    let signatures = load_named_artifacts(&args.signatures)?;
    let pq_public_key_file_bytes_list = load_binary_blobs(&args.pq_public_keys)?;
    let timestamps = load_named_artifacts(&args.timestamps)?;
    let shards = args
        .shards
        .iter()
        .map(|path| {
            let bytes = read_file(path)?;
            parse_qcont_shard(&bytes)
                .with_context(|| format!("Failed to parse shard {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    let attached = attach_manifest_bundle_to_shards(
        &shards,
        &AttachManifestBundleOptions {
            manifest_bytes,
            bundle_bytes,
            signatures,
            pq_public_key_file_bytes_list,
            timestamps,
            expected_ed25519_signer: normalize_optional_string(
                args.expected_ed25519_signer.as_deref(),
            ),
            embed_into_shards: Some(!args.bundle_only),
        },
    )?;

    let out_dir = args.out_dir.unwrap_or_else(|| {
        default_attach_out_dir(
            &args.shards,
            args.manifest.as_deref(),
            args.bundle.as_deref(),
        )
    });
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("Failed to create {}", out_dir.display()))?;
    let base_name = derive_attach_base_name(
        &args.shards,
        args.manifest.as_deref(),
        args.bundle.as_deref(),
    );
    let bundle_path = out_dir.join(format!("{base_name}.extended.qvmanifest.json"));
    fs::write(&bundle_path, &attached.bundle_bytes)
        .with_context(|| format!("Failed to write {}", bundle_path.display()))?;

    if !attached.shards.is_empty() {
        let total = attached.bundle.manifest.sharding.reed_solomon.n;
        for shard in &attached.shards {
            let part_number = usize::from(shard.index) + 1;
            let shard_path =
                out_dir.join(format!("{base_name}.part{part_number}-of-{total}.qcont"));
            fs::write(&shard_path, &shard.bytes)
                .with_context(|| format!("Failed to write {}", shard_path.display()))?;
        }
    }

    println!("Updated manifest bundle successfully.");
    println!("Manifest digest: {}", attached.manifest_digest_hex);
    println!("Bundle digest: {}", attached.bundle_digest_hex);
    println!(
        "Archive policy: {} (min valid signatures: {}).",
        attached.bundle.auth_policy.level.as_str(),
        attached.bundle.auth_policy.min_valid_signatures
    );
    println!("Extended bundle: {}", bundle_path.display());
    if attached.shards.is_empty() {
        println!("No shard files were rewritten.");
    } else {
        println!(
            "Updated {} shard(s) in {}.",
            attached.shards.len(),
            out_dir.display()
        );
    }
    Ok(())
}

fn print_authenticity_summary(report: &AuthenticityReport, manifest_source: &str) {
    println!("Archive context: {manifest_source}.");
    println!(
        "Archive policy: {} (min valid signatures: {}).",
        report.policy.level.as_str(),
        report.policy.min_valid_signatures
    );
    println!(
        "Signature counts: valid={}, strong-pq={}, pinned={}, bundle-pinned={}, user-pinned={}.",
        report.verification.counts.valid_total,
        report.verification.counts.valid_strong_pq,
        report.verification.counts.pinned_valid_total,
        report.verification.counts.bundle_pinned_valid_total,
        report.verification.counts.user_pinned_valid_total
    );

    match report.policy.level {
        AuthPolicyLevel::IntegrityOnly => {
            println!("Integrity verified. The content is correct, but may not be authentic.");
        }
        _ if report.status.archive_policy_satisfied => {
            println!("Authenticity verified. Archive policy is satisfied.");
        }
        _ => {
            println!(
                "Authenticity could not be established: {}.",
                report.policy.reason
            );
        }
    }

    let linked_timestamps = report
        .timestamp_evidence
        .iter()
        .filter(|item| item.linked)
        .count();
    if linked_timestamps > 0 {
        println!("Linked timestamp proof(s): {linked_timestamps}.");
    }
}

fn emit_restore_warnings(restored: &qvault_core::RestoredQcont) {
    let mut seen = HashSet::new();
    for warning in &restored.warnings {
        if seen.insert(warning.clone()) {
            eprintln!("warning: {warning}");
        }
    }
    for warning in &restored.authenticity.verification.warnings {
        if seen.insert(warning.clone()) {
            eprintln!("warning: {warning}");
        }
    }
    for warning in &restored.authenticity.warnings {
        if seen.insert(warning.clone()) {
            eprintln!("warning: {warning}");
        }
    }
}

fn output_base_name(path: &Path) -> String {
    path.file_stem()
        .or_else(|| path.file_name())
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "container".to_string())
}

fn default_encrypt_output_path(input: &Path) -> PathBuf {
    input.with_file_name(format!("{}.qenc", file_name_or_default(input, "container")))
}

fn default_bundle_output_path(inputs: &[PathBuf], bundle_name: &str) -> PathBuf {
    let out_name = format!("{bundle_name}.qenc");
    shared_parent_dir(inputs)
        .map(|parent| parent.join(&out_name))
        .unwrap_or_else(|| PathBuf::from(out_name))
}

fn default_split_out_dir(input_qenc: &Path) -> PathBuf {
    input_qenc.with_file_name(format!("{}-shards", output_base_name(input_qenc)))
}

fn default_restore_output_base(shards: &[PathBuf]) -> PathBuf {
    let Some(first) = shards.first() else {
        return PathBuf::from("restored");
    };

    let base_name = strip_shard_suffix(first)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| output_base_name(first));
    first.with_file_name(base_name)
}

fn default_attach_out_dir(
    shards: &[PathBuf],
    manifest: Option<&Path>,
    bundle: Option<&Path>,
) -> PathBuf {
    let base_name = derive_attach_base_name(shards, manifest, bundle);
    if let Some(parent) = attach_source_parent(shards, manifest, bundle) {
        parent.join(format!("{base_name}-attached"))
    } else {
        PathBuf::from(format!("{base_name}-attached"))
    }
}

fn derive_attach_base_name(
    shards: &[PathBuf],
    manifest: Option<&Path>,
    bundle: Option<&Path>,
) -> String {
    if let Some(first_shard) = shards.first() {
        return strip_shard_suffix(first_shard).unwrap_or_else(|| output_base_name(first_shard));
    }
    if let Some(manifest) = manifest {
        return strip_manifest_like_suffix(&file_name_or_default(manifest, "archive"));
    }
    if let Some(bundle) = bundle {
        return strip_manifest_like_suffix(&file_name_or_default(bundle, "archive"));
    }
    "archive".to_string()
}

fn attach_source_parent(
    shards: &[PathBuf],
    manifest: Option<&Path>,
    bundle: Option<&Path>,
) -> Option<PathBuf> {
    shards
        .first()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .or_else(|| manifest.and_then(|path| path.parent().map(Path::to_path_buf)))
        .or_else(|| bundle.and_then(|path| path.parent().map(Path::to_path_buf)))
}

fn strip_shard_suffix(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_string_lossy();
    let (base, suffix) = stem.rsplit_once(".part")?;
    let (part, total) = suffix.split_once("-of-")?;
    if part.chars().all(|c| c.is_ascii_digit()) && total.chars().all(|c| c.is_ascii_digit()) {
        Some(base.to_string())
    } else {
        None
    }
}

fn resolve_single_file_output_path(
    explicit_output: Option<&Path>,
    input_path: &Path,
    original_filename: Option<&str>,
) -> (PathBuf, Option<String>) {
    if let Some(path) = explicit_output {
        return (path.to_path_buf(), None);
    }

    if let Some(original_filename) = original_filename {
        match validate_safe_filename(original_filename) {
            Ok(safe_name) => {
                return (input_path.with_file_name(safe_name), None);
            }
            Err(error) => {
                return (
                    input_path.with_file_name(default_decrypt_fallback_name(input_path)),
                    Some(format!(
                        "Ignoring unsafe original filename from metadata ({error}); using fallback output name."
                    )),
                );
            }
        }
    }

    (
        input_path.with_file_name(default_decrypt_fallback_name(input_path)),
        None,
    )
}

fn resolve_bundle_output_dir(
    explicit_output: Option<&Path>,
    input_path: &Path,
    original_filename: Option<&str>,
) -> Result<(PathBuf, Option<String>)> {
    if let Some(path) = explicit_output {
        return Ok((path.to_path_buf(), None));
    }

    let (default_name, warning) = match original_filename {
        Some(name) => match validate_safe_filename(name) {
            Ok(safe_name) => (strip_known_extension(safe_name, ".qvpack"), None),
            Err(error) => (
                default_decrypt_fallback_name(input_path),
                Some(format!(
                    "Ignoring unsafe original filename from metadata ({error}); using fallback bundle directory name."
                )),
            ),
        },
        None => (default_decrypt_fallback_name(input_path), None),
    };

    Ok((input_path.with_file_name(default_name), warning))
}

fn default_decrypt_fallback_name(input_path: &Path) -> String {
    output_base_name(input_path)
}

fn strip_known_extension(name: &str, extension: &str) -> String {
    name.strip_suffix(extension).unwrap_or(name).to_string()
}

fn strip_manifest_like_suffix(name: &str) -> String {
    if let Some(stripped) = name.strip_suffix(".extended.qvmanifest.json") {
        return stripped.to_string();
    }
    if let Some(stripped) = name.strip_suffix(".qvmanifest.json") {
        return stripped.to_string();
    }
    Path::new(name)
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| name.to_string())
}

fn file_name_or_default(path: &Path, default: &str) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn append_file_name_suffix(path: &Path, suffix: &str) -> PathBuf {
    path.with_file_name(format!(
        "{}{}",
        file_name_or_default(path, "output"),
        suffix
    ))
}

fn shared_parent_dir(paths: &[PathBuf]) -> Option<PathBuf> {
    let first_parent = paths.first()?.parent()?.to_path_buf();
    if paths
        .iter()
        .all(|path| path.parent() == Some(first_parent.as_path()))
    {
        Some(first_parent)
    } else {
        None
    }
}

fn validate_safe_filename(name: &str) -> Result<&str> {
    if name.is_empty() {
        bail!("filename is empty");
    }
    if name.contains('\0') {
        bail!("filename contains NUL");
    }

    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == std::ffi::OsStr::new(name) => {
            Ok(name)
        }
        _ => bail!("filename must be a single path component"),
    }
}

fn extract_bundle_payload(bundle_bytes: &[u8], output_dir: &Path) -> Result<Vec<PathBuf>> {
    if output_dir.exists() && !output_dir.is_dir() {
        return Err(anyhow!(
            "Bundle output path is not a directory: {}",
            output_dir.display()
        ));
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    let entries = parse_bundle_payload(bundle_bytes)?;
    let mut seen_names = HashSet::new();
    let mut written_paths = Vec::with_capacity(entries.len());
    for entry in entries {
        let safe_name = validate_safe_filename(&entry.name)
            .map_err(|error| anyhow!("Unsafe bundle entry name {:?}: {error}", entry.name))?;
        if !seen_names.insert(safe_name.to_string()) {
            bail!("Bundle contains duplicate entry name: {safe_name}");
        }
        let output_path = output_dir.join(safe_name);
        if output_path.exists() {
            bail!(
                "Refusing to overwrite existing bundle output: {}",
                output_path.display()
            );
        }
        fs::write(&output_path, entry.bytes)
            .with_context(|| format!("Failed to write {}", output_path.display()))?;
        written_paths.push(output_path);
    }

    Ok(written_paths)
}

#[derive(Debug, Clone)]
struct NamedInputFile {
    path: PathBuf,
    file_name: String,
    bytes: Vec<u8>,
}

fn read_named_input_file(path: &Path) -> Result<NamedInputFile> {
    let file_name = validate_safe_filename(&file_name_or_default(path, "input.bin"))?.to_string();
    let bytes = read_file(path)?;
    Ok(NamedInputFile {
        path: path.to_path_buf(),
        file_name,
        bytes,
    })
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read {}", path.display()))
}

fn load_named_artifacts(paths: &[PathBuf]) -> Result<Vec<NamedBinaryArtifact>> {
    paths.iter().map(|path| load_named_artifact(path)).collect()
}

fn load_named_artifact(path: &Path) -> Result<NamedBinaryArtifact> {
    Ok(NamedBinaryArtifact {
        name: file_name_or_default(path, "attachment.bin"),
        bytes: read_file(path)?,
    })
}

fn load_binary_blobs(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    paths.iter().map(|path| read_file(path)).collect()
}

fn select_single_pinned_pqpk(artifacts: &[NamedBinaryArtifact]) -> Result<Option<Vec<u8>>> {
    let mut unique = Vec::<Vec<u8>>::new();
    for artifact in artifacts {
        if !unique.iter().any(|bytes| bytes == &artifact.bytes) {
            unique.push(artifact.bytes.clone());
        }
    }
    match unique.len() {
        0 => Ok(None),
        1 => Ok(unique.into_iter().next()),
        _ => bail!(
            "Multiple different .pqpk files were provided. Keep only one pinned PQ key for restore."
        ),
    }
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("Failed to flush {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set permissions on {}", path.display()))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes).with_context(|| format!("Failed to write {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        append_file_name_suffix, default_attach_out_dir, default_bundle_output_path,
        default_decrypt_fallback_name, default_encrypt_output_path, default_restore_output_base,
        extract_bundle_payload, resolve_single_file_output_path, select_single_pinned_pqpk,
        strip_manifest_like_suffix, strip_shard_suffix, validate_safe_filename, write_secret_file,
    };
    use qvault_core::{build_bundle_payload, BundleEntryRef, NamedBinaryArtifact};
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    #[test]
    fn write_secret_file_uses_owner_only_permissions() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("qvault-cli-secret-{unique}.qkey"));

        write_secret_file(&path, b"secret-bytes").expect("write secret file");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        fs::remove_file(&path).expect("cleanup");

        assert_eq!(mode, 0o600);
    }

    #[test]
    fn default_encrypt_output_appends_qenc_to_input_filename() {
        let output = default_encrypt_output_path(Path::new("data/input.bin"));
        assert_eq!(output, PathBuf::from("data/input.bin.qenc"));
    }

    #[test]
    fn default_bundle_output_uses_shared_parent_when_possible() {
        let output = default_bundle_output_path(
            &[PathBuf::from("data/a.txt"), PathBuf::from("data/b.bin")],
            "bundle-2026-03-07T09-08-07.qvpack",
        );
        assert_eq!(
            output,
            PathBuf::from("data/bundle-2026-03-07T09-08-07.qvpack.qenc")
        );
    }

    #[test]
    fn restore_output_base_strips_part_suffix() {
        let base = default_restore_output_base(&[PathBuf::from("shards/archive.part3-of-5.qcont")]);
        assert_eq!(base, PathBuf::from("shards/archive"));
        assert_eq!(
            strip_shard_suffix(Path::new("archive.part3-of-5.qcont")).as_deref(),
            Some("archive")
        );
        assert_eq!(
            strip_shard_suffix(Path::new("archive.qcont")).as_deref(),
            None
        );
        assert_eq!(
            append_file_name_suffix(Path::new("shards/archive.bin"), ".qenc"),
            PathBuf::from("shards/archive.bin.qenc")
        );
    }

    #[test]
    fn resolve_single_file_output_prefers_safe_original_filename() {
        let (output, warning) = resolve_single_file_output_path(
            None,
            Path::new("data/input.qenc"),
            Some("restored.bin"),
        );
        assert_eq!(output, PathBuf::from("data/restored.bin"));
        assert!(warning.is_none());
    }

    #[test]
    fn resolve_single_file_output_warns_on_unsafe_original_filename() {
        let (output, warning) = resolve_single_file_output_path(
            None,
            Path::new("data/input.qenc"),
            Some("../escape.bin"),
        );
        assert_eq!(output, PathBuf::from("data/input"));
        assert!(warning.is_some());
        assert_eq!(
            default_decrypt_fallback_name(Path::new("data/input.qenc")),
            "input"
        );
    }

    #[test]
    fn validate_safe_filename_rejects_paths() {
        assert!(validate_safe_filename("../escape.bin").is_err());
        assert!(validate_safe_filename("subdir/file.bin").is_err());
        assert!(validate_safe_filename("/absolute.bin").is_err());
        assert!(validate_safe_filename("plain.bin").is_ok());
    }

    #[test]
    fn extract_bundle_payload_rejects_unsafe_entry_name() {
        let bundle = build_bundle_payload(&[BundleEntryRef {
            name: "../escape.bin",
            bytes: b"payload",
        }])
        .expect("build bundle");

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("qvault-cli-bundle-test-{unique}"));
        let error =
            extract_bundle_payload(&bundle, &dir).expect_err("bundle extraction should fail");
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("cleanup bundle dir");
        }

        assert!(error.to_string().contains("Unsafe bundle entry name"));
    }

    #[test]
    fn strip_manifest_like_suffix_matches_cli_output_naming() {
        assert_eq!(
            strip_manifest_like_suffix("archive.extended.qvmanifest.json"),
            "archive"
        );
        assert_eq!(
            strip_manifest_like_suffix("archive.qvmanifest.json"),
            "archive"
        );
        assert_eq!(strip_manifest_like_suffix("archive.json"), "archive");
    }

    #[test]
    fn default_attach_out_dir_uses_source_base_name() {
        let out_dir = default_attach_out_dir(
            &[PathBuf::from("shards/archive.part2-of-5.qcont")],
            None,
            None,
        );
        assert_eq!(out_dir, PathBuf::from("shards/archive-attached"));
    }

    #[test]
    fn restore_pinned_pqpk_rejects_multiple_different_files() {
        let error = select_single_pinned_pqpk(&[
            NamedBinaryArtifact {
                name: "a.pqpk".to_string(),
                bytes: vec![1, 2, 3],
            },
            NamedBinaryArtifact {
                name: "b.pqpk".to_string(),
                bytes: vec![4, 5, 6],
            },
        ])
        .expect_err("different pqpk files should be rejected");
        assert!(error
            .to_string()
            .contains("Multiple different .pqpk files were provided"));
    }
}
