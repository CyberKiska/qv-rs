use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use qvault_core::{
    build_qcont_shards, decrypt_qenc, encrypt_qenc, generate_key_pair, parse_qcont_shard,
    restore_from_shards, EncryptQencOptions, QcontBuildOptions, QcontBuildParams,
    RestoreQcontOptions,
};

#[derive(Debug, Parser)]
#[command(name = "qvault", version, about = "Quantum Vault local CLI skeleton")]
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
}

#[derive(Debug, Args)]
struct KeygenArgs {
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long)]
    secret_key: PathBuf,
}

#[derive(Debug, Args)]
struct EncryptArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct DecryptArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    secret_key: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct SplitArgs {
    #[arg(long)]
    input_qenc: PathBuf,
    #[arg(long)]
    secret_key: PathBuf,
    #[arg(long)]
    n: u16,
    #[arg(long)]
    k: u16,
    #[arg(long)]
    out_dir: PathBuf,
}

#[derive(Debug, Args)]
struct RestoreArgs {
    #[arg(long)]
    output_qenc: PathBuf,
    #[arg(long)]
    output_secret_key: PathBuf,
    #[arg(long)]
    manifest: Option<PathBuf>,
    #[arg(required = true)]
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
    }
}

fn run_keygen(args: KeygenArgs) -> Result<()> {
    let (public_key, secret_key) = generate_key_pair(None)?;
    fs::write(&args.public_key, public_key)
        .with_context(|| format!("Failed to write {}", args.public_key.display()))?;
    fs::write(&args.secret_key, secret_key)
        .with_context(|| format!("Failed to write {}", args.secret_key.display()))?;
    Ok(())
}

fn run_encrypt(args: EncryptArgs) -> Result<()> {
    let input = fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;
    let public_key = fs::read(&args.public_key)
        .with_context(|| format!("Failed to read {}", args.public_key.display()))?;
    let original_filename = args
        .input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    let container = encrypt_qenc(
        &input,
        &public_key,
        &EncryptQencOptions {
            original_filename,
            ..EncryptQencOptions::default()
        },
    )?;
    fs::write(&args.output, container)
        .with_context(|| format!("Failed to write {}", args.output.display()))?;
    Ok(())
}

fn run_decrypt(args: DecryptArgs) -> Result<()> {
    let container = fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;
    let secret_key = fs::read(&args.secret_key)
        .with_context(|| format!("Failed to read {}", args.secret_key.display()))?;
    let decrypted = decrypt_qenc(&container, &secret_key)?;
    fs::write(&args.output, decrypted.file_bytes)
        .with_context(|| format!("Failed to write {}", args.output.display()))?;
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
        &QcontBuildOptions::default(),
    )?;

    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("Failed to create {}", args.out_dir.display()))?;

    let base_name = output_base_name(&args.input_qenc);
    let manifest_path = args.out_dir.join(format!("{base_name}.qvmanifest.json"));
    fs::write(&manifest_path, &built.manifest_bytes)
        .with_context(|| format!("Failed to write {}", manifest_path.display()))?;

    for shard in built.shards {
        let part_number = usize::from(shard.index) + 1;
        let shard_path = args
            .out_dir
            .join(format!("{base_name}.part{part_number}-of-{}.qcont", args.n));
        fs::write(&shard_path, shard.bytes)
            .with_context(|| format!("Failed to write {}", shard_path.display()))?;
    }

    Ok(())
}

fn run_restore(args: RestoreArgs) -> Result<()> {
    let manifest_bytes = args
        .manifest
        .as_ref()
        .map(|path| {
            fs::read(path).with_context(|| format!("Failed to read manifest {}", path.display()))
        })
        .transpose()?;

    let shards = args
        .shards
        .iter()
        .map(|path| {
            let bytes = fs::read(path)
                .with_context(|| format!("Failed to read shard {}", path.display()))?;
            parse_qcont_shard(&bytes)
                .with_context(|| format!("Failed to parse shard {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    let restored = restore_from_shards(&shards, &RestoreQcontOptions { manifest_bytes })?;
    fs::write(&args.output_qenc, &restored.qenc_bytes)
        .with_context(|| format!("Failed to write {}", args.output_qenc.display()))?;
    fs::write(&args.output_secret_key, &restored.priv_key)
        .with_context(|| format!("Failed to write {}", args.output_secret_key.display()))?;

    for warning in restored.warnings {
        eprintln!("warning: {warning}");
    }

    Ok(())
}

fn output_base_name(path: &PathBuf) -> String {
    path.file_stem()
        .or_else(|| path.file_name())
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "container".to_string())
}
