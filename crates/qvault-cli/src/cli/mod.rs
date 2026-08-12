use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

mod artifacts;
mod commands;
mod errors;
mod files;
mod signatures;
use artifacts::*;
use errors::{command_name_from_args, json_requested, map_qv_code_to_exit, reported_exit};
pub(crate) use errors::{emit_error, exit_code};
use files::*;
use signatures::*;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use clap::{Parser, Subcommand, ValueEnum};
use qvault_core::auth::AuthPolicyLevel;
use qvault_core::auth::{
    create_detached_qsig, generate_signing_keypair, get_signature_suite_info, pack_public_key_file,
    pack_secret_key_file, public_from_secret, unpack_secret_key_file, verify_qsig_against_bytes,
    DetachedSignOptions, PqSignatureSuite, VerificationInputs,
};
use qvault_core::bytes::to_hex;
use qvault_core::error::{coded, QvCode};
use qvault_core::hash::{sha3_256, sha3_512_hex};
use qvault_core::lifecycle::{
    build_source_file_evidence, parse_archive_state_descriptor_bytes, SourceFileEvidenceOptions,
    SOURCE_EVIDENCE_CANONICALIZATION, SOURCE_EVIDENCE_OBJECT_TYPE_FILE,
    SOURCE_EVIDENCE_RELATION_ENCRYPTED_SOURCE,
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
    RestoreQvqcont7Options, RestoreQvqcont7Selection, MAX_QVQCONT7_SHARD_BYTES,
};
use qvault_core::qenc::{MAX_FILE_SIZE, MAX_QENC_CONTAINER_SIZE};
use qvault_core::{
    current_iso8601_utc_millis, decrypt_qenc, encrypt_qenc, generate_key_pair,
    parse_bundle_payload, parse_qenc_header, EncryptQencOptions,
};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

const MAX_SIGNED_TARGET_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_SHARD_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CONFIGURABLE_SHARD_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_GENERIC_ARTIFACT_INPUT_BYTES: u64 = MAX_QVQCONT7_SHARD_BYTES as u64;

fn randomness_report(purposes: &[&str], deterministic_inputs_used: bool) -> Value {
    serde_json::json!({
        "source": if deterministic_inputs_used {
            "test-vector-inputs-and-operating-system-csprng"
        } else {
            "operating-system-csprng"
        },
        "provider": "getrandom",
        "deterministic": deterministic_inputs_used,
        "deterministicInputsUsed": deterministic_inputs_used,
        "testVectorFeatureEnabled": cfg!(feature = "deterministic-test-vectors"),
        "failureMode": "fail-closed",
        "purposes": purposes
    })
}

#[derive(Parser)]
#[command(name = "qvault-cli")]
#[command(about = "Quantum Vault successor migration CLI")]
struct Cli {
    #[arg(long, global = true, help = "Emit cliSchemaVersion:1 JSON")]
    json: bool,
    #[arg(long, global = true, help = "Suppress non-error text output")]
    quiet: bool,
    #[arg(long, global = true, help = "Permit symlink paths and path components")]
    allow_symlink: bool,
    #[arg(
        long = "no-color",
        global = true,
        help = "Accept plain-output color opt-out"
    )]
    no_color: bool,
    #[arg(long, global = true, help = "Accept color opt-in for JS CLI parity")]
    color: bool,
    #[arg(
        long,
        global = true,
        default_value_t = DEFAULT_MAX_SHARD_INPUT_BYTES,
        value_parser = clap::value_parser!(u64).range(1..=MAX_CONFIGURABLE_SHARD_INPUT_BYTES),
        help = "Aggregate QVqcont shard input budget in bytes (maximum 2 GiB)"
    )]
    max_shard_input_bytes: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen(KeygenArgs),
    SignerKeygen(SignerKeygenArgs),
    Sign(SignArgs),
    SigVerify(SigVerifyArgs),
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
    max_shard_input_bytes: u64,
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
struct SignerKeygenArgs {
    #[arg(long, value_enum, default_value = "mldsa-87")]
    suite: PqSignatureSuiteArg,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Parser)]
struct SignArgs {
    #[arg(help = "Input file whose exact bytes are signed")]
    input_file: PathBuf,
    #[arg(long, help = "Detached PQ signing secret key (.pqsk)")]
    secret_key: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, value_enum, default_value = "bytes")]
    target: SignTargetArg,
    #[arg(
        long,
        help = "Display filename stored in unauthenticated QSIG metadata"
    )]
    filename: Option<String>,
    #[arg(
        long,
        help = "Display creation timestamp normalized to UTC milliseconds"
    )]
    created_at: Option<String>,
    #[arg(long)]
    force: bool,
}

#[derive(Parser)]
struct SigVerifyArgs {
    #[arg(help = "Input file whose exact bytes are verified")]
    input_file: PathBuf,
    #[arg(long, help = "Detached .qsig signature")]
    sig: PathBuf,
    #[arg(long, help = "Authoritative PQ signer public key (.pqpk)")]
    pqpk: Option<PathBuf>,
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
    #[arg(long, help = "PQ signing secret key (.pqsk) for source-evidence")]
    source_evidence_key: Option<PathBuf>,
    #[arg(long, help = "Canonical source-evidence JSON output path")]
    source_evidence_out: Option<PathBuf>,
    #[arg(long, help = "Detached QSIG output path for source-evidence JSON")]
    source_evidence_sig_out: Option<PathBuf>,
    #[arg(long, help = "Derived PQ signer public key (.pqpk) output path")]
    source_evidence_pqpk_out: Option<PathBuf>,
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
    #[arg(long, help = "PQ signing secret key (.pqsk) for archive approval")]
    archive_approval_key: Option<PathBuf>,
    #[cfg(feature = "deterministic-test-vectors")]
    #[arg(long, hide = true, value_parser = parse_archive_id_selector)]
    archive_id: Option<String>,
    #[cfg(feature = "deterministic-test-vectors")]
    #[arg(long, hide = true)]
    archive_id_random: Option<String>,
    #[cfg(feature = "deterministic-test-vectors")]
    #[arg(long, hide = true, value_parser = parse_state_id_selector)]
    parent_state_id: Option<String>,
    #[cfg(feature = "deterministic-test-vectors")]
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
    #[arg(
        long,
        help = "Explicit archiveId selection filter",
        value_parser = parse_archive_id_selector
    )]
    archive_id: Option<String>,
    #[arg(
        long,
        help = "Explicit stateId selection filter",
        value_parser = parse_state_id_selector
    )]
    state_id: Option<String>,
    #[arg(
        long,
        help = "Explicit cohortId selection filter",
        value_parser = parse_cohort_id_selector
    )]
    cohort_id: Option<String>,
    #[arg(
        long = "bundle-digest",
        alias = "lifecycle-bundle-digest",
        help = "Explicit lifecycle bundle digest selection filter",
        value_parser = parse_bundle_digest_selector
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
    #[arg(long, value_parser = parse_archive_id_selector)]
    archive_id: Option<String>,
    #[arg(long, value_parser = parse_state_id_selector)]
    state_id: Option<String>,
    #[arg(long, value_parser = parse_cohort_id_selector)]
    cohort_id: Option<String>,
    #[arg(long = "bundle-digest", value_parser = parse_bundle_digest_selector)]
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

#[derive(Clone, PartialEq, Eq)]
struct SplitShardOutput {
    index: u16,
    bytes: Vec<u8>,
}

impl Drop for SplitShardOutput {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

struct SplitArchiveApproval {
    suite: PqSignatureSuite,
    signer_fingerprint_hex: String,
    public_key_digest_hex: String,
    public_key_file_digest_hex: String,
    signature_digest_hex: String,
    signature_bytes: Vec<u8>,
    public_key_file_bytes: Vec<u8>,
}

#[derive(Clone)]
struct EncryptSourceEvidencePaths {
    source_evidence: PathBuf,
    signature: PathBuf,
    public_key: PathBuf,
}

struct EncryptSourceEvidenceArtifact {
    paths: EncryptSourceEvidencePaths,
    source_evidence_bytes: Vec<u8>,
    suite: PqSignatureSuite,
    signer_fingerprint_hex: String,
    source_digests: Value,
    public_key_digest_hex: String,
    public_key_file_digest_hex: String,
    signature_digest_hex: String,
    signature_bytes: Vec<u8>,
    public_key_file_bytes: Vec<u8>,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum PqSignatureSuiteArg {
    #[value(name = "mldsa-44", alias = "ml-dsa-44")]
    MlDsa44,
    #[value(name = "mldsa-65", alias = "ml-dsa-65")]
    MlDsa65,
    #[value(name = "mldsa-87", alias = "ml-dsa-87")]
    MlDsa87,
    #[value(name = "slhdsa-shake-128s", alias = "slh-dsa-shake-128s")]
    SlhDsaShake128s,
    #[value(name = "slhdsa-shake-192s", alias = "slh-dsa-shake-192s")]
    SlhDsaShake192s,
    #[value(name = "slhdsa-shake-256s", alias = "slh-dsa-shake-256s")]
    SlhDsaShake256s,
    #[value(name = "slhdsa-shake-256f", alias = "slh-dsa-shake-256f")]
    SlhDsaShake256f,
}

impl From<PqSignatureSuiteArg> for PqSignatureSuite {
    fn from(value: PqSignatureSuiteArg) -> Self {
        match value {
            PqSignatureSuiteArg::MlDsa44 => PqSignatureSuite::MlDsa44,
            PqSignatureSuiteArg::MlDsa65 => PqSignatureSuite::MlDsa65,
            PqSignatureSuiteArg::MlDsa87 => PqSignatureSuite::MlDsa87,
            PqSignatureSuiteArg::SlhDsaShake128s => PqSignatureSuite::SlhDsaShake128s,
            PqSignatureSuiteArg::SlhDsaShake192s => PqSignatureSuite::SlhDsaShake192s,
            PqSignatureSuiteArg::SlhDsaShake256s => PqSignatureSuite::SlhDsaShake256s,
            PqSignatureSuiteArg::SlhDsaShake256f => PqSignatureSuite::SlhDsaShake256f,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SignTargetArg {
    Bytes,
    ArchiveState,
    TransitionRecord,
    SourceEvidence,
}

impl SignTargetArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::ArchiveState => "archive-state",
            Self::TransitionRecord => "transition-record",
            Self::SourceEvidence => "source-evidence",
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
        max_shard_input_bytes: cli.max_shard_input_bytes,
    };
    let _color_flags_accepted = (cli.color, cli.no_color);
    commands::run(cli.command, ctx)
}
