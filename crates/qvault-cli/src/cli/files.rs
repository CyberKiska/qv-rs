use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
#[cfg(feature = "deterministic-test-vectors")]
use qvault_core::bytes::from_hex;
use qvault_core::error::{coded, QvCode};
use qvault_core::qcont::{parse_qvqcont7_shard, Qvqcont7Shard, MAX_QVQCONT7_SHARD_BYTES};
use qvault_core::validate_portable_filename;
use zeroize::Zeroizing;

use super::{CliContext, DecryptArgs, RestoreArgs};

const PUBLIC_FILE_MODE: u32 = 0o644;
const SECRET_FILE_MODE: u32 = 0o600;
pub(crate) const SMALL_ARTIFACT_READ_LIMIT: u64 = 32 * 1024 * 1024;
static NEXT_ATOMIC_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "deterministic-test-vectors")]
pub(crate) fn parse_fixed_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = from_hex(value).map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must decode to exactly 32 bytes"))
}

fn parse_lower_hex_selector(
    value: &str,
    expected_len: usize,
    field: &str,
) -> std::result::Result<String, String> {
    let value = value.trim();
    if value.len() != expected_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{field} must be {expected_len} lowercase hex characters"
        ));
    }
    Ok(value.to_string())
}

pub(crate) fn parse_archive_id_selector(value: &str) -> std::result::Result<String, String> {
    parse_lower_hex_selector(value, 64, "--archive-id")
}

pub(crate) fn parse_state_id_selector(value: &str) -> std::result::Result<String, String> {
    parse_lower_hex_selector(value, 128, "--state-id")
}

pub(crate) fn parse_cohort_id_selector(value: &str) -> std::result::Result<String, String> {
    parse_lower_hex_selector(value, 64, "--cohort-id")
}

pub(crate) fn parse_bundle_digest_selector(value: &str) -> std::result::Result<String, String> {
    parse_lower_hex_selector(value, 128, "--bundle-digest")
}

pub(crate) fn split_base_name(input_path: &Path) -> Result<String> {
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

pub(crate) fn default_restore_output_base(shards: &[PathBuf]) -> PathBuf {
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

pub(crate) fn append_file_name_suffix(path: &Path, suffix: &str) -> PathBuf {
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

pub(crate) fn read_bounded_file_checked(
    path: &Path,
    ctx: CliContext,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    reject_symlink_components(path, ctx.allow_symlink)?;
    let file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} must be a regular file: {}", path.display());
    }
    if metadata.len() > max_bytes {
        return Err(coded(
            QvCode::UnsupportedFormat,
            format!(
                "{label} exceeds maximum supported size of {max_bytes} bytes: {}",
                path.display()
            ),
        )
        .into());
    }
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("invalid maximum read length"))?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(coded(
            QvCode::UnsupportedFormat,
            format!(
                "{label} exceeded maximum supported size of {max_bytes} bytes while reading: {}",
                path.display()
            ),
        )
        .into());
    }
    Ok(bytes)
}

pub(crate) fn read_small_artifact_checked(
    path: &Path,
    ctx: CliContext,
    label: &str,
) -> Result<Vec<u8>> {
    read_bounded_file_checked(path, ctx, SMALL_ARTIFACT_READ_LIMIT, label)
}

fn preflight_bounded_file_set_checked(
    paths: &[PathBuf],
    ctx: CliContext,
    per_file_max_bytes: u64,
    aggregate_max_bytes: u64,
    label: &str,
) -> Result<()> {
    let mut aggregate_bytes = 0u64;
    for path in paths {
        reject_symlink_components(path, ctx.allow_symlink)?;
        let file =
            fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if !metadata.is_file() {
            bail!("{label} must be a regular file: {}", path.display());
        }
        if metadata.len() > per_file_max_bytes {
            return Err(coded(
                QvCode::UnsupportedFormat,
                format!(
                    "{label} exceeds per-file limit of {per_file_max_bytes} bytes: {}",
                    path.display()
                ),
            )
            .into());
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(metadata.len())
            .filter(|total| *total <= aggregate_max_bytes)
            .ok_or_else(|| {
                coded(
                    QvCode::UnsupportedFormat,
                    format!(
                        "{label} input set exceeds aggregate limit of {aggregate_max_bytes} bytes"
                    ),
                )
            })?;
    }
    Ok(())
}

pub(crate) fn read_qcont_shards_checked(
    paths: &[PathBuf],
    ctx: CliContext,
) -> Result<Vec<Qvqcont7Shard>> {
    let per_file_max = MAX_QVQCONT7_SHARD_BYTES as u64;
    preflight_bounded_file_set_checked(
        paths,
        ctx,
        per_file_max,
        ctx.max_shard_input_bytes,
        "QVqcont shard",
    )?;

    let mut remaining = ctx.max_shard_input_bytes;
    let mut shards = Vec::new();
    shards
        .try_reserve_exact(paths.len())
        .map_err(|_| anyhow::anyhow!("unable to allocate shard input list"))?;
    for path in paths {
        let read_limit = per_file_max.min(remaining);
        let bytes = Zeroizing::new(
            read_bounded_file_checked(path, ctx, read_limit, "QVqcont shard")
                .with_context(|| format!("failed to read {}", path.display()))?,
        );
        remaining = remaining
            .checked_sub(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("QVqcont aggregate input budget exhausted"))?;
        let shard = parse_qvqcont7_shard(bytes.as_slice()).map_err(|error| {
            anyhow::Error::from(coded(
                QvCode::InvalidFormat,
                format!("failed to parse shard {}: {error}", path.display()),
            ))
        })?;
        shards.push(shard);
    }
    Ok(shards)
}

pub(crate) fn write_file_checked(
    path: &Path,
    bytes: &[u8],
    force: bool,
    ctx: CliContext,
) -> Result<()> {
    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        reject_symlink_components(parent, ctx.allow_symlink)?;
    }
    if path.exists() {
        reject_symlink_components(path, ctx.allow_symlink)?;
    }
    write_file_atomic_platform(path, bytes, force, PUBLIC_FILE_MODE)
        .with_context(|| format!("failed to write {}", path.display()))
}

pub(crate) fn write_secret_file_checked(
    path: &Path,
    bytes: &[u8],
    force: bool,
    ctx: CliContext,
) -> Result<()> {
    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        reject_symlink_components(parent, ctx.allow_symlink)?;
    }
    if path.exists() {
        reject_symlink_components(path, ctx.allow_symlink)?;
    }
    write_file_atomic_platform(path, bytes, force, SECRET_FILE_MODE)
        .with_context(|| format!("failed to write secret file {}", path.display()))
}

pub(crate) fn signer_key_output_paths(out_prefix: &Path) -> Result<(PathBuf, PathBuf)> {
    if out_prefix.as_os_str().is_empty() || out_prefix.file_name().is_none() {
        bail!("--out must name an output file prefix");
    }
    Ok((
        append_file_name_os_suffix(out_prefix, ".pqpk"),
        append_file_name_os_suffix(out_prefix, ".pqsk"),
    ))
}

fn append_file_name_os_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut file_name = path
        .file_name()
        .expect("caller checked file_name")
        .to_os_string();
    file_name.push(suffix);
    path.with_file_name(file_name)
}

pub(crate) fn prepare_output_parent_dirs(paths: &[PathBuf], ctx: CliContext) -> Result<()> {
    for path in paths {
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            reject_symlink_components(parent, ctx.allow_symlink)?;
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
            reject_symlink_components(parent, ctx.allow_symlink)?;
        }
    }
    Ok(())
}

fn create_unique_atomic_temp_file(path: &Path, mode: u32) -> Result<(PathBuf, fs::File)> {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("artifact"));
    for attempt in 0..100u32 {
        let unique_id = NEXT_ATOMIC_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = OsString::from(".");
        temp_name.push(file_name);
        temp_name.push(format!(
            ".qvault-atomic-{}-{unique_id}-{attempt}.tmp",
            std::process::id(),
        ));
        let temp_path = parent.join(temp_name);
        match open_atomic_temp_file(&temp_path, mode) {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!(
        "failed to create unique atomic temp file for {}",
        path.display()
    )
}

fn open_atomic_temp_file(path: &Path, mode: u32) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)
}

fn write_file_atomic_platform(path: &Path, bytes: &[u8], force: bool, mode: u32) -> Result<()> {
    let (temp_path, mut file) = create_unique_atomic_temp_file(path, mode)?;
    let staged = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = staged {
        let _ = fs::remove_file(&temp_path);
        return Err(error).with_context(|| format!("failed to stage {}", path.display()));
    }

    let mut destination_created = false;
    let committed = if force {
        replace_file(&temp_path, path)
    } else {
        match fs::hard_link(&temp_path, path) {
            Ok(()) => {
                destination_created = true;
                fs::remove_file(&temp_path)
            }
            Err(error) => Err(error),
        }
    };
    if let Err(error) = committed {
        if destination_created {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(&temp_path);
        return Err(error).with_context(|| {
            if force {
                format!("failed to atomically replace {}", path.display())
            } else {
                format!(
                    "refusing to overwrite or failed to commit {}",
                    path.display()
                )
            }
        });
    }
    sync_parent_directory(path)
        .with_context(|| format!("failed to sync output directory for {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn replace_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp_path, path)
}

#[cfg(not(unix))]
fn replace_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(temp_path, path)
}

pub(crate) fn preflight_outputs(paths: &[PathBuf], force: bool, ctx: CliContext) -> Result<()> {
    ensure_distinct_output_paths(paths)?;
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

pub(crate) fn ensure_distinct_output_paths(paths: &[PathBuf]) -> Result<()> {
    let mut normalized = HashSet::with_capacity(paths.len());
    for path in paths {
        let absolute = if path.is_absolute() {
            path.clone()
        } else {
            env::current_dir()?.join(path)
        };
        let mut normalized_path = PathBuf::new();
        for component in absolute.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    normalized_path.pop();
                }
                Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                    normalized_path.push(component.as_os_str());
                }
            }
        }
        let identity = normalized_path
            .parent()
            .and_then(|parent| fs::canonicalize(parent).ok())
            .and_then(|parent| normalized_path.file_name().map(|name| parent.join(name)))
            .unwrap_or(normalized_path);
        if !normalized.insert(identity) {
            bail!("output paths must be distinct: {}", path.display());
        }
    }
    Ok(())
}

pub(crate) fn reject_symlink_components(path: &Path, allow_symlink: bool) -> Result<()> {
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
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect path component {}", current.display())
                })
            }
        };
        if metadata.file_type().is_symlink() {
            #[cfg(target_os = "macos")]
            if current == Path::new("/tmp") || current == Path::new("/var") {
                continue;
            }
            bail!(
                "Refusing symlink path component without --allow-symlink: {}",
                current.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_safe_name_prefix(prefix: &str) -> Result<()> {
    validate_portable_filename(&format!("{prefix}publicKey.qkey"))
        .map_err(|error| anyhow::anyhow!("--name must form portable key filenames: {error}"))
}

pub(crate) fn validate_optional_filename(filename: Option<&str>) -> Result<()> {
    if let Some(filename) = filename {
        if filename.starts_with('.') {
            bail!("--filename must not be hidden or a dot path component");
        }
        validate_portable_filename(filename)
            .map_err(|error| anyhow::anyhow!("--filename must be a portable basename: {error}"))?;
    }
    Ok(())
}

pub(crate) fn validate_cohort_cli_params(n: u16, k: u16) -> Result<()> {
    if k < 2 || k >= n {
        bail!("cohort parameters must satisfy 2 <= k < n");
    }
    if n > 255 {
        bail!("--n must not exceed 255 for QV-RS-ErasureCodes-v1");
    }
    if !(n - k).is_multiple_of(2) {
        bail!("--n minus --k must be even for QV-RS-ErasureCodes-v1");
    }
    Ok(())
}

fn safe_recovered_filename(filename: Option<&str>) -> Result<String> {
    let filename = filename.unwrap_or("decrypted");
    if filename.starts_with('.') {
        bail!("recovered original filename is unsafe");
    }
    validate_portable_filename(filename)
        .map_err(|error| anyhow::anyhow!("recovered original filename is unsafe: {error}"))?;
    Ok(filename.to_string())
}

pub(crate) fn decrypt_output_path(
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

pub(crate) fn restore_shard_paths(args: &RestoreArgs) -> Result<Vec<PathBuf>> {
    let mut shards = args.shard_inputs.clone();
    shards.extend(args.shards.iter().cloned());
    if shards.is_empty() {
        bail!("restore requires at least one --shards path or positional shard path");
    }
    Ok(shards)
}

#[cfg(test)]
mod tests {
    use super::super::DEFAULT_MAX_SHARD_INPUT_BYTES;
    use super::*;

    #[cfg(unix)]
    fn unique_test_dir(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let base = fs::canonicalize(env::temp_dir()).unwrap_or_else(|_| env::temp_dir());
        base.join(format!("qvault-cli-{name}-{}-{id}", std::process::id()))
    }

    #[cfg(unix)]
    #[test]
    fn secret_writer_creates_and_replaces_owner_only_files() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_test_dir("secret-mode");
        fs::create_dir(&dir)?;
        let path = dir.join("private.qkey");
        let ctx = CliContext {
            json: false,
            quiet: true,
            allow_symlink: false,
            max_shard_input_bytes: DEFAULT_MAX_SHARD_INPUT_BYTES,
        };

        write_secret_file_checked(&path, b"first-secret", false, ctx)?;
        assert_eq!(fs::read(&path)?, b"first-secret");
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        write_secret_file_checked(&path, b"second-secret", true, ctx)?;
        assert_eq!(fs::read(&path)?, b"second-secret");
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writer_refuses_clobber_and_force_replaces_destination() -> Result<()> {
        let dir = unique_test_dir("atomic-public");
        fs::create_dir(&dir)?;
        let path = dir.join("archive-state.json");
        let ctx = CliContext {
            json: false,
            quiet: true,
            allow_symlink: false,
            max_shard_input_bytes: DEFAULT_MAX_SHARD_INPUT_BYTES,
        };

        write_file_checked(&path, b"first", false, ctx)?;
        assert!(write_file_checked(&path, b"clobber", false, ctx).is_err());
        assert_eq!(fs::read(&path)?, b"first");

        write_file_checked(&path, b"replacement", true, ctx)?;
        assert_eq!(fs::read(&path)?, b"replacement");
        assert!(fs::read_dir(&dir)?.all(|entry| {
            !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .contains(".qvault-atomic-")
        }));

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn forced_output_replaces_symlink_itself_without_touching_target() -> Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = unique_test_dir("atomic-symlink");
        fs::create_dir(&dir)?;
        let target = dir.join("target");
        let output = dir.join("output");
        fs::write(&target, b"target-must-survive")?;
        symlink(&target, &output)?;
        let ctx = CliContext {
            json: false,
            quiet: true,
            allow_symlink: true,
            max_shard_input_bytes: DEFAULT_MAX_SHARD_INPUT_BYTES,
        };

        write_secret_file_checked(&output, b"new-secret", true, ctx)?;
        assert!(!fs::symlink_metadata(&output)?.file_type().is_symlink());
        assert_eq!(fs::read(&output)?, b"new-secret");
        assert_eq!(fs::read(&target)?, b"target-must-survive");
        assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn distinct_output_check_normalizes_dot_and_parent_components() {
        let first = PathBuf::from("outputs/archive.qenc");
        let alias = PathBuf::from("outputs/./nested/../archive.qenc");
        assert!(ensure_distinct_output_paths(&[first, alias]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_file_set_rejects_per_file_and_aggregate_limits_before_reading() -> Result<()> {
        let dir = unique_test_dir("bounded-input-set");
        fs::create_dir(&dir)?;
        let first = dir.join("first.qcont");
        let second = dir.join("second.qcont");
        fs::write(&first, [0u8; 8])?;
        fs::write(&second, [0u8; 7])?;
        let ctx = CliContext {
            json: false,
            quiet: true,
            allow_symlink: false,
            max_shard_input_bytes: DEFAULT_MAX_SHARD_INPUT_BYTES,
        };

        let per_file_error = preflight_bounded_file_set_checked(
            std::slice::from_ref(&first),
            ctx,
            7,
            100,
            "test artifact",
        )
        .expect_err("per-file limit must fail");
        assert!(per_file_error.to_string().contains("per-file limit"));

        let aggregate_error =
            preflight_bounded_file_set_checked(&[first, second], ctx, 8, 14, "test artifact")
                .expect_err("aggregate limit must fail");
        assert!(aggregate_error.to_string().contains("aggregate limit"));

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn distinct_output_check_resolves_parent_symlink_aliases() -> Result<()> {
        use std::os::unix::fs::symlink;

        let dir = unique_test_dir("distinct-symlink-parent");
        let real = dir.join("real");
        let alias = dir.join("alias");
        fs::create_dir_all(&real)?;
        symlink(&real, &alias)?;
        assert!(ensure_distinct_output_paths(&[
            real.join("same-output"),
            alias.join("same-output"),
        ])
        .is_err());
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn selector_parser_requires_exact_lowercase_hex() {
        assert!(parse_archive_id_selector(&"ab".repeat(32)).is_ok());
        assert!(parse_archive_id_selector(&"AB".repeat(32)).is_err());
        assert!(parse_state_id_selector(&"ab".repeat(63)).is_err());
        assert!(parse_bundle_digest_selector(&"0g".repeat(64)).is_err());
    }

    #[test]
    fn filename_validation_rejects_cross_platform_special_names() {
        for name in ["CON", "nul.txt", "COM1.log", "name:stream", "trailing."] {
            assert!(validate_optional_filename(Some(name)).is_err(), "{name}");
            assert!(safe_recovered_filename(Some(name)).is_err(), "{name}");
        }
        assert!(validate_optional_filename(Some("report.txt")).is_ok());
        assert_eq!(
            safe_recovered_filename(Some("report.txt")).unwrap(),
            "report.txt"
        );
    }
}
