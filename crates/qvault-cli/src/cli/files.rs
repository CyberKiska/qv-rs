use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use qvault_core::bytes::from_hex;
use qvault_core::error::{coded, QvCode};

use super::{CliContext, DecryptArgs, RestoreArgs};

pub(crate) fn parse_fixed_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = from_hex(value).map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must decode to exactly 32 bytes"))
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

pub(crate) fn read_file_checked(path: &Path, ctx: CliContext) -> Result<Vec<u8>> {
    reject_symlink_components(path, ctx.allow_symlink)?;
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

pub(crate) fn read_bounded_file_checked(
    path: &Path,
    ctx: CliContext,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    reject_symlink_components(path, ctx.allow_symlink)?;
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
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
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
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

pub(crate) fn write_file_checked(path: &Path, bytes: &[u8], ctx: CliContext) -> Result<()> {
    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        reject_symlink_components(parent, ctx.allow_symlink)?;
    }
    if path.exists() {
        reject_symlink_components(path, ctx.allow_symlink)?;
    }
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
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
    write_secret_file_platform(path, bytes, force)
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

#[cfg(unix)]
fn write_secret_file_platform(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    fn create_secret_file(path: &Path) -> io::Result<fs::File> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    fn write_and_sync_secret_file(
        path: &Path,
        mut file: fs::File,
        bytes: &[u8],
        cleanup_path: &Path,
    ) -> Result<()> {
        let result = (|| -> io::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        drop(file);
        if let Err(error) = result {
            let _ = fs::remove_file(cleanup_path);
            return Err(error).with_context(|| format!("failed to write {}", path.display()));
        }
        Ok(())
    }

    if !force {
        let file = create_secret_file(path)?;
        return write_and_sync_secret_file(path, file, bytes, path);
    }

    let (temp_path, file) = create_unique_secret_temp_file(path)?;
    write_and_sync_secret_file(path, file, bytes, &temp_path)?;
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
}

#[cfg(unix)]
fn create_unique_secret_temp_file(path: &Path) -> Result<(PathBuf, fs::File)> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("secret"));
    for attempt in 0..100u32 {
        let mut temp_name = OsString::from(".");
        temp_name.push(file_name);
        temp_name.push(format!(
            ".qvault-secret-{}-{attempt}.tmp",
            std::process::id()
        ));
        let temp_path = parent.join(temp_name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!(
        "failed to create unique secret temp file for {}",
        path.display()
    )
}

#[cfg(not(unix))]
fn write_secret_file_platform(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn preflight_outputs(paths: &[PathBuf], force: bool, ctx: CliContext) -> Result<()> {
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

pub(crate) fn validate_safe_name_prefix(prefix: &str) -> Result<()> {
    if prefix.contains(['/', '\\', '\0']) {
        bail!("--name must not contain path separators or NUL");
    }
    Ok(())
}

pub(crate) fn validate_optional_filename(filename: Option<&str>) -> Result<()> {
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
}
