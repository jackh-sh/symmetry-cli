use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Write `bytes` to `path` atomically: a temp file in the same directory is
/// synced and renamed over the target, so a crash mid-write can't destroy
/// the existing file or leave a truncated one. `secret` restricts the file
/// to the current user (0600 on Unix).
pub fn write_atomic(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let write = || -> Result<()> {
        let dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        #[cfg(not(unix))]
        let _ = secret;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if secret { 0o600 } else { 0o644 };
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        tmp.write_all(bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path)?;
        Ok(())
    };
    write().with_context(|| format!("failed to write {}", path.display()))
}

/// Write a file containing secrets, readable only by the current user.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic(path, bytes, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn secret_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();

        let fresh = tmp.path().join("fresh.env");
        write_secret(&fresh, b"A=1\n").unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // An existing world-readable file gets tightened, not left as-is.
        let existing = tmp.path().join("existing.env");
        std::fs::write(&existing, b"OLD=1\n").unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret(&existing, b"NEW=1\n").unwrap();
        let mode = std::fs::metadata(&existing).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read(&existing).unwrap(), b"NEW=1\n");
    }

    #[test]
    fn atomic_write_replaces_existing_content() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("file.enc");
        write_atomic(&path, b"one", false).unwrap();
        write_atomic(&path, b"two", false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        // No temp file debris left behind.
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
    }
}
