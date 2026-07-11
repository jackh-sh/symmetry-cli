use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Write a file containing secrets, readable only by the current user
/// (0600 on Unix). Tightens the permissions of an existing file too.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // OpenOptions::mode only applies to newly created files; make sure a
        // pre-existing plaintext file ends up locked down as well.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))
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
}
