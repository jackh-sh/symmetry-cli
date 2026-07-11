use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::commands::{decrypt_entry_full, enc_path, resolve_target, seal_entry};
use crate::envfile;
use crate::fsutil;
use crate::keystore::KeySource;
use crate::manifest::require_project;
use crate::ui;

pub fn set(key: &str, value: &str, file: Option<PathBuf>) -> Result<()> {
    validate_key(key)?;
    edit(file, |text| Ok((envfile::set_var(text, key, value), format!("set {key}"))))
}

pub fn unset(key: &str, file: Option<PathBuf>) -> Result<()> {
    validate_key(key)?;
    edit(file, |text| {
        let (updated, found) = envfile::unset_var(text, key);
        if !found {
            bail!("{key} is not set in this file");
        }
        Ok((updated, format!("removed {key}")))
    })
}

/// Apply a text edit to the resolved env file, re-encrypting in place when
/// the file is locked and editing the plaintext when it isn't.
fn edit(
    file: Option<PathBuf>,
    apply: impl FnOnce(&str) -> Result<(String, String)>,
) -> Result<()> {
    let (root, manifest) = require_project()?;
    let rel = resolve_target(&root, &manifest, file)?;
    let plain = root.join(&rel);
    let locked = enc_path(&plain).exists();

    let mut keys = KeySource::new(&manifest.project_id);
    if locked {
        let (bytes, mode) = decrypt_entry_full(&root, &rel, &mut keys)?;
        let text = String::from_utf8(bytes)
            .with_context(|| format!("{} is not valid UTF-8", rel.display()))?;
        let (updated, action) = apply(&text)?;
        seal_entry(&root, &rel, &mut keys, updated.as_bytes(), &mode)?;
        ui::ok(format!("{action} in {} (encrypted)", ui::path(rel.display())));
        if plain.exists() {
            ui::warn(format!(
                "a plaintext copy of {} is also on disk and was not changed",
                ui::path(rel.display())
            ));
        }
    } else {
        if !plain.exists() {
            bail!("{} has no encrypted or plaintext version", rel.display());
        }
        let text = std::fs::read_to_string(&plain)
            .with_context(|| format!("failed to read {}", plain.display()))?;
        let (updated, action) = apply(&text)?;
        fsutil::write_secret(&plain, updated.as_bytes())?;
        ui::ok(format!(
            "{action} in {} (plaintext, not yet encrypted)",
            ui::path(rel.display())
        ));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<()> {
    let valid = !key.is_empty()
        && !key.starts_with(|c: char| c.is_ascii_digit())
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        bail!("invalid variable name: {key}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_variable_names() {
        assert!(validate_key("API_KEY").is_ok());
        assert!(validate_key("_private").is_ok());
        assert!(validate_key("KEY2").is_ok());
        assert!(validate_key("").is_err());
        assert!(validate_key("2KEY").is_err());
        assert!(validate_key("KEY=VALUE").is_err());
        assert!(validate_key("KEY NAME").is_err());
    }
}
